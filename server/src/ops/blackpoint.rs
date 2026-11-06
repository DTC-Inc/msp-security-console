//! Blackpoint's ops: its open detections per client and one detection, its tenants and the client each one is
//! (confirmed, suggested, or neither), and its dark-web exposures. Read-only, from the console's own store; the
//! mapping is changed through POST /api/blackpoint/tenant (src/ops/actions.rs). Worst first; a tenant that isn't a
//! confirmed client says so.

use super::{page_by, Failure, Store};
use crate::contract::Params;
use crate::db::Pool;
use serde_json::{json, Value};
use std::collections::BTreeSet;

type When = Option<chrono::DateTime<chrono::Utc>>;

/// When a job last succeeded (its data's "as of").
pub async fn job_ok(pool: &Pool, names: &[&str]) -> Value {
    let rows: Vec<(String, When)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT name, last_ok_at FROM job").fetch_all(p).await.unwrap_or_default());
    let mut m = serde_json::Map::new();
    for (n, t) in rows { if names.contains(&n.as_str()) { m.insert(n, json!(t)); } }
    Value::Object(m)
}

/// A detection's row as both drivers decode it (more columns than sqlx's tuples carry, so by position).
macro_rules! detection_rows {
    ($rows:expr) => {{
        use sqlx::Row as _;
        let mut out = Vec::new();
        for r in $rows {
            let id: String = r.try_get(0).map_err(|_| Failure::Db)?;
            let status: String = r.try_get(5).map_err(|_| Failure::Db)?;
            out.push(json!({ "detection_id": id, "tenant_id": r.try_get::<String, _>(1).map_err(|_| Failure::Db)?, "tenant_name": r.try_get::<String, _>(2).map_err(|_| Failure::Db)?,
                "org_id": r.try_get::<Option<i64>, _>(3).map_err(|_| Failure::Db)?, "client": r.try_get::<Option<String>, _>(4).map_err(|_| Failure::Db)?,
                "open": status == "OPEN", "status": status,
                "risk_score": r.try_get::<Option<i64>, _>(6).map_err(|_| Failure::Db)?, "alert_count": r.try_get::<Option<i64>, _>(7).map_err(|_| Failure::Db)?,
                "alert_types": r.try_get::<Option<Value>, _>(8).map_err(|_| Failure::Db)?.unwrap_or(json!([])),
                "hostname": r.try_get::<Option<String>, _>(9).map_err(|_| Failure::Db)?, "username": r.try_get::<Option<String>, _>(10).map_err(|_| Failure::Db)?,
                "detection_name": r.try_get::<Option<String>, _>(11).map_err(|_| Failure::Db)?, "rule_name": r.try_get::<Option<String>, _>(12).map_err(|_| Failure::Db)?,
                "created": r.try_get::<When, _>(13).map_err(|_| Failure::Db)?, "updated": r.try_get::<When, _>(14).map_err(|_| Failure::Db)?,
                "last_seen_open": r.try_get::<When, _>(15).map_err(|_| Failure::Db)?, "device_id": r.try_get::<Option<i64>, _>(16).map_err(|_| Failure::Db)?,
                "device_name": r.try_get::<Option<String>, _>(17).map_err(|_| Failure::Db)?, "halo_ticket_id": r.try_get::<Option<i64>, _>(18).map_err(|_| Failure::Db)?,
                "finding": format!("detection:{id}") }));
        }
        out
    }};
}

const SELECT: &str = "SELECT g.detection_id, g.tenant_id, t.name, t.org_id, c.name, g.status, g.risk_score, g.alert_count, g.alert_types, g.hostname, g.username, g.detection_name,
        g.rule_name, g.created, g.updated, g.last_seen_open, x.device_id, d.name, ft.halo_ticket_id
   FROM bp_detection g JOIN bp_tenant t ON t.tenant_id = g.tenant_id
   LEFT JOIN client c ON c.org_id = t.org_id
   LEFT JOIN (SELECT a.tenant_id, upper(a.hostname) AS h, min(a.device_id) AS device_id FROM bp_asset a
               WHERE a.deleted_at IS NULL AND a.device_id IS NOT NULL GROUP BY a.tenant_id, upper(a.hostname)) x ON x.tenant_id = g.tenant_id AND x.h = upper(g.hostname)
   LEFT JOIN device d ON d.device_id = x.device_id
   LEFT JOIN finding_ticket ft ON ft.finding_key = 'detection:' || g.detection_id AND ft.state = 'created'";

/// Open detections (and, with include_closed, those closed in the last 30 days), for one client or tenant or all,
/// worst first: open, then the risk score, then the newest. Totals are over the open ones, each one a filter the web
/// app applies to these rows.
pub async fn detections_list(s: &Store, p: &Params) -> Result<Value, Failure> {
    let closed = p.include_closed.unwrap_or(false);
    let since = crate::db::Ts(chrono::Utc::now() - chrono::Duration::days(30));
    let org = p.org_id.map(|x| x as i64);
    let list: Vec<Value> = crate::on_pool!(&s.pool, db, pg => {
        let sql = if pg { format!("{SELECT} WHERE (g.status = 'OPEN' OR ($1 AND g.last_seen_open > $2)) AND ($3::bigint IS NULL OR t.org_id = $3) AND ($4::text IS NULL OR g.tenant_id = $4)") }
                  else { format!("{SELECT} WHERE (g.status = 'OPEN' OR ($1 AND g.last_seen_open > $2)) AND ($3 IS NULL OR t.org_id = $3) AND ($4 IS NULL OR g.tenant_id = $4)") };
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(closed).bind(since).bind(org).bind(p.tenant_id.clone()).fetch_all(db).await.map_err(|_| Failure::Db)?;
        detection_rows!(rows)
    });
    let open: Vec<&Value> = list.iter().filter(|r| r["open"] == json!(true)).collect();
    let totals = json!({
        "open": open.len(),
        "clients": open.iter().filter_map(|r| r["org_id"].as_i64()).collect::<BTreeSet<_>>().len(),
        "high_risk": open.iter().filter(|r| r["risk_score"].as_i64().unwrap_or(0) >= 80).count(),
        "unmapped": open.iter().filter(|r| r["org_id"].is_null()).count(),
        "without_ticket": open.iter().filter(|r| r["halo_ticket_id"].is_null()).count(),
    });
    let ms = |v: &Value| v.as_str().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok()).map(|t| t.timestamp_millis()).unwrap_or(0);
    let key = |x: &Value| vec![json!(if x["open"] == json!(true) { 0 } else { 1 }), json!(-x["risk_score"].as_i64().unwrap_or(-1)), json!(-ms(&x["created"])), x["detection_id"].clone()];
    let (data, next) = page_by(list, key, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(200)).map_err(Failure::Bad)?;
    Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "as_of": job_ok(&s.pool, &["blackpoint_detections", "blackpoint_tenants"]).await }))
}

pub async fn detection_get(s: &Store, p: &Params) -> Result<Value, Failure> {
    let id = p.detection_id.clone().ok_or_else(|| Failure::Bad("detection_id is required".into()))?;
    // Within the caller's client (org_id, a pinned caller's own): another client's detection is a 404, as a device is.
    let org = p.org_id.map(|x| x as i64);
    let r: Vec<Value> = crate::on_pool!(&s.pool, db, pg => {
        let sql = if pg { format!("{SELECT} WHERE g.detection_id = $1 AND ($2::bigint IS NULL OR t.org_id = $2)") }
                  else { format!("{SELECT} WHERE g.detection_id = $1 AND ($2 IS NULL OR t.org_id = $2)") };
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(&id).bind(org).fetch_all(db).await.map_err(|_| Failure::Db)?;
        detection_rows!(rows)
    });
    let Some(one) = r.into_iter().next() else { return Err(Failure::NotFound("no such detection".into())) };
    Ok(json!({ "data": one, "next_cursor": null, "as_of": job_ok(&s.pool, &["blackpoint_detections"]).await }))
}

type TenantRow = (String, String, Option<String>, Option<i64>, Option<String>, bool, Option<String>, When, Option<i64>, Option<String>, Option<String>, bool, i64, i64, i64);

/// Every tenant and the client it is: unmapped first (no decision and no suggestion), then suggested, then decided,
/// each with how, who decided and when, its assets and how many are tied to devices, and its open detections. The
/// clients come too, for the picker. With org_id (a pinned caller's own client, or a filter), only the tenants
/// confirmed as that client, and only that client for the picker: never another client's tenant or name.
pub async fn tenants(s: &Store, p: &Params) -> Result<Value, Failure> {
    let org = p.org_id.map(|x| x as i64);
    let (rows, clients): (Vec<TenantRow>, Vec<(i64, String)>) = crate::on_pool!(&s.pool, db, _ => (
        sqlx::query_as(
            "SELECT t.tenant_id, t.name, t.domain, t.org_id, c.name, t.not_client, t.mapped_by, t.mapped_at, t.suggested_org_id, sc.name, t.suggested_by, t.vm_licensed, t.open_detections,
                    (SELECT count(*) FROM bp_asset a WHERE a.tenant_id = t.tenant_id AND a.deleted_at IS NULL),
                    (SELECT count(*) FROM bp_asset a WHERE a.tenant_id = t.tenant_id AND a.deleted_at IS NULL AND a.device_id IS NOT NULL)
               FROM bp_tenant t LEFT JOIN client c ON c.org_id = t.org_id LEFT JOIN client sc ON sc.org_id = t.suggested_org_id
              WHERE t.deleted_at IS NULL AND (CAST($1 AS BIGINT) IS NULL OR t.org_id = $1)").bind(org).fetch_all(db).await.map_err(|_| Failure::Db)?,
        sqlx::query_as("SELECT org_id, name FROM client WHERE deleted_at IS NULL AND (CAST($1 AS BIGINT) IS NULL OR org_id = $1) ORDER BY name, org_id").bind(org).fetch_all(db).await.map_err(|_| Failure::Db)?));
    let mut list: Vec<Value> = rows.into_iter().map(|(id, name, domain, org, cname, not_client, by, at, sorg, sname, sby, lic, open, assets, matched)| {
        let state = if org.is_some() { "confirmed" } else if not_client { "not_client" } else if sorg.is_some() { "suggested" } else { "unmapped" };
        json!({ "tenant_id": id, "name": name, "domain": domain, "state": state, "org_id": org, "client": cname, "mapped_by": by, "mapped_at": at,
                "suggested_org_id": sorg, "suggested_client": sname, "suggested_by": sby, "vm_licensed": lic, "open_detections": open, "assets": assets, "assets_matched": matched })
    }).collect();
    let rank = |s: &str| match s { "unmapped" => 0, "suggested" => 1, "confirmed" => 2, _ => 3 };
    list.sort_by(|a, b| rank(a["state"].as_str().unwrap_or("")).cmp(&rank(b["state"].as_str().unwrap_or(""))).then(a["name"].as_str().cmp(&b["name"].as_str())));
    let n = |st: &str| list.iter().filter(|r| r["state"] == st).count();
    let totals = json!({ "tenants": list.len(), "confirmed": n("confirmed"), "suggested": n("suggested"), "unmapped": n("unmapped"), "not_client": n("not_client") });
    Ok(json!({ "data": list, "clients": clients.into_iter().map(|(o, n)| json!({ "org_id": o, "name": n })).collect::<Vec<_>>(), "totals": totals,
               "next_cursor": null, "as_of": job_ok(&s.pool, &["blackpoint_tenants"]).await }))
}

/// Dark-web exposures: the email, where it was seen, when, and what kind of data. Nothing else is held to show.
pub async fn darkweb(s: &Store, p: &Params) -> Result<Value, Failure> {
    let org = p.org_id.map(|x| x as i64);
    type R = (String, Option<String>, Option<String>, Option<chrono::NaiveDate>, String, String, String, Option<i64>, Option<String>);
    let rows: Vec<R> = crate::on_pool!(&s.pool, db, pg => sqlx::query_as(if pg {
        "SELECT w.exposure_id, w.email, w.source, w.found_on, w.kind, w.tenant_id, t.name, t.org_id, c.name FROM bp_darkweb w JOIN bp_tenant t ON t.tenant_id = w.tenant_id
           LEFT JOIN client c ON c.org_id = t.org_id WHERE w.deleted_at IS NULL AND ($1::bigint IS NULL OR t.org_id = $1) AND ($2::text IS NULL OR w.tenant_id = $2)"
    } else {
        "SELECT w.exposure_id, w.email, w.source, w.found_on, w.kind, w.tenant_id, t.name, t.org_id, c.name FROM bp_darkweb w JOIN bp_tenant t ON t.tenant_id = w.tenant_id
           LEFT JOIN client c ON c.org_id = t.org_id WHERE w.deleted_at IS NULL AND ($1 IS NULL OR t.org_id = $1) AND ($2 IS NULL OR w.tenant_id = $2)"
    }).bind(org).bind(p.tenant_id.clone()).fetch_all(db).await.map_err(|_| Failure::Db)?);
    let list: Vec<Value> = rows.into_iter().map(|(id, email, source, on, kind, tid, tname, org, cname)| json!({ "exposure_id": id, "email": email, "source": source,
        "found_on": on, "kind": kind, "tenant_id": tid, "tenant_name": tname, "org_id": org, "client": cname })).collect();
    let totals = json!({ "exposures": list.len(), "passwords": list.iter().filter(|r| r["kind"] == "password").count(),
                         "emails": list.iter().filter_map(|r| r["email"].as_str()).collect::<BTreeSet<_>>().len() });
    let key = |x: &Value| vec![json!(if x["kind"] == "password" { 0 } else { 1 }), json!(x["found_on"].as_str().map(|d| -(d.replace('-', "").parse::<i64>().unwrap_or(0))).unwrap_or(0)),
                               x["email"].clone(), x["exposure_id"].clone()];
    let (data, next) = page_by(list, key, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(200)).map_err(Failure::Bad)?;
    Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "as_of": job_ok(&s.pool, &["blackpoint_vulns"]).await }))
}
