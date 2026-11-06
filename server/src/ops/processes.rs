//! Running processes, as evidence: `processes.list` (the binaries, one row each, with what product and version
//! each is, how sure, and that version's CVEs) and `processes.review` (the names the automatic mapping wouldn't
//! decide, running or installed); and a signed-in user's decision on one of those (`decide`, POST /api/review).

use super::{page_by, Failure, Store};
use crate::contract::{Decide, Params, ReviewDecision};
use crate::db as store;
use crate::process::{trust_rank, TRUST_ORDER};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

/// A device whose last run is older than this is "not reporting".
pub const STALE_DAYS: i64 = 3;
/// Devices listed with a binary, at most.
const DEVICES_PER_BINARY: usize = 100;

fn is_sha256(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) }

impl Store {
    /// The binaries running in scope (org_id, device_id), one row each: by hash, or text over the name, product,
    /// company and signer (`q`), or a product (`product_key`), or a trust class (`state`). Worst trust first, then
    /// the ones with CVEs, then the rarest. A hash, or one device, lists the devices and paths too.
    pub(super) async fn processes_list(&self, p: &Params) -> Result<Value, Failure> {
        if let Some(s) = &p.state && !TRUST_ORDER.contains(&s.as_str()) { return Err(Failure::Bad(format!("state must be one of {} for processes.list", TRUST_ORDER.join(", ")))); }
        let q = p.q.as_deref().map(str::trim).filter(|q| !q.is_empty()).map(String::from);
        let hash = q.as_deref().filter(|q| is_sha256(q)).map(str::to_lowercase);
        let like = q.as_deref().filter(|_| hash.is_none()).map(|q| format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
        type Bin = (i64, String, Option<String>, String, Value, Option<String>, Option<String>, Option<String>, Option<String>, String, i64, i64, Option<String>, String);
        let rows: Vec<Bin> = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT p.device_id, p.key, p.sha256, p.name, p.paths, p.file_version, p.product, p.company, p.signer, p.trust, p.instance_count, d.org_id, c.name, d.name
               FROM device_process p JOIN device d ON d.device_id = p.device_id AND d.deleted_at IS NULL LEFT JOIN client c ON c.org_id = d.org_id
              WHERE ($1::bigint IS NULL OR d.org_id = $1) AND ($2::bigint IS NULL OR p.device_id = $2) AND ($3::text IS NULL OR p.sha256 = $3)
                AND ($4::text IS NULL OR p.name ILIKE $4 OR p.product ILIKE $4 OR p.company ILIKE $4 OR p.signer ILIKE $4)
                AND ($5::text IS NULL OR p.trust = $5)"
        } else {
            "SELECT p.device_id, p.key, p.sha256, p.name, p.paths, p.file_version, p.product, p.company, p.signer, p.trust, p.instance_count, d.org_id, c.name, d.name
               FROM device_process p JOIN device d ON d.device_id = p.device_id AND d.deleted_at IS NULL LEFT JOIN client c ON c.org_id = d.org_id
              WHERE ($1 IS NULL OR d.org_id = $1) AND ($2 IS NULL OR p.device_id = $2) AND ($3 IS NULL OR p.sha256 = $3)
                AND ($4 IS NULL OR p.name LIKE $4 ESCAPE '\\' OR p.product LIKE $4 ESCAPE '\\' OR p.company LIKE $4 ESCAPE '\\' OR p.signer LIKE $4 ESCAPE '\\')
                AND ($5 IS NULL OR p.trust = $5)"
        }).bind(p.org_id.map(|x| x as i64)).bind(p.device_id.map(|x| x as i64)).bind(hash.clone()).bind(like).bind(p.state.clone()).fetch_all(db).await.map_err(|_| Failure::Db)?);
        // What each binary is: its class (product, company, version), the product's label, that version's CVEs.
        type Class = (String, String, String, String, Option<String>, String, f64, Option<String>);
        type Cves = (String, String, i64, i64, Option<f64>);
        let (classes, cves, fleet): (Vec<Class>, Vec<Cves>, Vec<(String, i64)>) = crate::on_pool!(&self.pool, db, _ => (
            sqlx::query_as("SELECT c.product, c.company, c.file_version, c.product_key, c.product_version, c.method, c.confidence, p.label
                              FROM sec_process_class c LEFT JOIN sec_product p ON p.product_key = c.product_key").fetch_all(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as("SELECT product_key, version, count(*), sum(CASE WHEN kev THEN 1 ELSE 0 END), max(cvss) FROM sec_pair_cve GROUP BY product_key, version")
                .fetch_all(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as("SELECT key, count(*) FROM device_process GROUP BY key").fetch_all(db).await.map_err(|_| Failure::Db)?));
        let classes: HashMap<(String, String, String), Class> = classes.into_iter().map(|c| ((c.0.clone(), c.1.clone(), c.2.clone()), c)).collect();
        let cves: HashMap<(String, String), Cves> = cves.into_iter().map(|c| ((c.0.clone(), c.1.clone()), c)).collect();
        let fleet: HashMap<String, i64> = fleet.into_iter().collect();
        let detailed = hash.is_some() || p.device_id.is_some();
        struct B { first: Bin, trust: String, devices: Vec<Value>, n: usize, orgs: std::collections::BTreeSet<i64>, instances: i64 }
        let mut by: BTreeMap<String, B> = BTreeMap::new();
        for r in rows {
            let b = by.entry(r.1.clone()).or_insert_with(|| B { first: r.clone(), trust: r.9.clone(), devices: vec![], n: 0, orgs: Default::default(), instances: 0 });
            if trust_rank(&r.9) < trust_rank(&b.trust) { b.trust = r.9.clone(); }
            b.orgs.insert(r.11); b.instances += r.10; b.n += 1;
            if b.devices.len() < DEVICES_PER_BINARY { b.devices.push(json!({ "device_id": r.0, "device_name": r.13, "org_id": r.11, "org_name": r.12, "paths": r.4, "file_version": r.5, "instance_count": r.10 })); }
        }
        let product_filter = p.product_key.as_deref();
        let mut list: Vec<Value> = Vec::new();
        for (key, b) in by {
            let f = &b.first;
            let class = classes.get(&(f.6.clone().unwrap_or_default(), f.7.clone().unwrap_or_default(), f.5.clone().unwrap_or_default()));
            if product_filter.is_some_and(|k| class.is_none_or(|c| c.3 != k)) { continue; }
            let found = class.and_then(|c| cves.get(&(c.3.clone(), c.4.clone().unwrap_or_default())));
            // Classified at a version with no CVE row is a clean version: 0. With no version, nothing was checked.
            let checked = class.is_some_and(|c| c.4.is_some());
            let mut row = json!({ "key": key, "sha256": f.2, "name": f.3, "product": f.6, "company": f.7, "file_version": f.5, "signer": f.8, "trust": b.trust,
                "devices": b.n, "clients": b.orgs.len(), "instances": b.instances, "fleet_devices": fleet.get(&key).copied().unwrap_or(0),
                "product_key": class.map(|c| c.3.clone()), "product_label": class.and_then(|c| c.7.clone()), "product_version": class.and_then(|c| c.4.clone()),
                "method": class.map(|c| c.5.clone()), "confidence": class.map(|c| c.6),
                "cve_count": found.map(|x| x.2).or(checked.then_some(0)), "kev_count": found.map(|x| x.3).or(checked.then_some(0)), "max_cvss": found.and_then(|x| x.4) });
            if detailed { row["device_list"] = json!(b.devices); }
            list.push(row);
        }
        let total = list.len();
        let key = |x: &Value| vec![json!(trust_rank(x["trust"].as_str().unwrap_or(""))), json!(if x["kev_count"].as_i64().unwrap_or(0) > 0 { 0 } else { 1 }),
            json!(if x["cve_count"].as_i64().unwrap_or(0) > 0 { 0 } else { 1 }), json!(x["fleet_devices"].as_i64().unwrap_or(0)), x["name"].clone(), x["key"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(100)).map_err(Failure::Bad)?;
        // Whether the devices in scope report: the endpoint script's last run, and the last read's error.
        let stale = store::Ts(store::now().0 - chrono::Duration::days(STALE_DAYS));
        let (reporting, not_reporting, failing): (i64, i64, i64) = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT count(*) FILTER (WHERE s.collected_at IS NOT NULL), count(*) FILTER (WHERE COALESCE(s.last_seen_at, s.collected_at) < $3), count(*) FILTER (WHERE s.error IS NOT NULL)
               FROM process_snapshot s JOIN device d ON d.device_id = s.device_id AND d.deleted_at IS NULL WHERE ($1::bigint IS NULL OR d.org_id = $1) AND ($2::bigint IS NULL OR d.device_id = $2)"
        } else {
            "SELECT count(s.collected_at), coalesce(sum(CASE WHEN COALESCE(s.last_seen_at, s.collected_at) < $3 THEN 1 ELSE 0 END), 0), count(s.error)
               FROM process_snapshot s JOIN device d ON d.device_id = s.device_id AND d.deleted_at IS NULL WHERE ($1 IS NULL OR d.org_id = $1) AND ($2 IS NULL OR d.device_id = $2)"
        }).bind(p.org_id.map(|x| x as i64)).bind(p.device_id.map(|x| x as i64)).bind(stale).fetch_one(db).await.map_err(|_| Failure::Db)?);
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "binaries": total, "devices_reporting": reporting, "devices_not_reporting": not_reporting, "devices_failing": failing },
            "as_of": self.as_of_jobs(&["ninja_processes", "process_match"]).await }))
    }

    /// The names the automatic mapping wouldn't decide, the pending first, most devices first; and those decided in
    /// the last 30 days, with who and when. `state` narrows to one status.
    pub(super) async fn processes_review(&self, p: &Params) -> Result<Value, Failure> {
        if let Some(s) = &p.state && !["pending", "accepted", "rejected"].contains(&s.as_str()) { return Err(Failure::Bad("state must be pending, accepted or rejected for processes.review".into())); }
        let since = store::Ts(store::now().0 - chrono::Duration::days(30));
        type R = (String, String, String, Value, Value, i64, String, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>);
        let rows: Vec<R> = crate::on_pool!(&self.pool, db, _ => sqlx::query_as(
            "SELECT kind, name, company, candidates, versions, devices, status, cpe, decided_by, decided_at, last_seen FROM sec_map_review
              WHERE status = 'pending' OR decided_at > $1").bind(since).fetch_all(db).await.map_err(|_| Failure::Db)?);
        let pending = rows.iter().filter(|r| r.6 == "pending").count();
        let list: Vec<Value> = rows.into_iter().filter(|r| p.state.as_deref().is_none_or(|s| r.6 == s)).map(|r| json!({ "kind": r.0, "name": r.1, "company": r.2, "candidates": r.3,
            "versions": r.4, "devices": r.5, "status": r.6, "cpe": r.7, "decided_by": r.8, "decided_at": r.9, "last_seen": r.10 })).collect();
        let total = list.len();
        let key = |x: &Value| vec![json!(if x["status"] == "pending" { 0 } else { 1 }), json!(-x["devices"].as_i64().unwrap_or(0)), x["kind"].clone(), x["name"].clone(), x["company"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(100)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "names": total, "pending": pending }, "as_of": self.as_of_jobs(&["process_match", "match"]).await }))
    }

    /// A person's decision on a name: one of its own candidates accepted, the name rejected, or reopened. Idempotent: a
    /// decision already in place changes nothing (so a double click is one decision). The match jobs apply it at their
    /// next run. Answers (status, body); the caller writes the audit line.
    pub async fn decide(&self, who: &str, d: &ReviewDecision) -> (u16, Value) {
        type R = (Value, String, Option<String>);
        let row: Result<Option<R>, sqlx::Error> = crate::on_pool!(&self.pool, db, _ => sqlx::query_as(
            "SELECT candidates, status, cpe FROM sec_map_review WHERE kind = $1 AND name = $2 AND company = $3").bind(d.kind.as_str()).bind(&d.name).bind(&d.company).fetch_optional(db).await);
        let Ok(row) = row else { return (503, json!({ "error": "the console's database didn't answer" })) };
        let Some((cands, status, cpe)) = row else { return (404, json!({ "error": "there's no such name to review" })) };
        if d.decision == Decide::Accept && !cands.as_array().into_iter().flatten().any(|c| Some(format!("{}:{}", c["vendor"].as_str().unwrap_or(""), c["product"].as_str().unwrap_or(""))) == d.cpe) {
            return (400, json!({ "error": "that isn't one of this name's candidates" }));
        }
        let want = match d.decision { Decide::Accept => "accepted", Decide::Reject => "rejected", Decide::Reopen => "pending" };
        let want_cpe = if d.decision == Decide::Accept { d.cpe.clone() } else { None };
        if status == want && cpe == want_cpe { return (200, json!({ "status": want, "cpe": want_cpe, "unchanged": true })); }
        let (by, at) = if d.decision == Decide::Reopen { (None, None) } else { (Some(who.to_string()), Some(store::now())) };
        let r = crate::on_pool!(&self.pool, db, _ => sqlx::query("UPDATE sec_map_review SET status = $4, cpe = $5, decided_by = $6, decided_at = $7 WHERE kind = $1 AND name = $2 AND company = $3")
            .bind(d.kind.as_str()).bind(&d.name).bind(&d.company).bind(want).bind(&want_cpe).bind(by).bind(at).execute(db).await.map(|_| ()));
        match r {
            Ok(_) => (200, json!({ "status": want, "cpe": want_cpe, "unchanged": false, "applies": "at the next match (within 30 minutes)" })),
            Err(_) => (503, json!({ "error": "the console's database didn't answer; try again in a minute" })),
        }
    }
}
