//! Windows itself, as evidence: `windows.devices` and `windows.cves`, answered from what the msrc match wrote
//! (sec_windows_device, sec_windows_finding). Every count opens its rows: a client's vulnerable devices are
//! `windows.devices` with that state, and a device's open CVEs are `windows.cves` with its device_id.

use super::{page_by, Failure, Store};
use crate::contract::Params;
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};

pub const STATES: &[&str] = &["vulnerable", "unknown", "untracked", "patched"];
fn rank(s: &str) -> i64 { STATES.iter().position(|x| *x == s).unwrap_or(STATES.len()) as i64 }

fn class_of(p: &Params) -> Option<String> { p.device_class.and_then(|c| serde_json::to_value(c).ok()).and_then(|v| v.as_str().map(String::from)) }

impl Store {
    /// When the jobs behind Windows last succeeded.
    pub(super) async fn as_of_jobs(&self, names: &[&str]) -> Value {
        let rows: Vec<(String, Option<chrono::DateTime<chrono::Utc>>)> = crate::on_pool!(&self.pool, p, _ =>
            sqlx::query_as("SELECT name, last_ok_at FROM job").fetch_all(p).await.unwrap_or_default());
        Value::Object(rows.into_iter().filter(|r| names.contains(&r.0.as_str())).map(|(n, t)| (n, json!(t))).collect())
    }

    /// Windows devices and where each stands, worst first: vulnerable (exploited, then most open CVEs), unknown (its
    /// patch level can't be read: never counted as patched), untracked, patched. `state` narrows to one; the totals
    /// are of the whole scope, so each opens its own rows. `cve_id` narrows the scope to the devices with that Windows
    /// CVE open, which is what a CVE's device count on the Windows view opens.
    pub(super) async fn windows_devices(&self, p: &Params) -> Result<Value, Failure> {
        if let Some(s) = &p.state && !STATES.contains(&s.as_str()) { return Err(Failure::Bad(format!("state must be one of {} for windows.devices", STATES.join(", ")))); }
        let rows: Vec<Value> = crate::on_pool!(&self.pool, db, pg => {
            let rows = sqlx::query(if pg {
                "SELECT w.device_id, d.name, d.org_id, c.name AS org_name, d.device_class, d.os_name, w.server, w.build_major, w.rev, w.rev_source, w.state,
                        w.needed_kb, w.needed_build, w.latest_kb, w.latest_build, w.cve_count, w.exploited_count, w.critical_count,
                        w.update_pending_kb, w.update_failed_kb, w.update_failed_at
                   FROM sec_windows_device w JOIN device d ON d.device_id = w.device_id AND d.deleted_at IS NULL LEFT JOIN client c ON c.org_id = d.org_id
                  WHERE ($1::bigint IS NULL OR d.org_id = $1) AND ($2::bigint IS NULL OR d.device_id = $2) AND ($3::text IS NULL OR d.device_class = $3)"
            } else {
                "SELECT w.device_id, d.name, d.org_id, c.name AS org_name, d.device_class, d.os_name, w.server, w.build_major, w.rev, w.rev_source, w.state,
                        w.needed_kb, w.needed_build, w.latest_kb, w.latest_build, w.cve_count, w.exploited_count, w.critical_count,
                        w.update_pending_kb, w.update_failed_kb, w.update_failed_at
                   FROM sec_windows_device w JOIN device d ON d.device_id = w.device_id AND d.deleted_at IS NULL LEFT JOIN client c ON c.org_id = d.org_id
                  WHERE ($1 IS NULL OR d.org_id = $1) AND ($2 IS NULL OR d.device_id = $2) AND ($3 IS NULL OR d.device_class = $3)"
            }).bind(p.org_id.map(|x| x as i64)).bind(p.device_id.map(|x| x as i64)).bind(class_of(p)).fetch_all(db).await.map_err(|_| Failure::Db)?;
            let mut out = Vec::new();
            for r in rows {
                let g = || -> Result<Value, sqlx::Error> {
                    let build: Option<i64> = r.try_get("build_major")?;
                    let rev: Option<i64> = r.try_get("rev")?;
                    Ok(json!({ "device_id": r.try_get::<i64, _>("device_id")?, "name": r.try_get::<String, _>("name")?, "org_id": r.try_get::<i64, _>("org_id")?,
                        "org_name": r.try_get::<Option<String>, _>("org_name")?, "device_class": r.try_get::<String, _>("device_class")?, "os_name": r.try_get::<Option<String>, _>("os_name")?,
                        "server": r.try_get::<bool, _>("server")?, "build": build.map(|b| match rev { Some(x) => format!("{b}.{x}"), None => b.to_string() }),
                        "rev_source": r.try_get::<Option<String>, _>("rev_source")?, "state": r.try_get::<String, _>("state")?,
                        "needed_kb": r.try_get::<Option<String>, _>("needed_kb")?, "needed_build": r.try_get::<Option<String>, _>("needed_build")?,
                        "latest_kb": r.try_get::<Option<String>, _>("latest_kb")?, "latest_build": r.try_get::<Option<String>, _>("latest_build")?,
                        "cve_count": r.try_get::<Option<i64>, _>("cve_count")?, "exploited_count": r.try_get::<Option<i64>, _>("exploited_count")?,
                        "critical_count": r.try_get::<Option<i64>, _>("critical_count")?, "update_pending_kb": r.try_get::<Option<String>, _>("update_pending_kb")?,
                        "update_failed_kb": r.try_get::<Option<String>, _>("update_failed_kb")?,
                        "update_failed_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("update_failed_at")? }))
                };
                out.push(g().map_err(|_| Failure::Db)?);
            }
            out
        });
        let rows = match p.cve_id.as_ref().map(|c| c.to_uppercase()) {
            None => rows,
            Some(cve) => {
                let open: Vec<(i64,)> = crate::on_pool!(&self.pool, db, _ => sqlx::query_as("SELECT DISTINCT device_id FROM sec_windows_finding WHERE cve = $1")
                    .bind(&cve).fetch_all(db).await.map_err(|_| Failure::Db)?);
                let open: BTreeSet<i64> = open.into_iter().map(|x| x.0).collect();
                rows.into_iter().filter(|r| r["device_id"].as_i64().is_some_and(|d| open.contains(&d))).collect()
            }
        };
        let mut totals: BTreeMap<String, i64> = STATES.iter().map(|s| (s.to_string(), 0)).collect();
        for r in &rows { *totals.entry(r["state"].as_str().unwrap_or("").to_string()).or_default() += 1; }
        totals.insert("devices".into(), rows.len() as i64);
        let list: Vec<Value> = rows.into_iter().filter(|r| p.state.as_deref().is_none_or(|s| r["state"] == s)).collect();
        let key = |x: &Value| vec![json!(rank(x["state"].as_str().unwrap_or(""))), json!(-x["exploited_count"].as_i64().unwrap_or(0)),
            json!(-x["cve_count"].as_i64().unwrap_or(0)), x["name"].clone(), x["device_id"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(100)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "as_of": self.as_of_jobs(&["msrc", "ninja_os_patches"]).await }))
    }

    /// Open Windows CVEs, one row each, with the update (KB) that fixes it on each build and how many devices still
    /// need it: in a client (org_id), on one device (device_id), or everywhere. Exploited first, then KEV, the score,
    /// and how many devices.
    pub(super) async fn windows_cves(&self, p: &Params) -> Result<Value, Failure> {
        let cve = p.cve_id.as_ref().map(|c| c.to_uppercase());
        type Row = (String, String, String, Option<String>, bool, Option<String>, i64, Option<f64>, bool);
        let rows: Vec<Row> = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT f.cve, f.kb, f.fixed_build, f.severity, f.exploited, f.title, f.device_id, n.cvss, k.cve_id IS NOT NULL
               FROM sec_windows_finding f JOIN device d ON d.device_id = f.device_id AND d.deleted_at IS NULL
                    LEFT JOIN sec_nvd_cve n ON n.cve_id = f.cve LEFT JOIN sec_kev k ON k.cve_id = f.cve
              WHERE ($1::bigint IS NULL OR d.org_id = $1) AND ($2::bigint IS NULL OR d.device_id = $2) AND ($3::text IS NULL OR f.cve = $3) AND ($4::text IS NULL OR d.device_class = $4)"
        } else {
            "SELECT f.cve, f.kb, f.fixed_build, f.severity, f.exploited, f.title, f.device_id, n.cvss, k.cve_id IS NOT NULL
               FROM sec_windows_finding f JOIN device d ON d.device_id = f.device_id AND d.deleted_at IS NULL
                    LEFT JOIN sec_nvd_cve n ON n.cve_id = f.cve LEFT JOIN sec_kev k ON k.cve_id = f.cve
              WHERE ($1 IS NULL OR d.org_id = $1) AND ($2 IS NULL OR d.device_id = $2) AND ($3 IS NULL OR f.cve = $3) AND ($4 IS NULL OR d.device_class = $4)"
        }).bind(p.org_id.map(|x| x as i64)).bind(p.device_id.map(|x| x as i64)).bind(cve).bind(class_of(p)).fetch_all(db).await.map_err(|_| Failure::Db)?);
        struct G { title: Option<String>, severity: Option<String>, exploited: bool, kev: bool, cvss: Option<f64>, devices: BTreeSet<i64>, kbs: BTreeMap<(String, String), BTreeSet<i64>> }
        let mut g: BTreeMap<String, G> = BTreeMap::new();
        let mut devices = BTreeSet::new();
        for (cve, kb, fixed, sev, exploited, title, dev, cvss, kev) in rows {
            let x = g.entry(cve).or_insert(G { title: None, severity: None, exploited: false, kev: false, cvss: None, devices: BTreeSet::new(), kbs: BTreeMap::new() });
            x.title = x.title.take().or(title); x.exploited |= exploited; x.kev |= kev; x.cvss = x.cvss.or(cvss);
            if sev.as_deref() == Some("critical") || x.severity.is_none() { x.severity = sev; }
            x.devices.insert(dev); devices.insert(dev);
            x.kbs.entry((kb, fixed)).or_default().insert(dev);
        }
        let all = g.len();
        let list: Vec<Value> = g.into_iter().filter(|(_, x)| !p.kev.unwrap_or(false) || x.kev).map(|(id, x)| json!({
            "cve_id": id, "title": x.title, "severity": x.severity, "exploited": x.exploited, "kev": x.kev, "cvss": x.cvss, "devices": x.devices.len(),
            "kbs": x.kbs.into_iter().map(|((kb, fixed), d)| json!({ "kb": kb, "fixed_build": fixed, "devices": d.len() })).collect::<Vec<_>>() })).collect();
        let key = |x: &Value| vec![json!(if x["exploited"] == json!(true) { 0 } else { 1 }), json!(if x["kev"] == json!(true) { 0 } else { 1 }),
            json!(-(x["cvss"].as_f64().unwrap_or(0.0))), json!(-(x["devices"].as_i64().unwrap_or(0))), x["cve_id"].clone()];
        let shown = list.len();
        let (data, next) = page_by(list, key, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(100)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "cves": shown, "all_cves": all, "devices": devices.len() }, "as_of": self.as_of_jobs(&["msrc", "ninja_os_patches"]).await }))
    }
}
