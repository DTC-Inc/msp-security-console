//! NinjaOne's OS patches per device, for Windows itself: the Windows cumulative updates each device installed
//! (its build revision is the newest of them: NinjaOne's own build number has none), and the OS patches NinjaOne has
//! waiting or saw fail, by KB. Read-only, through the NinjaOne connector's client (scope monitoring). What it
//! reads, only what the Windows match needs:
//!
//!   /v2/queries/os-patch-installs?installedAfter=yyyyMMdd   installs since the last run (45 days the first time)
//!   /v2/queries/os-patch-installs?status=FAILED             failed installs
//!   /v2/queries/os-patches?status=APPROVED | MANUAL         waiting: approved for the next window, or for approval
//!
//! Each query pages with a cursor (cursor.name, 1000 a page). A sweep that can't finish fails the run, so a partial
//! sweep never looks like a complete one, and nothing it read is written. Then the Windows match runs (msrc).

use super::ninja::{db, urlenc, Ninja};
use crate::db::{self as store, Pool};
use crate::scheduler::{Job, Outcome};
use crate::windows::{epoch, kb_of, os_update_row};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// The first sweep reaches past last month's Patch Tuesday, so every device has its newest cumulative update.
pub const BACKFILL_DAYS: i64 = 45;
/// Later sweeps overlap the last one by two days: an install NinjaOne reports late is still read.
pub const OVERLAP_DAYS: i64 = 2;
const KEEP_INSTALLED_DAYS: i64 = 400;
const KEEP_FAILED_DAYS: i64 = 90;
const PAGE: usize = 1000;
const MAX_PAGES: usize = 5000;

/// Every page of one of NinjaOne's patch queries.
pub async fn sweep(n: &Ninja, path: &str, query: &str) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let q = match &cursor { Some(c) => format!("{path}?pageSize={PAGE}&{query}&cursor={}", urlenc(c)), None => format!("{path}?pageSize={PAGE}&{query}") };
        let j = n.get(&q).await?;
        let res = j.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
        let len = res.len();
        out.extend(res);
        cursor = j.pointer("/cursor/name").and_then(Value::as_str).map(String::from);
        if cursor.is_none() || len == 0 || len < PAGE { return Ok(out); }
    }
    Err(format!("NinjaOne: {path} has more than {MAX_PAGES} pages; refusing to go on"))
}

#[derive(Clone)]
pub struct NinjaOs { pub ninja: Arc<Ninja> }

impl NinjaOs {
    pub fn new(ninja: Arc<Ninja>) -> Self { Self { ninja } }

    pub async fn sync(&self, pool: &Pool) -> Result<Outcome, String> {
        let (held,): (i64,) = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT count(*) FROM os_update_installed").fetch_one(p).await).map_err(db)?;
        let days = if held == 0 { BACKFILL_DAYS } else { OVERLAP_DAYS };
        let from = (chrono::Utc::now() - chrono::Duration::days(days)).format("%Y%m%d").to_string();
        let installs = sweep(&self.ninja, "/v2/queries/os-patch-installs", &format!("installedAfter={from}")).await?;
        let mut updates: BTreeMap<(i64, String), chrono::DateTime<chrono::Utc>> = BTreeMap::new();
        for p in &installs {
            if let Some((d, kb, at)) = os_update_row(p) { let e = updates.entry((d, kb)).or_insert(at); if at > *e { *e = at; } }
        }
        let failed_rows = sweep(&self.ninja, "/v2/queries/os-patch-installs", "status=FAILED").await?;
        let mut patches: Vec<Value> = Vec::new();
        let cutoff = chrono::Utc::now() - chrono::Duration::days(KEEP_FAILED_DAYS);
        for p in &failed_rows {
            let (Some(d), Some(id)) = (p.get("deviceId").and_then(Value::as_i64), p.get("id").filter(|v| !v.is_null()).map(id_text)) else { continue };
            let Some(at) = epoch(p.get("installedAt")).or_else(|| epoch(p.get("timestamp"))) else { continue };
            if at < cutoff { continue; }
            patches.push(json!({ "device_id": d, "patch_id": id, "status": "FAILED", "kb": kb_of(p.get("kbNumber"), p.get("name").and_then(Value::as_str)), "at": store::ts(at) }));
        }
        let mut waiting = 0usize;
        for status in ["APPROVED", "MANUAL"] {
            for p in sweep(&self.ninja, "/v2/queries/os-patches", &format!("status={status}")).await? {
                let (Some(d), Some(id)) = (p.get("deviceId").and_then(Value::as_i64), p.get("id").filter(|v| !v.is_null()).map(id_text)) else { continue };
                let name = p.get("name").or_else(|| p.get("title")).and_then(Value::as_str);
                patches.push(json!({ "device_id": d, "patch_id": id, "status": status, "kb": kb_of(p.get("kbNumber"), name), "at": epoch(p.get("timestamp")).map(store::ts) }));
                waiting += 1;
            }
        }
        let rows: Vec<Value> = updates.iter().map(|((d, kb), at)| json!({ "device_id": d, "kb": kb, "installed_at": store::ts(*at) })).collect();
        let now = store::now();
        crate::on_pool!(pool, p, pg => {
            let mut tx = p.begin().await.map_err(db)?;
            // Waiting is NinjaOne's current state: replaced whole. Failures accumulate, newest per patch, then age out.
            sqlx::query("DELETE FROM os_patch WHERE status IN ('APPROVED', 'MANUAL')").execute(&mut *tx).await.map_err(db)?;
            for c in rows.chunks(5000) {
                sqlx::query(if pg {
                    "INSERT INTO os_update_installed (device_id, kb, installed_at) SELECT x.device_id, x.kb, x.installed_at
                       FROM jsonb_to_recordset($1) AS x(device_id bigint, kb text, installed_at timestamptz)
                     ON CONFLICT (device_id, kb) DO UPDATE SET installed_at = GREATEST(os_update_installed.installed_at, excluded.installed_at)"
                } else {
                    "INSERT INTO os_update_installed (device_id, kb, installed_at) SELECT x.value ->> 'device_id', x.value ->> 'kb', x.value ->> 'installed_at'
                       FROM json_each($1) AS x WHERE true
                     ON CONFLICT (device_id, kb) DO UPDATE SET installed_at = max(os_update_installed.installed_at, excluded.installed_at)"
                }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
            }
            for c in patches.chunks(5000) {
                sqlx::query(if pg {
                    "INSERT INTO os_patch (device_id, patch_id, status, kb, at) SELECT x.device_id, x.patch_id, x.status, x.kb, x.at
                       FROM jsonb_to_recordset($1) AS x(device_id bigint, patch_id text, status text, kb text, at timestamptz)
                     ON CONFLICT (device_id, patch_id, status) DO UPDATE SET kb = excluded.kb, at = GREATEST(os_patch.at, excluded.at)"
                } else {
                    "INSERT INTO os_patch (device_id, patch_id, status, kb, at) SELECT x.value ->> 'device_id', x.value ->> 'patch_id', x.value ->> 'status', x.value ->> 'kb', x.value ->> 'at'
                       FROM json_each($1) AS x WHERE true
                     ON CONFLICT (device_id, patch_id, status) DO UPDATE SET kb = excluded.kb, at = CASE WHEN excluded.at IS NULL THEN os_patch.at WHEN os_patch.at IS NULL THEN excluded.at ELSE max(os_patch.at, excluded.at) END"
                }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
            }
            sqlx::query("DELETE FROM os_update_installed WHERE installed_at < $1").bind(days_ago(now, KEEP_INSTALLED_DAYS)).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("DELETE FROM os_patch WHERE status = 'FAILED' AND at < $1").bind(days_ago(now, KEEP_FAILED_DAYS)).execute(&mut *tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
        });
        let matched = super::msrc::match_windows(pool).await?;
        Ok(Outcome { detail: json!({ "days": days, "installs_read": installs.len(), "cumulative_updates": rows.len(), "failed": failed_rows.len(), "waiting": waiting, "match": matched }), cursor: None })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        vec![Job { name: "ninja_os_patches", every: Duration::from_secs(12 * 3600), run: Arc::new(move |pool, _| { let n = self.clone(); Box::pin(async move { n.sync(&pool).await }) }) }]
    }
}

fn days_ago(now: store::Ts, days: i64) -> store::Ts { store::Ts(now.0 - chrono::Duration::days(days)) }

/// A patch's id as text, whatever NinjaOne wrote it as.
fn id_text(v: &Value) -> String { v.as_str().map(String::from).unwrap_or_else(|| v.to_string()) }
