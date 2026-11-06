//! Microsoft's monthly security updates: MSRC's CVRF API, public, no key. On unless MSRC=off.
//!
//!   index  {MSRC_URL}/updates            one entry per month, with its revision date
//!   month  {MSRC_URL}/cvrf/<2026-Oct>    CVRF JSON: every CVE, its products, and per Windows product the KB and the
//!                                        build fixing it (a month is about 28 MB, read into the few fields used)
//!
//! The `msrc` job reads the last 24 months, newest first, each only when Microsoft has revised it since it was read,
//! then matches every Windows device against what's stored (match_windows): the `msrc` evidence source. NinjaOne's OS
//! patches (ninja_os) give each device's revision; without them a device's patch level is unknown, never patched.

use super::Limiter;
use crate::connectors::ninja::db;
use crate::db::{self as store, Pool};
use crate::scheduler::{Job, Outcome};
use crate::windows::{self, Cvrf, DeviceUpdates, Fix, IndexEntry};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_URL: &str = "https://api.msrc.microsoft.com/cvrf/v3.0";
/// How far back: two years of months.
pub const MONTHS: u32 = 24;
/// A run stops starting months after this; the rest are read next run, newest first.
pub const BUDGET: Duration = Duration::from_secs(10 * 60);
/// A failed install older than this says nothing about now.
const FAILED_DAYS: i64 = 60;

#[derive(Clone)]
pub struct Msrc { pub url: String, http: reqwest::Client, limiter: Limiter, pub budget: Duration }

impl std::fmt::Debug for Msrc { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("Msrc").field("url", &self.url).finish_non_exhaustive() } }

#[derive(serde::Deserialize)]
struct Updates { #[serde(default)] value: Vec<IndexEntry> }

impl Msrc {
    pub fn new(url: &str, http: reqwest::Client) -> Self {
        Self { url: url.trim_end_matches('/').into(), http, limiter: Limiter::new(2, Duration::from_secs(1)), budget: BUDGET }
    }

    /// A GET of MSRC's JSON into the types that read it, retrying 429 and 503 and a dropped connection. The error is
    /// the status and its standard reason, never the URL or the body.
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let url = format!("{}{path}", self.url);
        let mut last = String::new();
        for attempt in 0..3u64 {
            if attempt > 0 { tokio::time::sleep(Duration::from_secs(5 * attempt)).await; }
            self.limiter.acquire().await;
            let r = match self.http.get(&url).header(reqwest::header::ACCEPT, "application/json").timeout(Duration::from_secs(180)).send().await {
                Ok(r) => r,
                Err(e) => { last = if e.is_timeout() { "timed out".into() } else { "unreachable".into() }; continue; }
            };
            let st = r.status();
            if st == StatusCode::TOO_MANY_REQUESTS || st == StatusCode::SERVICE_UNAVAILABLE { last = format!("HTTP {}", st.as_u16()); continue; }
            if st.is_redirection() { return Err(format!("HTTP {}: the address redirected; set the final address", st.as_u16())); }
            if !st.is_success() { return Err(format!("HTTP {} {}", st.as_u16(), st.canonical_reason().unwrap_or("")).trim_end().to_string()); }
            let bytes = match r.bytes().await { Ok(b) => b, Err(_) => { last = "the answer was cut off".into(); continue; } };
            return serde_json::from_slice(&bytes).map_err(|_| "the answer isn't the JSON expected".to_string());
        }
        Err(last)
    }

    /// Read the months that changed, then match every Windows device. A month that fails is said, and the run fails so
    /// it's retried sooner; the months that loaded stay loaded.
    pub async fn sync(&self, pool: &Pool) -> Result<Outcome, String> {
        let t0 = Instant::now();
        type Doc = (String, Option<chrono::DateTime<chrono::Utc>>);
        let rows: Vec<Doc> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT doc_id, current_release_date FROM sec_msrc_doc").fetch_all(p).await).map_err(db)?;
        let loaded: BTreeMap<String, String> = rows.into_iter().filter_map(|(id, at)| Some((id, store::ts(at?)))).collect();
        let index: Updates = self.get("/updates").await.map_err(|e| format!("MSRC index: {e}"))?;
        let todo = windows::months_to_load(&index.value, &loaded, chrono::Utc::now(), MONTHS);
        let by_id: BTreeMap<&str, &IndexEntry> = index.value.iter().map(|e| (e.id.0.as_str(), e)).collect();
        let (mut done, mut deferred, mut failed, mut rows) = (Vec::new(), Vec::new(), Vec::new(), 0usize);
        for id in &todo {
            if t0.elapsed() > self.budget { deferred.push(id.clone()); continue; }
            let doc: Cvrf = match self.get(&format!("/cvrf/{}", crate::connectors::ninja::urlenc(id))).await {
                Ok(d) => d,
                Err(e) => { failed.push(format!("{id}: {e}")); continue; }
            };
            let fixes = windows::msrc_fixes(&doc);
            drop(doc);
            let e = by_id.get(id.as_str());
            let when = |s: Option<&String>| s.and_then(|s| store::ts_text(s));
            put_month(pool, id, e.and_then(|e| when(e.initial.as_ref())), e.and_then(|e| when(e.current.as_ref())), &fixes).await?;
            rows += fixes.len();
            done.push(id.clone());
        }
        // The match runs every run, loaded or not: the devices' updates change daily.
        let matched = match_windows(pool).await?;
        let detail = json!({ "months_loaded": done.len(), "deferred": deferred.len(), "failed": failed.len(), "fixes": rows, "match": matched });
        if !failed.is_empty() { return Err(format!("{} month(s) failed: {}", failed.len(), failed.join("; ")).chars().take(300).collect()); }
        Ok(Outcome { detail, cursor: None })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        // Daily: Microsoft publishes monthly, and revises recent months almost daily.
        vec![Job { name: "msrc", every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, _| { let m = self.clone(); Box::pin(async move { m.sync(&pool).await }) }) }]
    }
}

/// One month's fixes and its index row, in one transaction. A (CVE, product) seen in another month keeps the earliest
/// fix: Windows updates are cumulative, so the first build that has it is the threshold.
pub async fn put_month(pool: &Pool, id: &str, initial: Option<String>, current: Option<String>, fixes: &[Fix]) -> Result<(), String> {
    let rows: Vec<Value> = fixes.iter().map(|f| json!({ "cve": f.cve, "product_id": f.product_id, "product": f.product, "server": f.server, "build_major": f.build_major,
        "fixed_build": f.fixed_build, "fixed_rev": f.fixed_rev, "kb": f.kb, "severity": f.severity, "exploited": f.exploited, "title": f.title, "doc_id": id })).collect();
    const KEEP_EARLIEST: &str = "ON CONFLICT (cve, product_id) DO UPDATE SET product = excluded.product, server = excluded.server, severity = excluded.severity,
           exploited = excluded.exploited, title = excluded.title,
           build_major = CASE WHEN excluded.fixed_rev < sec_msrc_fix.fixed_rev THEN excluded.build_major ELSE sec_msrc_fix.build_major END,
           fixed_build = CASE WHEN excluded.fixed_rev < sec_msrc_fix.fixed_rev THEN excluded.fixed_build ELSE sec_msrc_fix.fixed_build END,
           kb          = CASE WHEN excluded.fixed_rev < sec_msrc_fix.fixed_rev THEN excluded.kb ELSE sec_msrc_fix.kb END,
           doc_id      = CASE WHEN excluded.fixed_rev < sec_msrc_fix.fixed_rev THEN excluded.doc_id ELSE sec_msrc_fix.doc_id END,
           fixed_rev   = CASE WHEN excluded.fixed_rev < sec_msrc_fix.fixed_rev THEN excluded.fixed_rev ELSE sec_msrc_fix.fixed_rev END";
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO sec_msrc_doc (doc_id, initial_release_date, current_release_date, fixes, loaded_at) VALUES ($1, $2::timestamptz, $3::timestamptz, $4, now())
             ON CONFLICT (doc_id) DO UPDATE SET initial_release_date = excluded.initial_release_date, current_release_date = excluded.current_release_date,
               fixes = excluded.fixes, loaded_at = excluded.loaded_at"
        } else {
            "INSERT INTO sec_msrc_doc (doc_id, initial_release_date, current_release_date, fixes, loaded_at) VALUES ($1, $2, $3, $4, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
             ON CONFLICT (doc_id) DO UPDATE SET initial_release_date = excluded.initial_release_date, current_release_date = excluded.current_release_date,
               fixes = excluded.fixes, loaded_at = excluded.loaded_at"
        }).bind(id).bind(initial).bind(current).bind(fixes.len() as i64).execute(&mut *tx).await.map_err(db)?;
        for chunk in rows.chunks(2000) {
            let sql = if pg {
                format!("INSERT INTO sec_msrc_fix (cve, product_id, product, server, build_major, fixed_build, fixed_rev, kb, severity, exploited, title, doc_id)
                         SELECT x.cve, x.product_id, x.product, x.server, x.build_major, x.fixed_build, x.fixed_rev, x.kb, x.severity, x.exploited, x.title, x.doc_id
                           FROM jsonb_to_recordset($1) AS x(cve text, product_id text, product text, server boolean, build_major bigint, fixed_build text, fixed_rev bigint,
                                kb text, severity text, exploited boolean, title text, doc_id text) {KEEP_EARLIEST}")
            } else {
                format!("INSERT INTO sec_msrc_fix (cve, product_id, product, server, build_major, fixed_build, fixed_rev, kb, severity, exploited, title, doc_id)
                         SELECT x.value ->> 'cve', x.value ->> 'product_id', x.value ->> 'product', x.value ->> 'server', x.value ->> 'build_major', x.value ->> 'fixed_build',
                                x.value ->> 'fixed_rev', x.value ->> 'kb', x.value ->> 'severity', x.value ->> 'exploited', x.value ->> 'title', x.value ->> 'doc_id'
                           FROM json_each($1) AS x WHERE true {KEEP_EARLIEST}")
            };
            sqlx::query(sqlx::AssertSqlSafe(sql)).bind(Value::Array(chunk.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

type FixRow = (String, String, String, bool, i64, String, i64, String, Option<String>, bool, Option<String>);

/// Every Windows device against every Windows CVE held: sec_msrc_fix × device × the device's installed, pending and
/// failed updates (os_update_installed, os_patch, from ninja_os). Replaces sec_windows_device and sec_windows_finding,
/// and the `msrc` evidence, in one transaction, so readers see the old set or the new one. Vulnerable CVEs only are
/// rows; patched is the absence of one, and the device row says its state. Nothing is written before Microsoft's data
/// is: with no fixes held, every device would read as untracked.
pub async fn match_windows(pool: &Pool) -> Result<Value, String> {
    let (held,): (i64,) = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT count(*) FROM sec_msrc_fix").fetch_one(p).await).map_err(db)?;
    if held == 0 { return Ok(json!({ "skipped": "no Microsoft updates loaded yet" })); }
    let devices: Vec<(i64, Option<String>, Option<String>)> = crate::on_pool!(pool, p, _ =>
        sqlx::query_as("SELECT device_id, os_name, os_build FROM device WHERE deleted_at IS NULL ORDER BY device_id").fetch_all(p).await).map_err(db)?;
    let devices: Vec<(i64, &'static str, String)> = devices.into_iter().map(|(id, n, b)| (id, windows::os_family(n.as_deref().unwrap_or("")), b.unwrap_or_default()))
        .filter(|d| d.1.starts_with("Windows")).collect();
    let majors: Vec<i64> = devices.iter().filter_map(|d| windows::parse_build(&d.2).map(|b| b.major)).collect::<BTreeSet<_>>().into_iter().collect();
    let since = store::now().0 - chrono::Duration::days(FAILED_DAYS);
    type Kb = (i64, String);
    type Failed = (i64, String, chrono::DateTime<chrono::Utc>);
    let (fixes, installed, pending, failed): (Vec<FixRow>, Vec<Kb>, Vec<Kb>, Vec<Failed>) = crate::on_pool!(pool, p, pg => (
        sqlx::query_as(if pg {
            "SELECT cve, product_id, product, server, build_major, fixed_build, fixed_rev, kb, severity, exploited, title FROM sec_msrc_fix WHERE build_major = ANY($1)"
        } else {
            "SELECT cve, product_id, product, server, build_major, fixed_build, fixed_rev, kb, severity, exploited, title FROM sec_msrc_fix WHERE build_major IN (SELECT value FROM json_each($1))"
        }).bind(store::list(&majors)).fetch_all(p).await.map_err(db)?,
        sqlx::query_as("SELECT device_id, kb FROM os_update_installed").fetch_all(p).await.map_err(db)?,
        sqlx::query_as("SELECT device_id, kb FROM os_patch WHERE status IN ('APPROVED', 'MANUAL') AND kb IS NOT NULL").fetch_all(p).await.map_err(db)?,
        sqlx::query_as("SELECT device_id, kb, at FROM os_patch WHERE status = 'FAILED' AND kb IS NOT NULL AND at > $1").bind(store::Ts(since)).fetch_all(p).await.map_err(db)?));
    let mut by_key: BTreeMap<(i64, bool), Vec<Fix>> = BTreeMap::new();
    for (cve, product_id, product, server, build_major, fixed_build, fixed_rev, kb, severity, exploited, title) in fixes {
        by_key.entry((build_major, server)).or_default().push(Fix { cve, product_id, product, server, build_major, fixed_build, fixed_rev, kb, severity, exploited, title });
    }
    let group = |rows: Vec<Kb>| { let mut m: BTreeMap<i64, Vec<String>> = BTreeMap::new(); for (d, k) in rows { m.entry(d).or_default().push(k); } m };
    let (installed, pending) = (group(installed), group(pending));
    let mut fail: BTreeMap<i64, Vec<(String, String)>> = BTreeMap::new();
    for (d, k, at) in failed { fail.entry(d).or_default().push((k, store::ts(at))); }
    let (mut dev_rows, mut find_rows) = (Vec::new(), Vec::new());
    let mut by_state: BTreeMap<&str, usize> = BTreeMap::new();
    for (id, family, build) in &devices {
        let server = *family == "Windows Server";
        let key = windows::parse_build(build).map(|b| (b.major, server));
        let none = Vec::new();
        let mine = key.and_then(|k| by_key.get(&k)).unwrap_or(&none);
        let u = DeviceUpdates { device_id: *id, os_family: family.to_string(), os_build: build.clone(), installed_kbs: installed.get(id).cloned().unwrap_or_default(),
            pending_kbs: pending.get(id).cloned().unwrap_or_default(), failed: fail.get(id).cloned().unwrap_or_default() };
        let (d, f) = windows::windows_device(&u, mine);
        *by_state.entry(d.state).or_default() += 1;
        dev_rows.push(serde_json::to_value(&d).unwrap_or_default());
        find_rows.extend(f.into_iter().map(|x| serde_json::to_value(x).unwrap_or_default()));
    }
    let version = |d: &Value| d["build_major"].as_i64().map(|m| match d["rev"].as_i64() { Some(r) => format!("{m}.{r}"), None => m.to_string() });
    let evidence: Vec<Value> = dev_rows.iter().filter_map(|d| Some(json!({ "device_id": d["device_id"], "version": version(d)?,
        "detail": { "server": d["server"], "state": d["state"], "needed_kb": d["needed_kb"], "needed_build": d["needed_build"], "latest_kb": d["latest_kb"],
                    "update_pending_kb": d["update_pending_kb"], "update_failed_kb": d["update_failed_kb"], "rev_source": d["rev_source"] } }))).collect();
    let versions: BTreeMap<i64, String> = dev_rows.iter().filter_map(|d| Some((d["device_id"].as_i64()?, version(d)?))).collect();
    let cves: Vec<Value> = find_rows.iter().filter_map(|f| Some(json!({ "device_id": f["device_id"], "cve_id": f["cve"], "version": versions.get(&f["device_id"].as_i64()?)?,
        "exploited": f["exploited"], "detail": { "kb": f["kb"], "fixed_build": f["fixed_build"], "severity": f["severity"], "title": f["title"] } }))).collect();
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM sec_windows_finding").execute(&mut *tx).await.map_err(db)?;
        sqlx::query("DELETE FROM sec_windows_device").execute(&mut *tx).await.map_err(db)?;
        sqlx::query("DELETE FROM sec_evidence WHERE source = 'msrc'").execute(&mut *tx).await.map_err(db)?;
        sqlx::query("DELETE FROM sec_evidence_cve WHERE source = 'msrc'").execute(&mut *tx).await.map_err(db)?;
        for c in dev_rows.chunks(2000) {
            sqlx::query(if pg {
                "INSERT INTO sec_windows_device (device_id, server, build_major, rev, rev_source, state, needed_kb, needed_build, latest_kb, latest_build, cve_count,
                        exploited_count, critical_count, update_pending_kb, update_failed_kb, update_failed_at)
                 SELECT * FROM jsonb_to_recordset($1) AS x(device_id bigint, server boolean, build_major bigint, rev bigint, rev_source text, state text, needed_kb text,
                        needed_build text, latest_kb text, latest_build text, cve_count bigint, exploited_count bigint, critical_count bigint, update_pending_kb text,
                        update_failed_kb text, update_failed_at timestamptz)"
            } else {
                "INSERT INTO sec_windows_device (device_id, server, build_major, rev, rev_source, state, needed_kb, needed_build, latest_kb, latest_build, cve_count,
                        exploited_count, critical_count, update_pending_kb, update_failed_kb, update_failed_at)
                 SELECT x.value ->> 'device_id', x.value ->> 'server', x.value ->> 'build_major', x.value ->> 'rev', x.value ->> 'rev_source', x.value ->> 'state',
                        x.value ->> 'needed_kb', x.value ->> 'needed_build', x.value ->> 'latest_kb', x.value ->> 'latest_build', x.value ->> 'cve_count',
                        x.value ->> 'exploited_count', x.value ->> 'critical_count', x.value ->> 'update_pending_kb', x.value ->> 'update_failed_kb', x.value ->> 'update_failed_at'
                   FROM json_each($1) AS x WHERE true"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        for c in find_rows.chunks(5000) {
            sqlx::query(if pg {
                "INSERT INTO sec_windows_finding (device_id, cve, kb, fixed_build, severity, exploited, title)
                 SELECT * FROM jsonb_to_recordset($1) AS x(device_id bigint, cve text, kb text, fixed_build text, severity text, exploited boolean, title text) ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO sec_windows_finding (device_id, cve, kb, fixed_build, severity, exploited, title)
                 SELECT x.value ->> 'device_id', x.value ->> 'cve', x.value ->> 'kb', x.value ->> 'fixed_build', x.value ->> 'severity', x.value ->> 'exploited', x.value ->> 'title'
                   FROM json_each($1) AS x WHERE true ON CONFLICT DO NOTHING"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        // The evidence model: Windows as source 'msrc', product 'msrc:windows', version the build; its CVEs as
        // Microsoft names them. Only this source's rows are replaced.
        for c in evidence.chunks(2000) {
            sqlx::query(if pg {
                "INSERT INTO sec_evidence (device_id, product_key, version, source, detail)
                 SELECT x.device_id, 'msrc:windows', x.version, 'msrc', x.detail FROM jsonb_to_recordset($1) AS x(device_id bigint, version text, detail jsonb)"
            } else {
                "INSERT INTO sec_evidence (device_id, product_key, version, source, detail)
                 SELECT x.value ->> 'device_id', 'msrc:windows', x.value ->> 'version', 'msrc', x.value -> 'detail' FROM json_each($1) AS x WHERE true"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        for c in cves.chunks(5000) {
            sqlx::query(if pg {
                "INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, exploited, detail)
                 SELECT x.device_id, x.cve_id, 'msrc:windows', x.version, 'msrc', x.exploited, x.detail
                   FROM jsonb_to_recordset($1) AS x(device_id bigint, cve_id text, version text, exploited boolean, detail jsonb) ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, exploited, detail)
                 SELECT x.value ->> 'device_id', x.value ->> 'cve_id', 'msrc:windows', x.value ->> 'version', 'msrc', x.value ->> 'exploited', x.value -> 'detail'
                   FROM json_each($1) AS x WHERE true ON CONFLICT DO NOTHING"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
    });
    Ok(json!({ "devices": dev_rows.len(), "findings": find_rows.len(), "by_state": by_state }))
}
