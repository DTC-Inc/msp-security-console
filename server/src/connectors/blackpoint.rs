//! Blackpoint CompassOne: tenants (each one a client, once someone confirms which), their device assets (each
//! one a device), their vulnerability findings (as `blackpoint` evidence), their open detections, and their dark-web
//! exposures. Read-only against Blackpoint.
//!
//! - **Auth:** a bearer token issued in CompassOne's portal (`BLACKPOINT_API_TOKEN`), and `x-tenant-id` on every
//!   tenant's own route.
//! - **The rate budget:** Blackpoint counts calls per API user per window and says so on every answer
//!   (`x-ratelimit-remaining`, `x-ratelimit-reset` in seconds). Each call reads them. Below a job's reserve, a call
//!   waits for the reset when it's near and otherwise stops the job's sweep (`Fail::Budget`), so the rest waits for the
//!   next run rather than failing one tenant at a time. A 429 pauses every call on this connector until its reset. The
//!   detections poll keeps a larger reserve, so it never spends what the daily sweeps need.
//! - **The mapping (the console's rule for every vendor's clients: a vendor's own link confirms, a name only suggests):** the connector only suggests which client a tenant is, by the tenant's domain
//!   (one client whose website shares it) or its name (one client with the same name, corporate suffixes aside). A
//!   suggestion scopes nothing. A tenant is a client once a signed-in user confirms it, and a re-match never touches a
//!   user's decision. Assets are tied to devices only inside a confirmed client, by the hostname.
//! - **Dark web:** each exposure keeps its email, where it was seen, when, and what kind of data it was. The rest of
//!   Blackpoint's row is never read, so a password, a hash or another secret it sends goes nowhere.

use super::Limiter;
use crate::connectors::ninja::db;
use crate::db::{self as store, Pool};
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub const DEFAULT_URL: &str = "https://api.blackpointcyber.com";
/// Calls a sweep leaves in Blackpoint's window for everything else.
pub const RESERVE: i64 = 100;
/// The detections poll leaves this many for the daily sweeps.
pub const DETECTIONS_RESERVE: i64 = 1000;
/// How long a call waits for Blackpoint's window to reset before the sweep stops for this run.
pub const MAX_WAIT: Duration = Duration::from_secs(60);
/// A listing with less than this share of what's stored is a bad answer, not a mass deletion.
const MIN_KEEP: f64 = 0.5;

#[derive(Clone)]
pub struct BlackpointCfg { pub base: String, pub token: String }
impl std::fmt::Debug for BlackpointCfg { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("BlackpointCfg").field("base", &self.base).finish_non_exhaustive() } }

/// Blackpoint's settings: on when both are there, off when neither is, a refusal when only one is.
pub fn settings(get: &dyn Fn(&str) -> Option<String>, secret: Option<String>, url: &dyn Fn(&str, String) -> Result<String, String>) -> Result<Option<BlackpointCfg>, String> {
    match (get("BLACKPOINT_BASE_URL"), secret) {
        (Some(b), Some(t)) => Ok(Some(BlackpointCfg { base: url("BLACKPOINT_BASE_URL", b)?, token: t })),
        (None, None) => Ok(None),
        _ => Err("Blackpoint needs BLACKPOINT_BASE_URL and BLACKPOINT_API_TOKEN (or _FILE) together".into()),
    }
}

/// Why a call failed: the window is spent (the sweep stops here for this run), or anything else, as a status and a
/// short reason, never the URL.
#[derive(Debug, Clone, PartialEq)]
pub enum Fail { Budget(String), Other(String) }
impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { match self { Fail::Budget(w) => write!(f, "Blackpoint's rate budget: {w}"), Fail::Other(w) => write!(f, "Blackpoint: {w}") } }
}

#[derive(Default)]
struct Window { remaining: Option<i64>, reset_at: Option<Instant>, paused_until: Option<Instant> }

#[derive(Clone)]
pub struct Blackpoint {
    pub base: String, token: String, http: reqwest::Client, limiter: Limiter,
    window: Arc<Mutex<Window>>, calls: Arc<std::sync::atomic::AtomicU64>,
    /// How long a sweep may run; shorter in tests.
    pub budget: Duration,
    /// How long a call waits for Blackpoint's window before the sweep stops; shorter in tests.
    pub max_wait: Duration,
}
impl std::fmt::Debug for Blackpoint { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("Blackpoint").field("base", &self.base).finish_non_exhaustive() } }

impl Blackpoint {
    pub fn new(c: &BlackpointCfg, http: reqwest::Client) -> Self {
        Self { base: c.base.trim_end_matches('/').into(), token: c.token.clone(), http, limiter: Limiter::new(5, Duration::from_secs(1)),
               window: Default::default(), calls: Default::default(), budget: Duration::from_secs(20 * 60), max_wait: MAX_WAIT }
    }
    pub fn calls(&self) -> u64 { self.calls.load(std::sync::atomic::Ordering::Relaxed) }

    /// Wait out a 429's pause or a spent window, or refuse when the wait would be long.
    async fn gate(&self, reserve: i64) -> Result<(), Fail> {
        loop {
            let wait = {
                let mut w = self.window.lock().await;
                let now = Instant::now();
                if let Some(p) = w.paused_until.filter(|p| *p > now) {
                    if p - now > self.max_wait { return Err(Fail::Budget(format!("paused {} s after a 429", (p - now).as_secs()))); }
                    p - now
                } else if let (Some(rem), Some(at)) = (w.remaining, w.reset_at.filter(|a| *a > now)) && rem <= reserve {
                    if at - now > self.max_wait { return Err(Fail::Budget(format!("{rem} calls left (reserve {reserve}), resets in {} s", (at - now).as_secs()))); }
                    w.remaining = None;
                    at - now
                } else { return Ok(()); }
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// One GET of a path under the API, for a tenant when given. Retries a 429 (after its reset) and a 503.
    pub async fn call(&self, path_and_query: &str, tenant: Option<&str>, reserve: i64) -> Result<(u16, Value), Fail> {
        let url = format!("{}{}", self.base, path_and_query);
        for attempt in 0..5u32 {
            self.gate(reserve).await?;
            self.limiter.acquire().await;
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut rb = self.http.get(&url).bearer_auth(&self.token).timeout(Duration::from_secs(60));
            if let Some(t) = tenant { rb = rb.header("x-tenant-id", t); }
            let r = match rb.send().await {
                Ok(r) => r,
                Err(e) if attempt < 2 => { let _ = e; tokio::time::sleep(Duration::from_millis(500 << attempt)).await; continue; }
                Err(e) => return Err(Fail::Other(if e.is_timeout() { "timed out".into() } else { "unreachable".into() })),
            };
            let num = |k: &str| r.headers().get(k).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<f64>().ok());
            let (rem, reset) = (num("x-ratelimit-remaining"), num("x-ratelimit-reset"));
            let reset_at = reset.map(|s| Instant::now() + Duration::from_secs_f64(s.max(0.0)));
            {
                let mut w = self.window.lock().await;
                if let Some(x) = rem { w.remaining = Some(x as i64); }
                if reset_at.is_some() { w.reset_at = reset_at; }
            }
            let st = r.status().as_u16();
            if st == 429 && attempt < 4 {
                let until = reset_at.unwrap_or_else(|| Instant::now() + Duration::from_secs(2 << attempt));
                let mut w = self.window.lock().await;
                w.paused_until = Some(w.paused_until.map_or(until, |p| p.max(until)));
                continue;
            }
            if st == 503 && attempt < 4 { tokio::time::sleep(Duration::from_millis(1000 << attempt)).await; continue; }
            if (300..400).contains(&st) { return Err(Fail::Other(format!("HTTP {st}: the address redirected; set the final address"))); }
            if st == 429 { return Err(Fail::Budget("still rate-limited after waiting".into())); }
            if !(200..300).contains(&st) {
                // Blackpoint's own short reason ({"message"}), cut short; never the URL.
                let why = r.json::<Value>().await.ok().and_then(|j| j.get("message").and_then(Value::as_str).map(|s| s.chars().take(100).collect::<String>()));
                return Ok((st, json!({ "error": why })));
            }
            return r.json::<Value>().await.map(|j| (st, j)).map_err(|_| Fail::Other("the answer isn't JSON".into()));
        }
        Err(Fail::Other("still failing after retrying".into()))
    }

    async fn ok(&self, path: &str, tenant: Option<&str>, reserve: i64) -> Result<Value, Fail> {
        let (st, j) = self.call(path, tenant, reserve).await?;
        if (200..300).contains(&st) { return Ok(j); }
        Err(Fail::Other(match j.get("error").and_then(Value::as_str) { Some(w) => format!("HTTP {st}: {w}"), None => format!("HTTP {st}") }))
    }

    /// Every page of a page/pageSize route ({data, meta: {totalPages}}).
    pub async fn pages(&self, path: &str, tenant: Option<&str>, reserve: i64) -> Result<Vec<Value>, Fail> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut out = Vec::new();
        for page in 1..10_000u32 {
            let j = self.ok(&format!("{path}{sep}pageSize=100&page={page}"), tenant, reserve).await?;
            let data = j.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
            let total = j.pointer("/meta/totalPages").and_then(Value::as_u64).unwrap_or(1);
            let empty = data.is_empty();
            out.extend(data);
            if empty || u64::from(page) >= total { break; }
        }
        Ok(out)
    }

    /// Every item of a take/skip route ({items, total}).
    pub async fn items(&self, path: &str, tenant: Option<&str>, reserve: i64) -> Result<Vec<Value>, Fail> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut out = Vec::new();
        for skip in (0..100_000u32).step_by(100) {
            let j = self.ok(&format!("{path}{sep}take=100&skip={skip}"), tenant, reserve).await?;
            let list = j.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
            let total = j.get("total").and_then(Value::as_u64).unwrap_or(0);
            let empty = list.is_empty();
            out.extend(list);
            if empty || out.len() as u64 >= total { break; }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- tenants and assets (every 6 hours)

    pub async fn sync_tenants(&self, pool: &Pool) -> Result<Outcome, String> {
        let started = Instant::now();
        let tenants = self.pages("/v1/tenants", None, RESERVE).await.map_err(|e| e.to_string())?;
        let rows: Vec<Value> = tenants.iter().filter_map(|t| {
            let id = t.get("id").and_then(Value::as_str)?;
            let name = t.get("name").and_then(Value::as_str).unwrap_or("").trim();
            Some(json!({ "tenant_id": id, "name": name, "name_key": store::name_key(name),
                         "domain": t.get("domain").and_then(Value::as_str).map(|d| d.trim().to_lowercase()).filter(|d| !d.is_empty()) }))
        }).collect();
        let now = store::now();
        let ids: Vec<String> = rows.iter().filter_map(|r| r["tenant_id"].as_str().map(String::from)).collect();
        crate::on_pool!(pool, p, pg => {
            let mut tx = p.begin().await.map_err(db)?;
            sqlx::query(if pg {
                "INSERT INTO bp_tenant (tenant_id, name, name_key, domain, seen_at, deleted_at)
                 SELECT x.tenant_id, x.name, x.name_key, x.domain, $2, NULL FROM jsonb_to_recordset($1) AS x(tenant_id text, name text, name_key text, domain text)
                 ON CONFLICT (tenant_id) DO UPDATE SET name = excluded.name, name_key = excluded.name_key, domain = excluded.domain, seen_at = excluded.seen_at, deleted_at = NULL"
            } else {
                "INSERT INTO bp_tenant (tenant_id, name, name_key, domain, seen_at, deleted_at)
                 SELECT x.value ->> 'tenant_id', x.value ->> 'name', x.value ->> 'name_key', x.value ->> 'domain', $2, NULL FROM json_each($1) AS x WHERE true
                 ON CONFLICT (tenant_id) DO UPDATE SET name = excluded.name, name_key = excluded.name_key, domain = excluded.domain, seen_at = excluded.seen_at, deleted_at = NULL"
            }).bind(Value::Array(rows.clone())).bind(now).execute(&mut *tx).await.map_err(db)?;
            let (held,): (i64,) = sqlx::query_as("SELECT count(*) FROM bp_tenant WHERE deleted_at IS NULL").fetch_one(&mut *tx).await.map_err(db)?;
            if !ids.is_empty() && ids.len() as f64 >= held as f64 * MIN_KEEP {
                sqlx::query(if pg { "UPDATE bp_tenant SET deleted_at = $2 WHERE deleted_at IS NULL AND NOT (tenant_id = ANY($1))" }
                            else { "UPDATE bp_tenant SET deleted_at = $2 WHERE deleted_at IS NULL AND tenant_id NOT IN (SELECT value FROM json_each($1))" })
                    .bind(store::list(&ids)).bind(now).execute(&mut *tx).await.map_err(db)?;
            }
            tx.commit().await.map_err(db)?;
        });
        let suggested = suggest(pool).await?;
        // Each tenant: is its vulnerability detail licensed, and its device assets. Least recently swept first, so a
        // sweep that stops early is carried on by the next.
        let order: Vec<(String,)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT tenant_id FROM bp_tenant WHERE deleted_at IS NULL ORDER BY synced_at IS NOT NULL, synced_at, tenant_id").fetch_all(p).await).map_err(db)?;
        let (mut swept, mut licensed, mut assets_n, mut failed, mut deferred) = (0usize, 0usize, 0usize, 0usize, 0usize);
        let mut stopped: Option<String> = None;
        for (tid,) in &order {
            if stopped.is_some() || started.elapsed() > self.budget { deferred += 1; continue; }
            let probe = self.call("/v1/vulnerability-management/vulnerabilities/stats/count-by-severity?hasAffectedAssets=true", Some(tid), RESERVE).await;
            let lic = match probe { Ok((st, _)) => st == 200, Err(Fail::Budget(w)) => { stopped = Some(w); deferred += 1; continue; } Err(_) => { failed += 1; continue; } };
            let list = match self.pages("/v1/assets?class=DEVICE", Some(tid), RESERVE).await {
                Ok(l) => l,
                Err(Fail::Budget(w)) => { stopped = Some(w); deferred += 1; continue; }
                Err(_) => { failed += 1; continue; }
            };
            let rows: Vec<Value> = list.iter().filter_map(|a| {
                let id = a.get("id").and_then(Value::as_str)?;
                let host = a.get("hostname").or_else(|| a.get("name")).and_then(Value::as_str).map(|h| h.trim().chars().take(255).collect::<String>()).filter(|h| !h.is_empty());
                Some(json!({ "asset_id": id, "hostname": host, "os_name": a.get("osName").and_then(Value::as_str).map(|s| s.chars().take(200).collect::<String>()),
                             "last_seen_on": a.get("lastSeenOn").and_then(Value::as_str).and_then(store::ts_text) }))
            }).collect();
            write_assets(pool, tid, &rows, lic).await?;
            swept += 1; assets_n += rows.len(); if lic { licensed += 1; }
        }
        let matched = rematch(pool).await?;
        if !order.is_empty() && failed * 2 > order.len() { return Err(format!("{failed} of {} tenants' assets failed to read", order.len())); }
        Ok(Outcome { detail: json!({ "tenants": rows.len(), "suggested": suggested, "swept": swept, "licensed": licensed, "assets": assets_n, "assets_matched": matched,
                                      "failed": failed, "deferred": deferred, "rate_budget_stop": stopped, "api_calls": self.calls() }), cursor: None })
    }

    // ---------------------------------------------------------------- open detections (every 10 minutes)

    pub async fn sync_detections(&self, pool: &Pool) -> Result<Outcome, String> {
        let started = Instant::now();
        let order: Vec<(String,)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT tenant_id FROM bp_tenant WHERE deleted_at IS NULL ORDER BY detections_at IS NOT NULL, detections_at, tenant_id").fetch_all(p).await).map_err(db)?;
        if order.is_empty() { return Ok(Outcome { detail: json!({ "tenants": 0, "skipped": "no Blackpoint tenants yet; the tenants job lists them" }), cursor: None }); }
        let (mut polled, mut open, mut failed, mut deferred) = (0usize, 0usize, 0usize, 0usize);
        let mut stopped: Option<String> = None;
        let budget = self.budget.min(Duration::from_secs(4 * 60));
        for (tid,) in &order {
            if stopped.is_some() || started.elapsed() > budget { deferred += 1; continue; }
            let groups = match self.items("/v1/alert-groups?status=OPEN", Some(tid), DETECTIONS_RESERVE).await {
                Ok(g) => g,
                Err(Fail::Budget(w)) => { stopped = Some(w); deferred += 1; continue; }
                // A failed listing closes nothing: the tenant keeps what it had.
                Err(_) => { failed += 1; continue; }
            };
            let rows: Vec<Value> = groups.iter().filter_map(detection_row).collect();
            write_detections(pool, tid, &rows).await?;
            polled += 1; open += rows.len();
        }
        if failed * 2 > order.len() { return Err(format!("{failed} of {} tenants' detections failed to read", order.len())); }
        Ok(Outcome { detail: json!({ "tenants": order.len(), "polled": polled, "open": open, "failed": failed, "deferred": deferred, "rate_budget_stop": stopped }), cursor: None })
    }

    // ---------------------------------------------------------------- findings, devices, dark web (daily)

    pub async fn sync_vulns(&self, pool: &Pool) -> Result<Outcome, String> {
        let started = Instant::now();
        let tenants: Vec<(String,)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT tenant_id FROM bp_tenant WHERE deleted_at IS NULL AND vm_licensed ORDER BY vulns_at IS NOT NULL, vulns_at, tenant_id").fetch_all(p).await).map_err(db)?;
        let (mut listed, mut findings, mut list_failed, mut deferred, mut darkweb, mut darkweb_failed) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        let mut stopped: Option<String> = None;
        // The lists get two thirds of the run; device links the rest.
        let list_budget = self.budget * 2 / 3;
        for (tid,) in &tenants {
            if stopped.is_some() || started.elapsed() > list_budget { deferred += 1; continue; }
            match self.pages("/v1/vulnerability-management/vulnerabilities?hasAffectedAssets=true", Some(tid), RESERVE).await {
                Ok(list) => {
                    let rows: Vec<Value> = list.iter().filter_map(vuln_row).collect();
                    if write_vulns(pool, tid, &rows).await? { listed += 1; findings += rows.len(); } else { list_failed += 1; }
                }
                Err(Fail::Budget(w)) => { stopped = Some(w); deferred += 1; continue; }
                Err(_) => { list_failed += 1; }
            }
            match self.pages("/v1/vulnerability-management/darkweb/scan/exposures", Some(tid), RESERVE).await {
                Ok(list) => { let rows: Vec<Value> = list.iter().filter_map(darkweb_row).collect(); darkweb += rows.len(); write_darkweb(pool, tid, &rows).await?; }
                Err(Fail::Budget(w)) => { stopped = Some(w); }
                Err(_) => { darkweb_failed += 1; }
            }
        }
        // Which devices carry a finding: one call per finding, so the ones that matter most first (actively attacked,
        // prioritized, critical, then high), least recently linked first, as far as the budget reaches.
        let cands: Vec<(String, String)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
            "SELECT v.vuln_id, v.tenant_id FROM bp_vulnerability v JOIN bp_tenant t ON t.tenant_id = v.tenant_id
              WHERE t.vm_licensed AND t.deleted_at IS NULL AND COALESCE(v.assets_amount, 1) > 0
                AND (v.exploitability = 'Attacked' OR v.prioritized OR v.severity IN ('CRITICAL', 'HIGH'))
              ORDER BY (v.exploitability = 'Attacked') DESC, v.prioritized DESC, (v.severity = 'CRITICAL') DESC, v.linked_at IS NOT NULL, v.linked_at, v.base_score DESC, v.vuln_id")
            .fetch_all(p).await).map_err(db)?;
        let (mut linked, mut links, mut link_failed, mut link_deferred) = (0usize, 0usize, 0usize, 0usize);
        for (vid, tid) in &cands {
            if stopped.is_some() || started.elapsed() > self.budget { link_deferred += 1; continue; }
            let path = format!("/v1/vulnerability-management/vulnerabilities/{}/assets?class=DEVICE", crate::connectors::ninja::urlenc(vid));
            match self.pages(&path, Some(tid), RESERVE).await {
                Ok(list) => {
                    let rows: Vec<Value> = list.iter().filter_map(|a| Some(json!({ "asset_id": a.get("id").and_then(Value::as_str)?,
                        "status": a.get("status").and_then(Value::as_str), "last_seen_on": a.get("lastSeenOn").and_then(Value::as_str).and_then(store::ts_text) }))).collect();
                    links += rows.len(); linked += 1;
                    write_links(pool, vid, tid, &rows).await?;
                }
                Err(Fail::Budget(w)) => { stopped = Some(w); link_deferred += 1; }
                Err(_) => link_failed += 1,
            }
        }
        let evidence = build_evidence(pool).await?;
        if !tenants.is_empty() && list_failed * 2 > tenants.len() { return Err(format!("{list_failed} of {} tenants' findings failed to read", tenants.len())); }
        Ok(Outcome { detail: json!({ "licensed_tenants": tenants.len(), "listed": listed, "findings": findings, "list_failed": list_failed, "deferred": deferred,
                                      "linked": linked, "links": links, "link_failed": link_failed, "link_deferred": link_deferred,
                                      "darkweb": darkweb, "darkweb_failed": darkweb_failed, "evidence": evidence, "rate_budget_stop": stopped, "api_calls": self.calls() }), cursor: None })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        let (a, b, c) = (self.clone(), self.clone(), self.clone());
        vec![
            Job { name: "blackpoint_tenants", every: Duration::from_secs(6 * 3600), run: Arc::new(move |pool, _| { let x = a.clone(); Box::pin(async move { x.sync_tenants(&pool).await }) }) },
            Job { name: "blackpoint_detections", every: Duration::from_secs(10 * 60), run: Arc::new(move |pool, _| { let x = b.clone(); Box::pin(async move { x.sync_detections(&pool).await }) }) },
            Job { name: "blackpoint_vulns", every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, _| { let x = c.clone(); Box::pin(async move { x.sync_vulns(&pool).await }) }) },
        ]
    }
}

// ---------------------------------------------------------------- rows: only what the console keeps

fn clip(v: Option<&Value>, n: usize) -> Option<String> { v.and_then(Value::as_str).map(|s| s.trim().chars().take(n).collect::<String>()).filter(|s| !s.is_empty()) }

/// One open alert group as a detection row.
pub fn detection_row(g: &Value) -> Option<Value> {
    let id = g.get("id").and_then(Value::as_str)?;
    let a = g.get("alert").cloned().unwrap_or(Value::Null);
    let types: Vec<String> = g.get("alertTypes").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(|s| s.chars().take(100).collect()).take(20).collect();
    Some(json!({ "detection_id": id, "status": "OPEN", "risk_score": g.get("riskScore").and_then(Value::as_i64), "alert_count": g.get("alertCount").and_then(Value::as_i64),
        "alert_types": types, "hostname": clip(a.get("hostname"), 255), "username": clip(a.get("username"), 255),
        "detection_name": clip(a.get("action"), 300), "rule_name": clip(a.get("ruleName"), 300),
        "created": g.get("created").and_then(Value::as_str).and_then(store::ts_text), "updated": g.get("updated").and_then(Value::as_str).and_then(store::ts_text) }))
}

pub fn vuln_row(v: &Value) -> Option<Value> {
    let id = v.get("id").map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).filter(|s| !s.is_empty() && s != "null")?;
    let cve = v.get("cveId").and_then(Value::as_str).map(|s| s.trim().to_uppercase()).filter(|s| s.starts_with("CVE-"));
    Some(json!({ "vuln_id": id, "cve_id": cve, "name": clip(v.get("name").or_else(|| v.get("displayName")), 300), "severity": clip(v.get("severity"), 20).map(|s| s.to_uppercase()),
        "base_score": v.get("baseScore").and_then(|x| x.as_f64().or_else(|| x.as_str().and_then(|s| s.parse().ok()))), "exploitability": clip(v.get("exploitability"), 40),
        "status": clip(v.get("status"), 40), "prioritized": v.get("prioritized").and_then(Value::as_bool).unwrap_or(false), "assets_amount": v.get("assetsAmount").and_then(Value::as_i64),
        "app_vendor": clip(v.get("applicationVendor"), 200), "app_name": clip(v.get("applicationName").or_else(|| v.get("applicationFamily")), 200),
        "found_on": v.get("foundOn").and_then(Value::as_str).and_then(store::ts_text), "last_seen_on": v.get("lastSeenOn").and_then(Value::as_str).and_then(store::ts_text) }))
}

/// A dark-web exposure: the email, the breach's name, the date, and what kind of data was exposed. Only these fields
/// are read; whatever else Blackpoint sends (a password, a hash, a username) is never looked at.
pub fn darkweb_row(x: &Value) -> Option<Value> {
    let id = x.get("id").map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).filter(|s| !s.is_empty() && s != "null")?;
    let email = x.get("email").and_then(Value::as_str).map(|e| e.trim().to_lowercase()).filter(|e| e.contains('@') && e.len() <= 320);
    let kind = if x.get("passwordExposed").and_then(Value::as_bool) == Some(true) { "password" }
               else if x.get("usernameExposed").and_then(Value::as_bool) == Some(true) { "username" } else { "email" };
    let date = ["breachCreatedAt", "createdAt", "foundOn"].iter().find_map(|k| x.get(*k).and_then(Value::as_str)).and_then(store::ts_text).map(|t| t[..10].to_string());
    Some(json!({ "exposure_id": id, "email": email, "source": clip(x.get("breachName"), 200), "found_on": date, "kind": kind }))
}

// ---------------------------------------------------------------- writes

async fn write_assets(pool: &Pool, tid: &str, rows: &[Value], licensed: bool) -> Result<(), String> {
    let now = store::now();
    let ids: Vec<String> = rows.iter().filter_map(|r| r["asset_id"].as_str().map(String::from)).collect();
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO bp_asset (asset_id, tenant_id, hostname, os_name, last_seen_on, synced_at, deleted_at)
             SELECT x.asset_id, $2, x.hostname, x.os_name, x.last_seen_on, $3, NULL FROM jsonb_to_recordset($1) AS x(asset_id text, hostname text, os_name text, last_seen_on timestamptz)
             ON CONFLICT (asset_id) DO UPDATE SET tenant_id = excluded.tenant_id, hostname = excluded.hostname, os_name = excluded.os_name, last_seen_on = excluded.last_seen_on,
               synced_at = excluded.synced_at, deleted_at = NULL"
        } else {
            "INSERT INTO bp_asset (asset_id, tenant_id, hostname, os_name, last_seen_on, synced_at, deleted_at)
             SELECT x.value ->> 'asset_id', $2, x.value ->> 'hostname', x.value ->> 'os_name', x.value ->> 'last_seen_on', $3, NULL FROM json_each($1) AS x WHERE true
             ON CONFLICT (asset_id) DO UPDATE SET tenant_id = excluded.tenant_id, hostname = excluded.hostname, os_name = excluded.os_name, last_seen_on = excluded.last_seen_on,
               synced_at = excluded.synced_at, deleted_at = NULL"
        }).bind(Value::Array(rows.to_vec())).bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(if pg { "UPDATE bp_asset SET deleted_at = $3 WHERE tenant_id = $2 AND deleted_at IS NULL AND NOT (asset_id = ANY($1))" }
                    else { "UPDATE bp_asset SET deleted_at = $3 WHERE tenant_id = $2 AND deleted_at IS NULL AND asset_id NOT IN (SELECT value FROM json_each($1))" })
            .bind(store::list(&ids)).bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE bp_tenant SET vm_licensed = $2, synced_at = $3 WHERE tenant_id = $1").bind(tid).bind(licensed).bind(now).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

/// A tenant's complete list of open detections: upserted, and any it had open that isn't listed now is closed.
pub async fn write_detections(pool: &Pool, tid: &str, rows: &[Value]) -> Result<(), String> {
    let now = store::now();
    let ids: Vec<String> = rows.iter().filter_map(|r| r["detection_id"].as_str().map(String::from)).collect();
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO bp_detection (detection_id, tenant_id, status, risk_score, alert_count, alert_types, hostname, username, detection_name, rule_name, created, updated, last_seen_open, synced_at)
             SELECT x.detection_id, $2, 'OPEN', x.risk_score, x.alert_count, x.alert_types, x.hostname, x.username, x.detection_name, x.rule_name, x.created, x.updated, $3, $3
               FROM jsonb_to_recordset($1) AS x(detection_id text, risk_score bigint, alert_count bigint, alert_types jsonb, hostname text, username text, detection_name text, rule_name text, created timestamptz, updated timestamptz)
             ON CONFLICT (detection_id) DO UPDATE SET tenant_id = excluded.tenant_id, status = 'OPEN', risk_score = excluded.risk_score, alert_count = excluded.alert_count,
               alert_types = excluded.alert_types, hostname = excluded.hostname, username = excluded.username, detection_name = excluded.detection_name, rule_name = excluded.rule_name,
               created = excluded.created, updated = excluded.updated, last_seen_open = excluded.last_seen_open, synced_at = excluded.synced_at"
        } else {
            "INSERT INTO bp_detection (detection_id, tenant_id, status, risk_score, alert_count, alert_types, hostname, username, detection_name, rule_name, created, updated, last_seen_open, synced_at)
             SELECT x.value ->> 'detection_id', $2, 'OPEN', x.value ->> 'risk_score', x.value ->> 'alert_count', x.value -> 'alert_types', x.value ->> 'hostname', x.value ->> 'username',
                    x.value ->> 'detection_name', x.value ->> 'rule_name', x.value ->> 'created', x.value ->> 'updated', $3, $3
               FROM json_each($1) AS x WHERE true
             ON CONFLICT (detection_id) DO UPDATE SET tenant_id = excluded.tenant_id, status = 'OPEN', risk_score = excluded.risk_score, alert_count = excluded.alert_count,
               alert_types = excluded.alert_types, hostname = excluded.hostname, username = excluded.username, detection_name = excluded.detection_name, rule_name = excluded.rule_name,
               created = excluded.created, updated = excluded.updated, last_seen_open = excluded.last_seen_open, synced_at = excluded.synced_at"
        }).bind(Value::Array(rows.to_vec())).bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(if pg { "UPDATE bp_detection SET status = 'closed', synced_at = $3 WHERE tenant_id = $2 AND status = 'OPEN' AND NOT (detection_id = ANY($1))" }
                    else { "UPDATE bp_detection SET status = 'closed', synced_at = $3 WHERE tenant_id = $2 AND status = 'OPEN' AND detection_id NOT IN (SELECT value FROM json_each($1))" })
            .bind(store::list(&ids)).bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE bp_tenant SET open_detections = $2, detections_at = $3 WHERE tenant_id = $1").bind(tid).bind(rows.len() as i64).bind(now).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

/// A tenant's findings, replacing what it had. false: the listing was too short against what's stored to believe.
async fn write_vulns(pool: &Pool, tid: &str, rows: &[Value]) -> Result<bool, String> {
    let now = store::now();
    let ids: Vec<String> = rows.iter().filter_map(|r| r["vuln_id"].as_str().map(String::from)).collect();
    let ok = crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        let (stored,): (i64,) = sqlx::query_as("SELECT count(*) FROM bp_vulnerability WHERE tenant_id = $1").bind(tid).fetch_one(&mut *tx).await.map_err(db)?;
        if stored >= 50 && (rows.len() as f64) < stored as f64 * MIN_KEEP { false } else {
            sqlx::query(if pg {
                "INSERT INTO bp_vulnerability (vuln_id, tenant_id, cve_id, name, severity, base_score, exploitability, status, prioritized, assets_amount, app_vendor, app_name, found_on, last_seen_on, synced_at)
                 SELECT x.vuln_id, $2, x.cve_id, x.name, x.severity, x.base_score, x.exploitability, x.status, x.prioritized, x.assets_amount, x.app_vendor, x.app_name, x.found_on, x.last_seen_on, $3
                   FROM jsonb_to_recordset($1) AS x(vuln_id text, cve_id text, name text, severity text, base_score double precision, exploitability text, status text, prioritized boolean,
                                                    assets_amount bigint, app_vendor text, app_name text, found_on timestamptz, last_seen_on timestamptz)
                 ON CONFLICT (vuln_id) DO UPDATE SET tenant_id = excluded.tenant_id, cve_id = excluded.cve_id, name = excluded.name, severity = excluded.severity, base_score = excluded.base_score,
                   exploitability = excluded.exploitability, status = excluded.status, prioritized = excluded.prioritized, assets_amount = excluded.assets_amount, app_vendor = excluded.app_vendor,
                   app_name = excluded.app_name, found_on = excluded.found_on, last_seen_on = excluded.last_seen_on, synced_at = excluded.synced_at"
            } else {
                "INSERT INTO bp_vulnerability (vuln_id, tenant_id, cve_id, name, severity, base_score, exploitability, status, prioritized, assets_amount, app_vendor, app_name, found_on, last_seen_on, synced_at)
                 SELECT x.value ->> 'vuln_id', $2, x.value ->> 'cve_id', x.value ->> 'name', x.value ->> 'severity', x.value ->> 'base_score', x.value ->> 'exploitability', x.value ->> 'status',
                        coalesce(x.value ->> 'prioritized', 0), x.value ->> 'assets_amount', x.value ->> 'app_vendor', x.value ->> 'app_name', x.value ->> 'found_on', x.value ->> 'last_seen_on', $3
                   FROM json_each($1) AS x WHERE true
                 ON CONFLICT (vuln_id) DO UPDATE SET tenant_id = excluded.tenant_id, cve_id = excluded.cve_id, name = excluded.name, severity = excluded.severity, base_score = excluded.base_score,
                   exploitability = excluded.exploitability, status = excluded.status, prioritized = excluded.prioritized, assets_amount = excluded.assets_amount, app_vendor = excluded.app_vendor,
                   app_name = excluded.app_name, found_on = excluded.found_on, last_seen_on = excluded.last_seen_on, synced_at = excluded.synced_at"
            }).bind(Value::Array(rows.to_vec())).bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
            let gone: Vec<(String,)> = sqlx::query_as(if pg { "DELETE FROM bp_vulnerability WHERE tenant_id = $2 AND NOT (vuln_id = ANY($1)) RETURNING vuln_id" }
                                                       else { "DELETE FROM bp_vulnerability WHERE tenant_id = $2 AND vuln_id NOT IN (SELECT value FROM json_each($1)) RETURNING vuln_id" })
                .bind(store::list(&ids)).bind(tid).fetch_all(&mut *tx).await.map_err(db)?;
            let gone: Vec<String> = gone.into_iter().map(|g| g.0).collect();
            sqlx::query(if pg { "DELETE FROM bp_vulnerability_asset WHERE vuln_id = ANY($1)" } else { "DELETE FROM bp_vulnerability_asset WHERE vuln_id IN (SELECT value FROM json_each($1))" })
                .bind(store::list(&gone)).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("UPDATE bp_tenant SET vulns_at = $2 WHERE tenant_id = $1").bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
            true
        }
    });
    Ok(ok)
}

async fn write_links(pool: &Pool, vid: &str, tid: &str, rows: &[Value]) -> Result<(), String> {
    let ids: Vec<String> = rows.iter().filter_map(|r| r["asset_id"].as_str().map(String::from)).collect();
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO bp_vulnerability_asset (vuln_id, asset_id, tenant_id, status, last_seen_on)
             SELECT $2, x.asset_id, $3, x.status, x.last_seen_on FROM jsonb_to_recordset($1) AS x(asset_id text, status text, last_seen_on timestamptz)
             ON CONFLICT (vuln_id, asset_id) DO UPDATE SET status = excluded.status, last_seen_on = excluded.last_seen_on"
        } else {
            "INSERT INTO bp_vulnerability_asset (vuln_id, asset_id, tenant_id, status, last_seen_on)
             SELECT $2, x.value ->> 'asset_id', $3, x.value ->> 'status', x.value ->> 'last_seen_on' FROM json_each($1) AS x WHERE true
             ON CONFLICT (vuln_id, asset_id) DO UPDATE SET status = excluded.status, last_seen_on = excluded.last_seen_on"
        }).bind(Value::Array(rows.to_vec())).bind(vid).bind(tid).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(if pg { "DELETE FROM bp_vulnerability_asset WHERE vuln_id = $2 AND NOT (asset_id = ANY($1))" }
                    else { "DELETE FROM bp_vulnerability_asset WHERE vuln_id = $2 AND asset_id NOT IN (SELECT value FROM json_each($1))" })
            .bind(store::list(&ids)).bind(vid).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE bp_vulnerability SET linked_at = $2 WHERE vuln_id = $1").bind(vid).bind(store::now()).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

async fn write_darkweb(pool: &Pool, tid: &str, rows: &[Value]) -> Result<(), String> {
    let now = store::now();
    let ids: Vec<String> = rows.iter().filter_map(|r| r["exposure_id"].as_str().map(String::from)).collect();
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO bp_darkweb (exposure_id, tenant_id, email, source, found_on, kind, synced_at, deleted_at)
             SELECT x.exposure_id, $2, x.email, x.source, x.found_on, x.kind, $3, NULL FROM jsonb_to_recordset($1) AS x(exposure_id text, email text, source text, found_on date, kind text)
             ON CONFLICT (exposure_id) DO UPDATE SET tenant_id = excluded.tenant_id, email = excluded.email, source = excluded.source, found_on = excluded.found_on, kind = excluded.kind,
               synced_at = excluded.synced_at, deleted_at = NULL"
        } else {
            "INSERT INTO bp_darkweb (exposure_id, tenant_id, email, source, found_on, kind, synced_at, deleted_at)
             SELECT x.value ->> 'exposure_id', $2, x.value ->> 'email', x.value ->> 'source', x.value ->> 'found_on', x.value ->> 'kind', $3, NULL FROM json_each($1) AS x WHERE true
             ON CONFLICT (exposure_id) DO UPDATE SET tenant_id = excluded.tenant_id, email = excluded.email, source = excluded.source, found_on = excluded.found_on, kind = excluded.kind,
               synced_at = excluded.synced_at, deleted_at = NULL"
        }).bind(Value::Array(rows.to_vec())).bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(if pg { "UPDATE bp_darkweb SET deleted_at = $3 WHERE tenant_id = $2 AND deleted_at IS NULL AND NOT (exposure_id = ANY($1))" }
                    else { "UPDATE bp_darkweb SET deleted_at = $3 WHERE tenant_id = $2 AND deleted_at IS NULL AND exposure_id NOT IN (SELECT value FROM json_each($1))" })
            .bind(store::list(&ids)).bind(tid).bind(now).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

// ---------------------------------------------------------------- the mapping

/// Corporate suffixes that don't make two names different ("Example Dental PC" and "Example Dental, P.C.").
const SUFFIX: &[&str] = &["llc", "inc", "pc", "pllc", "pa", "corp", "corporation", "ltd", "co", "company", "lp", "llp", "incorporated", "the"];

/// A name as both systems might spell it: name_key, with "&" read as "and", dots dropped first (so "P.C." is one
/// word), and trailing corporate suffixes gone.
pub fn match_key(name: &str) -> String {
    let k = store::name_key(&name.replace('.', "").replace('&', " and "));
    let mut words: Vec<&str> = k.split_whitespace().collect();
    while words.len() > 1 && words.last().is_some_and(|w| SUFFIX.contains(w)) { words.pop(); }
    if words.len() > 1 && words.first() == Some(&"the") { words.remove(0); }
    words.join(" ")
}

/// Suggestions, recomputed whole each run for the tenants no user has decided: a client whose website's domain is the
/// tenant's (exactly one), else a client whose name reads the same (exactly one). Returns how many have one.
pub async fn suggest(pool: &Pool) -> Result<usize, String> {
    type T = (String, String, Option<String>);
    type Rows = (Vec<T>, Vec<(i64, String)>, Vec<(i64, Option<Value>)>);
    let (tenants, clients, sites): Rows = crate::on_pool!(pool, p, _ => (
        sqlx::query_as("SELECT tenant_id, name, domain FROM bp_tenant WHERE deleted_at IS NULL AND org_id IS NULL AND NOT not_client").fetch_all(p).await.map_err(db)?,
        sqlx::query_as("SELECT org_id, name FROM client WHERE deleted_at IS NULL").fetch_all(p).await.map_err(db)?,
        // Websites only where Halo's link to the client is confirmed (its own NinjaOne link), never a name guess.
        sqlx::query_as("SELECT c.org_id, h.website_sites FROM client c JOIN halo_client h ON h.halo_client_id = c.halo_client_id
                         WHERE c.deleted_at IS NULL AND h.deleted_at IS NULL AND c.halo_matched_by = 'ninjarmm_id'").fetch_all(p).await.map_err(db)?));
    let mut by_apex: HashMap<String, Vec<i64>> = HashMap::new();
    for (org, s) in &sites {
        for w in s.as_ref().and_then(Value::as_array).into_iter().flatten() {
            if let Some(a) = w.get("apex").and_then(Value::as_str) { let e = by_apex.entry(a.to_string()).or_default(); if !e.contains(org) { e.push(*org); } }
        }
    }
    let mut by_name: HashMap<String, Vec<i64>> = HashMap::new();
    for (org, n) in &clients { let k = match_key(n); if !k.is_empty() { by_name.entry(k).or_default().push(*org); } }
    let picks: Vec<Value> = tenants.iter().map(|(id, name, domain)| {
        let apex = domain.as_deref().and_then(crate::website::normalise_host).map(|h| crate::website::apex_of(&h));
        let (org, by) = match apex.and_then(|a| by_apex.get(&a)).filter(|v| v.len() == 1) {
            Some(v) => (Some(v[0]), Some("domain")),
            None => match by_name.get(&match_key(name)).filter(|v| v.len() == 1) { Some(v) => (Some(v[0]), Some("name")), None => (None, None) },
        };
        json!({ "tenant_id": id, "org_id": org, "by": by })
    }).collect();
    let n = picks.iter().filter(|p| !p["org_id"].is_null()).count();
    crate::on_pool!(pool, p, pg => {
        sqlx::query(if pg {
            "UPDATE bp_tenant SET suggested_org_id = x.org_id, suggested_by = x.by FROM jsonb_to_recordset($1) AS x(tenant_id text, org_id bigint, by text)
              WHERE bp_tenant.tenant_id = x.tenant_id AND bp_tenant.org_id IS NULL AND NOT bp_tenant.not_client"
        } else {
            "UPDATE bp_tenant SET suggested_org_id = x.value ->> 'org_id', suggested_by = x.value ->> 'by' FROM json_each($1) AS x
              WHERE bp_tenant.tenant_id = x.value ->> 'tenant_id' AND bp_tenant.org_id IS NULL AND NOT bp_tenant.not_client"
        }).bind(Value::Array(picks)).execute(p).await.map_err(db)?;
    });
    Ok(n)
}

/// Assets to devices: the hostname, inside the tenant's confirmed client, when exactly one live device there has it.
/// Rebuilt whole, so a tenant mapped to another client (or unmapped) moves its assets with it. Returns how many matched.
pub async fn rematch(pool: &Pool) -> Result<u64, String> {
    crate::on_pool!(pool, p, _ => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("UPDATE bp_asset SET device_id = NULL WHERE device_id IS NOT NULL").execute(&mut *tx).await.map_err(db)?;
        let n = sqlx::query(
            "UPDATE bp_asset SET device_id = (
                 SELECT min(d.device_id) FROM device d JOIN bp_tenant t ON t.org_id = d.org_id
                  WHERE t.tenant_id = bp_asset.tenant_id AND d.deleted_at IS NULL AND upper(d.name) = upper(bp_asset.hostname)
                 HAVING count(*) = 1)
              WHERE bp_asset.deleted_at IS NULL AND bp_asset.hostname IS NOT NULL")
            .execute(&mut *tx).await.map_err(db)?;
        let _ = n;
        let (m,): (i64,) = sqlx::query_as("SELECT count(*) FROM bp_asset WHERE device_id IS NOT NULL AND deleted_at IS NULL").fetch_one(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(m as u64)
    })
}

/// Blackpoint's findings as `blackpoint` evidence: each finding on each matched
/// device, closed ones left out. Blackpoint names the CVE and an application but no version, so the product is
/// attributed and marked so: `nvd-match` when one of the CVE's NVD products is already known on that device (its
/// version is that evidence's), else `bp-app`, Blackpoint's own app as bp:<vendor>:<app> with no version. The source's
/// rows are replaced whole. Returns the counts.
pub async fn build_evidence(pool: &Pool) -> Result<Value, String> {
    type L = (i64, String, Option<String>, Option<String>, Option<f64>, Option<String>, bool, Option<String>, Option<String>, Option<String>, Option<String>);
    let links: Vec<L> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT a.device_id, v.vuln_id, v.cve_id, v.name, v.base_score, v.exploitability, v.prioritized, v.app_vendor, v.app_name, COALESCE(l.status, v.status), v.severity
           FROM bp_vulnerability_asset l JOIN bp_asset a ON a.asset_id = l.asset_id AND a.deleted_at IS NULL AND a.device_id IS NOT NULL
           JOIN bp_vulnerability v ON v.vuln_id = l.vuln_id
           JOIN device d ON d.device_id = a.device_id AND d.deleted_at IS NULL
          WHERE lower(COALESCE(l.status, v.status, 'open')) <> 'closed'
          ORDER BY a.device_id, v.vuln_id").fetch_all(p).await).map_err(db)?;
    let cves: Vec<String> = { let mut c: Vec<String> = links.iter().filter_map(|l| l.2.clone()).collect(); c.sort(); c.dedup(); c };
    let devices: Vec<i64> = { let mut d: Vec<i64> = links.iter().map(|l| l.0).collect(); d.sort(); d.dedup(); d };
    type Known = (Vec<(String, String)>, Vec<(i64, String, String)>);
    let (cve_products, known): Known = crate::on_pool!(pool, p, pg => (
        sqlx::query_as(if pg { "SELECT c.cve_id, p.product_key FROM sec_nvd_cpe c JOIN sec_product p ON p.cpe = c.cpe WHERE c.cve_id = ANY($1) ORDER BY p.product_key" }
                       else { "SELECT c.cve_id, p.product_key FROM sec_nvd_cpe c JOIN sec_product p ON p.cpe = c.cpe WHERE c.cve_id IN (SELECT value FROM json_each($1)) ORDER BY p.product_key" })
            .bind(store::list(&cves)).fetch_all(p).await.map_err(db)?,
        sqlx::query_as(if pg { "SELECT device_id, product_key, max(version) FROM sec_evidence WHERE source IN ('ninja_software', 'process') AND device_id = ANY($1) GROUP BY device_id, product_key" }
                       else { "SELECT device_id, product_key, max(version) FROM sec_evidence WHERE source IN ('ninja_software', 'process') AND device_id IN (SELECT value FROM json_each($1)) GROUP BY device_id, product_key" })
            .bind(store::list(&devices)).fetch_all(p).await.map_err(db)?));
    let mut products: HashMap<&str, Vec<&str>> = HashMap::new();
    for (c, k) in &cve_products { products.entry(c.as_str()).or_default().push(k.as_str()); }
    let mut on: HashMap<i64, HashMap<&str, &str>> = HashMap::new();
    for (d, k, v) in &known { on.entry(*d).or_default().insert(k.as_str(), v.as_str()); }
    let slug = |s: Option<&str>| { let k = store::name_key(s.unwrap_or("")).trim().replace(' ', "_"); if k.is_empty() { "unknown".to_string() } else { k } };
    let mut ev: std::collections::BTreeMap<(i64, String, String), Value> = Default::default();
    let mut evc: std::collections::BTreeMap<(i64, String, String), Value> = Default::default();
    for (device, vid, cve, name, score, exploit, prio, vendor, app, status, sev) in &links {
        let found = cve.as_deref().and_then(|c| products.get(c)).and_then(|ks| ks.iter().find_map(|k| on.get(device).and_then(|m| m.get(k)).map(|v| (k.to_string(), v.to_string()))));
        let (key, version, attribution) = match found {
            Some((k, v)) => (k, v, "nvd-match"),
            None => (format!("bp:{}:{}", slug(vendor.as_deref()), slug(app.as_deref().or(name.as_deref()))), String::new(), "bp-app"),
        };
        let app_label = [vendor.as_deref(), app.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" ");
        let e = ev.entry((*device, key.clone(), version.clone())).or_insert_with(|| json!({ "device_id": device, "product_key": key, "version": version, "attribution": attribution,
            "detail": { "app": app_label, "vuln_ids": [] } }));
        if let Some(a) = e["detail"]["vuln_ids"].as_array_mut() && !a.contains(&json!(vid)) { a.push(json!(vid)); }
        let Some(cve) = cve else { continue };
        evc.entry((*device, cve.clone(), key.clone())).or_insert_with(|| json!({ "device_id": device, "cve_id": cve, "product_key": key, "version": version, "attribution": attribution,
            "cvss": score, "exploited": exploit.as_deref() == Some("Attacked"),
            "detail": { "vuln_id": vid, "status": status, "severity": sev, "prioritized": prio, "exploitability": exploit, "app": app_label } }));
    }
    let (evidence, cve_rows): (Vec<Value>, Vec<Value>) = (ev.into_values().collect(), evc.into_values().collect());
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM sec_evidence WHERE source = 'blackpoint'").execute(&mut *tx).await.map_err(db)?;
        sqlx::query("DELETE FROM sec_evidence_cve WHERE source = 'blackpoint'").execute(&mut *tx).await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO sec_evidence (device_id, product_key, version, source, attribution, detail)
             SELECT x.device_id, x.product_key, x.version, 'blackpoint', x.attribution, x.detail FROM jsonb_to_recordset($1) AS x(device_id bigint, product_key text, version text, attribution text, detail jsonb)"
        } else {
            "INSERT INTO sec_evidence (device_id, product_key, version, source, attribution, detail)
             SELECT x.value ->> 'device_id', x.value ->> 'product_key', x.value ->> 'version', 'blackpoint', x.value ->> 'attribution', x.value -> 'detail' FROM json_each($1) AS x"
        }).bind(Value::Array(evidence.clone())).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, attribution, cvss, exploited, detail)
             SELECT x.device_id, x.cve_id, x.product_key, x.version, 'blackpoint', x.attribution, x.cvss, x.exploited, x.detail
               FROM jsonb_to_recordset($1) AS x(device_id bigint, cve_id text, product_key text, version text, attribution text, cvss double precision, exploited boolean, detail jsonb)"
        } else {
            "INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, attribution, cvss, exploited, detail)
             SELECT x.value ->> 'device_id', x.value ->> 'cve_id', x.value ->> 'product_key', x.value ->> 'version', 'blackpoint', x.value ->> 'attribution', x.value ->> 'cvss',
                    x.value ->> 'exploited', x.value -> 'detail' FROM json_each($1) AS x"
        }).bind(Value::Array(cve_rows.clone())).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    let nvd_match = evidence.iter().filter(|e| e["attribution"] == "nvd-match").count();
    Ok(json!({ "devices": devices.len(), "evidence": evidence.len(), "device_cves": cve_rows.len(), "nvd_match": nvd_match, "bp_app": evidence.len() - nvd_match }))
}

/// How long a dark-web exposure Blackpoint no longer lists is kept, soft-deleted, before it's gone from the store: the
/// row is a person's email address in a breach, so it isn't kept past the reason to (the next store backup after the
/// purge no longer has it; older backups age out with BACKUP_KEEP).
pub const DARKWEB_KEEP_DAYS: i64 = 30;

/// The retention purge: every dark-web row soft-deleted more than DARKWEB_KEEP_DAYS before `now`, deleted.
pub async fn purge_darkweb(pool: &Pool, now: chrono::DateTime<chrono::Utc>) -> Result<Outcome, String> {
    let cut = store::Ts(now - chrono::Duration::days(DARKWEB_KEEP_DAYS));
    let n = crate::on_pool!(pool, p, _ => sqlx::query("DELETE FROM bp_darkweb WHERE deleted_at IS NOT NULL AND deleted_at < $1").bind(cut).execute(p).await.map(|r| r.rows_affected())).map_err(db)?;
    Ok(Outcome { detail: json!({ "purged": n, "keep_days": DARKWEB_KEEP_DAYS }), cursor: None })
}

/// The purge runs daily whether Blackpoint is on or not, so turning Blackpoint off doesn't keep its rows for good.
pub fn retention_jobs() -> Vec<Job> {
    vec![Job { name: "darkweb_purge", every: Duration::from_secs(24 * 3600), run: Arc::new(|pool, _| Box::pin(async move { purge_darkweb(&pool, chrono::Utc::now()).await })) }]
}
