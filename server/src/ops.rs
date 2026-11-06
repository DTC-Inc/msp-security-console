//! Contract v1, answered from the console's own store: `cve.similar` from the console's own embedder
//! (src/embed.rs) here, and every other op in ops/core.rs and beside it. Keyset pages throughout. A caller's scope (`Scope`) is applied before
//! any op reads anything, and never widened by its own filters.

mod core;
pub use self::core::{NO_MSA, SOURCES};
pub mod actions;
pub mod blackpoint;
pub mod exposure;
pub mod tickets;

use crate::contract::{EvidenceRequest, Params, ReadOp};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::{json, Value};
use crate::db::{self as store, Pool};
use std::cmp::Ordering;

mod processes;
mod windows;

pub const MAX_LIMIT: usize = 500;
/// The most `cve.similar` hands back at once.
pub const SIMILAR_MAX: usize = 50;

/// The store, whether this process has similar-CVE search (its embedder, or why not), and which job keeps NVD's data
/// (`nvd_feeds` for the whole of NVD, the default; `nvd_products` with NVD_FEEDS=curated), so `as_of` names the one
/// that's scheduled and never a stale row from the other mode.
#[derive(Clone)]
pub struct Store { pub pool: Pool, pub similar: crate::embed::State, pub nvd_job: &'static str }

impl Store {
    /// A store without an embedder: `cve.similar` answers that it's off. NVD as the default (the whole feeds).
    pub fn new(pool: Pool) -> Self { Self { pool, similar: crate::embed::State::Off(NO_EMBEDDER.into()), nvd_job: NVD_FULL_JOB } }
    /// The same store, with this process's embedder.
    pub fn with_similar(self, similar: crate::embed::State) -> Self { Self { similar, ..self } }
    /// The NVD job this configuration schedules (crate::jobs): the feeds when `NVD_FEEDS=full`, else the per-product API.
    pub fn nvd_job_for(full_feeds: bool) -> &'static str { if full_feeds { NVD_FULL_JOB } else { NVD_CURATED_JOB } }
}
pub const NVD_FULL_JOB: &str = "nvd_feeds";
/// The ops over the whole fleet, which no one client's scope can narrow: the names waiting for a person to map them
/// come from every client's devices at once. A scoped caller (a client portal) is refused them.
pub const FLEET_OPS: &[ReadOp] = &[ReadOp::ProcessesReview];
/// The ops that take `state`, each with its own values (contract.rs, Params::state).
const STATE_OPS: &[ReadOp] = &[ReadOp::WindowsDevices, ReadOp::ProcessesList, ReadOp::ProcessesReview];
pub const NVD_CURATED_JOB: &str = "nvd_products";
pub const NO_EMBEDDER: &str = "similar-CVE search is off: this process has no embedder";

fn err(op: &str, e: impl Into<String>) -> Value { json!({ "v": 1, "op": op, "error": e.into() }) }

impl Store {
    /// An answer in contract v1's shape and its HTTP status; a failure is an `error`, never a panic, never a SQL
    /// message with data in it.
    pub async fn call(&self, req: &EvidenceRequest) -> (u16, Value) { self.call_scoped(req, &Scope::default()).await }

    /// An answer for a caller with limits (`Scope`): its pinned client applied first, a call naming another refused.
    pub async fn call_scoped(&self, req: &EvidenceRequest, scope: &Scope) -> (u16, Value) {
        let op = req.op.as_str();
        if *scope != Scope::default() && FLEET_OPS.contains(&req.op) {
            let mut e = err(op, format!("{op} is the whole fleet's, with no one client in it: a caller limited to one client can't read it"));
            e["refused"] = json!(true);
            return (403, e);
        }
        let p = match scope.apply(&req.params) {
            Ok(p) => p,
            Err(why) => { let mut e = err(op, why); e["refused"] = json!(true); return (403, e); }
        };
        let p = &p;
        if p.state.is_some() && !STATE_OPS.contains(&req.op) {
            return (400, err(op, format!("state isn't a filter of {op}: only windows.devices, processes.list and processes.review take one, each its own")));
        }
        // Every op answers: the match is exhaustive, so an op added to the contract without an answer doesn't build.
        let r = match req.op {
            ReadOp::Search => self.search(p).await,
            ReadOp::CvesList => self.cves_list(p).await,
            ReadOp::DevicesList => self.devices_list(p).await,
            ReadOp::ClientsList => self.clients_list(p).await,
            ReadOp::CveGet => self.cve_get(p).await,
            ReadOp::CveProducts => self.cve_products(p).await,
            ReadOp::CveDevices => self.cve_devices(p).await,
            ReadOp::CveSimilar => self.cve_similar(p).await,
            ReadOp::DeviceGet => self.device_get(p).await,
            ReadOp::DeviceCves => self.device_cves(p).await,
            ReadOp::DeviceProducts => self.device_products(p).await,
            ReadOp::DeviceSoftware => self.device_software(p).await,
            ReadOp::ProductGet => self.product_get(p).await,
            ReadOp::ProductVersions => self.product_versions(p).await,
            ReadOp::ProductDevices => self.product_devices(p).await,
            ReadOp::ProductsList => self.products_list(p).await,
            ReadOp::VersionCves => self.version_cves(p).await,
            ReadOp::ClientGet => self.client_get(p).await,
            ReadOp::ClientsOverview => self.clients_overview(p).await,
            ReadOp::CoverageList => self.coverage_list(p).await,
            ReadOp::CoverageDevices => self.coverage_devices(p).await,
            ReadOp::AdvisoriesList => self.advisories_list(p).await,
            ReadOp::DetectionsList => blackpoint::detections_list(self, p).await,
            ReadOp::DetectionGet => blackpoint::detection_get(self, p).await,
            ReadOp::BlackpointTenants => blackpoint::tenants(self, p).await,
            ReadOp::DarkwebList => blackpoint::darkweb(self, p).await,
            ReadOp::ExposureList => exposure::list(self, p).await,
            ReadOp::ExposureGet => exposure::get(self, p).await,
            ReadOp::WindowsDevices => self.windows_devices(p).await,
            ReadOp::WindowsCves => self.windows_cves(p).await,
            ReadOp::ProcessesList => self.processes_list(p).await,
            ReadOp::ProcessesReview => self.processes_review(p).await,
        };
        match r {
            Ok(mut v) => { v["v"] = json!(1); v["op"] = json!(op); (200, v) }
            Err(Failure::Bad(m)) => (400, err(op, m)),
            Err(Failure::NotFound(m)) => (404, err(op, m)),
            Err(Failure::Db) => (503, err(op, "the console's database didn't answer")),
        }
    }

    pub(crate) async fn as_of(&self) -> Value {
        type When = Option<chrono::DateTime<chrono::Utc>>;
        let (row, jobs): (Option<(When,)>, Vec<(String, When)>) = crate::on_pool!(&self.pool, p, _ => (
            sqlx::query_as("SELECT max(synced_at) FROM software_sync").fetch_optional(p).await.ok().flatten(),
            sqlx::query_as("SELECT name, last_ok_at FROM job").fetch_all(p).await.unwrap_or_default()));
        let mut m = serde_json::Map::new();
        m.insert("inventory".into(), json!(row.and_then(|r| r.0)));
        for (n, t) in jobs { if n == "kev" || n == self.nvd_job || n == "match" { m.insert(n, json!(t)); } }
        Value::Object(m)
    }
}

impl Store {
    fn sources(p: &Params) -> store::List<String> { store::List(self::core::source_list(p)) }

    /// The CVEs whose NVD descriptions are nearest in meaning to `cve_id`'s, nearest first, each with its cosine
    /// distance (0 the same meaning, 1 unrelated), NVD's score and severity, whether it's in KEV, and how many devices
    /// carry it (at `org_id` when given, from the sources asked for). Off (no embedder, or a store without vectors):
    /// no rows, and `off` says why. On, but this CVE has no vector yet: no rows, and `note` says so.
    async fn cve_similar(&self, p: &Params) -> Result<Value, Failure> {
        let cve = p.cve_id.clone().ok_or_else(|| Failure::Bad("cve_id must be a CVE id".into()))?.to_uppercase();
        let k = p.limit.map(|l| l as usize).unwrap_or(10);
        if !(1..=SIMILAR_MAX).contains(&k) { return Err(Failure::Bad(format!("limit must be 1 to {SIMILAR_MAX} for cve.similar"))); }
        let model = match self.similar.model() { Ok(m) => m, Err(why) => return Ok(json!({ "data": [], "off": why, "next_cursor": null })) };
        let near = crate::vectors::similar_cves(&self.pool, &cve, model, k).await.map_err(|_| Failure::Db)?;
        if near.is_empty() {
            let note = if crate::vectors::has_cve(&self.pool, &cve, model).await.map_err(|_| Failure::Db)? { "no other CVE's description has been embedded yet" }
                       else { "this CVE hasn't been compared yet: the embed job makes its vector once NVD's description of it is in the store" };
            return Ok(json!({ "data": [], "model": model, "note": note, "next_cursor": null, "as_of": self.as_of().await }));
        }
        let ids: Vec<String> = near.iter().map(|(id, _)| id.clone()).collect();
        type Facts = (Vec<(String, Option<f64>, Option<String>, bool)>, Vec<(String, i64)>);
        let (facts, devices): Facts = crate::on_pool!(&self.pool, db, pg => (
            sqlx::query_as(if pg {
                "SELECT n.cve_id, n.cvss, n.severity, k.cve_id IS NOT NULL FROM sec_nvd_cve n LEFT JOIN sec_kev k ON k.cve_id = n.cve_id WHERE n.cve_id = ANY($1)"
            } else {
                "SELECT n.cve_id, n.cvss, n.severity, k.cve_id IS NOT NULL FROM sec_nvd_cve n LEFT JOIN sec_kev k ON k.cve_id = n.cve_id WHERE n.cve_id IN (SELECT value FROM json_each($1))"
            }).bind(store::list(&ids)).fetch_all(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as(if pg {
                "SELECT e.cve_id, count(DISTINCT e.device_id) FROM sec_cve_evidence e JOIN device d ON d.device_id = e.device_id AND d.deleted_at IS NULL
                  WHERE e.cve_id = ANY($1) AND e.source = ANY($2) AND ($3::bigint IS NULL OR d.org_id = $3) GROUP BY e.cve_id"
            } else {
                "SELECT e.cve_id, count(DISTINCT e.device_id) FROM sec_cve_evidence e JOIN device d ON d.device_id = e.device_id AND d.deleted_at IS NULL
                  WHERE e.cve_id IN (SELECT value FROM json_each($1)) AND e.source IN (SELECT value FROM json_each($2)) AND ($3 IS NULL OR d.org_id = $3) GROUP BY e.cve_id"
            }).bind(store::list(&ids)).bind(Self::sources(p)).bind(p.org_id.map(|x| x as i64)).fetch_all(db).await.map_err(|_| Failure::Db)?));
        let data: Vec<Value> = near.into_iter().map(|(id, distance)| {
            let f = facts.iter().find(|x| x.0 == id);
            json!({ "cve_id": id, "distance": distance, "cvss": f.and_then(|x| x.1), "severity": f.and_then(|x| x.2.clone()), "kev": f.is_some_and(|x| x.3),
                    "devices": devices.iter().find(|x| x.0 == id).map(|x| x.1).unwrap_or(0) })
        }).collect();
        Ok(json!({ "data": data, "model": model, "next_cursor": null, "as_of": self.as_of().await }))
    }
}

pub enum Failure { Bad(String), NotFound(String), Db }

/// A caller's limits, never widened by its own filters: `org_id` pins one client, and a call
/// naming another is refused, never quietly answered for the pinned one; `require_org` refuses a call naming none.
/// The console's own signed-in staff read the whole fleet (no scope); a scoped caller (a client portal) is pinned.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scope { pub org_id: Option<u64>, pub require_org: bool }

impl Scope {
    pub fn apply(&self, p: &Params) -> Result<Params, String> {
        let mut out = p.clone();
        if let Some(o) = self.org_id {
            if p.org_id.is_some_and(|x| x != o) { return Err("this caller may only ask about its own client (org_id)".into()); }
            out.org_id = Some(o);
        }
        if self.require_org && out.org_id.is_none() { return Err("this caller must name one client (org_id)".into()); }
        Ok(out)
    }
}

/// How two sort keys compare: numbers by value, strings by code point, element by element.
pub(crate) fn cmp_keys(a: &[Value], b: &[Value]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).unwrap_or(&Value::Null), b.get(i).unwrap_or(&Value::Null));
        let o = match (x, y) {
            (Value::Number(m), Value::Number(n)) => m.as_f64().unwrap_or(0.0).partial_cmp(&n.as_f64().unwrap_or(0.0)).unwrap_or(Ordering::Equal),
            (Value::String(m), Value::String(n)) => m.cmp(n),
            _ => x.to_string().cmp(&y.to_string()),
        };
        if o != Ordering::Equal { return o; }
    }
    Ordering::Equal
}

/// Keyset pages over an ordered list: the cursor is the last key served, so a page holds still while the data
/// refreshes. A malformed cursor is refused, never read as "from the start".
pub fn page_by(mut items: Vec<Value>, key: impl Fn(&Value) -> Vec<Value>, cursor: Option<&str>, limit: usize) -> Result<(Vec<Value>, Option<String>), String> {
    let n = limit.clamp(1, MAX_LIMIT);
    let after: Option<Vec<Value>> = match cursor {
        Some(c) => Some(B64.decode(c).ok().and_then(|b| serde_json::from_slice::<Vec<Value>>(&b).ok()).ok_or("invalid cursor")?),
        None => None,
    };
    items.sort_by(|a, b| cmp_keys(&key(a), &key(b)));
    let rest: Vec<Value> = match &after { Some(a) => items.into_iter().filter(|x| cmp_keys(&key(x), a) == Ordering::Greater).collect(), None => items };
    let more = rest.len() > n;
    let data: Vec<Value> = rest.into_iter().take(n).collect();
    let next = if more { data.last().map(|x| B64.encode(serde_json::to_vec(&key(x)).unwrap_or_default())) } else { None };
    Ok((data, next))
}
