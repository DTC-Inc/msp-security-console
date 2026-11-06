//! The rest of contract v1, answered from the console's own store: every list and drill-down op the core views
//! read, with the list filters on each (keyset pages), plus the views' own ops (clients.overview, products.list, coverage.list and
//! coverage.devices, device.software, advisories.list).
//!
//! The rule every op keeps, so a count always opens exactly the rows it counts: devices in scope are read once (org,
//! class, device, role), evidence is read through the same view with the same source filter, and a count is the size
//! of the set a list op would return for the same filter. Three counting rules are deliberate (docs/design.md,
//! "Counting rules"): a device's CVEs are distinct (a CVE in two products on one device is one), a version's CVEs
//! are the union of every source's, and "vulnerable" is the evidence tied to each device.
//!
//! What it never does: answer for a device outside the caller's scope, or carry anything from a vendor beyond what the
//! store already holds. The ops whose rows come from another source (Windows updates and processes in ops/windows.rs and
//! ops/processes.rs, Blackpoint and exposure in ops/blackpoint.rs and ops/exposure.rs) live beside this file.

// The tallies here are small tuples that live for one function; naming each
// as a type would say less than the tuple does.
#![allow(clippy::type_complexity)]

use super::{page_by, Failure, Store};
use crate::contract::{Has, Params, Source};
use crate::db::List;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Every evidence source, in the order answers list them.
pub const SOURCES: [&str; 5] = ["ninja_software", "process", "msrc", "blackpoint", "advisory"];
/// The console doesn't know which clients are on a managed-services agreement: no vendor it reads says so.
pub const NO_MSA: &str = "msa: this console doesn't know which clients are MSA clients yet, so it can't filter by it";

type When = Option<DateTime<Utc>>;

/// A device in scope, as every answer names it.
#[derive(Debug, Clone)]
pub struct Dev { pub id: i64, pub name: String, pub org_id: i64, pub org_name: Option<String>, pub class: String, pub role: Option<String>, pub os: Option<String>, pub last_contact: When }

impl Dev {
    fn json(&self) -> Value {
        json!({ "device_id": self.id, "device_name": self.name, "org_id": self.org_id, "org_name": self.org_name, "device_class": self.class, "role": self.role })
    }
}

/// One row of sec_cve_evidence: a device, a CVE, the product and version that carry it, and which source saw it.
#[derive(Debug, Clone)]
pub struct CveRow { pub device_id: i64, pub cve_id: String, pub product_key: String, pub version: String, pub source: String, pub attribution: Option<String>, pub detail: Option<Value>, pub cvss: Option<f64>, pub kev: bool, pub exploited: bool }
type CveTuple = (i64, String, String, String, String, Option<String>, Option<Value>, Option<f64>, bool, bool);

/// One row of sec_evidence: a product and version a source saw on a device.
#[derive(Debug, Clone)]
pub struct EvRow { pub device_id: i64, pub product_key: String, pub version: String, pub source: String, pub attribution: Option<String>, pub detail: Option<Value>, pub seen_at: When }
type EvTuple = (i64, String, String, String, Option<String>, Option<Value>, When);

// ---- the filters -------------------------------------------------------------------------------------------------

fn class_of(p: &Params) -> Option<String> { p.device_class.and_then(|c| serde_json::to_value(c).ok()).and_then(|v| v.as_str().map(String::from)) }
/// The version filter: "(none)" is the empty version (a source that names no version), so it can sit in a link; an
/// empty string is no filter.
fn version_of(p: &Params) -> Option<String> {
    match p.version.as_deref() { Some("(none)") => Some(String::new()), Some("") | None => None, Some(v) => Some(v.to_string()) }
}
/// critical is CVSS 9 or more, as the inventory counts it.
fn cvss_min(p: &Params) -> f64 { let m = p.cvss_min.unwrap_or(-1.0); if p.critical == Some(true) { m.max(9.0) } else { m } }
fn cve_ok(p: &Params, kev: bool, cvss: Option<f64>) -> bool {
    let min = cvss_min(p);
    (p.kev != Some(true) || kev) && (min < 0.0 || cvss.unwrap_or(0.0) >= min)
}
fn run_ok(p: &Params, sources: &[String]) -> bool { p.running_only != Some(true) || sources.iter().any(|s| s == "process") }
/// Whether the device filter narrows anything: when it doesn't, evidence is read whole and kept to the devices in scope.
fn narrowed(p: &Params) -> bool { p.org_id.is_some() || p.device_class.is_some() || p.device_id.is_some() || p.role.is_some() }
pub(crate) fn source_list(p: &Params) -> Vec<String> {
    match &p.source {
        Some(s) => s.iter().map(|x| match x { Source::NinjaSoftware => "ninja_software", Source::Process => "process", Source::Msrc => "msrc", Source::Blackpoint => "blackpoint", Source::Advisory => "advisory" }.to_string()).collect(),
        None => SOURCES.iter().map(|s| s.to_string()).collect(),
    }
}
fn push(v: &mut Vec<String>, s: &str) { if !v.iter().any(|x| x == s) { v.push(s.to_string()); } }
fn max_of(a: Option<f64>, b: Option<f64>) -> Option<f64> { match (a, b) { (Some(x), Some(y)) => Some(x.max(y)), (x, None) => x, (None, y) => y } }
/// The severity order: exploited, then KEV, then the score.
fn sev_key(exploited: bool, kev: bool, cvss: Option<f64>) -> Vec<Value> { vec![json!(if exploited { 0 } else { 1 }), json!(if kev { 0 } else { 1 }), json!(-cvss.unwrap_or(0.0))] }
fn limit(p: &Params) -> usize { p.limit.map(|l| l as usize).unwrap_or(100) }
/// The advisories an evidence row's detail names (strings, or objects with an advisory_id).
fn names_advisory(detail: &Option<Value>, id: &str) -> bool {
    detail.as_ref().and_then(|d| d.get("advisories")).and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|x| x.as_str().or_else(|| x.get("advisory_id").and_then(Value::as_str)) == Some(id)))
}

/// One CVE on one device, all its rows folded together.
#[derive(Debug, Clone)]
struct Agg { cve_id: String, kev: bool, exploited: bool, cvss: Option<f64>, sources: Vec<String>, versions: Vec<String> }

/// A device's CVEs, distinct, from rows already kept to scope.
fn per_device(rows: &[CveRow]) -> BTreeMap<i64, BTreeMap<String, Agg>> {
    let mut out: BTreeMap<i64, BTreeMap<String, Agg>> = BTreeMap::new();
    for r in rows {
        let c = out.entry(r.device_id).or_default().entry(r.cve_id.clone())
            .or_insert_with(|| Agg { cve_id: r.cve_id.clone(), kev: false, exploited: false, cvss: None, sources: vec![], versions: vec![] });
        c.kev |= r.kev; c.exploited |= r.exploited; c.cvss = max_of(c.cvss, r.cvss);
        push(&mut c.sources, &r.source); push(&mut c.versions, &r.version);
    }
    out
}

/// The device x CVE rows grouped by device (one CVE's devices) or by CVE (one device's CVEs), with every piece of
/// evidence behind each.
fn group(rows: &[CveRow], by_device: bool) -> Vec<Value> {
    let mut g: BTreeMap<String, (Value, Vec<String>, bool, bool, Option<f64>, Vec<Value>)> = BTreeMap::new();
    for r in rows {
        let k = if by_device { format!("{:020}", r.device_id) } else { r.cve_id.clone() };
        let x = g.entry(k).or_insert_with(|| (if by_device { json!(r.device_id) } else { json!(r.cve_id) }, vec![], false, false, None, vec![]));
        push(&mut x.1, &r.source); x.2 |= r.kev; x.3 |= r.exploited; x.4 = max_of(x.4, r.cvss);
        let mut e = json!({ "evidence_id": format!("{}|{}|{}|{}", r.source, r.device_id, r.product_key, r.version), "source": r.source, "product_key": r.product_key,
            "version": r.version, "attribution": r.attribution, "detail": r.detail });
        if !by_device { e["cve_id"] = json!(r.cve_id); }
        x.5.push(e);
    }
    g.into_values().map(|(id, sources, kev, exploited, cvss, evidence)| {
        let mut v = json!({ "sources": sources, "kev": kev, "exploited": exploited, "cvss": cvss, "evidence": evidence });
        v[if by_device { "device_id" } else { "cve_id" }] = id;
        v
    }).collect()
}
fn sources_of(v: &Value) -> Vec<String> { v["sources"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default() }

impl Store {
    // ---- reading ---------------------------------------------------------------------------------------------------

    /// The devices in scope, once: org, class, one device, role (NinjaOne's node class). Every answer is filtered and
    /// named through it.
    pub(crate) async fn scoped(&self, p: &Params) -> Result<BTreeMap<i64, Dev>, Failure> {
        if p.msa == Some(true) { return Err(Failure::Bad(NO_MSA.into())); }
        type Row = (i64, String, i64, Option<String>, String, Option<String>, Option<String>, When);
        let (org, class, dev, role) = (p.org_id.map(|x| x as i64), class_of(p), p.device_id.map(|x| x as i64), p.role.clone());
        let rows: Vec<Row> = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT d.device_id, d.name, d.org_id, c.name, d.device_class, d.node_class, d.os_name, d.last_contact
               FROM device d LEFT JOIN client c ON c.org_id = d.org_id
              WHERE d.deleted_at IS NULL AND ($1::bigint IS NULL OR d.org_id = $1) AND ($2::text IS NULL OR d.device_class = $2)
                AND ($3::bigint IS NULL OR d.device_id = $3) AND ($4::text IS NULL OR lower(d.node_class) = lower($4))"
        } else {
            "SELECT d.device_id, d.name, d.org_id, c.name, d.device_class, d.node_class, d.os_name, d.last_contact
               FROM device d LEFT JOIN client c ON c.org_id = d.org_id
              WHERE d.deleted_at IS NULL AND ($1 IS NULL OR d.org_id = $1) AND ($2 IS NULL OR d.device_class = $2)
                AND ($3 IS NULL OR d.device_id = $3) AND ($4 IS NULL OR lower(d.node_class) = lower($4))"
        }).bind(org).bind(class).bind(dev).bind(role).fetch_all(db).await.map_err(|_| Failure::Db)?);
        Ok(rows.into_iter().map(|(id, name, org_id, org_name, class, role, os, last_contact)| (id, Dev { id, name, org_id, org_name, class, role, os, last_contact })).collect())
    }

    /// Device x CVE rows from the sources asked for, narrowed in SQL where it can be (the devices, one CVE, one product
    /// and version), and always kept to the devices in scope.
    pub(crate) async fn cve_rows(&self, p: &Params, devs: &BTreeMap<i64, Dev>, cve: Option<&str>, product: Option<&str>, version: Option<&str>) -> Result<Vec<CveRow>, Failure> {
        let ids: Option<List<i64>> = narrowed(p).then(|| List(devs.keys().copied().collect()));
        let rows: Vec<CveTuple> = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT device_id, cve_id, product_key, version, source, attribution, detail, cvss, kev, exploited FROM sec_cve_evidence
              WHERE source = ANY($1) AND ($2::bigint[] IS NULL OR device_id = ANY($2)) AND ($3::text IS NULL OR cve_id = $3)
                AND ($4::text IS NULL OR product_key = $4) AND ($5::text IS NULL OR version = $5)"
        } else {
            "SELECT device_id, cve_id, product_key, version, source, attribution, detail, cvss, kev, exploited FROM sec_cve_evidence
              WHERE source IN (SELECT value FROM json_each($1)) AND ($2 IS NULL OR device_id IN (SELECT value FROM json_each($2))) AND ($3 IS NULL OR cve_id = $3)
                AND ($4 IS NULL OR product_key = $4) AND ($5 IS NULL OR version = $5)"
        }).bind(List(source_list(p))).bind(ids).bind(cve).bind(product).bind(version).fetch_all(db).await.map_err(|_| Failure::Db)?);
        Ok(rows.into_iter().filter(|r| devs.contains_key(&r.0)).map(|(device_id, cve_id, product_key, version, source, attribution, detail, cvss, kev, exploited)|
            CveRow { device_id, cve_id, product_key, version, source, attribution, detail, cvss, kev, exploited }).collect())
    }

    /// sec_evidence rows (what a source saw installed or running) from the sources asked for, kept to scope.
    pub(crate) async fn ev_rows(&self, p: &Params, devs: &BTreeMap<i64, Dev>, product: Option<&str>, version: Option<&str>) -> Result<Vec<EvRow>, Failure> {
        let ids: Option<List<i64>> = narrowed(p).then(|| List(devs.keys().copied().collect()));
        let rows: Vec<EvTuple> = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT device_id, product_key, version, source, attribution, detail, seen_at FROM sec_evidence
              WHERE source = ANY($1) AND ($2::bigint[] IS NULL OR device_id = ANY($2)) AND ($3::text IS NULL OR product_key = $3) AND ($4::text IS NULL OR version = $4)"
        } else {
            "SELECT device_id, product_key, version, source, attribution, detail, seen_at FROM sec_evidence
              WHERE source IN (SELECT value FROM json_each($1)) AND ($2 IS NULL OR device_id IN (SELECT value FROM json_each($2))) AND ($3 IS NULL OR product_key = $3) AND ($4 IS NULL OR version = $4)"
        }).bind(List(source_list(p))).bind(ids).bind(product).bind(version).fetch_all(db).await.map_err(|_| Failure::Db)?);
        Ok(rows.into_iter().filter(|r| devs.contains_key(&r.0)).map(|(device_id, product_key, version, source, attribution, detail, seen_at)|
            EvRow { device_id, product_key, version, source, attribution, detail, seen_at }).collect())
    }

    /// Which device each source saw at all, by any evidence (installed, running, or a CVE it named): (device, source).
    async fn seen_pairs(&self, p: &Params, devs: &BTreeMap<i64, Dev>) -> Result<BTreeSet<(i64, String)>, Failure> {
        let ids: Option<List<i64>> = narrowed(p).then(|| List(devs.keys().copied().collect()));
        let rows: Vec<(i64, String)> = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT device_id, source FROM sec_evidence WHERE ($1::bigint[] IS NULL OR device_id = ANY($1))
             UNION SELECT device_id, source FROM sec_evidence_cve WHERE ($1::bigint[] IS NULL OR device_id = ANY($1))"
        } else {
            "SELECT device_id, source FROM sec_evidence WHERE ($1 IS NULL OR device_id IN (SELECT value FROM json_each($1)))
             UNION SELECT device_id, source FROM sec_evidence_cve WHERE ($1 IS NULL OR device_id IN (SELECT value FROM json_each($1)))"
        }).bind(ids).fetch_all(db).await.map_err(|_| Failure::Db)?);
        Ok(rows.into_iter().filter(|r| devs.contains_key(&r.0)).collect())
    }

    /// How many installed-software rows NinjaOne gave for each device in scope (no row: no inventory).
    async fn software_counts(&self, p: &Params, devs: &BTreeMap<i64, Dev>) -> Result<HashMap<i64, i64>, Failure> {
        let ids: Option<List<i64>> = narrowed(p).then(|| List(devs.keys().copied().collect()));
        let rows: Vec<(i64, i64)> = crate::on_pool!(&self.pool, db, pg => sqlx::query_as(if pg {
            "SELECT device_id, count(*) FROM software WHERE ($1::bigint[] IS NULL OR device_id = ANY($1)) GROUP BY device_id"
        } else {
            "SELECT device_id, count(*) FROM software WHERE ($1 IS NULL OR device_id IN (SELECT value FROM json_each($1))) GROUP BY device_id"
        }).bind(ids).fetch_all(db).await.map_err(|_| Failure::Db)?);
        Ok(rows.into_iter().filter(|r| devs.contains_key(&r.0)).collect())
    }

    /// What each product key reads as: the product map's label, else an advisory's, else Windows for Microsoft's
    /// updates, else Blackpoint's words.
    pub(crate) async fn labels(&self, keys: &[String]) -> Result<HashMap<String, String>, Failure> {
        let mut m: HashMap<String, String> = HashMap::from([("msrc:windows".to_string(), "Windows".to_string())]);
        let want: Vec<String> = keys.iter().filter(|k| !m.contains_key(*k)).cloned().collect();
        if !want.is_empty() {
            let (a, b): (Vec<(String, String)>, Vec<(String, Option<String>)>) = crate::on_pool!(&self.pool, db, pg => (
                sqlx::query_as(if pg { "SELECT product_key, label FROM sec_product WHERE product_key = ANY($1)" } else { "SELECT product_key, label FROM sec_product WHERE product_key IN (SELECT value FROM json_each($1))" })
                    .bind(List(want.clone())).fetch_all(db).await.map_err(|_| Failure::Db)?,
                sqlx::query_as(if pg { "SELECT product_key, product_label FROM sec_advisory WHERE product_key = ANY($1) ORDER BY advisory_id" } else { "SELECT product_key, product_label FROM sec_advisory WHERE product_key IN (SELECT value FROM json_each($1)) ORDER BY advisory_id" })
                    .bind(List(want)).fetch_all(db).await.map_err(|_| Failure::Db)?));
            for (k, l) in a { m.insert(k, l); }
            for (k, l) in b { if let Some(l) = l { m.entry(k).or_insert(l); } }
        }
        for k in keys {
            if !m.contains_key(k) && let Some(rest) = k.strip_prefix("bp:") {
                m.insert(k.clone(), rest.split(':').map(|w| w.replace('_', " ")).collect::<Vec<_>>().join(" "));
            }
        }
        Ok(m)
    }

    // ---- the lists: a count is a list's totals, its rows the list --------------------------------------------------

    /// Devices with evidence that meets the filters: a CVE that passes kev / critical / cvss_min, from the sources asked
    /// for, optionally of one CVE, one product and version, or one advisory. `has: product` instead lists devices with
    /// the product at all, vulnerable or not.
    pub(crate) async fn device_rows(&self, p: &Params) -> Result<(Vec<Value>, BTreeMap<i64, Dev>), Failure> {
        let devs = self.scoped(p).await?;
        let (product, version) = (p.product_key.clone(), version_of(p));
        let mut list = Vec::new();
        if p.has == Some(Has::Product) {
            let mut by: BTreeMap<i64, (Vec<String>, Vec<String>)> = BTreeMap::new();
            for r in self.ev_rows(p, &devs, product.as_deref(), version.as_deref()).await? {
                let x = by.entry(r.device_id).or_default();
                push(&mut x.0, &r.source); push(&mut x.1, &r.version);
            }
            for (id, (sources, versions)) in by {
                let mut v = devs[&id].json();
                v["sources"] = json!(sources); v["versions"] = json!(versions);
                v["cves"] = json!(0); v["kev_cves"] = json!(0); v["max_cvss"] = Value::Null; v["worst"] = json!([]);
                list.push(v);
            }
        } else {
            let cve = p.cve_id.as_ref().map(|c| c.to_uppercase());
            let mut rows = self.cve_rows(p, &devs, cve.as_deref(), product.as_deref(), version.as_deref()).await?;
            if let Some(a) = &p.advisory_id { rows.retain(|r| r.source == "advisory" && names_advisory(&r.detail, a)); }
            for (id, m) in per_device(&rows) {
                let mut ok: Vec<&Agg> = m.values().filter(|c| cve_ok(p, c.kev, c.cvss)).collect();
                let mut srcs: Vec<String> = vec![];
                for c in &ok { for s in &c.sources { push(&mut srcs, s); } }
                if ok.is_empty() || !run_ok(p, &srcs) { continue; }
                ok.sort_by(|a, b| b.kev.cmp(&a.kev).then(b.cvss.unwrap_or(0.0).total_cmp(&a.cvss.unwrap_or(0.0))).then(a.cve_id.cmp(&b.cve_id)));
                let mut versions = vec![];
                for c in &ok { for v in &c.versions { push(&mut versions, v); } }
                let mut v = devs[&id].json();
                v["sources"] = json!(srcs); v["versions"] = json!(versions);
                v["cves"] = json!(ok.len()); v["kev_cves"] = json!(ok.iter().filter(|c| c.kev).count());
                v["max_cvss"] = json!(ok.iter().fold(None, |a, c| max_of(a, c.cvss)));
                v["worst"] = json!(ok.iter().take(3).map(|c| json!({ "cve_id": c.cve_id, "cvss": c.cvss, "kev": c.kev })).collect::<Vec<_>>());
                list.push(v);
            }
        }
        Ok((list, devs))
    }

    pub(crate) async fn devices_list(&self, p: &Params) -> Result<Value, Failure> {
        let (list, _) = self.device_rows(p).await?;
        let clients = list.iter().map(|x| x["org_id"].as_i64()).collect::<BTreeSet<_>>().len();
        let total = list.len();
        let key = |x: &Value| vec![json!(if x["kev_cves"].as_i64().unwrap_or(0) > 0 { 0 } else { 1 }), json!(-x["max_cvss"].as_f64().unwrap_or(0.0)),
            json!(x["org_name"].as_str().unwrap_or("")), json!(x["device_name"].as_str().unwrap_or("")), x["device_id"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "devices": total, "clients": clients }, "as_of": self.as_of().await }))
    }

    pub(crate) async fn clients_list(&self, p: &Params) -> Result<Value, Failure> {
        let (list, _) = self.device_rows(p).await?;
        let mut g: BTreeMap<i64, (Value, i64, i64, Option<f64>)> = BTreeMap::new();
        for x in &list {
            let org = x["org_id"].as_i64().unwrap_or(0);
            let c = g.entry(org).or_insert_with(|| (x["org_name"].clone(), 0, 0, None));
            c.1 += 1; if x["kev_cves"].as_i64().unwrap_or(0) > 0 { c.2 += 1; }
            c.3 = max_of(c.3, x["max_cvss"].as_f64());
        }
        let cl: Vec<Value> = g.into_iter().map(|(org, (name, d, k, m))| json!({ "org_id": org, "org_name": name, "devices": d, "kev_devices": k, "max_cvss": m })).collect();
        let total = cl.len();
        let key = |x: &Value| vec![json!(-x["devices"].as_i64().unwrap_or(0)), json!(x["org_name"].as_str().unwrap_or("")), x["org_id"].clone()];
        let (data, next) = page_by(cl, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "clients": total, "devices": list.len() }, "as_of": self.as_of().await }))
    }

    pub(crate) async fn cves_list(&self, p: &Params) -> Result<Value, Failure> {
        let devs = self.scoped(p).await?;
        let cve = p.cve_id.as_ref().map(|c| c.to_uppercase());
        let mut rows = self.cve_rows(p, &devs, cve.as_deref(), p.product_key.as_deref(), version_of(p).as_deref()).await?;
        if let Some(a) = &p.advisory_id { rows.retain(|r| r.source == "advisory" && names_advisory(&r.detail, a)); }
        struct G { sources: Vec<String>, devices: BTreeSet<i64>, running: BTreeSet<i64>, kev: bool, exploited: bool, cvss: Option<f64> }
        let mut g: BTreeMap<String, G> = BTreeMap::new();
        for r in &rows {
            let x = g.entry(r.cve_id.clone()).or_insert(G { sources: vec![], devices: BTreeSet::new(), running: BTreeSet::new(), kev: false, exploited: false, cvss: None });
            push(&mut x.sources, &r.source);
            x.devices.insert(r.device_id);
            if r.source == "process" { x.running.insert(r.device_id); }
            x.kev |= r.kev; x.exploited |= r.exploited; x.cvss = max_of(x.cvss, r.cvss);
        }
        let list: Vec<Value> = g.into_iter()
            .filter(|(_, x)| cve_ok(p, x.kev, x.cvss) && (p.running_only != Some(true) || !x.running.is_empty()))
            .map(|(id, x)| json!({ "cve_id": id, "sources": x.sources, "devices": x.devices.len(), "running_devices": x.running.len(), "kev": x.kev, "exploited": x.exploited, "cvss": x.cvss }))
            .collect();
        let total = list.len();
        let key = |x: &Value| { let mut k = sev_key(x["exploited"] == json!(true), x["kev"] == json!(true), x["cvss"].as_f64()); k.push(json!(-x["devices"].as_i64().unwrap_or(0))); k.push(x["cve_id"].clone()); k };
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "cves": total }, "as_of": self.as_of().await }))
    }

    // ---- one CVE ---------------------------------------------------------------------------------------------------

    fn cve_param(p: &Params) -> Result<String, Failure> { p.cve_id.clone().map(|c| c.to_uppercase()).ok_or_else(|| Failure::Bad("cve_id must be a CVE id".into())) }

    pub(crate) async fn cve_get(&self, p: &Params) -> Result<Value, Failure> {
        let cve = Self::cve_param(p)?;
        let devs = self.scoped(p).await?;
        let rows = self.cve_rows(p, &devs, Some(&cve), None, None).await?;
        type NvdRow = (String, Option<f64>, Option<String>, When, Option<String>);
        type KevRow = (String, Option<String>, bool, Option<chrono::NaiveDate>, Option<chrono::NaiveDate>);
        let (nvd, kev): (Option<NvdRow>, Option<KevRow>) = crate::on_pool!(&self.pool, db, _ => (
            sqlx::query_as("SELECT cve_id, cvss, severity, published, description FROM sec_nvd_cve WHERE cve_id = $1").bind(&cve).fetch_optional(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as("SELECT cve_id, name, ransomware, date_added, due_date FROM sec_kev WHERE cve_id = $1").bind(&cve).fetch_optional(db).await.map_err(|_| Failure::Db)?));
        let advisories = crate::advisory::list(&self.pool, Some(&cve)).await.map_err(|_| Failure::Db)?.into_iter().map(|mut a| {
            let id = a["advisory_id"].as_str().unwrap_or("").to_string();
            a["devices"] = json!(rows.iter().filter(|r| r.source == "advisory" && names_advisory(&r.detail, &id)).map(|r| r.device_id).collect::<BTreeSet<_>>().len());
            a
        }).collect::<Vec<_>>();
        let every = self.cve_rows(&Params { source: None, ..p.clone() }, &devs, Some(&cve), None, None).await?;
        let mut by_source = Map::new();
        for s in SOURCES { by_source.insert(s.into(), json!(every.iter().filter(|r| r.source == s).map(|r| r.device_id).collect::<BTreeSet<_>>().len())); }
        Ok(json!({ "data": {
            "cve_id": cve,
            "nvd": nvd.map(|(id, cvss, sev, published, desc)| json!({ "cve_id": id, "cvss": cvss, "severity": sev, "published": published, "description": desc })),
            "kev": kev.map(|(id, name, ransomware, added, due)| json!({ "cve_id": id, "name": name, "ransomware": ransomware, "date_added": added, "due_date": due })),
            "advisories": advisories,
            "devices": rows.iter().map(|r| r.device_id).collect::<BTreeSet<_>>().len(),
            "devices_by_source": by_source,
            "clients": rows.iter().filter_map(|r| devs.get(&r.device_id).map(|d| d.org_id)).collect::<BTreeSet<_>>().len(),
            // The public addresses it's seen on (Shodan, by address, never a device): ops/exposure.rs.
            "internet_facing": super::exposure::facing(&self.pool, p.org_id.map(|x| x as i64), &cve).await?,
        }, "next_cursor": null, "as_of": self.as_of().await }))
    }

    pub(crate) async fn cve_products(&self, p: &Params) -> Result<Value, Failure> {
        let cve = Self::cve_param(p)?;
        let devs = self.scoped(p).await?;
        let rows = self.cve_rows(p, &devs, Some(&cve), None, None).await?;
        let mut g: BTreeMap<(String, String), (Vec<String>, BTreeSet<i64>, BTreeSet<String>)> = BTreeMap::new();
        for r in &rows {
            let x = g.entry((r.product_key.clone(), r.version.clone())).or_default();
            push(&mut x.0, &r.source); x.1.insert(r.device_id);
            if let Some(a) = &r.attribution { x.2.insert(a.clone()); }
        }
        let lab = self.labels(&g.keys().map(|k| k.0.clone()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>()).await?;
        let mut list: Vec<Value> = g.into_iter().map(|((k, v), (sources, d, att))| json!({ "product_key": k, "label": lab.get(&k).cloned().unwrap_or(k.clone()), "version": v,
            "sources": sources, "attribution": att.into_iter().collect::<Vec<_>>(), "devices": d.len() })).collect();
        list.sort_by(|a, b| b["devices"].as_i64().cmp(&a["devices"].as_i64()).then(a["label"].as_str().cmp(&b["label"].as_str())));
        Ok(json!({ "data": list.clone(), "next_cursor": null, "totals": { "products": list.len() }, "as_of": self.as_of().await }))
    }

    pub(crate) async fn cve_devices(&self, p: &Params) -> Result<Value, Failure> {
        let cve = Self::cve_param(p)?;
        let devs = self.scoped(p).await?;
        let rows = self.cve_rows(p, &devs, Some(&cve), None, None).await?;
        let list: Vec<Value> = group(&rows, true).into_iter().filter(|x| run_ok(p, &sources_of(x))).map(|mut x| {
            let d = devs[&x["device_id"].as_i64().unwrap_or(0)].json();
            for (k, v) in d.as_object().into_iter().flatten() { x[k] = v.clone(); }
            x
        }).collect();
        let (total, clients) = (list.len(), list.iter().map(|x| x["org_id"].as_i64()).collect::<BTreeSet<_>>().len());
        let key = |x: &Value| { let mut k = sev_key(x["exploited"] == json!(true), x["kev"] == json!(true), x["cvss"].as_f64());
            k.extend([json!(x["org_name"].as_str().unwrap_or("")), json!(x["device_name"].as_str().unwrap_or("")), x["device_id"].clone()]); k };
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "devices": total, "clients": clients }, "as_of": self.as_of().await }))
    }

    // ---- one device ------------------------------------------------------------------------------------------------

    async fn one_device(&self, p: &Params) -> Result<(Dev, BTreeMap<i64, Dev>), Failure> {
        let id = p.device_id.ok_or_else(|| Failure::Bad("device_id is required".into()))? as i64;
        let devs = self.scoped(p).await?;
        let d = devs.get(&id).cloned().ok_or_else(|| Failure::NotFound("no such device in scope".into()))?;
        Ok((d, devs))
    }

    pub(crate) async fn device_get(&self, p: &Params) -> Result<Value, Failure> {
        let (d, devs) = self.one_device(p).await?;
        let ev = self.ev_rows(p, &devs, None, None).await?;
        let cv = self.cve_rows(p, &devs, None, None, None).await?;
        let soft = self.software_counts(p, &devs).await?;
        let all_p = Params { source: None, ..p.clone() };
        let (ev_all, cv_all) = (self.ev_rows(&all_p, &devs, None, None).await?, self.cve_rows(&all_p, &devs, None, None, None).await?);
        let mut by = Map::new();
        for s in SOURCES {
            let (ev, cv) = (&ev_all, &cv_all);
            let c: BTreeSet<&str> = cv.iter().filter(|r| r.source == s).map(|r| r.cve_id.as_str()).collect();
            let k: BTreeSet<&str> = cv.iter().filter(|r| r.source == s && r.kev).map(|r| r.cve_id.as_str()).collect();
            by.insert(s.into(), json!({ "products": ev.iter().filter(|r| r.source == s).map(|r| (&r.product_key, &r.version)).collect::<BTreeSet<_>>().len(), "cves": c.len(), "kev": k.len() }));
        }
        let all = per_device(&cv).remove(&d.id).unwrap_or_default();
        let ok: Vec<&Agg> = all.values().filter(|c| cve_ok(p, c.kev, c.cvss)).collect();
        let mut out = d.json();
        out["os_name"] = json!(d.os); out["last_contact"] = json!(d.last_contact);
        out["by_source"] = Value::Object(by);
        out["cves"] = json!(ok.len()); out["kev_cves"] = json!(ok.iter().filter(|c| c.kev).count());
        out["max_cvss"] = json!(ok.iter().fold(None, |a, c| max_of(a, c.cvss)));
        out["software"] = json!(soft.get(&d.id).copied().unwrap_or(0));
        out["products"] = json!(ev.iter().map(|r| (&r.product_key, &r.version)).collect::<BTreeSet<_>>().len());
        Ok(json!({ "data": out, "next_cursor": null, "as_of": self.as_of().await }))
    }

    pub(crate) async fn device_cves(&self, p: &Params) -> Result<Value, Failure> {
        let (_, devs) = self.one_device(p).await?;
        let cve = p.cve_id.as_ref().map(|c| c.to_uppercase());
        let rows = self.cve_rows(p, &devs, cve.as_deref(), p.product_key.as_deref(), version_of(p).as_deref()).await?;
        let list: Vec<Value> = group(&rows, false).into_iter()
            .filter(|x| cve_ok(p, x["kev"] == json!(true), x["cvss"].as_f64()) && run_ok(p, &sources_of(x))).collect();
        let total = list.len();
        let key = |x: &Value| { let mut k = sev_key(x["exploited"] == json!(true), x["kev"] == json!(true), x["cvss"].as_f64()); k.push(x["cve_id"].clone()); k };
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "cves": total }, "as_of": self.as_of().await }))
    }

    pub(crate) async fn device_products(&self, p: &Params) -> Result<Value, Failure> {
        let (d, devs) = self.one_device(p).await?;
        let rows = self.ev_rows(p, &devs, None, None).await?;
        let cv = self.cve_rows(p, &devs, None, None, None).await?;
        let mut cves: HashMap<(String, String), (BTreeSet<String>, bool, Option<f64>)> = HashMap::new();
        for r in &cv { let x = cves.entry((r.product_key.clone(), r.version.clone())).or_default(); x.0.insert(r.cve_id.clone()); x.1 |= r.kev; x.2 = max_of(x.2, r.cvss); }
        let mut g: BTreeMap<(String, String), (Vec<String>, Vec<Value>)> = BTreeMap::new();
        for r in &rows {
            let x = g.entry((r.product_key.clone(), r.version.clone())).or_default();
            push(&mut x.0, &r.source);
            x.1.push(json!({ "evidence_id": format!("{}|{}|{}|{}", r.source, d.id, r.product_key, r.version), "source": r.source, "attribution": r.attribution, "detail": r.detail, "seen_at": r.seen_at }));
        }
        let lab = self.labels(&g.keys().map(|k| k.0.clone()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>()).await?;
        let mut list: Vec<Value> = g.into_iter().filter(|(_, x)| run_ok(p, &x.0)).map(|((k, v), (sources, evidence))| {
            let c = cves.get(&(k.clone(), v.clone()));
            json!({ "product_key": k, "label": lab.get(&k).cloned().unwrap_or(k.clone()), "version": v, "sources": sources, "evidence": evidence,
                    "cves": c.map(|x| x.0.len()).unwrap_or(0), "kev": c.is_some_and(|x| x.1), "max_cvss": c.and_then(|x| x.2) })
        }).collect();
        list.sort_by(|a, b| b["kev"].as_bool().cmp(&a["kev"].as_bool()).then(b["cves"].as_i64().cmp(&a["cves"].as_i64())).then(a["label"].as_str().cmp(&b["label"].as_str())));
        Ok(json!({ "data": list.clone(), "next_cursor": null, "totals": { "products": list.len() }, "as_of": self.as_of().await }))
    }

    /// One device's whole installed-software list from NinjaOne, with the product each entry was recognised as.
    pub(crate) async fn device_software(&self, p: &Params) -> Result<Value, Failure> {
        let (d, _) = self.one_device(p).await?;
        type Row = (String, String, String, Option<String>, Option<String>, Option<String>);
        let rows: Vec<Row> = crate::on_pool!(&self.pool, db, _ => sqlx::query_as(
            "SELECT s.name, s.publisher, s.version, c.product_key, c.product_version, p.label FROM software s
               LEFT JOIN sec_software_class c ON c.name = s.name AND c.publisher = s.publisher AND c.version = s.version
               LEFT JOIN sec_product p ON p.product_key = c.product_key
              WHERE s.device_id = $1").bind(d.id).fetch_all(db).await.map_err(|_| Failure::Db)?);
        let mut list: Vec<Value> = rows.into_iter().map(|(name, publisher, version, key, pv, label)| json!({ "name": name, "publisher": publisher, "version": version,
            "product_key": key, "product_version": pv, "product_label": label })).collect();
        list.sort_by(|a, b| a["product_key"].is_null().cmp(&b["product_key"].is_null())
            .then(a["name"].as_str().unwrap_or("").to_lowercase().cmp(&b["name"].as_str().unwrap_or("").to_lowercase())));
        let recognised = list.iter().filter(|x| !x["product_key"].is_null()).count();
        Ok(json!({ "data": list.clone(), "next_cursor": null, "totals": { "software": list.len(), "recognised": recognised }, "as_of": self.as_of().await }))
    }

    // ---- one product -----------------------------------------------------------------------------------------------

    fn product_param(p: &Params) -> Result<String, Failure> { p.product_key.clone().ok_or_else(|| Failure::Bad("product_key is required".into())) }

    pub(crate) async fn product_get(&self, p: &Params) -> Result<Value, Failure> {
        let key = Self::product_param(p)?;
        let devs = self.scoped(p).await?;
        let ver = version_of(p);
        let rows = self.ev_rows(p, &devs, Some(&key), ver.as_deref()).await?;
        let cv = self.cve_rows(p, &devs, None, Some(&key), ver.as_deref()).await?;
        let lab = self.labels(std::slice::from_ref(&key)).await?;
        type Meta = (String, String, String);
        let (meta, known): (Option<Meta>, (i64, i64)) = crate::on_pool!(&self.pool, db, _ => (
            sqlx::query_as("SELECT product_key, label, cpe FROM sec_product WHERE product_key = $1").bind(&key).fetch_optional(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as("SELECT count(DISTINCT c.cve_id), count(DISTINCT k.cve_id) FROM sec_product p JOIN sec_nvd_cpe c ON c.cpe = p.cpe LEFT JOIN sec_kev k ON k.cve_id = c.cve_id WHERE p.product_key = $1")
                .bind(&key).fetch_one(db).await.map_err(|_| Failure::Db)?));
        let devices: BTreeSet<i64> = rows.iter().map(|r| r.device_id).collect();
        let mut by = Map::new();
        for s in SOURCES { by.insert(s.into(), json!(rows.iter().filter(|r| r.source == s).map(|r| r.device_id).collect::<BTreeSet<_>>().len())); }
        Ok(json!({ "data": {
            "product_key": key, "label": lab.get(&key).cloned().unwrap_or(key.clone()), "cpe": meta.map(|m| m.2),
            "versions": rows.iter().map(|r| r.version.as_str()).collect::<BTreeSet<_>>().len(), "devices": devices.len(),
            "vulnerable_devices": cv.iter().map(|r| r.device_id).collect::<BTreeSet<_>>().len(),
            "cves": cv.iter().map(|r| r.cve_id.as_str()).collect::<BTreeSet<_>>().len(),
            "clients": cv.iter().filter_map(|r| devs.get(&r.device_id).map(|d| d.org_id)).collect::<BTreeSet<_>>().len(),
            "by_source": by, "known_cves": known.0, "known_kev": known.1,
        }, "next_cursor": null, "as_of": self.as_of().await }))
    }

    pub(crate) async fn product_versions(&self, p: &Params) -> Result<Value, Failure> {
        let key = Self::product_param(p)?;
        let devs = self.scoped(p).await?;
        let ver = version_of(p);
        let rows = self.ev_rows(p, &devs, Some(&key), ver.as_deref()).await?;
        let cv = self.cve_rows(p, &devs, None, Some(&key), ver.as_deref()).await?;
        // Each version's CVEs: every source's, together, on the devices in scope.
        let mut vv: HashMap<String, (BTreeSet<String>, bool, Option<f64>)> = HashMap::new();
        for r in &cv { let x = vv.entry(r.version.clone()).or_default(); x.0.insert(r.cve_id.clone()); x.1 |= r.kev; x.2 = max_of(x.2, r.cvss); }
        let mut g: BTreeMap<String, (Vec<String>, BTreeSet<i64>, BTreeSet<i64>)> = BTreeMap::new();
        for r in &rows {
            let x = g.entry(r.version.clone()).or_default();
            push(&mut x.0, &r.source); x.1.insert(r.device_id);
            if r.source == "process" { x.2.insert(r.device_id); }
        }
        let lab = self.labels(std::slice::from_ref(&key)).await?;
        let mut list: Vec<Value> = g.into_iter().map(|(v, (sources, d, run))| { let c = vv.get(&v);
            json!({ "version": v, "sources": sources, "devices": d.len(), "running_devices": run.len(), "cves": c.map(|x| x.0.len()).unwrap_or(0), "kev": c.is_some_and(|x| x.1), "cvss": c.and_then(|x| x.2) }) })
            .filter(|x| run_ok(p, &sources_of(x)) && cve_ok(p, x["kev"] == json!(true), x["cvss"].as_f64())).collect();
        list.sort_by(|a, b| b["kev"].as_bool().cmp(&a["kev"].as_bool()).then(b["cves"].as_i64().cmp(&a["cves"].as_i64())).then(b["devices"].as_i64().cmp(&a["devices"].as_i64()))
            .then(crate::matching::cmp_version(b["version"].as_str().unwrap_or(""), a["version"].as_str().unwrap_or(""))));
        Ok(json!({ "data": list.clone(), "next_cursor": null, "totals": { "versions": list.len() }, "label": lab.get(&key).cloned().unwrap_or(key.clone()), "as_of": self.as_of().await }))
    }

    /// One product version's CVEs as NVD's ranges put them (sec_pair_cve), whichever source saw it: what a running
    /// binary's CVE count counts (processes.list). Each with its score, KEV, and the devices in scope carrying it at this
    /// version, every source's together. `kev`, `critical` and `cvss_min` narrow it; keyset pages, worst first.
    pub(crate) async fn version_cves(&self, p: &Params) -> Result<Value, Failure> {
        let key = Self::product_param(p)?;
        let ver = version_of(p).ok_or_else(|| Failure::Bad("version is required for version.cves (\"(none)\" for the empty version)".into()))?;
        let devs = self.scoped(p).await?;
        let pairs: Vec<(String, Option<f64>, bool, When)> = crate::on_pool!(&self.pool, db, _ =>
            sqlx::query_as("SELECT cve_id, cvss, kev, published FROM sec_pair_cve WHERE product_key = $1 AND version = $2").bind(&key).bind(&ver)
                .fetch_all(db).await.map_err(|_| Failure::Db)?);
        let cv = self.cve_rows(&Params { source: None, ..p.clone() }, &devs, None, Some(&key), Some(&ver)).await?;
        let mut on: HashMap<&str, (Vec<String>, BTreeSet<i64>, BTreeSet<i64>)> = HashMap::new();
        for r in &cv {
            let x = on.entry(r.cve_id.as_str()).or_default();
            push(&mut x.0, &r.source); x.1.insert(r.device_id);
            if r.source == "process" { x.2.insert(r.device_id); }
        }
        let rows: Vec<Value> = pairs.iter().filter(|(_, cvss, kev, _)| cve_ok(p, *kev, *cvss)).map(|(id, cvss, kev, published)| {
            let d = on.get(id.as_str());
            json!({ "cve_id": id, "cvss": cvss, "kev": kev, "published": published, "sources": d.map(|x| x.0.clone()).unwrap_or_default(),
                    "devices": d.map(|x| x.1.len()).unwrap_or(0), "running_devices": d.map(|x| x.2.len()).unwrap_or(0) })
        }).collect();
        let totals = json!({ "cves": rows.len(), "kev": rows.iter().filter(|r| r["kev"] == json!(true)).count() });
        let sort = |x: &Value| vec![json!(if x["kev"] == json!(true) { 0 } else { 1 }), json!(-x["cvss"].as_f64().unwrap_or(-1.0)), x["cve_id"].clone()];
        let (data, next) = super::page_by(rows, sort, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(200)).map_err(Failure::Bad)?;
        let lab = self.labels(std::slice::from_ref(&key)).await?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "label": lab.get(&key).cloned().unwrap_or(key.clone()), "version": ver, "as_of": self.as_of().await }))
    }

    pub(crate) async fn product_devices(&self, p: &Params) -> Result<Value, Failure> {
        let key = Self::product_param(p)?;
        let devs = self.scoped(p).await?;
        let ver = version_of(p);
        let rows = self.ev_rows(p, &devs, Some(&key), ver.as_deref()).await?;
        let cv = self.cve_rows(p, &devs, None, Some(&key), ver.as_deref()).await?;
        let mut dc: HashMap<i64, (BTreeSet<String>, bool)> = HashMap::new();
        for r in &cv { let x = dc.entry(r.device_id).or_default(); x.0.insert(r.cve_id.clone()); x.1 |= r.kev; }
        let mut g: BTreeMap<i64, (Vec<String>, Vec<String>, Vec<Value>)> = BTreeMap::new();
        for r in &rows {
            let x = g.entry(r.device_id).or_default();
            push(&mut x.0, &r.version); push(&mut x.1, &r.source);
            x.2.push(json!({ "evidence_id": format!("{}|{}|{}|{}", r.source, r.device_id, key, r.version), "source": r.source, "version": r.version, "attribution": r.attribution, "detail": r.detail }));
        }
        let lab = self.labels(std::slice::from_ref(&key)).await?;
        let list: Vec<Value> = g.into_iter().filter(|(_, x)| run_ok(p, &x.1)).map(|(id, (versions, sources, evidence))| {
            let mut v = devs[&id].json();
            let c = dc.get(&id);
            v["versions"] = json!(versions); v["sources"] = json!(sources); v["evidence"] = json!(evidence);
            v["cves"] = json!(c.map(|x| x.0.len()).unwrap_or(0)); v["kev"] = json!(c.is_some_and(|x| x.1));
            v
        }).collect();
        let total = list.len();
        let key_of = |x: &Value| vec![json!(if x["kev"] == json!(true) { 0 } else { 1 }), json!(-x["cves"].as_i64().unwrap_or(0)), json!(x["org_name"].as_str().unwrap_or("")),
            json!(x["device_name"].as_str().unwrap_or("")), x["device_id"].clone()];
        let (data, next) = page_by(list, key_of, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "devices": total }, "label": lab.get(&key).cloned().unwrap_or(key.clone()), "as_of": self.as_of().await }))
    }

    /// The Software tab: every product the map knows that a source saw on a device in scope, worst first, each with the
    /// counts its row shows (installed, vulnerable, exploited, critical, running, clients, the worst score) and NVD's
    /// whole catalogue for it.
    pub(crate) async fn products_list(&self, p: &Params) -> Result<Value, Failure> {
        let devs = self.scoped(p).await?;
        let ev = self.ev_rows(p, &devs, p.product_key.as_deref(), version_of(p).as_deref()).await?;
        let cv = self.cve_rows(p, &devs, None, p.product_key.as_deref(), version_of(p).as_deref()).await?;
        type Meta = (String, String, String, i64, i64, i64);
        let meta: Vec<Meta> = crate::on_pool!(&self.pool, db, _ => sqlx::query_as(
            "SELECT p.product_key, p.label, p.cpe, CAST(p.sort_order AS BIGINT), count(DISTINCT c.cve_id), count(DISTINCT k.cve_id)
               FROM sec_product p LEFT JOIN sec_nvd_cpe c ON c.cpe = p.cpe LEFT JOIN sec_kev k ON k.cve_id = c.cve_id
              WHERE p.active GROUP BY p.product_key, p.label, p.cpe, p.sort_order").fetch_all(db).await.map_err(|_| Failure::Db)?);
        let mut installed: HashMap<&str, BTreeSet<i64>> = HashMap::new();
        for r in &ev { installed.entry(r.product_key.as_str()).or_default().insert(r.device_id); }
        // Per product, per device: its distinct CVEs that pass the filters, and the flags the row counts.
        let mut by: HashMap<&str, BTreeMap<i64, BTreeMap<&str, (bool, Option<f64>, bool)>>> = HashMap::new();
        for r in &cv {
            let x = by.entry(r.product_key.as_str()).or_default().entry(r.device_id).or_default().entry(r.cve_id.as_str()).or_insert((false, None, false));
            x.0 |= r.kev; x.1 = max_of(x.1, r.cvss); x.2 |= r.source == "process";
        }
        let mut list: Vec<Value> = Vec::new();
        for (key, label, cpe, order, known, known_kev) in meta {
            let inst = installed.get(key.as_str()).map(|s| s.len()).unwrap_or(0);
            let empty = BTreeMap::new();
            let pd = by.get(key.as_str()).unwrap_or(&empty);
            let (mut vuln, mut kev, mut crit, mut run, mut clients, mut max) = (0, 0, 0, 0, BTreeSet::new(), None);
            for (dev, cves) in pd {
                let ok: Vec<&(bool, Option<f64>, bool)> = cves.values().filter(|c| cve_ok(p, c.0, c.1)).collect();
                if ok.is_empty() { continue; }
                if p.running_only == Some(true) && !ok.iter().any(|c| c.2) { continue; }
                vuln += 1; clients.insert(devs[dev].org_id);
                if ok.iter().any(|c| c.0) { kev += 1; }
                if ok.iter().any(|c| c.1.unwrap_or(0.0) >= 9.0) { crit += 1; }
                if ok.iter().any(|c| c.2) { run += 1; }
                max = ok.iter().fold(max, |a, c| max_of(a, c.1));
            }
            if inst == 0 && vuln == 0 { continue; }
            list.push(json!({ "product_key": key, "label": label, "cpe": cpe, "sort_order": order, "installed_devices": inst, "vulnerable_devices": vuln, "kev_devices": kev,
                "critical_devices": crit, "running_devices": run, "clients": clients.len(), "max_cvss": max, "known_cves": known, "known_kev": known_kev }));
        }
        let totals = json!({ "products": list.len(),
            "vulnerable_devices": cv.iter().map(|r| r.device_id).collect::<BTreeSet<_>>().len() });
        let key = |x: &Value| vec![json!(-x["kev_devices"].as_i64().unwrap_or(0)), json!(-x["vulnerable_devices"].as_i64().unwrap_or(0)), x["sort_order"].clone(), x["product_key"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "as_of": self.as_of().await }))
    }

    // ---- clients ---------------------------------------------------------------------------------------------------

    /// One client: its devices, what each source saw, its worst CVEs, and the rows its page lists: every device with its
    /// counts, and every product with a vulnerable version there.
    pub(crate) async fn client_get(&self, p: &Params) -> Result<Value, Failure> {
        let org = p.org_id.ok_or_else(|| Failure::Bad("org_id is required".into()))? as i64;
        let devs = self.scoped(p).await?;
        let name: Option<(String,)> = crate::on_pool!(&self.pool, db, _ => sqlx::query_as("SELECT name FROM client WHERE org_id = $1").bind(org).fetch_optional(db).await.map_err(|_| Failure::Db)?);
        if name.is_none() && devs.is_empty() { return Err(Failure::NotFound("no such client in scope".into())); }
        let rows = self.cve_rows(p, &devs, None, None, None).await?;
        let seen = self.seen_pairs(p, &devs).await?;
        let soft = self.software_counts(p, &devs).await?;
        let ev = self.ev_rows(p, &devs, None, None).await?;
        // What each source saw is every source's own count, whichever sources the rest of the page is filtered to.
        let every = self.cve_rows(&Params { source: None, ..p.clone() }, &devs, None, None, None).await?;
        let mut by = Map::new();
        for s in SOURCES {
            let r: Vec<&CveRow> = every.iter().filter(|r| r.source == s).collect();
            by.insert(s.into(), json!({
                "devices_seen": seen.iter().filter(|x| x.1 == s).count(),
                "devices_with_cves": r.iter().map(|x| x.device_id).collect::<BTreeSet<_>>().len(),
                "cves": r.iter().map(|x| x.cve_id.as_str()).collect::<BTreeSet<_>>().len(),
                "kev_devices": r.iter().filter(|x| x.kev).map(|x| x.device_id).collect::<BTreeSet<_>>().len() }));
        }
        let mut worst: Vec<Value> = group(&rows, false).into_iter().filter(|x| cve_ok(p, x["kev"] == json!(true), x["cvss"].as_f64())).map(|x| {
            let d = x["evidence"].as_array().map(|e| e.iter().filter_map(|e| e["evidence_id"].as_str().and_then(|s| s.split('|').nth(1)).map(String::from)).collect::<BTreeSet<_>>().len()).unwrap_or(0);
            json!({ "cve_id": x["cve_id"], "sources": x["sources"], "kev": x["kev"], "exploited": x["exploited"], "cvss": x["cvss"], "devices": d })
        }).collect();
        let wk = |x: &Value| { let mut k = sev_key(x["exploited"] == json!(true), x["kev"] == json!(true), x["cvss"].as_f64()); k.push(json!(-x["devices"].as_i64().unwrap_or(0))); k.push(x["cve_id"].clone()); k };
        worst.sort_by(|a, b| super::cmp_keys(&wk(a), &wk(b)));
        worst.truncate(25);
        // The page's device rows: every device of the client, worst first.
        let pd = per_device(&rows);
        let mut prods_by_dev: HashMap<i64, BTreeSet<&str>> = HashMap::new();
        for r in &rows { prods_by_dev.entry(r.device_id).or_default().insert(r.product_key.as_str()); }
        let mut device_rows: Vec<Value> = devs.values().map(|d| {
            let m = pd.get(&d.id);
            let ok: Vec<&Agg> = m.map(|m| m.values().filter(|c| cve_ok(p, c.kev, c.cvss)).collect()).unwrap_or_default();
            let mut v = d.json();
            v["os_name"] = json!(d.os); v["last_contact"] = json!(d.last_contact);
            v["cves"] = json!(ok.len()); v["kev_cves"] = json!(ok.iter().filter(|c| c.kev).count()); v["max_cvss"] = json!(ok.iter().fold(None, |a, c| max_of(a, c.cvss)));
            v["vulnerable_products"] = json!(prods_by_dev.get(&d.id).map(|s| s.len()).unwrap_or(0));
            v["software"] = json!(soft.get(&d.id).copied().unwrap_or(0));
            v["sources"] = json!(SOURCES.iter().filter(|s| seen.contains(&(d.id, s.to_string()))).collect::<Vec<_>>());
            v
        }).collect();
        let dk = |x: &Value| vec![json!(-x["kev_cves"].as_i64().unwrap_or(0)), json!(-x["max_cvss"].as_f64().unwrap_or(-1.0)), json!(-x["cves"].as_i64().unwrap_or(0)),
            json!(if x["device_class"] == json!("server") { 0 } else { 1 }), json!(x["device_name"].as_str().unwrap_or("")), x["device_id"].clone()];
        device_rows.sort_by(|a, b| super::cmp_keys(&dk(a), &dk(b)));
        // The page's product rows: each product with a vulnerable version here.
        let mut pg: BTreeMap<&str, (BTreeSet<i64>, BTreeSet<i64>, Option<f64>, Vec<String>)> = BTreeMap::new();
        for (dev, m) in &pd { for c in m.values().filter(|c| cve_ok(p, c.kev, c.cvss)) {
            for r in rows.iter().filter(|r| r.device_id == *dev && r.cve_id == c.cve_id) {
                let x = pg.entry(r.product_key.as_str()).or_default();
                x.0.insert(*dev); if r.kev { x.1.insert(*dev); } x.2 = max_of(x.2, r.cvss); push(&mut x.3, &r.version);
            }
        } }
        let lab = self.labels(&pg.keys().map(|k| k.to_string()).collect::<Vec<_>>()).await?;
        let mut products: Vec<Value> = pg.into_iter().map(|(k, (d, kd, m, mut v))| { v.sort_by(|a, b| crate::matching::cmp_version(b, a));
            json!({ "product_key": k, "label": lab.get(k).cloned().unwrap_or(k.to_string()), "devices": d.len(), "kev_devices": kd.len(), "max_cvss": m, "versions": v }) }).collect();
        products.sort_by(|a, b| b["kev_devices"].as_i64().cmp(&a["kev_devices"].as_i64()).then(b["devices"].as_i64().cmp(&a["devices"].as_i64())).then(a["label"].as_str().cmp(&b["label"].as_str())));
        let mut by_class = Map::new();
        for c in ["server", "desktop", "laptop", "other"] { by_class.insert(c.into(), json!(devs.values().filter(|d| d.class == c).count())); }
        Ok(json!({ "data": {
            "org_id": org, "org_name": name.map(|n| n.0).or_else(|| devs.values().next().and_then(|d| d.org_name.clone())),
            "devices": devs.len(), "devices_with_cves": rows.iter().map(|r| r.device_id).collect::<BTreeSet<_>>().len(),
            "cves": rows.iter().map(|r| r.cve_id.as_str()).collect::<BTreeSet<_>>().len(),
            "inventoried": soft.len(), "products_seen": ev.iter().map(|r| (&r.product_key, &r.version)).collect::<BTreeSet<_>>().len(),
            "by_source": by, "by_class": by_class, "worst": worst, "device_rows": device_rows, "products": products,
        }, "next_cursor": null, "as_of": self.as_of().await }))
    }

    /// The Clients tab: every client with devices in scope, its devices by class, and the counts its row shows, each
    /// computed exactly as devices.list would list it for the same filter (so each opens its rows).
    pub(crate) async fn clients_overview(&self, p: &Params) -> Result<Value, Failure> {
        let devs = self.scoped(p).await?;
        let rows = self.cve_rows(p, &devs, None, p.product_key.as_deref(), version_of(p).as_deref()).await?;
        let pd = per_device(&rows);
        #[derive(Default)]
        struct C { name: Option<String>, devices: i64, servers: i64, desktops: i64, laptops: i64, vuln: i64, kev: i64, crit: i64, run: i64, kev_servers: i64,
                   vuln_servers: i64, vuln_desktops: i64, vuln_laptops: i64, max: Option<f64> }
        let mut g: BTreeMap<i64, C> = BTreeMap::new();
        let mut by_class: BTreeMap<&str, (i64, i64, i64)> = BTreeMap::new();
        let (mut fleet_vuln, mut fleet_kev, mut kev_clients) = (0, 0, BTreeSet::new());
        for d in devs.values() {
            let c = g.entry(d.org_id).or_default();
            c.name = d.org_name.clone(); c.devices += 1;
            match d.class.as_str() { "server" => c.servers += 1, "desktop" => c.desktops += 1, "laptop" => c.laptops += 1, _ => {} }
            let bc = by_class.entry(match d.class.as_str() { "server" => "server", "desktop" => "desktop", "laptop" => "laptop", _ => "other" }).or_default();
            bc.0 += 1;
            let ok: Vec<&Agg> = pd.get(&d.id).map(|m| m.values().filter(|x| cve_ok(p, x.kev, x.cvss)).collect()).unwrap_or_default();
            let mut srcs = vec![]; for x in &ok { for s in &x.sources { push(&mut srcs, s); } }
            if ok.is_empty() || !run_ok(p, &srcs) { continue; }
            let (kev, crit, run) = (ok.iter().any(|x| x.kev), ok.iter().any(|x| x.cvss.unwrap_or(0.0) >= 9.0), srcs.iter().any(|s| s == "process"));
            c.vuln += 1; bc.1 += 1; fleet_vuln += 1;
            if kev { c.kev += 1; bc.2 += 1; fleet_kev += 1; kev_clients.insert(d.org_id); if d.class == "server" { c.kev_servers += 1; } }
            if crit { c.crit += 1; }
            if run { c.run += 1; }
            match d.class.as_str() { "server" => c.vuln_servers += 1, "desktop" => c.vuln_desktops += 1, "laptop" => c.vuln_laptops += 1, _ => {} }
            c.max = ok.iter().fold(c.max, |a, x| max_of(a, x.cvss));
        }
        let list: Vec<Value> = g.into_iter().map(|(org, c)| json!({ "org_id": org, "org_name": c.name, "devices": c.devices, "servers": c.servers, "desktops": c.desktops,
            "laptops": c.laptops, "vulnerable_devices": c.vuln, "kev_devices": c.kev, "critical_devices": c.crit, "running_devices": c.run, "kev_servers": c.kev_servers,
            "vuln_servers": c.vuln_servers, "vuln_desktops": c.vuln_desktops, "vuln_laptops": c.vuln_laptops, "max_cvss": c.max })).collect();
        let totals = json!({ "clients": list.len(), "devices": devs.len(), "vulnerable_devices": fleet_vuln, "kev_devices": fleet_kev, "kev_clients": kev_clients.len() });
        let by_class: Vec<Value> = by_class.into_iter().map(|(c, (d, v, k))| json!({ "device_class": c, "devices": d, "vulnerable": v, "kev": k })).collect();
        let key = |x: &Value| vec![json!(-x["kev_devices"].as_i64().unwrap_or(0)), json!(-x["vulnerable_devices"].as_i64().unwrap_or(0)), json!(x["org_name"].as_str().unwrap_or("")), x["org_id"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "by_class": by_class, "as_of": self.as_of().await }))
    }

    // ---- coverage: which sources saw which devices -----------------------------------------------------------------

    /// Per client: how many devices, how many each source saw, and how many NinjaOne gave an installed-software list
    /// for. A gap is a device a source should see and didn't.
    pub(crate) async fn coverage_list(&self, p: &Params) -> Result<Value, Failure> {
        let devs = self.scoped(p).await?;
        let seen = self.seen_pairs(p, &devs).await?;
        let soft = self.software_counts(p, &devs).await?;
        let mut g: BTreeMap<i64, (Option<String>, i64, BTreeMap<&str, i64>, i64)> = BTreeMap::new();
        let mut fleet: BTreeMap<&str, i64> = SOURCES.iter().map(|s| (*s, 0)).collect();
        for d in devs.values() {
            let c = g.entry(d.org_id).or_insert_with(|| (d.org_name.clone(), 0, SOURCES.iter().map(|s| (*s, 0)).collect(), 0));
            c.1 += 1;
            for s in SOURCES { if seen.contains(&(d.id, s.to_string())) { *c.2.entry(s).or_default() += 1; *fleet.entry(s).or_default() += 1; } }
            if soft.contains_key(&d.id) { c.3 += 1; }
        }
        let list: Vec<Value> = g.into_iter().map(|(org, (name, n, by, inv))| json!({ "org_id": org, "org_name": name, "devices": n, "inventoried": inv, "by_source": by })).collect();
        let totals = json!({ "clients": list.len(), "devices": devs.len(), "inventoried": soft.len(), "by_source": fleet });
        let key = |x: &Value| vec![json!(x["org_name"].as_str().unwrap_or("")), x["org_id"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "as_of": self.as_of().await }))
    }

    /// Devices with the sources that saw each. `source` with `seen` keeps the devices any of those sources saw (true) or
    /// none did (false); `has: software` the devices with (or, with seen false, without) an installed-software list.
    pub(crate) async fn coverage_devices(&self, p: &Params) -> Result<Value, Failure> {
        let devs = self.scoped(p).await?;
        let all = Params { source: None, ..p.clone() };
        let seen = self.seen_pairs(&all, &devs).await?;
        let soft = self.software_counts(p, &devs).await?;
        let want = p.source.as_ref().map(|_| source_list(p));
        let list: Vec<Value> = devs.values().filter_map(|d| {
            let by: Vec<&str> = SOURCES.iter().copied().filter(|s| seen.contains(&(d.id, s.to_string()))).collect();
            let sw = soft.get(&d.id).copied().unwrap_or(0);
            let flag = p.seen.unwrap_or(true);
            if let Some(w) = &want && w.iter().any(|s| by.contains(&s.as_str())) != flag { return None; }
            if p.has == Some(Has::Software) && (sw > 0) != flag { return None; }
            let mut v = d.json();
            v["os_name"] = json!(d.os); v["last_contact"] = json!(d.last_contact); v["sources"] = json!(by); v["software"] = json!(sw);
            Some(v)
        }).collect();
        let total = list.len();
        let key = |x: &Value| vec![json!(x["org_name"].as_str().unwrap_or("")), json!(x["device_name"].as_str().unwrap_or("")), x["device_id"].clone()];
        let (data, next) = page_by(list, key, p.cursor.as_deref(), limit(p)).map_err(Failure::Bad)?;
        Ok(json!({ "data": data, "next_cursor": next, "totals": { "devices": total }, "as_of": self.as_of().await }))
    }

    // ---- advisories --------------------------------------------------------------------------------------------------

    /// Every advisory, active first, with how many devices in scope each names now (its own evidence rows).
    pub(crate) async fn advisories_list(&self, p: &Params) -> Result<Value, Failure> {
        let devs = self.scoped(p).await?;
        let cve = p.cve_id.as_ref().map(|c| c.to_uppercase());
        let only = Params { source: Some(vec![Source::Advisory]), ..p.clone() };
        let rows = self.cve_rows(&only, &devs, cve.as_deref(), None, None).await?;
        let list: Vec<Value> = crate::advisory::list(&self.pool, cve.as_deref()).await.map_err(|_| Failure::Db)?.into_iter().map(|mut a| {
            let id = a["advisory_id"].as_str().unwrap_or("").to_string();
            a["devices"] = json!(rows.iter().filter(|r| names_advisory(&r.detail, &id)).map(|r| r.device_id).collect::<BTreeSet<_>>().len());
            a
        }).collect();
        let active = list.iter().filter(|a| a["status"] == json!("active")).count();
        Ok(json!({ "data": list.clone(), "next_cursor": null, "totals": { "advisories": list.len(), "active": active }, "as_of": self.as_of().await }))
    }

    // ---- search ------------------------------------------------------------------------------------------------------

    /// A CVE id, or text: clients, products (by the map's label or NVD's name), advisories (by title or product: their
    /// CVE), and devices, within scope.
    pub(crate) async fn search(&self, p: &Params) -> Result<Value, Failure> {
        let q = p.q.as_deref().unwrap_or("").trim().to_string();
        if q.is_empty() { return Ok(json!({ "data": [] })); }
        let upper = q.to_uppercase();
        if upper.starts_with("CVE-") { return Ok(json!({ "data": [{ "type": "cve", "id": upper }] })); }
        // Case-insensitive, `\` escaping the pattern's own % and _: SQLite names it (ESCAPE); it's ILIKE's default, and
        // PostgreSQL's SQL here holds no backslash, so it reads the same whatever standard_conforming_strings is. The
        // order is SQLite's NOCASE on both: ASCII letters folded, then byte order (lower(...) COLLATE "C"), and ties
        // broken by the name's own bytes. Matching folds every letter on both (É matches é): ILIKE on PostgreSQL, and on
        // SQLite msp_fold (db/fold.rs), Rust's Unicode lowercase, on both sides of LIKE.
        let like = format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        let org = p.org_id.map(|x| x as i64);
        type Found = (Vec<(i64, String)>, Vec<(i64, String, Option<String>)>, Vec<(String, String)>, Vec<(String,)>);
        let (clients, devices, products, advisories): Found = crate::on_pool!(&self.pool, db, pg => (
            sqlx::query_as(if pg { "SELECT org_id, name FROM client WHERE deleted_at IS NULL AND name ILIKE $1 AND ($2::bigint IS NULL OR org_id = $2) ORDER BY lower(name) COLLATE \"C\", name COLLATE \"C\" LIMIT 25" }
                           else { "SELECT org_id, name FROM client WHERE deleted_at IS NULL AND msp_fold(name) LIKE msp_fold($1) ESCAPE '\\' AND ($2 IS NULL OR org_id = $2) ORDER BY name COLLATE NOCASE, name LIMIT 25" })
                .bind(&like).bind(org).fetch_all(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as(if pg { "SELECT d.device_id, d.name, c.name FROM device d LEFT JOIN client c ON c.org_id = d.org_id WHERE d.deleted_at IS NULL AND d.name ILIKE $1 AND ($2::bigint IS NULL OR d.org_id = $2) ORDER BY lower(d.name) COLLATE \"C\", d.name COLLATE \"C\" LIMIT 25" }
                           else { "SELECT d.device_id, d.name, c.name FROM device d LEFT JOIN client c ON c.org_id = d.org_id WHERE d.deleted_at IS NULL AND msp_fold(d.name) LIKE msp_fold($1) ESCAPE '\\' AND ($2 IS NULL OR d.org_id = $2) ORDER BY d.name COLLATE NOCASE, d.name LIMIT 25" })
                .bind(&like).bind(org).fetch_all(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as(if pg { "SELECT product_key, label FROM sec_product WHERE active AND (label ILIKE $1 OR cpe ILIKE $1) ORDER BY lower(label) COLLATE \"C\", label COLLATE \"C\" LIMIT 25" }
                           else { "SELECT product_key, label FROM sec_product WHERE active AND (msp_fold(label) LIKE msp_fold($1) ESCAPE '\\' OR msp_fold(cpe) LIKE msp_fold($1) ESCAPE '\\') ORDER BY label COLLATE NOCASE, label LIMIT 25" })
                .bind(&like).fetch_all(db).await.map_err(|_| Failure::Db)?,
            sqlx::query_as(if pg { "SELECT DISTINCT cve_id FROM sec_advisory WHERE status = 'active' AND (title ILIKE $1 OR product_label ILIKE $1) ORDER BY cve_id LIMIT 25" }
                           else { "SELECT DISTINCT cve_id FROM sec_advisory WHERE status = 'active' AND (msp_fold(title) LIKE msp_fold($1) ESCAPE '\\' OR msp_fold(product_label) LIKE msp_fold($1) ESCAPE '\\') ORDER BY cve_id LIMIT 25" })
                .bind(&like).fetch_all(db).await.map_err(|_| Failure::Db)?));
        let mut data: Vec<Value> = clients.into_iter().map(|(id, n)| json!({ "type": "client", "id": id, "label": n })).collect();
        data.extend(advisories.into_iter().map(|(c,)| json!({ "type": "cve", "id": c, "label": "named by an advisory" })));
        data.extend(products.into_iter().map(|(id, l)| json!({ "type": "product", "id": id, "label": l })));
        data.extend(devices.into_iter().map(|(id, n, o)| json!({ "type": "device", "id": id, "label": n, "org_name": o })));
        Ok(json!({ "data": data }))
    }
}
