//! Vendor advisories entered by hand ahead of NVD. An advisory is a person's rule for a CVE NVD doesn't cover yet: which software it's about, the
//! affected versions, and the fixed ones. Saving one is an admin's (src/admin.rs), checked here field by field, and it
//! applies at once: `apply` rebuilds the `advisory` evidence from the installed software, and the match job runs it
//! again after every inventory. The process match (another area: running binaries) applies the same rules to what's
//! running with `Rules::hits`, and writes its own rows (`via` other than "installed"), which `apply` never touches.
//!
//! What it stores: vendor facts, and which staff member entered or changed each advisory. Never client data: an
//! advisory's evidence rows are the devices it names, in sec_evidence_cve like every other source's.

// The tallies here are small tuples that live for one function; naming each
// as a type would say less than the tuple does.
#![allow(clippy::type_complexity)]

use crate::db::{self as store, Pool};
use crate::matching::{affects, norm_version, Range};
use regex::{Regex, RegexBuilder};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The keys of an advisory's `match`: every one given must hold. name_re and company_re are checked against an
/// installed program's name and publisher (and a running binary's name and company); product_re and path_re only
/// against a running binary, so an advisory that names either applies to running software alone.
pub const MATCH_KEYS: [&str; 4] = ["name_re", "product_re", "company_re", "path_re"];
const RANGE_KEYS: [&str; 5] = ["exact", "si", "se", "ei", "ee"];
pub const VIA_INSTALLED: &str = "installed";

/// One advisory as checked for saving.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub advisory_id: String, pub cve_id: String, pub title: String, pub severity: Option<String>, pub cvss: Option<f64>, pub exploited: bool,
    pub url: Option<String>, pub product_key: String, pub product_label: Option<String>, pub matcher: BTreeMap<String, String>,
    pub ranges: Vec<Range>, pub fixed_in: Vec<String>, pub remedy: Option<String>,
}

fn is_version(s: &str) -> bool { !s.is_empty() && s.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) }
fn ci(s: &str) -> Option<Regex> { RegexBuilder::new(s).case_insensitive(true).size_limit(1 << 20).build().ok() }
fn text(v: &Value, k: &str) -> String { match v.get(k) { Some(Value::String(s)) => s.trim().to_string(), Some(Value::Number(n)) => n.to_string(), _ => String::new() } }
fn is_cve(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 13 && s.starts_with("CVE-") && b[4..8].iter().all(u8::is_ascii_digit) && b[8] == b'-' && b[9..].iter().all(u8::is_ascii_digit)
}

/// One advisory as an admin submits it, checked field by field. The errors say which
/// field and what it needs, never echoing what was sent.
pub fn validate(a: &Value) -> Result<Advisory, Vec<String>> {
    let mut errors = Vec::new();
    let id = text(a, "advisory_id");
    if !(3..=120).contains(&id.chars().count()) || !id.chars().all(|c| c.is_ascii_alphanumeric() || "._/:-".contains(c)) { errors.push("advisory_id: 3 to 120 letters, digits or . _ / : -".to_string()); }
    let cve = text(a, "cve_id").to_uppercase();
    if !is_cve(&cve) { errors.push("cve_id: a CVE id, like CVE-2026-12345".into()); }
    let title = text(a, "title");
    if title.is_empty() || title.chars().count() > 300 { errors.push("title: required, at most 300 characters".into()); }
    let product_key = text(a, "product_key");
    if product_key.is_empty() || product_key.chars().count() > 200 { errors.push("product_key: required, at most 200 characters".into()); }
    let m = a.get("match").cloned().unwrap_or(json!({}));
    let mut matcher = BTreeMap::new();
    if !m.is_object() { errors.push("match: an object of name_re, product_re, company_re, path_re".into()); }
    for (k, _) in m.as_object().into_iter().flatten() { if !MATCH_KEYS.contains(&k.as_str()) { errors.push(format!("match: only {}", MATCH_KEYS.join(", "))); break; } }
    for k in MATCH_KEYS {
        let v = text(&m, k);
        if v.is_empty() { continue; }
        if v.chars().count() > 300 { errors.push(format!("match.{k}: at most 300 characters")); continue; }
        if ci(&v).is_none() { errors.push(format!("match.{k}: not a valid regular expression")); continue; }
        matcher.insert(k.to_string(), v);
    }
    if matcher.is_empty() && m.is_object() { errors.push("match: at least one of name_re, product_re, company_re, path_re".into()); }
    let raw = a.get("ranges").and_then(Value::as_array).cloned().unwrap_or_default();
    if raw.is_empty() || raw.len() > 20 { errors.push("ranges: 1 to 20".into()); }
    let mut ranges = Vec::new();
    for r in &raw {
        let o = r.as_object().cloned().unwrap_or_default();
        let given: Vec<(&String, String)> = o.iter().map(|(k, v)| (k, v.as_str().map(|s| s.trim().to_string()).unwrap_or_else(|| v.to_string()))).filter(|(_, v)| !v.is_empty() && v != "null").collect();
        if given.is_empty() { errors.push("ranges: each needs a bound (exact, si, se, ei or ee)".into()); continue; }
        if given.iter().any(|(k, _)| !RANGE_KEYS.contains(&k.as_str())) { errors.push(format!("ranges: only {}", RANGE_KEYS.join(", "))); continue; }
        if given.iter().any(|(_, v)| !is_version(v)) { errors.push("ranges: versions are numbers, like 22.23.4".into()); continue; }
        let g = |k: &str| given.iter().find(|(n, _)| n.as_str() == k).map(|(_, v)| v.clone());
        ranges.push(Range { exact: g("exact"), si: g("si"), se: g("se"), ei: g("ei"), ee: g("ee") });
    }
    let fixed_in: Vec<String> = a.get("fixed_in").and_then(Value::as_array).into_iter().flatten().filter_map(|v| v.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect();
    if fixed_in.iter().any(|v| !is_version(v)) || fixed_in.len() > 20 { errors.push("fixed_in: up to 20 versions, like 24.22.1".into()); }
    let url = text(a, "url");
    if !url.is_empty() && (!url.starts_with("https://") || url.len() > 500 || url.chars().any(char::is_whitespace)) { errors.push("url: an https link".into()); }
    let severity = text(a, "severity");
    if !severity.is_empty() && !["critical", "high", "medium", "low"].contains(&severity.as_str()) { errors.push("severity: critical, high, medium or low".into()); }
    let cvss = match a.get("cvss") { None | Some(Value::Null) => None, Some(Value::String(s)) if s.trim().is_empty() => None, Some(v) => {
        let n = v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()));
        if !n.is_some_and(|n| (0.0..=10.0).contains(&n)) { errors.push("cvss: 0 to 10".into()); }
        n
    } };
    let label = text(a, "product_label");
    if label.chars().count() > 200 { errors.push("product_label: at most 200 characters".into()); }
    let remedy = text(a, "remedy");
    if remedy.chars().count() > 2000 { errors.push("remedy: at most 2000 characters".into()); }
    if !errors.is_empty() { return Err(errors); }
    let opt = |s: String| if s.is_empty() { None } else { Some(s) };
    Ok(Advisory { advisory_id: id, cve_id: cve, title, severity: opt(severity), cvss, exploited: a.get("exploited").and_then(Value::as_bool).unwrap_or(false),
        url: opt(url), product_key, product_label: opt(label), matcher, ranges, fixed_in, remedy: opt(remedy) })
}

/// Active advisories with their regexes compiled once. A rule whose regex doesn't compile, or that names nothing,
/// matches nothing.
pub struct Rules(Vec<Rule>);
pub struct Rule { pub advisory_id: String, pub cve_id: String, pub product_key: String, pub cvss: Option<f64>, pub exploited: bool, name: Option<Regex>, product: Option<Regex>, company: Option<Regex>, path: Option<Regex>, ranges: Vec<Range> }

/// What a source saw that an advisory might be about: an installed program (name, publisher as company, its version)
/// or a running binary (name, product, company, file version, paths).
pub struct Seen<'a> { pub name: &'a str, pub product: Option<&'a str>, pub company: Option<&'a str>, pub version: &'a str, pub paths: &'a [String] }

impl Rules {
    pub fn new(rows: &[(String, String, String, Option<f64>, bool, Value, Value)]) -> Self {
        Self(rows.iter().filter_map(|(id, cve, key, cvss, exploited, m, ranges)| {
            let get = |k: &str| m.get(k).and_then(Value::as_str).filter(|s| !s.trim().is_empty());
            let compile = |k: &str| -> Option<Option<Regex>> { match get(k) { None => Some(None), Some(s) => ci(s).map(Some) } };
            let (name, product, company, path) = (compile("name_re")?, compile("product_re")?, compile("company_re")?, compile("path_re")?);
            if name.is_none() && product.is_none() && company.is_none() && path.is_none() { return None; }
            Some(Rule { advisory_id: id.clone(), cve_id: cve.clone(), product_key: key.clone(), cvss: *cvss, exploited: *exploited, name, product, company, path,
                ranges: serde_json::from_value(ranges.clone()).unwrap_or_default() })
        }).collect())
    }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Every rule this holds for, with the version it matched at and the path (a binary's first matching path).
    pub fn hits(&self, s: &Seen) -> Vec<(&Rule, String, Option<String>)> {
        let Some(v) = norm_version(s.version) else { return vec![] };
        self.0.iter().filter_map(|r| {
            if r.name.as_ref().is_some_and(|re| !re.is_match(s.name)) { return None; }
            if r.product.as_ref().is_some_and(|re| !s.product.is_some_and(|p| re.is_match(p))) { return None; }
            if r.company.as_ref().is_some_and(|re| !s.company.is_some_and(|c| re.is_match(c))) { return None; }
            let path = match &r.path { Some(re) => Some(s.paths.iter().find(|p| re.is_match(p))?.clone()), None => s.paths.first().cloned() };
            if !affects(&v, &r.ranges) { return None; }
            Some((r, v.clone(), path))
        }).collect()
    }
}

/// The active advisories, as the rules read them.
pub async fn rules(pool: &Pool) -> Result<Rules, sqlx::Error> {
    let rows: Vec<(String, String, String, Option<f64>, bool, Value, Value)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT advisory_id, cve_id, product_key, cvss, exploited, match, ranges FROM sec_advisory WHERE status = 'active' ORDER BY advisory_id").fetch_all(p).await)?;
    Ok(Rules::new(&rows))
}

/// Rebuild the advisories' evidence from installed software: every live device with a program an active advisory
/// names, at a version in its ranges, is a row of source `advisory` for that CVE (sec_evidence_cve), the advisories
/// that named it in its detail. Rows the process match wrote (running binaries) are left as they are.
pub async fn apply(pool: &Pool) -> Result<Value, String> {
    let rules = rules(pool).await.map_err(|e| store::why(&e))?;
    // Each distinct installed entry once; only the ones a rule holds for are read again, device by device.
    let distinct: Vec<(String, String, String)> = if rules.is_empty() { vec![] } else {
        crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT DISTINCT name, publisher, version FROM software").fetch_all(p).await).map_err(|e| store::why(&e))?
    };
    let mut hit: BTreeMap<(String, String, String), Vec<(usize, String)>> = BTreeMap::new();
    for (n, p, v) in &distinct {
        let s = Seen { name: n, product: None, company: Some(p), version: v, paths: &[] };
        let h: Vec<(usize, String)> = rules.hits(&s).into_iter().map(|(r, ver, _)| (rules.0.iter().position(|x| std::ptr::eq(x, r)).unwrap_or(0), ver)).collect();
        if !h.is_empty() { hit.insert((n.clone(), p.clone(), v.clone()), h); }
    }
    let names: Vec<String> = hit.keys().map(|k| k.0.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let installs: Vec<(i64, String, String, String)> = if names.is_empty() { vec![] } else {
        crate::on_pool!(pool, p, pg => sqlx::query_as(if pg {
            "SELECT s.device_id, s.name, s.publisher, s.version FROM software s JOIN device d ON d.device_id = s.device_id AND d.deleted_at IS NULL WHERE s.name = ANY($1)"
        } else {
            "SELECT s.device_id, s.name, s.publisher, s.version FROM software s JOIN device d ON d.device_id = s.device_id AND d.deleted_at IS NULL WHERE s.name IN (SELECT value FROM json_each($1))"
        }).bind(store::list(&names)).fetch_all(p).await).map_err(|e| store::why(&e))?
    };
    // (device, CVE, product) → the version, the advisories, the programs, the worst score, exploited.
    type Ev = (String, BTreeSet<String>, BTreeSet<String>, Option<f64>, bool);
    let mut ev: BTreeMap<(i64, String, String), Ev> = BTreeMap::new();
    for (dev, n, p, v) in &installs {
        for (i, ver) in hit.get(&(n.clone(), p.clone(), v.clone())).into_iter().flatten() {
            let r = &rules.0[*i];
            let x = ev.entry((*dev, r.cve_id.clone(), r.product_key.clone())).or_insert_with(|| (ver.clone(), BTreeSet::new(), BTreeSet::new(), None, false));
            x.1.insert(r.advisory_id.clone()); x.2.insert(n.clone());
            x.3 = match (x.3, r.cvss) { (Some(a), Some(b)) => Some(a.max(b)), (a, b) => a.or(b) };
            x.4 |= r.exploited;
        }
    }
    let rows = ev.len();
    crate::on_pool!(pool, p, _ => {
        let mut tx = p.begin().await.map_err(|e| store::why(&e))?;
        sqlx::query("DELETE FROM sec_evidence_cve WHERE source = 'advisory' AND detail ->> 'via' = 'installed'").execute(&mut *tx).await.map_err(|e| store::why(&e))?;
        for ((dev, cve, key), (ver, ids, names, cvss, exploited)) in &ev {
            let detail = json!({ "via": VIA_INSTALLED, "advisories": ids.iter().map(|a| json!({ "advisory_id": a })).collect::<Vec<_>>(), "names": names });
            sqlx::query("INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, attribution, cvss, exploited, detail) VALUES ($1, $2, $3, $4, 'advisory', $5, $6, $7, $8)
                         ON CONFLICT (device_id, cve_id, source, product_key) DO UPDATE SET version = excluded.version, attribution = excluded.attribution, cvss = excluded.cvss, exploited = excluded.exploited, detail = excluded.detail")
                .bind(dev).bind(cve).bind(key).bind(ver).bind(names.iter().next().cloned()).bind(cvss).bind(exploited).bind(detail).execute(&mut *tx).await.map_err(|e| store::why(&e))?;
        }
        tx.commit().await.map_err(|e| store::why(&e))?;
    });
    Ok(json!({ "advisories": rules.0.len(), "advisory_rows": rows }))
}

#[derive(sqlx::FromRow)]
struct Row {
    advisory_id: String, cve_id: String, title: String, severity: Option<String>, cvss: Option<f64>, exploited: bool, url: Option<String>, product_key: String,
    product_label: Option<String>, #[sqlx(rename = "match")] matcher: Value, ranges: Value, fixed_in: Value, remedy: Option<String>, status: String, added_by: Option<String>,
    added_at: chrono::DateTime<chrono::Utc>, edited_by: Option<String>, edited_at: Option<chrono::DateTime<chrono::Utc>>, notes: Option<String>,
}
const COLUMNS: &str = "advisory_id, cve_id, title, severity, cvss, exploited, url, product_key, product_label, match, ranges, fixed_in, remedy, status, added_by, added_at, edited_by, edited_at, notes";

/// Every advisory (or one CVE's), active first, then by CVE (newest first) and id.
pub async fn list(pool: &Pool, cve: Option<&str>) -> Result<Vec<Value>, sqlx::Error> {
    let q = format!("SELECT {COLUMNS} FROM sec_advisory WHERE ($1 IS NULL OR cve_id = $1) ORDER BY CASE WHEN status = 'active' THEN 0 ELSE 1 END, cve_id DESC, advisory_id");
    let pgq = q.replace("($1 IS NULL", "($1::text IS NULL");
    let rows: Vec<Row> = crate::on_pool!(pool, p, pg => sqlx::query_as(sqlx::AssertSqlSafe(if pg { pgq } else { q })).bind(cve).fetch_all(p).await)?;
    Ok(rows.into_iter().map(|r| json!({ "advisory_id": r.advisory_id, "cve_id": r.cve_id, "title": r.title, "severity": r.severity, "cvss": r.cvss, "exploited": r.exploited,
        "url": r.url, "product_key": r.product_key, "product_label": r.product_label, "match": r.matcher, "ranges": r.ranges, "fixed_in": r.fixed_in, "remedy": r.remedy,
        "status": r.status, "added_by": r.added_by, "added_at": r.added_at, "edited_by": r.edited_by, "edited_at": r.edited_at, "notes": r.notes })).collect())
}

/// What a save asks for: the advisory itself, or to supersede it (a reviewed decision, with a reason) or bring it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action { Save, Supersede, Reactivate }

impl Action {
    pub fn parse(s: &str) -> Option<Self> { match s { "save" => Some(Self::Save), "supersede" => Some(Self::Supersede), "reactivate" => Some(Self::Reactivate), _ => None } }
    pub fn as_str(&self) -> &'static str { match self { Self::Save => "save", Self::Supersede => "supersede", Self::Reactivate => "reactivate" } }
}

pub enum SaveError { Bad(String), NotFound, Db(String) }

/// Save an advisory as `by` (a signed-in admin), then apply every advisory again. Saving the same advisory twice
/// leaves one row: the id is the key, so a double click changes nothing more. Superseding needs a reason, kept in
/// its notes with who and when; it's never automatic.
pub async fn save(pool: &Pool, action: Action, body: &Value, reason: &str, by: &str) -> Result<Value, SaveError> {
    let db = |e: sqlx::Error| SaveError::Db(store::why(&e));
    let id = match action {
        Action::Save => {
            let a = validate(body).map_err(|e| SaveError::Bad(e.join("; ")))?;
            let matcher = Value::Object(a.matcher.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<Map<_, _>>());
            let ranges = serde_json::to_value(&a.ranges).unwrap_or(json!([]));
            let now = store::now();
            crate::on_pool!(pool, p, _ => sqlx::query(
                "INSERT INTO sec_advisory (advisory_id, cve_id, title, severity, cvss, exploited, url, product_key, product_label, match, ranges, fixed_in, remedy, added_by, added_at, edited_by, edited_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $14, $15)
                 ON CONFLICT (advisory_id) DO UPDATE SET cve_id = excluded.cve_id, title = excluded.title, severity = excluded.severity, cvss = excluded.cvss, exploited = excluded.exploited,
                   url = excluded.url, product_key = excluded.product_key, product_label = excluded.product_label, match = excluded.match, ranges = excluded.ranges,
                   fixed_in = excluded.fixed_in, remedy = excluded.remedy, edited_by = excluded.edited_by, edited_at = excluded.edited_at")
                .bind(&a.advisory_id).bind(&a.cve_id).bind(&a.title).bind(&a.severity).bind(a.cvss).bind(a.exploited).bind(&a.url).bind(&a.product_key).bind(&a.product_label)
                .bind(&matcher).bind(&ranges).bind(json!(a.fixed_in)).bind(&a.remedy).bind(by).bind(now).execute(p).await.map(|_| ())).map_err(db)?;
            a.advisory_id
        }
        Action::Supersede | Action::Reactivate => {
            let id = text(body, "advisory_id");
            let reason = reason.trim();
            if action == Action::Supersede && reason.is_empty() { return Err(SaveError::Bad("superseding is a reviewed decision: say why (NVD now covers it, with its ranges, say)".into())); }
            let old: Option<(Option<String>,)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT notes FROM sec_advisory WHERE advisory_id = $1").bind(&id).fetch_optional(p).await).map_err(db)?;
            let Some((notes,)) = old else { return Err(SaveError::NotFound) };
            let day = store::ts(chrono::Utc::now());
            let what = if action == Action::Supersede { "superseded" } else { "reactivated" };
            let note = format!("{what} by {by} on {}{}", &day[..10], if reason.is_empty() { String::new() } else { format!(": {}", reason.chars().take(500).collect::<String>()) });
            let notes = match notes { Some(n) if !n.is_empty() => format!("{n}\n{note}"), _ => note };
            let status = if action == Action::Supersede { "superseded" } else { "active" };
            crate::on_pool!(pool, p, _ => sqlx::query("UPDATE sec_advisory SET status = $2, edited_by = $3, edited_at = $4, notes = $5 WHERE advisory_id = $1")
                .bind(&id).bind(status).bind(by).bind(store::now()).bind(&notes).execute(p).await.map(|_| ())).map_err(db)?;
            id
        }
    };
    let applied = apply(pool).await.map_err(SaveError::Db)?;
    Ok(json!({ "ok": true, "action": action.as_str(), "advisory_id": id, "applied": applied }))
}
