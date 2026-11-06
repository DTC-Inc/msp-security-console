//! Running processes: the endpoint script's payload (endpoint/process, schema 1), read from a NinjaOne custom
//! field, and what each running binary is as a product. Pure: no I/O, so the tests hold it to the rules.
//!
//! What's kept of a binary: its name, hash, paths, version, product, company, signer and signature, and how many
//! instances ran. Never a command line (the script never collects one) and never the user names it ran as.

use crate::cpe_map::{self, Candidate, Index};
use crate::matching::{classify, norm_version, Compiled};
use base64::Engine;
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::OnceLock;

pub const SCHEMAS: &[i64] = &[1];
/// A decompressed payload larger than this is refused (the script caps itself near 190,000 characters of base64).
pub const MAX_PAYLOAD: u64 = 16 * 1024 * 1024;
const PATHS_KEPT: usize = 5;

/// Control characters stripped, trimmed, capped; None when nothing's left.
pub fn clean(v: Option<&Value>, max: usize) -> Option<String> {
    let s = match v? { Value::String(s) => s.clone(), Value::Number(n) => n.to_string(), Value::Bool(b) => b.to_string(), _ => return None };
    let s: String = s.chars().filter(|c| !matches!(*c as u32, 0..=8 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F..=0x9F)).collect();
    let s = s.trim();
    (!s.is_empty()).then(|| s.chars().take(max).collect())
}

/// An ISO time the payload carries ("2026-10-26T17:53:17Z"), in the store's form; None when it isn't one.
pub fn iso(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    if s.len() < 11 || !s.as_bytes()[..10].iter().enumerate().all(|(i, b)| if i == 4 || i == 7 { *b == b'-' } else { b.is_ascii_digit() }) || s.as_bytes()[10] != b'T' { return None; }
    crate::db::ts_text(s)
}

/// The field's text: NinjaOne returns a WYSIWYG value as { text, html }, either possibly wrapped in tags and broken
/// across lines by the editor. The base64 alphabet has no HTML specials, so stripping tags and whitespace is lossless.
pub fn field_text(value: &Value) -> Option<String> {
    static TAGS: OnceLock<Regex> = OnceLock::new();
    let raw = match value {
        Value::String(s) => s.as_str(),
        Value::Object(o) => o.get("text").and_then(Value::as_str).filter(|s| !s.is_empty()).or_else(|| o.get("html").and_then(Value::as_str)).unwrap_or(""),
        _ => "",
    };
    let t = TAGS.get_or_init(|| Regex::new(r"<[^>]*>").unwrap()).replace_all(raw, "").replace("&nbsp;", "");
    let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    (!t.is_empty()).then_some(t)
}

#[derive(Debug, PartialEq)]
pub enum Decoded { Absent, Bad(String), Doc(Value) }

/// base64, then gzip, then JSON; an unknown schema, a payload without rows or without a valid collectedAt is refused,
/// never half-read.
pub fn decode_inventory(value: &Value) -> Decoded {
    let Some(t) = field_text(value) else { return Decoded::Absent };
    if !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') { return Decoded::Bad("the value is not base64".into()); }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&t) else { return Decoded::Bad("the value is not base64".into()) };
    let mut out = Vec::new();
    match flate2::read::GzDecoder::new(&bytes[..]).take(MAX_PAYLOAD + 1).read_to_end(&mut out) {
        Err(_) => return Decoded::Bad("could not decompress the value (not gzip)".into()),
        Ok(n) if n as u64 > MAX_PAYLOAD => return Decoded::Bad("the decompressed value is larger than any payload the script writes".into()),
        Ok(_) => {}
    }
    let Ok(doc) = serde_json::from_slice::<Value>(&out) else { return Decoded::Bad("the decompressed value is not JSON".into()) };
    if !doc.is_object() { return Decoded::Bad("the payload is not an object".into()); }
    let schema = doc.get("schema").and_then(Value::as_i64);
    if !schema.is_some_and(|s| SCHEMAS.contains(&s)) {
        let said = clean(doc.get("schema"), 20).unwrap_or_else(|| "(none)".into());
        return Decoded::Bad(format!("unknown payload schema {said}; this console reads schema {}", SCHEMAS.iter().map(i64::to_string).collect::<Vec<_>>().join(", ")));
    }
    if !doc.get("binaries").is_some_and(Value::is_array) { return Decoded::Bad("the payload has no binaries array".into()); }
    if iso(doc.get("collectedAt")).is_none() { return Decoded::Bad("the payload has no valid collectedAt".into()); }
    Decoded::Doc(doc)
}

/// The endpoint script's own classes, worst first: invalid is signed but not Valid (HashMismatch, NotTrusted ...),
/// unchecked could not be checked (Unavailable).
pub const TRUST_ORDER: &[&str] = &["invalid", "unsigned", "unchecked", "unhashed", "valid"];
pub fn trust_of(status: Option<&str>, unhashed: bool) -> &'static str {
    if unhashed { return "unhashed"; }
    match status { Some("Valid") => "valid", Some("NotSigned") => "unsigned", None | Some("") | Some("Unavailable") => "unchecked", _ => "invalid" }
}
pub fn trust_rank(t: &str) -> usize { TRUST_ORDER.iter().position(|x| *x == t).unwrap_or(TRUST_ORDER.len()) }

/// One running binary on one device, as stored (device_process).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Binary {
    pub device_id: i64, pub key: String, pub sha256: Option<String>, pub name: String, pub paths: Vec<String>, pub path_count: i64,
    pub file_version: Option<String>, pub product: Option<String>, pub company: Option<String>, pub signer: Option<String>,
    pub signature_status: Option<String>, pub trust: &'static str, pub instance_count: i64, pub collected_at: Option<String>,
}

fn is_sha256(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn int(v: Option<&Value>) -> i64 { v.and_then(|x| x.as_f64().or_else(|| x.as_str().and_then(|s| s.parse().ok()))).map(|f| f.trunc() as i64).unwrap_or(0) }

/// The payload's binaries, one row per key (the first when a key repeats).
pub fn process_rows(device_id: i64, doc: &Value) -> Vec<Binary> {
    let collected = iso(doc.get("collectedAt"));
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for b in doc.get("binaries").and_then(Value::as_array).into_iter().flatten() {
        if !b.is_object() { continue; }
        let Some(key) = clean(b.get("key"), 1000) else { continue };
        if !seen.insert(key.clone()) { continue; }
        let sha = b.get("sha256").and_then(Value::as_str).filter(|s| is_sha256(s)).map(String::from);
        let unhashed = b.get("unhashed") == Some(&Value::Bool(true)) || sha.is_none();
        let status = clean(b.get("signatureStatus"), 40);
        let paths: Vec<String> = b.get("paths").and_then(Value::as_array).into_iter().flatten().filter(|p| p.is_string()).filter_map(|p| clean(Some(p), 1000)).collect();
        out.push(Binary {
            device_id, name: clean(b.get("name"), 260).unwrap_or_else(|| key.clone()), key, trust: trust_of(status.as_deref(), unhashed), sha256: sha,
            path_count: int(b.get("pathCount")).max(paths.len() as i64), paths: paths.into_iter().take(PATHS_KEPT).collect(),
            file_version: clean(b.get("fileVersion"), 100), product: clean(b.get("product"), 500), company: clean(b.get("company"), 500),
            signer: clean(b.get("signer"), 500), signature_status: status, instance_count: int(b.get("count")), collected_at: collected.clone(),
        });
    }
    out
}

/// What's held for a device: when its payload was collected, the content hash it was read at (endpoint 1.2.1), when
/// NinjaOne said its bytes field was written, and whether the last read failed.
#[derive(Debug, Clone, Default)]
pub struct Held { pub collected_at: Option<String>, pub bytes_updated_at: Option<String>, pub content_hash: Option<String>, pub error: bool }

/// Whether to download a device's payload at all. A content hash (endpoint 1.2.1) decides when there is one; before
/// that, the bytes field's NinjaOne time (written in the same run as the payload). Nothing held, or a last read that
/// failed: always download. So a quiet run downloads nothing.
pub fn plan_fetch(held: Option<&Held>, bytes_updated: Option<&str>, hash: Option<&str>) -> bool {
    let Some(h) = held else { return true };
    if h.error { return true; }
    if let Some(x) = hash { return h.content_hash.as_deref() != Some(x); }
    match (bytes_updated, h.bytes_updated_at.as_deref()) { (Some(a), Some(b)) => a != b, _ => true }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Write { Replace, Same, Older }
/// A payload replaces what's held only when it was collected later: the same time touches the snapshot, and an older
/// one never replaces newer rows. Times are the store's one text form, so text order is time order.
pub fn decide_write(held_collected: Option<&str>, collected: &str) -> Write {
    match held_collected { None => Write::Replace, Some(h) if collected > h => Write::Replace, Some(h) if collected == h => Write::Same, _ => Write::Older }
}

/// The device's last run: the CollectedAt field (a Text field: a string, or { text }), or the payload's collectedAt
/// when the endpoint predates it; never earlier than the payload.
pub fn last_seen(field: Option<&Value>, doc_collected: Option<&str>) -> Option<String> {
    let raw = field.and_then(|f| f.as_str().map(String::from).or_else(|| f.get("text").and_then(Value::as_str).map(String::from)));
    let f = iso(raw.map(|s| Value::String(s.trim().to_string())).as_ref());
    match (f, doc_collected.map(String::from)) { (None, d) => d, (f, None) => f, (Some(f), Some(d)) => Some(if f >= d { f } else { d }) }
}

/// The content hash field (endpoint 1.2.1): the SHA-256 of the content; anything else isn't one.
pub fn content_hash(field: Option<&Value>) -> Option<String> {
    let raw = field.and_then(|f| f.as_str().map(String::from).or_else(|| f.get("text").and_then(Value::as_str).map(String::from)))?;
    let t = raw.trim().to_lowercase();
    is_sha256(&t).then_some(t)
}

/// Windows itself: a Microsoft binary whose product names Windows (the OS, Search, Script Host, WSL). Microsoft's apps
/// (Edge, Teams, Office) are not, and neither is a third party's "... for Windows". Microsoft's monthly updates cover
/// these per device (the `msrc` source), and matching them here would count them twice.
pub fn is_windows_os(product: &str, company: &str) -> bool {
    static MS: OnceLock<Regex> = OnceLock::new();
    static WIN: OnceLock<Regex> = OnceLock::new();
    MS.get_or_init(|| Regex::new(r"(?i)^microsoft\b").unwrap()).is_match(company.trim()) && WIN.get_or_init(|| Regex::new(r"(?i)\bwindows\b").unwrap()).is_match(product)
}

/// How a binary became a product, and how sure that is.
pub fn confidence_of(method: &str) -> f64 { match method { "rule" | "reviewed" => 1.0, "auto" => cpe_map::AUTO_CONFIDENCE, "cpe" => cpe_map::AUTO_CONFIDENCE, _ => 0.0 } }

/// A running binary as a product, by a curated rule on its product and company, or by the automatic map the
/// inventory match recorded for that (name, publisher). The version is the file's, never read from a name.
pub fn product_for(product: &str, company: &str, file_version: &str, rules: &[Compiled], class_map: &HashMap<(String, String), String>) -> Option<(String, Option<String>, &'static str)> {
    if product.is_empty() { return None; }
    let v = (!file_version.is_empty()).then(|| norm_version(file_version)).flatten();
    if let Some((key, _)) = classify(product, company, file_version, rules) { return Some((key, v, "rule")); }
    class_map.get(&(product.to_string(), company.to_string())).map(|k| (k.clone(), v, "auto"))
}

/// One distinct (product, company, file version) running, and on how many devices.
#[derive(Debug, Clone)]
pub struct Combo { pub product: String, pub company: String, pub file_version: String, pub devices: i64 }

/// A decision a person made about a name: accepted (with the NVD product it is) or rejected.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision { pub status: String, pub cpe: Option<String> }

#[derive(Debug, Clone, Serialize)]
pub struct Class { pub product: String, pub company: String, pub file_version: String, pub product_key: String, pub product_version: Option<String>, pub method: &'static str, pub confidence: f64, pub devices: i64 }
#[derive(Debug, Clone, Serialize)]
pub struct Review { pub name: String, pub company: String, pub candidates: Vec<Candidate>, pub versions: Vec<String>, pub devices: i64 }

#[derive(Debug, Default)]
pub struct Plan { pub classes: Vec<Class>, pub review: Vec<Review>, pub auto_products: BTreeMap<String, (String, String)>, pub windows: i64 }

/// Every combination becomes a class, a review row, or nothing. In order: Windows itself is skipped; a curated rule or
/// the inventory's automatic map; a person's decision (rejected is never matched; accepted is that NVD product); then
/// the CPE match on its own when it's sure (one NVD product whose vendor is the company). A name the match wouldn't
/// decide, with candidates, waits for a person, and isn't matched until they decide.
pub fn plan_classes(combos: &[Combo], rules: &[Compiled], class_map: &HashMap<(String, String), String>, decisions: &HashMap<(String, String), Decision>, idx: &Index) -> Plan {
    let mut plan = Plan::default();
    let mut memo: HashMap<(String, String), cpe_map::Search> = HashMap::new();
    let mut review: BTreeMap<(String, String), Review> = BTreeMap::new();
    for c in combos {
        if is_windows_os(&c.product, &c.company) { plan.windows += c.devices; continue; }
        let version = (!c.file_version.is_empty()).then(|| norm_version(&c.file_version)).flatten();
        let class = |key: String, method: &'static str, confidence: f64| Class { product: c.product.clone(), company: c.company.clone(), file_version: c.file_version.clone(),
            product_key: key, product_version: version.clone(), method, confidence, devices: c.devices };
        if let Some((key, _, method)) = product_for(&c.product, &c.company, &c.file_version, rules, class_map) {
            plan.classes.push(class(key, method, confidence_of(method)));
            continue;
        }
        let nk = (c.product.clone(), c.company.clone());
        let d = decisions.get(&nk);
        if d.is_some_and(|d| d.status == "rejected") { continue; }
        let (cpe, method) = match d.filter(|d| d.status == "accepted").and_then(|d| d.cpe.clone()) {
            Some(cpe) => (Some(cpe), "reviewed"),
            None if !idx.is_empty() => {
                let m = memo.entry(nk.clone()).or_insert_with(|| cpe_map::cpe_candidates(&c.product, &c.company, idx));
                if let Some(x) = &m.mapping { (Some(format!("{}:{}", x.vendor, x.product)), "cpe") }
                else {
                    if !m.candidates.is_empty() {
                        let r = review.entry(nk.clone()).or_insert_with(|| Review { name: c.product.clone(), company: c.company.clone(), candidates: m.candidates.clone(), versions: vec![], devices: 0 });
                        if !c.file_version.is_empty() && !r.versions.contains(&c.file_version) { r.versions.push(c.file_version.clone()); }
                        r.devices += c.devices;
                    }
                    (None, "")
                }
            }
            None => (None, ""),
        };
        let Some(cpe) = cpe else { continue };
        let Some(p) = cpe_map::CpeProduct::parse(&cpe) else { continue };
        let key = cpe_map::auto_key(&p);
        plan.classes.push(class(key.clone(), method, confidence_of(method)));
        plan.auto_products.entry(key).or_insert_with(|| (cpe_map::auto_label(&c.product), cpe));
    }
    plan.review = review.into_values().map(|mut r| { r.versions.sort(); r }).collect();
    plan
}

/// What a device runs, as products: (device, product key, version) → its binaries (name, first path, hash). Only
/// binaries whose class has a version: one with no version has nothing to compare.
pub fn running(rows: &[Binary], classes: &[Class]) -> BTreeMap<(i64, String, String), Vec<Value>> {
    let by: HashMap<(&str, &str, &str), &Class> = classes.iter().filter(|c| c.product_version.is_some())
        .map(|c| ((c.product.as_str(), c.company.as_str(), c.file_version.as_str()), c)).collect();
    let mut out: BTreeMap<(i64, String, String), Vec<Value>> = BTreeMap::new();
    for r in rows {
        let k = (r.product.as_deref().unwrap_or(""), r.company.as_deref().unwrap_or(""), r.file_version.as_deref().unwrap_or(""));
        let Some(c) = by.get(&k) else { continue };
        let list = out.entry((r.device_id, c.product_key.clone(), c.product_version.clone().unwrap_or_default())).or_default();
        let bin = json!({ "name": r.name, "path": r.paths.first(), "sha256": r.sha256, "file_version": r.file_version, "method": c.method, "confidence": c.confidence });
        if !list.iter().any(|b| b["name"] == bin["name"] && b["path"] == bin["path"]) { list.push(bin); }
    }
    out
}
