//! Which installed software is which product, and which of NVD's affected versions it falls in. Pure: no I/O, so the
//! tests hold it to the rules.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeMap;

/// A product rule, as stored in sec_product.match. Regexes are case-insensitive.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    #[serde(default)] pub product_key: String,
    pub name_re: String,
    #[serde(default)] pub publisher_re: Option<String>,
    #[serde(default)] pub exclude_re: Option<String>,
    /// "field" (default: the version field, else the name) or "name".
    #[serde(default)] pub version_from: Option<String>,
    /// Capture group 1 is the version, applied to the chosen source.
    #[serde(default)] pub version_re: Option<String>,
}

/// A rule with its regexes compiled once.
pub struct Compiled { pub product_key: String, name: Regex, publisher: Option<Regex>, exclude: Option<Regex>, from_name: bool, version: Option<Regex> }

fn ci(s: &str) -> Option<Regex> { RegexBuilder::new(s).case_insensitive(true).build().ok() }

impl Compiled {
    /// None when a regex doesn't compile: a broken rule matches nothing rather than everything.
    pub fn new(r: &Rule) -> Option<Self> {
        Some(Self {
            product_key: r.product_key.clone(), name: ci(&r.name_re)?,
            publisher: match &r.publisher_re { Some(p) => Some(ci(p)?), None => None },
            exclude: match &r.exclude_re { Some(p) => Some(ci(p)?), None => None },
            from_name: r.version_from.as_deref() == Some("name"),
            version: match &r.version_re { Some(p) => Some(ci(p)?), None => None },
        })
    }
}

/// The leading dotted-numeric part of a version string: "26.05 (x64)" is "26.05", "8u504-b01" is "8".
pub fn norm_version(v: &str) -> Option<String> {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d+(?:\.\d+)*").unwrap()).find(v).map(|m| m.as_str().to_string())
}

/// Numeric, segment by segment; a missing segment is 0 ("0.85" equals "0.85.0.0"); leading zeros don't matter.
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let seg = |s: &str| -> Vec<u64> { s.split(['.', '-', '_']).map(leading_int).collect() };
    let (pa, pb) = (seg(a), seg(b));
    for i in 0..pa.len().max(pb.len()) {
        let (x, y) = (pa.get(i).copied().unwrap_or(0), pb.get(i).copied().unwrap_or(0));
        if x != y { return x.cmp(&y); }
    }
    Ordering::Equal
}
/// JavaScript's parseInt: the leading digits, 0 when there are none.
fn leading_int(s: &str) -> u64 { s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0) }

/// Which product an inventory entry is, and its version. First matching rule wins (rules come in sort_order).
pub fn classify(name: &str, publisher: &str, version: &str, rules: &[Compiled]) -> Option<(String, Option<String>)> {
    let n = name.trim();
    if n.is_empty() { return None; }
    for r in rules {
        if !r.name.is_match(n) { continue; }
        if r.exclude.as_ref().is_some_and(|x| x.is_match(n)) { continue; }
        if r.publisher.as_ref().is_some_and(|p| !p.is_match(publisher)) { continue; }
        let pick = |src: &str| -> Option<String> {
            match &r.version { None => norm_version(src), Some(re) => re.captures(src).and_then(|c| c.get(1)).and_then(|m| norm_version(m.as_str())) }
        };
        let v = if r.from_name { pick(n) } else { pick(version).or_else(|| pick(n)) };
        return Some((r.product_key.clone(), v));
    }
    None
}

/// One affected-version statement from NVD: an exact version, or a range with any of the four bounds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Range {
    #[serde(skip_serializing_if = "Option::is_none", default)] pub exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub si: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub se: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub ei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)] pub ee: Option<String>,
}

pub fn in_range(v: &str, r: &Range) -> bool {
    if let Some(x) = &r.exact { return cmp_version(v, x) == Ordering::Equal; }
    if r.si.is_none() && r.se.is_none() && r.ei.is_none() && r.ee.is_none() { return false; } // "every version" is too broad to trust
    if r.si.as_ref().is_some_and(|b| cmp_version(v, b) == Ordering::Less) { return false; }
    if r.se.as_ref().is_some_and(|b| cmp_version(v, b) != Ordering::Greater) { return false; }
    if r.ei.as_ref().is_some_and(|b| cmp_version(v, b) == Ordering::Greater) { return false; }
    if r.ee.as_ref().is_some_and(|b| cmp_version(v, b) != Ordering::Less) { return false; }
    true
}
pub fn affects(v: &str, ranges: &[Range]) -> bool { ranges.iter().any(|r| in_range(v, r)) }

/// A CPE 2.3 string split on its unescaped colons ("\:" stays inside a field).
pub fn split_cpe(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' && let Some(n) = it.next() { cur.push(c); cur.push(n); continue; }
        if c == ':' { out.push(std::mem::take(&mut cur)); continue; }
        cur.push(c);
    }
    out.push(cur);
    out
}

/// Every application ("vendor:product") and operating system ("o:vendor:product") an NVD 2.0 `cve` object marks
/// vulnerable, with its affected-version statements. A pinned version is an exact match only for a release build;
/// an entry with neither a range nor a concrete version says nothing about versions and is skipped.
pub fn nvd_all_ranges(cve: &Value) -> BTreeMap<String, Vec<Range>> {
    let mut out: BTreeMap<String, Vec<Range>> = BTreeMap::new();
    fn walk(node: &Value, out: &mut BTreeMap<String, Vec<Range>>) {
        for m in node.get("cpeMatch").and_then(Value::as_array).into_iter().flatten() {
            if !m.get("vulnerable").and_then(Value::as_bool).unwrap_or(false) { continue; }
            let parts = split_cpe(m.get("criteria").and_then(Value::as_str).unwrap_or(""));
            let part = parts.get(2).map(String::as_str).unwrap_or("");
            let (vendor, product) = (parts.get(3).cloned().unwrap_or_default(), parts.get(4).cloned().unwrap_or_default());
            if (part != "a" && part != "o") || vendor.is_empty() || product.is_empty() { continue; }
            let s = |k: &str| m.get(k).and_then(Value::as_str).filter(|x| !x.is_empty()).map(String::from);
            let mut r = Range { si: s("versionStartIncluding"), se: s("versionStartExcluding"), ei: s("versionEndIncluding"), ee: s("versionEndExcluding"), exact: None };
            if r.si.is_none() && r.se.is_none() && r.ei.is_none() && r.ee.is_none() {
                let ver = parts.get(5).map(String::as_str);
                let upd = parts.get(6).map(String::as_str);
                match ver { Some(v) if v != "*" && v != "-" && matches!(upd, None | Some("*") | Some("-")) => r.exact = Some(v.to_string()), _ => continue }
            }
            let key = if part == "a" { format!("{vendor}:{product}") } else { format!("o:{vendor}:{product}") };
            let list = out.entry(key).or_default();
            if !list.contains(&r) { list.push(r); }
        }
        for c in node.get("children").and_then(Value::as_array).into_iter().flatten() { walk(c, out); }
    }
    for conf in cve.get("configurations").and_then(Value::as_array).into_iter().flatten() {
        for node in conf.get("nodes").and_then(Value::as_array).into_iter().flatten() { walk(node, &mut out); }
    }
    out
}

/// The best available base score: CVSS 4.0, then 3.1, 3.0, 2.0 (NVD's primary first, then any).
pub fn cvss_of(cve: &Value) -> Option<f64> {
    let m = cve.get("metrics")?;
    for k in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let list = m.get(k).and_then(Value::as_array);
        let pick = list.and_then(|l| l.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("Primary")).or_else(|| l.first()));
        if let Some(s) = pick.and_then(|p| p.pointer("/cvssData/baseScore")).and_then(Value::as_f64) { return Some(s); }
    }
    None
}

/// NVD's severity word for the score cvss_of picked.
pub fn severity_of(cve: &Value) -> Option<String> {
    let m = cve.get("metrics")?;
    for k in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let list = m.get(k).and_then(Value::as_array);
        let pick = list.and_then(|l| l.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("Primary")).or_else(|| l.first()));
        if let Some(p) = pick { return p.pointer("/cvssData/baseSeverity").or_else(|| p.get("baseSeverity")).and_then(Value::as_str).map(String::from); }
    }
    None
}
