//! Windows itself: which Microsoft security update fixes each CVE on each Windows build, and where every Windows
//! device stands against them. Pure: no I/O, so the tests hold it to the rules.
//!
//! What bit there, and is pinned in tests/windows.rs:
//!   - Build 26100 is Windows 11 24H2 AND Server 2025, fixed at different revisions, so a match keys on (build, server),
//!     never the build alone.
//!   - One CVE lists the first fix and later rollups for the same product; the EARLIEST fixed build is the threshold
//!     (Windows updates are cumulative).
//!   - The update index is ordered by name ("2026-Oct" before "2026-Sep"); order by date.
//!   - Microsoft revises recent months almost daily, so a month is reloaded only when its revision date moved.
//!   - NinjaOne's build number has no revision ("22631"), so a device's revision comes from the newest cumulative
//!     update it installed, through the KB → build map Microsoft's own data gives. No revision is "unknown", never
//!     patched.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// A Windows build: the build number and, when known, the revision ("26100.2033" is 26100, 2033).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Build { pub major: i64, pub rev: Option<i64> }

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex { cell.get_or_init(|| Regex::new(pat).expect("a fixed pattern")) }

/// A device's build as NinjaOne or anyone else writes it: "22631", "10.0.22631", "26100.2033", "10.0.26100.2033",
/// "6.3.9600.23470". The major is the build (the third part of a four-part version), the revision the fourth.
pub fn parse_build(s: &str) -> Option<Build> {
    static R: OnceLock<Regex> = OnceLock::new();
    let c = re(&R, r"^(?:\d+\.\d+\.)?(\d{4,5})(?:\.(\d+))?$").captures(s.trim())?;
    Some(Build { major: c[1].parse().ok()?, rev: c.get(2).and_then(|m| m.as_str().parse().ok()) })
}

/// A FixedBuild from MSRC is a Windows build only in its full form (10.0.x.y, or 6.0 to 6.3 for 2008 to 2012 R2).
/// Everything else there is another product's version (Azure Linux packages, Edge, Office).
pub fn windows_fixed_build(s: &str) -> Option<Build> {
    static R: OnceLock<Regex> = OnceLock::new();
    let c = re(&R, r"^(?:10\.0|6\.[0-3])\.(\d+)\.(\d+)$").captures(s.trim())?;
    Some(Build { major: c[1].parse().ok()?, rev: Some(c[2].parse().ok()?) })
}

/// One row per (CVE, Windows product): the earliest build that fixes it, and the update (KB) that brings it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fix {
    pub cve: String, pub product_id: String, pub product: String, pub server: bool, pub build_major: i64,
    pub fixed_build: String, pub fixed_rev: i64, pub kb: String, pub severity: Option<String>, pub exploited: bool, pub title: Option<String>,
}

// ---- The CVRF document, only the parts read. Unknown fields (the long Notes, References, scores) are skipped, so a
// 28 MB month parses into a few MB of these.
#[derive(Debug, Default, Deserialize)]
pub struct Cvrf {
    #[serde(rename = "ProductTree", default)] pub product_tree: ProductTree,
    #[serde(rename = "Vulnerability", default)] pub vulnerability: Vec<Vuln>,
}
#[derive(Debug, Default, Deserialize)]
pub struct ProductTree { #[serde(rename = "FullProductName", default)] pub full_product_name: Vec<ProductName> }
#[derive(Debug, Default, Deserialize)]
pub struct ProductName { #[serde(rename = "ProductID", default)] pub product_id: Text, #[serde(rename = "Value", default)] pub value: Text }
#[derive(Debug, Default, Deserialize)]
pub struct Vuln {
    #[serde(rename = "CVE", default)] pub cve: Text,
    #[serde(rename = "Title", default)] pub title: Option<Valued>,
    #[serde(rename = "Threats", default)] pub threats: Vec<Threat>,
    #[serde(rename = "Remediations", default)] pub remediations: Vec<Remediation>,
}
#[derive(Debug, Default, Deserialize)]
pub struct Valued { #[serde(rename = "Value", default)] pub value: Text }
#[derive(Debug, Default, Deserialize)]
pub struct Threat {
    #[serde(rename = "Type", default)] pub kind: Option<i64>,
    #[serde(rename = "Description", default)] pub description: Option<Valued>,
    #[serde(rename = "ProductID", default)] pub product_id: Vec<Text>,
}
#[derive(Debug, Default, Deserialize)]
pub struct Remediation {
    #[serde(rename = "Type", default)] pub kind: Option<i64>,
    #[serde(rename = "Description", default)] pub description: Option<Valued>,
    #[serde(rename = "ProductID", default)] pub product_id: Vec<Text>,
    #[serde(rename = "FixedBuild", default)] pub fixed_build: Option<Text>,
}

/// A string Microsoft sometimes writes as a number (ProductID "12390" or 12390), or leaves null.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Text(pub String);
impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Text(match serde_json::Value::deserialize(d)? {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => String::new(),
        }))
    }
}

const THREAT_EXPLOIT: i64 = 1;
const THREAT_SEVERITY: i64 = 3;
const REM_VENDOR_FIX: i64 = 2;

/// One CVRF month into one row per (CVE, Windows product), at the earliest build that fixes it.
pub fn msrc_fixes(doc: &Cvrf) -> Vec<Fix> {
    static WINDOWS: OnceLock<Regex> = OnceLock::new();
    static SERVER: OnceLock<Regex> = OnceLock::new();
    static EXPLOITED: OnceLock<Regex> = OnceLock::new();
    static KB: OnceLock<Regex> = OnceLock::new();
    let windows = re(&WINDOWS, r"(?i)^Windows\b");
    let server = re(&SERVER, r"(?i)\bServer\b");
    let exploited_re = re(&EXPLOITED, r"(?i)(^|;)\s*Exploited:\s*Yes");
    let kb_re = re(&KB, r"(?i)^KB");
    let names: BTreeMap<&str, &str> = doc.product_tree.full_product_name.iter().map(|p| (p.product_id.0.as_str(), p.value.0.as_str())).collect();
    let mut out = Vec::new();
    for v in &doc.vulnerability {
        let cve = v.cve.0.trim();
        if cve.is_empty() { continue; }
        let mut severity: BTreeMap<&str, String> = BTreeMap::new();
        let mut exploited: std::collections::BTreeSet<&str> = Default::default();
        for t in &v.threats {
            let text = t.description.as_ref().map(|d| d.value.0.as_str()).unwrap_or("");
            for id in &t.product_id {
                if t.kind == Some(THREAT_SEVERITY) && !text.is_empty() { severity.insert(id.0.as_str(), text.to_lowercase()); }
                if t.kind == Some(THREAT_EXPLOIT) && exploited_re.is_match(text) { exploited.insert(id.0.as_str()); }
            }
        }
        let mut best: BTreeMap<&str, Fix> = BTreeMap::new();
        for r in &v.remediations {
            if r.kind != Some(REM_VENDOR_FIX) { continue; }
            let fixed = r.fixed_build.as_ref().map(|t| t.0.trim()).unwrap_or("");
            let Some(b) = windows_fixed_build(fixed) else { continue };
            let kb = kb_re.replace(r.description.as_ref().map(|d| d.value.0.trim()).unwrap_or(""), "").to_string();
            for id in &r.product_id {
                let id = id.0.as_str();
                let product = names.get(id).copied().unwrap_or("");
                // Only Windows itself: Skype for Business Server 2015's version (6.0.9319.886) is shaped like a build.
                if !windows.is_match(product) { continue; }
                let rev = b.rev.unwrap_or(0);
                if best.get(id).is_some_and(|prev| prev.fixed_rev <= rev) { continue; }
                best.insert(id, Fix {
                    cve: cve.to_string(), product_id: id.to_string(), product: product.to_string(), server: server.is_match(product), build_major: b.major,
                    fixed_build: fixed.to_string(), fixed_rev: rev, kb: kb.clone(), severity: severity.get(id).cloned(), exploited: exploited.contains(id),
                    title: v.title.as_ref().map(|t| t.value.0.clone()).filter(|s| !s.is_empty()),
                });
            }
        }
        out.extend(best.into_values());
    }
    out
}

/// One device against one CVE's fixes.
#[derive(Debug, Clone, PartialEq)]
pub struct State { pub state: &'static str, pub kb: Option<String>, pub fixed_build: Option<String>, pub exploited: bool, pub severity: Option<String> }

/// One device against one CVE's fixes. `rev` is the device's revision when it came from elsewhere (its installed
/// updates); a revision inside `build` wins over none. No revision is unknown, never patched.
pub fn windows_state(windows: bool, build: Option<&str>, rev: Option<i64>, server: bool, fixes: &[Fix]) -> State {
    let none = |state| State { state, kb: None, fixed_build: None, exploited: false, severity: None };
    if !windows { return none("not_present"); }
    let Some(b) = build.and_then(parse_build) else { return none("unknown") };
    let mine: Vec<&Fix> = fixes.iter().filter(|f| f.build_major == b.major && f.server == server).collect();
    // Products sharing a (build, server) key (x64, ARM64, Server Core) are fixed by the same update; if they ever
    // differ, the latest of them is the conservative threshold.
    let Some(need) = mine.iter().copied().reduce(|a, f| if f.fixed_rev > a.fixed_rev { f } else { a }) else { return none("not_present") };
    let base = |state| State { state, kb: Some(need.kb.clone()), fixed_build: Some(need.fixed_build.clone()), exploited: mine.iter().any(|f| f.exploited), severity: need.severity.clone() };
    match b.rev.or(rev) {
        None => base("unknown"),
        Some(r) => base(if r >= need.fixed_rev { "patched" } else { "vulnerable" }),
    }
}

/// An entry of MSRC's update index.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexEntry {
    #[serde(rename = "ID", default)] pub id: Text,
    #[serde(rename = "InitialReleaseDate", default)] pub initial: Option<String>,
    #[serde(rename = "CurrentReleaseDate", default)] pub current: Option<String>,
}

fn when(s: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = s?.trim();
    chrono::DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&chrono::Utc)).ok()
        .or_else(|| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok().map(|t| t.and_utc()))
}

/// Which months to (re)load: inside the window by first release, and either never loaded or revised by Microsoft
/// since. Newest first, so a run cut short by its budget has the months that matter most.
pub fn months_to_load(index: &[IndexEntry], loaded: &BTreeMap<String, String>, now: chrono::DateTime<chrono::Utc>, months: u32) -> Vec<String> {
    let from = now.checked_sub_months(chrono::Months::new(months)).unwrap_or(now);
    let mut todo: Vec<(chrono::DateTime<chrono::Utc>, String)> = index.iter().filter_map(|e| {
        let id = e.id.0.trim();
        if id.is_empty() { return None; }
        let first = when(e.initial.as_deref())?;
        if first < from { return None; }
        let revised = when(e.current.as_deref());
        let fresh = match loaded.get(id).and_then(|at| when(Some(at))) { None => true, Some(at) => revised.is_some_and(|r| r > at) };
        fresh.then(|| (first, id.to_string()))
    }).collect();
    todo.sort_by_key(|x| std::cmp::Reverse(x.0));
    todo.into_iter().map(|x| x.1).collect()
}

fn strip_kb(k: &str) -> &str { let k = k.trim(); if k.len() >= 2 && k[..2].eq_ignore_ascii_case("kb") { &k[2..] } else { k } }

/// A device's revision from the updates it has installed: the newest cumulative update for its own build.
pub fn device_revision(major: i64, installed_kbs: &[String], kb_builds: &BTreeMap<String, Vec<String>>) -> Option<i64> {
    installed_kbs.iter().flat_map(|raw| kb_builds.get(strip_kb(raw)).into_iter().flatten())
        .filter_map(|fb| windows_fixed_build(fb)).filter(|b| b.major == major).filter_map(|b| b.rev).max()
}

/// A device's Windows patch state, one row of sec_windows_device.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WindowsDevice {
    pub device_id: i64, pub server: bool, pub build_major: Option<i64>, pub rev: Option<i64>, pub rev_source: Option<&'static str>,
    /// vulnerable | patched | unknown | untracked | not_windows
    pub state: &'static str,
    pub needed_kb: Option<String>, pub needed_build: Option<String>, pub latest_kb: Option<String>, pub latest_build: Option<String>,
    pub cve_count: Option<i64>, pub exploited_count: Option<i64>, pub critical_count: Option<i64>,
    pub update_pending_kb: Option<String>, pub update_failed_kb: Option<String>, pub update_failed_at: Option<String>,
}
/// An open Windows CVE on a device, and the update that closes it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WindowsFinding { pub device_id: i64, pub cve: String, pub kb: String, pub fixed_build: String, pub severity: Option<String>, pub exploited: bool, pub title: Option<String> }

/// What a device has from NinjaOne: its OS, build, and the updates it installed, has waiting, and has failed.
#[derive(Debug, Clone, Default)]
pub struct DeviceUpdates { pub device_id: i64, pub os_family: String, pub os_build: String, pub installed_kbs: Vec<String>, pub pending_kbs: Vec<String>, pub failed: Vec<(String, String)> }

/// "Windows Server" or "Windows" from NinjaOne's OS name, anything else as it is.
pub fn os_family(os_name: &str) -> &'static str {
    let n = os_name.to_lowercase();
    if n.contains("windows server") || n.contains("small business server") { "Windows Server" } else if n.contains("windows") { "Windows" } else { "other" }
}

/// One device against every Windows CVE held for its own (build, server) key. States:
///   vulnerable / patched  the device's revision is below / at or above a fix it needs
///   unknown               Windows, but no revision (no build, or no installed update Microsoft's data names)
///   untracked             a build Microsoft's data doesn't cover (Windows 7, a retired release)
///   not_windows
/// update_pending_kb / update_failed_kb: an update that would bring it to the needed build is waiting or has failed in
/// NinjaOne, so the console can say "approved, installs tonight" or "failed on the 20th" beside the CVEs. `failed` is
/// (kb, when) with `when` in the store's time form, so the newest sorts last.
pub fn windows_device(dev: &DeviceUpdates, fixes: &[Fix]) -> (WindowsDevice, Vec<WindowsFinding>) {
    let server = dev.os_family == "Windows Server";
    let mut base = WindowsDevice { device_id: dev.device_id, server, build_major: None, rev: None, rev_source: None, state: "not_windows",
        needed_kb: None, needed_build: None, latest_kb: None, latest_build: None, cve_count: None, exploited_count: None, critical_count: None,
        update_pending_kb: None, update_failed_kb: None, update_failed_at: None };
    if !dev.os_family.starts_with("Windows") { return (base, vec![]); }
    let Some(b) = parse_build(&dev.os_build) else { base.state = "unknown"; return (base, vec![]) };
    let mine: Vec<&Fix> = fixes.iter().filter(|f| f.build_major == b.major && f.server == server).collect();
    base.build_major = Some(b.major);
    if mine.is_empty() { base.state = "untracked"; return (base, vec![]); }
    let mut kb_builds: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in &mine { let l = kb_builds.entry(f.kb.clone()).or_default(); if !l.contains(&f.fixed_build) { l.push(f.fixed_build.clone()); } }
    let latest = mine.iter().copied().reduce(|a, f| if f.fixed_rev > a.fixed_rev { f } else { a }).expect("not empty");
    let from_updates = device_revision(b.major, &dev.installed_kbs, &kb_builds);
    let rev = b.rev.or(from_updates);
    base.rev = rev;
    base.rev_source = if b.rev.is_some() { Some("build") } else if from_updates.is_some() { Some("updates") } else { None };
    base.latest_kb = Some(latest.kb.clone());
    base.latest_build = Some(latest.fixed_build.clone());
    // NinjaOne's pending and failed updates that reach `min_rev` on this device's own build, newest first.
    let ninja = |min_rev: i64| -> (Option<String>, Option<String>, Option<String>) {
        let rev_of = |kb: &str| device_revision(b.major, &[kb.to_string()], &kb_builds).unwrap_or(-1);
        let mut pending: Vec<&str> = dev.pending_kbs.iter().map(|k| strip_kb(k)).filter(|k| rev_of(k) >= min_rev).collect();
        pending.sort_by_key(|k| std::cmp::Reverse(rev_of(k)));
        let mut failed: Vec<(&str, &str)> = dev.failed.iter().map(|(k, at)| (strip_kb(k), at.as_str())).filter(|(k, _)| rev_of(k) >= min_rev).collect();
        failed.sort_by(|x, y| y.1.cmp(x.1));
        (pending.first().map(|s| s.to_string()), failed.first().map(|f| f.0.to_string()), failed.first().map(|f| f.1.to_string()))
    };
    let Some(rev) = rev else {
        // Unknown still says what NinjaOne knows: any fix for its own build waiting or failed.
        let (p, f, fa) = ninja(0);
        return (WindowsDevice { state: "unknown", update_pending_kb: p, update_failed_kb: f, update_failed_at: fa, ..base }, vec![]);
    };
    let mut by_cve: BTreeMap<&str, Vec<Fix>> = BTreeMap::new();
    for f in &mine { by_cve.entry(f.cve.as_str()).or_default().push((*f).clone()); }
    let mut findings = Vec::new();
    let mut need: Option<(String, String, i64)> = None;
    for (cve, list) in &by_cve {
        let s = windows_state(true, Some(&b.major.to_string()), Some(rev), server, list);
        if s.state != "vulnerable" { continue; }
        let (kb, fixed) = (s.kb.clone().unwrap_or_default(), s.fixed_build.clone().unwrap_or_default());
        let r = windows_fixed_build(&fixed).and_then(|x| x.rev).unwrap_or(0);
        if need.as_ref().is_none_or(|n| r > n.2) { need = Some((kb.clone(), fixed.clone(), r)); }
        findings.push(WindowsFinding { device_id: dev.device_id, cve: cve.to_string(), kb, fixed_build: fixed, severity: s.severity, exploited: s.exploited, title: list[0].title.clone() });
    }
    let crit = |f: &WindowsFinding| f.severity.as_deref() == Some("critical");
    findings.sort_by(|a, b| b.exploited.cmp(&a.exploited).then(crit(b).cmp(&crit(a))).then(a.cve.cmp(&b.cve)));
    // Only an update that reaches the needed build counts as the fix waiting or failing.
    let (p, f, fa) = match &need { Some(n) => ninja(n.2), None => (None, None, None) };
    let n = findings.len() as i64;
    let device = WindowsDevice {
        state: if need.is_some() { "vulnerable" } else { "patched" },
        needed_kb: need.as_ref().map(|n| n.0.clone()), needed_build: need.as_ref().map(|n| n.1.clone()),
        cve_count: Some(n), exploited_count: Some(findings.iter().filter(|f| f.exploited).count() as i64), critical_count: Some(findings.iter().filter(|f| crit(f)).count() as i64),
        update_pending_kb: p, update_failed_kb: f, update_failed_at: fa, ..base
    };
    (device, findings)
}

/// A Windows cumulative update (or a 2012 / 2012 R2 monthly rollup) that installed, from one row of NinjaOne's
/// os-patch-installs: (device, KB without its prefix). .NET's cumulative updates are another product; definition
/// updates aren't updates of Windows at all. Previews are kept: they're cumulative, and a KB Microsoft's security data
/// doesn't list is simply never matched.
pub fn os_update_row(p: &serde_json::Value) -> Option<(i64, String, chrono::DateTime<chrono::Utc>)> {
    static OS: OnceLock<Regex> = OnceLock::new();
    static NET: OnceLock<Regex> = OnceLock::new();
    static KB_IN: OnceLock<Regex> = OnceLock::new();
    static KB_OK: OnceLock<Regex> = OnceLock::new();
    let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let device = p.get("deviceId").and_then(|v| v.as_i64()).filter(|d| *d > 0)?;
    if !re(&OS, r"(?i)cumulative update|monthly quality rollup|monthly rollup").is_match(name) || re(&NET, r"(?i)\.NET").is_match(name) { return None; }
    if p.get("status").and_then(|v| v.as_str()).is_some_and(|s| s.eq_ignore_ascii_case("FAILED")) { return None; }
    let at = epoch(p.get("installedAt")).or_else(|| epoch(p.get("timestamp")))?;
    let from_field = p.get("kbNumber").and_then(|v| v.as_str()).map(|k| strip_kb(k).trim().to_string()).filter(|k| !k.is_empty());
    let kb = from_field.or_else(|| re(&KB_IN, r"(?i)\bKB(\d{6,8})\b").captures(name).map(|c| c[1].to_string()))?;
    re(&KB_OK, r"^\d{6,8}$").is_match(&kb).then_some((device, kb, at))
}

/// NinjaOne's epoch seconds (sometimes fractional, sometimes a string), when above zero.
pub fn epoch(v: Option<&serde_json::Value>) -> Option<chrono::DateTime<chrono::Utc>> {
    let v = v?;
    let s = v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<f64>().ok())).filter(|s| *s > 0.0)?;
    chrono::DateTime::from_timestamp(s.trunc() as i64, (s.fract() * 1e9) as u32)
}

/// A KB as NinjaOne writes it ("KB5127648", "5127648", or nothing), without its prefix; None when it isn't one.
pub fn kb_of(v: Option<&serde_json::Value>, name: Option<&str>) -> Option<String> {
    static KB_IN: OnceLock<Regex> = OnceLock::new();
    let k = v.and_then(|v| v.as_str()).map(|k| strip_kb(k).trim().to_string()).filter(|k| k.len() >= 6 && k.chars().all(|c| c.is_ascii_digit()));
    k.or_else(|| name.and_then(|n| re(&KB_IN, r"(?i)\bKB(\d{6,8})\b").captures(n).map(|c| c[1].to_string())))
}
