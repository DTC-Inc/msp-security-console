//! Inventory name → NVD product, automatically, for the whole inventory: every installed program and running
//! binary, not only the curated product list, compared with all of NVD. Pure: no I/O.
//!
//! Precision over recall, because a wrong mapping is a false finding on a client's device. A mapping is made only when
//! the software's CORE name (its name without versions, architecture, locale and parenthetical notes, optionally
//! without the publisher's leading words) is EXACTLY an NVD product's name AND the NVD vendor is the publisher (or is
//! named in the software's name besides the product words). Name-only matches without a vendor were mostly wrong when
//! they were measured (NVIDIA drivers as intel:graphics_driver, Windows Terminal as ak-systems:windows_terminal),
//! so there's no name-only path: those become candidates for a person to review instead. Microsoft Store package
//! names ("Microsoft.VisualStudioCode") are never mapped: the version they report is the package's, not the
//! product's.

use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex { cell.get_or_init(|| Regex::new(pat).expect("a fixed pattern")) }

/// Words that say nothing about which product it is. "setup" and "installer" are NOT here on purpose: "SQL Server
/// 2014 Setup" is the setup bootstrapper, not SQL Server, and must not map to it.
const ARCH_LOCALE: &[&str] = &["x64", "x86", "amd64", "arm64", "arm", "64", "32", "bit", "64bit", "32bit", "win32", "win64",
    "en", "us", "gb", "es", "fr", "de", "enus", "mui", "msi", "exe", "version", "ver", "v"];
const CORP: &[&str] = &["inc", "incorporated", "corp", "corporation", "llc", "ltd", "limited", "co", "company", "gmbh", "ag", "sa", "s", "a",
    "bv", "b", "v", "srl", "pty", "plc", "kg", "oy", "ab", "as", "sas", "the", "lp", "spa", "nv", "kk", "sl"];

/// Words of a name: CamelCase and dotted package names split ("Microsoft.WindowsCalculator" is microsoft windows
/// calculator), "++" kept as "plusplus" so notepad++ isn't notepad.
pub fn words(s: &str) -> Vec<String> {
    static CAMEL: OnceLock<Regex> = OnceLock::new();
    static ACRO: OnceLock<Regex> = OnceLock::new();
    let s = s.replace("++", " plusplus ");
    let s = re(&CAMEL, r"([a-z])([A-Z])").replace_all(&s, "$1 $2");
    let s = re(&ACRO, r"([A-Z]+)([A-Z][a-z])").replace_all(&s, "$1 $2");
    s.to_lowercase().split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())).filter(|w| !w.is_empty()).map(String::from).collect()
}

/// An NVD vendor or product field as words: NVD writes "acrobat_reader_dc", "notepad\+\+", "7-zip".
pub fn cpe_words(field: &str) -> Vec<String> {
    static ESC: OnceLock<Regex> = OnceLock::new();
    words(&re(&ESC, r"\\(.)").replace_all(field, "$1").replace('_', " "))
}

fn versionish(w: &str) -> bool {
    static DOTTED: OnceLock<Regex> = OnceLock::new();
    static YEAR: OnceLock<Regex> = OnceLock::new();
    (w.len() >= 3 && w.chars().all(|c| c.is_ascii_digit())) || re(&DOTTED, r"^v?\d+(\.\d+)+$").is_match(w) || re(&YEAR, r"^(19|20)\d\d$").is_match(w)
}

pub fn publisher_words(p: &str) -> Vec<String> { words(p).into_iter().filter(|w| !CORP.contains(&w.as_str())).collect() }

/// The core name: parentheticals and bracketed notes dropped, versions and architecture/locale words dropped.
pub fn core_words(name: &str) -> Vec<String> {
    static NOTES: OnceLock<Regex> = OnceLock::new();
    static DASH: OnceLock<Regex> = OnceLock::new();
    static VER: OnceLock<Regex> = OnceLock::new();
    let n = re(&NOTES, r"\([^)]*\)|\[[^\]]*\]").replace_all(name, " ");
    let n = re(&DASH, r"\s-\s.*$").replace(&n, " ");
    let raw = n.replace("++", " plusplus ");
    // Dotted versions go before splitting on dots.
    let no_ver = re(&VER, r"(?i)(?-u:\b)v?\d+(?:\.\d+)+(?-u:\b)").replace_all(&raw, " ");
    words(&no_ver).into_iter().filter(|w| !ARCH_LOCALE.contains(&w.as_str()) && !versionish(w)).collect()
}

/// An NVD application: its vendor and product fields, as NVD writes them (escapes kept).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CpeProduct { pub vendor: String, pub product: String }

impl CpeProduct {
    /// "vendor:product" split on its first unescaped colon.
    pub fn parse(cpe: &str) -> Option<Self> {
        let parts = crate::matching::split_cpe(cpe);
        match parts.as_slice() { [v, p] if !v.is_empty() && !p.is_empty() => Some(Self { vendor: v.clone(), product: p.clone() }), _ => None }
    }
    pub fn key(&self) -> String { format!("{}:{}", self.vendor, self.product) }
}

/// The lookup the mapper uses: product words joined by " " → every vendor:product with that name.
pub type Index = HashMap<String, Vec<CpeProduct>>;
pub fn product_index(products: impl IntoIterator<Item = CpeProduct>) -> Index {
    let mut idx: Index = HashMap::new();
    for p in products {
        let k = cpe_words(&p.product).join(" ");
        if k.is_empty() { continue; }
        idx.entry(k).or_default().push(p);
    }
    idx
}

/// Is this NVD vendor the software's publisher? Publisher words (corporate suffixes dropped) against the vendor's:
/// equal, a prefix ("adobe" and "Adobe Systems"), a shared distinctive word ("Sirona Dental" and dentsply_sirona), or
/// the vendor named in the software's own name besides the product words ("Dell Command | Update", vendor dell).
/// `key_words`: the product words just matched. A publisher sharing only those is no evidence (many inventory entries
/// carry their own name as publisher: "Florida Probe PDF Printer" and printer_project:printer).
pub fn vendor_matches(vendor: &str, publisher: &[String], name_rest: &[String], key_words: &[String]) -> bool {
    let v = cpe_words(vendor);
    if v.is_empty() { return false; }
    let (vj, pj) = (v.concat(), publisher.concat());
    if vj.len() >= 3 && !pj.is_empty() && (pj == vj || pj.starts_with(&vj) || vj.starts_with(&pj)) { return true; }
    if v.iter().any(|w| w.len() >= 4 && publisher.contains(w) && !key_words.contains(w)) { return true; }
    if v.iter().all(|w| publisher.contains(w)) { return true; }
    vj.len() >= 3 && v.iter().all(|w| name_rest.contains(w))
}

/// "Microsoft.VisualStudioCode", "Clipchamp.Clipchamp": a Store package identity, not a program name.
pub fn is_store_package(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[A-Za-z0-9]+(\.[A-Za-z0-9]+)+$").is_match(name.trim())
}

/// A candidate NVD product for a name, with whether its vendor is the publisher, and how sure the console is of it
/// (0 to 1): a vendor match on the whole core name is the surest, a name-only match the least.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Candidate { pub vendor: String, pub product: String, pub key: String, pub vendor_match: bool, pub confidence: f64 }

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Search { pub mapping: Option<Candidate>, pub ambiguous: bool, pub candidates: Vec<Candidate> }

/// The confidence of an automatic mapping that the console applies on its own (one vendor-matched product).
pub const AUTO_CONFIDENCE: f64 = 0.9;
/// Below this a candidate is never applied without a person: it waits in the review list.
pub const REVIEW_BELOW: f64 = 0.85;

/// The mapper's search for one (name, publisher): the NVD products whose name matches, key by key, and the mapping it
/// settles on. The first key with a product whose vendor is the publisher decides: one such product is the mapping;
/// two or more is ambiguous (no mapping). Every candidate seen up to that point is kept, so a person can review a name
/// the mapper wouldn't decide.
pub fn cpe_candidates(name: &str, publisher: &str, idx: &Index) -> Search {
    let mut out = Search::default();
    if is_store_package(name) { return out; }
    let core = core_words(name);
    if core.is_empty() { return out; }
    let publisher = publisher_words(publisher);
    // Candidate keys: the whole core name; without leading publisher words ("Mozilla Firefox" is "firefox"); without a
    // trailing "for windows" or "for mac" ("Git for Windows" is "git").
    let mut keys: Vec<(String, bool)> = Vec::new();
    let mut add = |ws: &[String], whole: bool| { let k = ws.join(" "); if !k.is_empty() && !keys.iter().any(|x| x.0 == k) { keys.push((k, whole)); } };
    let mut variants = vec![core.clone()];
    if core.len() > 2 && core[core.len() - 2] == "for" { variants.push(core[..core.len() - 2].to_vec()); }
    for (i, c) in variants.iter().enumerate() {
        add(c, i == 0);
        let mut j = 0;
        while j + 1 < c.len() && publisher.contains(&c[j]) { j += 1; }
        if j > 0 { add(&c[j..], false); }
    }
    for (k, whole) in &keys {
        let Some(cands) = idx.get(k) else { continue };
        if cands.is_empty() { continue; }
        let kw: Vec<String> = k.split(' ').map(String::from).collect();
        let rest: Vec<String> = core.iter().filter(|w| !kw.contains(w)).cloned().collect();
        let by_vendor: Vec<&CpeProduct> = cands.iter().filter(|c| vendor_matches(&c.vendor, &publisher, &rest, &kw)).collect();
        for c in cands {
            let vm = by_vendor.contains(&c);
            // A vendor match is strong, and more so on the whole name; a name alone is weak, and weaker when several
            // vendors share it.
            let confidence = match (vm, *whole) {
                (true, _) if by_vendor.len() == 1 => AUTO_CONFIDENCE,
                (true, _) => 0.6,
                (false, true) => if cands.len() == 1 { 0.4 } else { 0.25 },
                (false, false) => if cands.len() == 1 { 0.3 } else { 0.2 },
            };
            out.candidates.push(Candidate { vendor: c.vendor.clone(), product: c.product.clone(), key: k.clone(), vendor_match: vm, confidence });
        }
        if by_vendor.len() == 1 {
            out.mapping = out.candidates.iter().find(|c| c.vendor_match && c.vendor == by_vendor[0].vendor && c.product == by_vendor[0].product).cloned();
            return out;
        }
        if by_vendor.len() > 1 { out.ambiguous = true; return out; }
    }
    out
}

/// Map one inventory (name, publisher) to an NVD product, or None.
pub fn map_to_cpe(name: &str, publisher: &str, idx: &Index) -> Option<Candidate> { cpe_candidates(name, publisher, idx).mapping }

/// Every major version a product's NVD ranges mention.
pub fn majors_of(ranges: &[crate::matching::Range]) -> Vec<u64> {
    let lead = |v: &Option<String>| v.as_deref().and_then(|s| { let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect(); d.parse().ok() });
    ranges.iter().flat_map(|r| [lead(&r.exact), lead(&r.si), lead(&r.se), lead(&r.ei), lead(&r.ee)]).flatten().collect()
}

/// A product's version scheme against an installed version. NVD's ranges for a product name versions one way (7-Zip
/// 23.01); an inventory entry mapped to it may version itself another way (a Store app's 11.2607.14.0 against ranges
/// written as 2023.x, or the reverse). Matching across schemes makes false findings: "below every fixed version" is
/// true of any small number. So a version whose major is far from every major the product's NVD data mentions is a
/// scheme mismatch, not matched.
pub fn scheme_mismatch(version: &str, majors: &[u64]) -> bool {
    if majors.is_empty() { return false; }
    let d: String = version.chars().take_while(|c| c.is_ascii_digit()).collect();
    let Ok(major) = d.parse::<u64>() else { return true };
    let (min, max) = (*majors.iter().min().unwrap(), *majors.iter().max().unwrap());
    (major < min && min >= 2 * major + 3 && min >= 10) || (major > 3 * max + 10 && max < 100)
}

/// The product key an automatic mapping gets, beside the curated ones: `nvd:vendor:product`.
pub fn auto_key(c: &CpeProduct) -> String { format!("nvd:{}:{}", c.vendor, c.product) }

/// A label for an automatic product from the most-installed name that maps to it, its versions and notes dropped.
pub fn auto_label(name: &str) -> String {
    static NOTES: OnceLock<Regex> = OnceLock::new();
    static VER: OnceLock<Regex> = OnceLock::new();
    let s = re(&NOTES, r"\([^)]*\)").replace_all(name, "");
    let s = re(&VER, r"(?-u:\b)v?\d+(?:\.\d+)+(?-u:\b)").replace_all(&s, "");
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let s = if s.is_empty() { core_words(name).join(" ") } else { s };
    s.chars().take(200).collect()
}
