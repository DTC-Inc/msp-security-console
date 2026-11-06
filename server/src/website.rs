//! A client's websites, from what someone typed into Halo's Client website and domain fields: each becomes
//! { url, hostname, apex }. The url is rebuilt from the hostname, so whatever else was typed (credentials, a port, a
//! path) is never kept.

use serde::Serialize;

/// Two-part public suffixes a client's site could plausibly sit under (not the whole Public Suffix List: a miss only
/// makes the apex one label too short).
const TWO_PART: &[&str] = &[
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "ac.uk", "gov.uk", "nhs.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz", "co.za", "com.br", "com.mx", "co.jp", "co.in", "co.il", "com.sg", "com.hk", "co.kr", "com.tw", "com.cn",
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Website { pub url: String, pub hostname: String, pub apex: String }

fn has_scheme(s: &str) -> Option<usize> {
    let i = s.find("://")?;
    let scheme = &s[..i];
    (scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))).then_some(i + 3)
}

fn label_ok(l: &str) -> bool {
    !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// One hostname, or None when the text isn't one (an e-mail address, a placeholder, an IP, a single word).
pub fn normalise_host(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_lowercase();
    let scheme_at = has_scheme(&s);
    if s.is_empty() || (s.contains('@') && scheme_at.is_none()) { return None; }
    if let Some(i) = scheme_at { s = s[i..].to_string(); }
    if let Some(at) = s.split(['/', '?', '#', '\\']).next().and_then(|h| h.rfind('@')) { s = s[at + 1..].to_string(); }
    let mut host = s.split(['/', '?', '#', '\\']).next().unwrap_or("").to_string();
    if let Some(c) = host.rfind(':') && host[c + 1..].chars().all(|d| d.is_ascii_digit()) && c + 1 < host.len() { host.truncate(c); }
    let host = host.trim_end_matches('.').to_string();
    if host.is_empty() || host.len() > 253 { return None; }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() == 4 && labels.iter().all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit())) { return None; } // an IP is a WAN, not a site
    let tld = labels.last().copied().unwrap_or("");
    if labels.len() < 2 || !labels.iter().all(|l| label_ok(l)) || !(2..=63).contains(&tld.len()) || !tld.chars().all(|c| c.is_ascii_lowercase()) { return None; }
    Some(host)
}

pub fn apex_of(hostname: &str) -> String {
    let labels: Vec<&str> = hostname.split('.').collect();
    let last2 = labels[labels.len().saturating_sub(2)..].join(".");
    if TWO_PART.contains(&last2.as_str()) && labels.len() >= 3 { labels[labels.len() - 3..].join(".") } else { last2 }
}

/// Every site in Halo's two fields, deduplicated by hostname, website first; placeholders and junk dropped; at most 20.
pub fn parse(website: Option<&str>, domain: Option<&str>) -> Vec<Website> {
    let mut out: Vec<Website> = Vec::new();
    for field in [website, domain].into_iter().flatten() {
        for part in field.split(|c: char| c.is_whitespace() || ",;|".contains(c)).filter(|p| !p.is_empty()) {
            let Some(hostname) = normalise_host(part) else { continue };
            if out.iter().any(|w| w.hostname == hostname) { continue; }
            let scheme = if part.trim().to_lowercase().starts_with("https://") { "https" } else { "http" };
            out.push(Website { url: format!("{scheme}://{hostname}/"), apex: apex_of(&hostname), hostname });
        }
    }
    out.truncate(20);
    out
}
