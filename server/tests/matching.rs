//! The pure parts the evidence rests on, held to their rules: which installed software is which product and
//! version, NVD's affected-version statements, version comparison, website normalisation, keyset pages.
use msp_console::matching::{affects, classify, cmp_version, cvss_of, in_range, norm_version, nvd_all_ranges, split_cpe, Compiled, Range, Rule};
use msp_console::ops::page_by;
use msp_console::website::{apex_of, parse};
use serde_json::json;
use std::cmp::Ordering;

fn rules() -> Vec<Compiled> {
    // The real seed, read back out of its migration: ('key', 'label', 'cpe', '{json}', n). Both stores carry the same
    // text (store.rs checks), so the rules are the same on either.
    let seed = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/sqlite/0002_products.sql")).unwrap();
    let re = regex::Regex::new(r"\('([^']+)', '(?:[^']|'')*', '(?:[^']|'')*', '((?:[^']|'')*)', (\d+)\)").unwrap();
    let mut rows: Vec<(i64, Compiled)> = re.captures_iter(&seed).map(|c| {
        let mut r: Rule = serde_json::from_str(&c[2].replace("''", "'")).unwrap();
        r.product_key = c[1].to_string();
        (c[3].parse().unwrap(), Compiled::new(&r).expect("every seeded rule compiles"))
    }).collect();
    rows.sort_by_key(|r| r.0);
    assert_eq!(rows.len(), 22, "the seed's 22 products");
    rows.into_iter().map(|r| r.1).collect()
}

#[test]
fn installed_software_is_classified_by_the_curated_rules() {
    let r = rules();
    let c = |n: &str, p: &str, v: &str| classify(n, p, v, &r);
    assert_eq!(c("Google Chrome", "Google LLC", "120.0.6099.71"), Some(("chrome".into(), Some("120.0.6099.71".into()))));
    assert_eq!(c("Mozilla Firefox ESR 115.4.0 (x64 en-US)", "Mozilla", "115.4.0").unwrap().0, "firefox_esr", "ESR before plain Firefox");
    assert_eq!(c("Mozilla Firefox (x64 en-US)", "Mozilla", "121.0").unwrap().0, "firefox");
    assert_eq!(c("PuTTY release 0.79 (64-bit)", "Simon Tatham", "0.79.0.0"), Some(("putty".into(), Some("0.79".into()))), "PuTTY's version comes from its name");
    assert_eq!(c("Python 3.11.4 (64-bit)", "Python Software Foundation", "3.11.4150.0").unwrap().0, "python");
    assert_eq!(c("Python 3.11.4 Core Interpreter (64-bit)", "Python Software Foundation", "3.11.4150.0"), None, "a Python component isn't Python");
    assert_eq!(c("Google Chrome Helper", "", "1"), None);
    assert_eq!(c("  ", "", ""), None);
    assert_eq!(c("Notepad++ (64-bit x64)", "Notepad++ Team", "8.5.8"), Some(("notepadpp".into(), Some("8.5.8".into()))));
    assert_eq!(c("7-Zip 23.01 (x64)", "Igor Pavlov", "23.01"), Some(("7zip".into(), Some("23.01".into()))));
    // Kept on purpose: with no version field the name's FIRST number is taken, so "7-Zip 23.01" reads as 7.
    // NinjaOne always sends the version for 7-Zip; a product whose name leads with a number needs a version_re.
    assert_eq!(c("7-Zip 23.01 (x64)", "Igor Pavlov", ""), Some(("7zip".into(), Some("7".into()))));
}

#[test]
fn versions_compare_by_number_segments() {
    assert_eq!(cmp_version("0.85", "0.85.0.0"), Ordering::Equal);
    assert_eq!(cmp_version("24.001.20604", "24.1.20604"), Ordering::Equal);
    assert_eq!(cmp_version("120.0.6099.71", "121"), Ordering::Less);
    assert_eq!(cmp_version("10.0", "9.9.9"), Ordering::Greater);
    assert_eq!(norm_version("26.05 (x64)").as_deref(), Some("26.05"));
    assert_eq!(norm_version("8u504-b01").as_deref(), Some("8"));
    assert_eq!(norm_version("none"), None);
}

#[test]
fn affected_version_statements_hold_at_their_edges() {
    let r = |si: Option<&str>, se: Option<&str>, ei: Option<&str>, ee: Option<&str>| Range { si: si.map(Into::into), se: se.map(Into::into), ei: ei.map(Into::into), ee: ee.map(Into::into), exact: None };
    assert!(in_range("120.0", &r(None, None, None, Some("121.0"))) && !in_range("121.0", &r(None, None, None, Some("121.0"))), "end excluding");
    assert!(in_range("121.0", &r(None, None, Some("121.0"), None)) && !in_range("121.0.1", &r(None, None, Some("121.0"), None)), "end including");
    assert!(in_range("2.0", &r(Some("2.0"), None, None, Some("3"))) && !in_range("1.9", &r(Some("2.0"), None, None, Some("3"))), "start including");
    assert!(!in_range("2.0", &r(None, Some("2.0"), None, Some("3"))), "start excluding");
    assert!(!in_range("5", &Range::default()), "a statement with no bounds says nothing");
    assert!(in_range("1.2.0", &Range { exact: Some("1.2".into()), ..Default::default() }));
    assert!(affects("1.5", &[r(None, None, None, Some("1.0")), r(Some("1.4"), None, Some("1.6"), None)]));
}

#[test]
fn nvd_configurations_become_ranges_per_product() {
    let cve = json!({ "configurations": [{ "nodes": [
        { "cpeMatch": [
            { "vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "121.0.6167.85" },
            { "vulnerable": true, "criteria": "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.5.7:*:*:*:*:*:*:*" },
            { "vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:122.0:beta1:*:*:*:*:*:*" },
            { "vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*" },
            { "vulnerable": true, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" } ],
          "children": [{ "cpeMatch": [{ "vulnerable": true, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionStartIncluding": "7.0", "versionEndIncluding": "7.0.12" }] }] }] }],
        "metrics": { "cvssMetricV31": [{ "type": "Secondary", "cvssData": { "baseScore": 7.0 } }, { "type": "Primary", "cvssData": { "baseScore": 8.8, "baseSeverity": "HIGH" } }] } });
    let m = nvd_all_ranges(&cve);
    assert_eq!(m["google:chrome"], vec![Range { ee: Some("121.0.6167.85".into()), ..Default::default() }], "the beta pin is skipped, the range kept");
    assert_eq!(m["notepad-plus-plus:notepad\\+\\+"], vec![Range { exact: Some("8.5.7".into()), ..Default::default() }], "escapes kept as NVD writes them");
    assert_eq!(m["o:fortinet:fortios"][0].ei.as_deref(), Some("7.0.12"), "children walked; operating systems keyed o:");
    assert!(!m.contains_key("o:microsoft:windows") && !m.contains_key("vendor:product"), "not vulnerable, or saying nothing about versions");
    assert_eq!(cvss_of(&cve), Some(8.8), "NVD's primary score first");
    assert_eq!(split_cpe("cpe:2.3:a:a\\:b:c"), vec!["cpe", "2.3", "a", "a\\:b", "c"]);
}

#[test]
fn websites_from_halo_are_normalised_and_keep_nothing_else() {
    let w = parse(Some("https://admin:Secret1@portal.example.com:8443/login, www.Example.com; N/A"), Some("info@clinic.example 10.1.2.3 example.co.uk"));
    let hosts: Vec<_> = w.iter().map(|x| x.hostname.as_str()).collect();
    assert_eq!(hosts, vec!["portal.example.com", "www.example.com", "example.co.uk"]);
    assert_eq!(w[0].url, "https://portal.example.com/", "credentials, port and path never kept");
    assert_eq!(apex_of("shop.example.co.uk"), "example.co.uk");
    assert!(parse(Some("localhost"), None).is_empty() && parse(Some("foo..com"), None).is_empty());
}

#[test]
fn keyset_pages_hold_still_and_refuse_a_bad_cursor() {
    let items: Vec<_> = (1..=5).map(|i| json!({ "id": format!("CVE-2026-000{i}"), "n": 6 - i })).collect();
    let key = |x: &serde_json::Value| vec![json!(-(x["n"].as_i64().unwrap())), x["id"].clone()];
    let (p1, next) = page_by(items.clone(), key, None, 2).unwrap();
    assert_eq!(p1.iter().map(|x| x["n"].as_i64().unwrap()).collect::<Vec<_>>(), vec![5, 4]);
    let (p2, _) = page_by(items.clone(), key, next.as_deref(), 2).unwrap();
    assert_eq!(p2.iter().map(|x| x["n"].as_i64().unwrap()).collect::<Vec<_>>(), vec![3, 2]);
    assert!(page_by(items.clone(), key, Some("not-a-cursor"), 2).is_err());
    let (all, none) = page_by(items, key, None, 10).unwrap();
    assert_eq!((all.len(), none), (5, None));
}
