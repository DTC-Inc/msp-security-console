//! The full NVD dataset: the streaming reader, the rows, which years to read, the automatic name → NVD product
//! mapping, and the feed job end to end on both stores against a made-up feed host. Acceptance criteria: a corrupt or truncated download is refused and the previous data
//! kept; the mapping tests (names that must map, and the ones that must not) pass in Rust; the seed is
//! resumable. (Memory: tests/nvd_memory.rs.)
mod common;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::*;
use msp_console::connectors::nvd_feed::*;
use msp_console::cpe_map::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

both!(the_feeds_load_resumably_refuse_bad_downloads_and_feed_the_automatic_mapping);

fn cve(id: &str, modified: &str, extra: Value) -> Value {
    let mut c = json!({ "id": id, "published": "2026-01-01T09:15:51.113", "lastModified": modified, "vulnStatus": "Analyzed",
        "descriptions": [{ "lang": "en", "value": format!("tricky {{ [ \"quoted\" \\ }} ] text for {id}") }],
        "metrics": { "cvssMetricV31": [{ "type": "Primary", "cvssData": { "baseScore": 8.8, "baseSeverity": "HIGH" } }] } });
    for (k, v) in extra.as_object().unwrap() { c[k] = v.clone(); }
    json!({ "cve": c })
}
fn feed(items: &[Value]) -> String { serde_json::to_string_pretty(&json!({ "resultsPerPage": items.len(), "format": "NVD_CVE", "version": "2.0", "vulnerabilities": items })).unwrap() }
fn hex(b: &[u8]) -> String { Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect() }
fn ids(r: &mut FeedReader) -> Vec<String> {
    let mut out = vec![];
    while let Some(x) = r.take() { out.push(serde_json::from_slice::<Value>(&x).unwrap()["cve"]["id"].as_str().unwrap().to_string()); }
    out
}

// ---------------------------------------------------------------- 1. the reader

#[test]
fn every_chunk_size_yields_the_cves_intact_and_the_hash_covers_every_byte() {
    let doc = feed(&[cve("CVE-2026-0001", "2026-06-17T10:10:55.270", json!({})), cve("CVE-2026-0002", "2026-06-17T10:10:55.270", json!({})), cve("CVE-2026-0003", "2026-06-17T10:10:55.270", json!({}))]) + "\n";
    let want = hex(doc.as_bytes());
    for size in [1, 2, 3, 7, 17, 64, 1000, doc.len()] {
        let mut r = FeedReader::new();
        let mut got = vec![];
        for c in doc.as_bytes().chunks(size) { r.feed(c); got.extend(ids(&mut r)); }
        assert_eq!(got, ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"], "chunk size {size}");
        assert!(r.complete() && r.sha256() == want && r.bytes == doc.len() as u64, "chunk size {size}: read to the end, the trailing newline too");
    }
    let mut r = FeedReader::new();
    r.feed(feed(&[cve("CVE-2026-0001", "2026-06-17T10:10:55.270", json!({}))]).as_bytes());
    let item: Value = serde_json::from_slice(&r.take().unwrap()).unwrap();
    assert!(item["cve"]["descriptions"][0]["value"].as_str().unwrap().contains("{ [ \"quoted\" \\ } ]"), "braces and brackets in strings don't count");
    let mut cut = FeedReader::new();
    cut.feed(&doc.as_bytes()[..doc.len() / 2]);
    assert!(!cut.complete(), "a stream cut short never says it ended");
}

// ---------------------------------------------------------------- 2. rows

#[test]
fn rows_carry_every_vulnerable_product_and_rejected_ones_carry_none() {
    let conf = json!({ "configurations": [{ "nodes": [{ "operator": "OR", "cpeMatch": [
        { "vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "156.0.8087.47" },
        { "vulnerable": true, "criteria": "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6:*:*:*:*:*:*:*" },
        { "vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:157.0:beta1:*:*:*:*:*:*" },
        { "vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*" },
        { "vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*" },
        { "vulnerable": true, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "versionStartIncluding": "7.2.0", "versionEndExcluding": "7.2.5" }],
        "children": [{ "cpeMatch": [{ "vulnerable": true, "criteria": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*", "versionStartIncluding": "100", "versionEndIncluding": "120.1" }] }] }] }] });
    let (c, p) = rows_for(&cve("CVE-2026-0042", "2026-06-17T10:10:55.270", conf.clone())).unwrap();
    let by: BTreeMap<&str, &Value> = p.iter().map(|x| (x["cpe"].as_str().unwrap(), &x["ranges"])).collect();
    assert_eq!(by.keys().copied().collect::<Vec<_>>(), ["google:chrome", "mozilla:firefox", "notepad-plus-plus:notepad\\+\\+", "o:fortinet:fortios"]);
    assert_eq!(by["google:chrome"], &json!([{ "ee": "156.0.8087.47" }]), "the beta pin and the bare '*' skipped");
    assert_eq!(p.iter().find(|x| x["cpe"] == "o:fortinet:fortios").unwrap()["part"], "o");
    assert_eq!((c["cvss"].as_f64(), c["year"].as_i64(), c["last_modified"].as_str()), (Some(8.8), Some(2026), Some("2026-06-17T10:10:55.270Z")), "NVD's zone-less times are UTC");
    let mut rej = conf;
    rej["vulnStatus"] = json!("Rejected");
    let (c, p) = rows_for(&cve("CVE-2026-0099", "2026-06-17T10:10:55.270", rej)).unwrap();
    assert!(c["rejected"] == json!(true) && p.is_empty());
    assert!(rows_for(&json!({ "cve": { "id": "GHSA-xxxx" } })).is_none() && rows_for(&Value::Null).is_none());
    let m = parse_meta("lastModifiedDate:2026-10-22T03:00:22-04:00\r\nsize:473185036\r\nzipSize:38618164\r\ngzSize:38618028\r\nsha256:F3E5D26F59225478B60B11B718F582E5D893A605DE23EB7C956B4CED086E5767\r\n");
    assert_eq!((m.last_modified.as_deref(), m.gz_size, m.sha256.as_deref()), (Some("2026-10-22T03:00:22-04:00"), Some(38618028), Some("f3e5d26f59225478b60b11b718f582e5d893a605de23eb7c956b4ced086e5767")));
}

// ---------------------------------------------------------------- 3. which years

#[test]
fn never_loaded_years_first_a_gap_reads_everything_and_weekly_refreshes() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-22T05:00:00Z").unwrap().to_utc();
    let day = chrono::Duration::days(1);
    let all: Vec<i32> = (FIRST_YEAR..=2026).collect();
    assert_eq!(years_to_load(now, &BTreeMap::new(), None, false), all);
    let fresh: BTreeMap<String, _> = all.iter().map(|y| (y.to_string(), now - day)).collect();
    assert!(years_to_load(now, &fresh, Some(now - day), false).is_empty());
    let mut partial = fresh.clone();
    partial.remove("2019"); partial.remove("2025");
    assert_eq!(years_to_load(now, &partial, Some(now - day), false), [2019, 2025], "a seed cut short continues with the missing years");
    assert_eq!(years_to_load(now, &fresh, Some(now - day * 8), false).len(), all.len(), "a gap in the modified chain re-reads every year");
    let mut old = fresh.clone();
    old.insert("2010".into(), now - day * 9);
    assert_eq!(years_to_load(now, &old, Some(now - day), false), [2010]);
    assert_eq!(years_to_load(now, &fresh, Some(now - day), true).len(), all.len());
}

// ---------------------------------------------------------------- 4. the automatic mapping

#[test]
fn the_real_programs_map_and_the_look_alikes_dont() {
    let idx = product_index(["google:chrome", "mozilla:firefox", "mozilla:firefox_esr", "mozilla:bleach", "videolan:vlc_media_player", "microsoft:asp.net_core", "microsoft:sql_server",
        "microsoft:visual_studio_code", "microsoft:outlook", "dell:command_update", "dell:command\\|configure", "artifex:gpl_ghostscript", "veeam:veeam_backup_\\&_replication",
        "patterson_dental:eaglesoft", "dentsply_sirona:cdr_dicom", "intel:graphics_driver", "ak-systems:windows_terminal", "sayakbanerjee:sticky_notes", "apple:remote_desktop",
        "progress:progress", "printer_project:printer", "nokia:series", "vmware:workstation", "git:git", "zoom:zoom", "notepad-plus-plus:notepad\\+\\+", "devsaran:business",
        "cisco:webex", "apache:http_server", "novell:apache_http_server", "microsoft:.net_framework"].iter().filter_map(|c| CpeProduct::parse(c)));
    let map = |n: &str, p: &str| map_to_cpe(n, p, &idx).map(|m| format!("{}:{}", m.vendor, m.product));
    let must = [("Google Chrome", "Google LLC", "google:chrome"), ("Mozilla Firefox (x64 en-US)", "Mozilla", "mozilla:firefox"), ("Mozilla Firefox ESR (x64 en-US)", "Mozilla", "mozilla:firefox_esr"),
        ("Mozilla Firefox 84.0.2 (x64 en-US)", "Mozilla", "mozilla:firefox"), ("VLC media player", "VideoLAN", "videolan:vlc_media_player"),
        ("Microsoft ASP.NET Core 8.0.32 - Shared Framework (x64)", "Microsoft Corporation", "microsoft:asp.net_core"),
        ("Microsoft SQL Server 2016 (64-bit) (VEEAMSQL2016)", "Microsoft Corporation", "microsoft:sql_server"), ("Microsoft Visual Studio Code", "Microsoft Corporation", "microsoft:visual_studio_code"),
        ("Dell Command | Update", "Dell Inc.", "dell:command_update"), ("Dell Command | Configure", "Dell Inc.", "dell:command\\|configure"), ("GPL Ghostscript", "Artifex Software Inc.", "artifex:gpl_ghostscript"),
        ("Veeam Backup & Replication", "Veeam Software Group GmbH", "veeam:veeam_backup_\\&_replication"), ("Patterson Eaglesoft", "Patterson Eaglesoft", "patterson_dental:eaglesoft"),
        ("CDR DICOM for Windows", "Sirona Dental, Inc.", "dentsply_sirona:cdr_dicom"), ("Git", "The Git Development Community", "git:git"), ("Zoom", "Zoom", "zoom:zoom"),
        ("Notepad++ (64-bit x64)", "Notepad++ Team", "notepad-plus-plus:notepad\\+\\+"), ("Webex", "Cisco Systems, Inc", "cisco:webex"),
        ("Apache HTTP Server 2.2.15", "Apache Software Foundation", "apache:http_server"), ("Microsoft .NET Framework 1.1", "Microsoft", "microsoft:.net_framework")];
    let wrong: Vec<_> = must.iter().filter(|(n, p, w)| map(n, p).as_deref() != Some(*w)).map(|(n, _, w)| (n, w, map(n, "x"))).collect();
    assert!(wrong.is_empty(), "these must map: {wrong:?}");
    let must_not = [("NVIDIA Graphics Driver 560.94", "NVIDIA Corporation"), ("Microsoft.WindowsTerminal", "Microsoft Corporation"), ("Microsoft.MicrosoftStickyNotes", "Microsoft Corporation"),
        ("Microsoft.RemoteDesktop", "Microsoft Corporation"), ("BleachBit", "BleachBit"), ("Installer Progress", "Apple"), ("Florida Probe PDF Printer", "Florida Probe PDF Printer"),
        ("HP LaserJet Professional P1100-P1560-P1600 Series", "HP LaserJet Professional P1100-P1560-P1600 Series"),
        ("CS PracticeWorks Practice Management Software Workstation", "CS PracticeWorks Practice Management Software Workstation"), ("Splashtop Business", "Splashtop Inc."),
        ("Microsoft.VisualStudioCode", "Microsoft Corporation"), ("Microsoft.OutlookForWindows", "Microsoft Corporation"), ("Microsoft SQL Server 2014 Setup (English)", "Microsoft Corporation")];
    let wrongly: Vec<_> = must_not.iter().filter_map(|(n, p)| map(n, p).map(|m| (n, m))).collect();
    assert!(wrongly.is_empty(), "these must not map (a looser mapper got them wrong): {wrongly:?}");
    assert!(is_store_package("Microsoft.WindowsCalculator") && is_store_package("Clipchamp.Clipchamp") && !is_store_package("Microsoft Edge") && !is_store_package("Node.js 20"));
    assert_eq!(core_words("Mozilla Firefox 84.0.2 (x64 en-US)").join(" "), "mozilla firefox");
    assert!(core_words("Microsoft SQL Server 2014 Setup (English)").contains(&"setup".to_string()));
    assert_eq!(core_words("7-Zip 23.01 (x64 edition)").join(" "), "7 zip");
    assert_eq!((cpe_words("acrobat_reader_dc").join(" "), cpe_words("notepad\\+\\+").join(" ")), ("acrobat reader dc".into(), "notepad plusplus".into()));
    // A name the mapping won't decide keeps its candidates, unsure, for a person: Bleach's only NVD product isn't BleachBit's.
    let s = cpe_candidates("Webex Meetings", "Someone Else", &product_index([CpeProduct::parse("cisco:webex_meetings").unwrap(), CpeProduct::parse("other:webex_meetings").unwrap()]));
    assert!(s.mapping.is_none() && s.candidates.len() == 2 && s.candidates.iter().all(|c| c.confidence < REVIEW_BELOW), "{s:?}");
}

#[test]
fn versions_numbered_another_way_are_not_compared() {
    use msp_console::matching::Range;
    let r = |ee: &str| Range { ee: Some(ee.into()), ..Default::default() };
    let chrome = majors_of(&[r("156.0.8087.47"), Range { si: Some("100".into()), ei: Some("120.1".into()), ..Default::default() }]);
    let mut sorted = chrome.clone(); sorted.sort();
    assert_eq!(sorted, [100, 120, 156]);
    assert!(!scheme_mismatch("80.0.3987.149", &chrome) && !scheme_mismatch("156.0.8078.48", &chrome));
    assert!(scheme_mismatch("11.2607.14.0", &[2016, 2019, 2023]), "a small installed number against calendar versions");
    assert!(scheme_mismatch("2607.1.0", &[1, 3, 5]));
    assert!(!scheme_mismatch("9.20", &[9, 16, 23]) && !scheme_mismatch("1.2", &[]) && scheme_mismatch("abc", &[1]));
}

// ---------------------------------------------------------------- 5. the job end to end

/// How the made-up host answers each file: its JSON, and what goes wrong with it.
#[derive(Clone, Default)]
struct File { json: String, cut_at: Option<usize>, cut_times: usize, refuse_range: bool, wrong_sha: bool }
type Host = Arc<Mutex<(HashMap<String, File>, Vec<String>)>>;
fn gz(s: &str) -> Vec<u8> { let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()); e.write_all(s.as_bytes()).unwrap(); e.finish().unwrap() }

async fn host() -> (String, Host) {
    let h: Host = Default::default();
    let r = Router::new().route("/feeds/{file}", get(|State(h): State<Host>, Path(file): Path<String>, hd: HeaderMap| async move {
        let mut g = h.lock().unwrap();
        g.1.push(format!("{file} {}", hd.get("range").and_then(|v| v.to_str().ok()).unwrap_or("")));
        let (name, ext) = file.strip_prefix("nvdcve-2.0-").and_then(|f| f.split_once('.')).unwrap_or(("", ""));
        // Any year not set up is a feed with one CVE of that year, so a whole seed can run.
        let f = g.0.entry(name.to_string()).or_insert_with(|| File { json: feed(&[cve(&format!("CVE-{name}-1000"), "2026-01-01T00:00:00.000", json!({}))]), ..Default::default() }).clone();
        let body = gz(&f.json);
        match ext {
            "meta" => {
                let sha = if f.wrong_sha { "AB".repeat(32) } else { hex(f.json.as_bytes()).to_uppercase() };
                format!("lastModifiedDate:2026-10-22T03:00:22-04:00\r\nsize:{}\r\ngzSize:{}\r\nsha256:{sha}\r\n", f.json.len(), body.len()).into_response()
            }
            _ => match hd.get("range").and_then(|v| v.to_str().ok()).and_then(|r| r.strip_prefix("bytes=")).and_then(|r| r.trim_end_matches('-').parse::<usize>().ok()) {
                Some(_) if f.refuse_range => (StatusCode::OK, body).into_response(),
                Some(from) => (StatusCode::PARTIAL_CONTENT, body[from..].to_vec()).into_response(),
                None => match f.cut_at {
                    Some(at) if f.cut_times > 0 => { g.0.get_mut(name).unwrap().cut_times -= 1; (StatusCode::OK, body[..at.min(body.len())].to_vec()).into_response() }
                    _ => (StatusCode::OK, body).into_response(),
                },
            },
        }
    })).with_state(h.clone());
    (serve(r).await, h)
}
fn set(h: &Host, name: &str, f: File) { h.lock().unwrap().0.insert(name.into(), f); }
fn year(n: usize, from: usize, modified: &str) -> String { feed(&(0..n).map(|i| cve(&format!("CVE-2026-{}", 10000 + from + i), modified, json!({ "configurations": [{ "nodes": [{ "cpeMatch": [
    { "vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "versionEndExcluding": "3.0" }] }] }] }))).collect::<Vec<_>>()) }

async fn the_feeds_load_resumably_refuse_bad_downloads_and_feed_the_automatic_mapping(db: TestDb) {
    let (base, h) = host().await;
    let url = format!("{base}/feeds");
    set(&h, "2026", File { json: year(150, 0, "2026-06-01T00:00:00.000"), ..Default::default() });
    let mut f = NvdFeed::new(&url, msp_console::http_client());
    // A seed spread over runs, as a restart would: the first run (a budget too small for more) reads one year and the
    // modified feed; a new connector, as after a restart, carries on with the next year from what's stored.
    f.budget = Duration::ZERO;
    let o = f.sync(&db.pool).await.unwrap();
    let total = (2026 - FIRST_YEAR + 1) as i64;
    assert_eq!((o.detail["years_loaded_now"].as_i64(), o.detail["deferred"].as_i64(), o.detail["years_loaded"].as_i64()), (Some(1), Some(total - 1), Some(1)), "{}", o.detail);
    assert!(!o.detail["modified"].is_null(), "the modified feed is applied after a year loads");
    let mut f2 = NvdFeed::new(&url, msp_console::http_client());
    f2.budget = Duration::ZERO;
    assert_eq!(f2.sync(&db.pool).await.unwrap().detail["years_loaded"].as_i64(), Some(2), "the next run reads the next year, not the first again");
    f2.budget = BUDGET;
    let o = f2.sync(&db.pool).await.unwrap();
    assert_eq!((o.detail["years_loaded"].as_i64(), o.detail["deferred"].as_i64()), (Some(total), Some(0)), "{}", o.detail);
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_nvd_cve WHERE cve_id LIKE 'CVE-2026-1%'").await, 150, "2026's 150");
    let o = f2.sync(&db.pool).await.unwrap();
    assert_eq!((o.detail["years_loaded_now"].as_i64(), o.detail["modified"].clone()), (Some(0), Value::Null), "nothing due: nothing downloaded");
    let fetched = |h: &Host, n: &str| h.lock().unwrap().1.iter().filter(|x| x.starts_with(&format!("nvdcve-2.0-{n}.json.gz"))).count();
    assert_eq!(fetched(&h, "2002"), 1);

    // Bad downloads are refused and what's stored stays: a wrong hash, a host that won't resume, a truncated body.
    let before = count(&db.pool, "SELECT count(*) FROM sec_nvd_cpe").await;
    set(&h, "2026", File { json: year(150, 500, "2026-07-01T00:00:00.000"), wrong_sha: true, ..Default::default() });
    let e = f2.load(&db.pool, "2026", Some(2026)).await.unwrap_err();
    assert!(e.contains("SHA-256"), "{e}");
    set(&h, "2026", File { json: year(150, 500, "2026-07-01T00:00:00.000"), cut_at: Some(200), cut_times: 1, refuse_range: true, ..Default::default() });
    let e = f2.load(&db.pool, "2026", Some(2026)).await.unwrap_err();
    assert!(e.contains("HTTP 200"), "a host that won't resume: {e}");
    assert_eq!((count(&db.pool, "SELECT count(*) FROM sec_nvd_cve WHERE cve_id >= 'CVE-2026-10500'").await, count(&db.pool, "SELECT count(*) FROM sec_nvd_cpe").await), (0, before),
               "nothing of a refused feed was kept");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM nvd_stage_cve").await, 0, "and the staging is empty again");
    // A download cut short that resumes is whole.
    set(&h, "2026", File { json: year(150, 0, "2026-07-01T00:00:00.000"), cut_at: Some(300), cut_times: 1, ..Default::default() });
    let n = f2.load(&db.pool, "2026", Some(2026)).await.unwrap();
    assert_eq!((n.resumes, n.cves), (1, 150));
    // The guard: a year whose count falls below half of what's stored is refused.
    set(&h, "2026", File { json: year(10, 0, "2026-08-01T00:00:00.000"), ..Default::default() });
    let e = f2.load(&db.pool, "2026", Some(2026)).await.unwrap_err();
    assert!(e.contains("kept what's stored"), "{e}");
    // A CVE the file no longer lists goes, unless it's newer than the file; a stored copy newer than the file's stays.
    exec(&db.pool, "UPDATE sec_nvd_cve SET last_modified = '2026-12-01T00:00:00.000Z' WHERE cve_id IN ('CVE-2026-10149', 'CVE-2026-10000')").await;
    set(&h, "2026", File { json: year(140, 0, "2026-09-01T00:00:00.000"), ..Default::default() });
    let n = f2.load(&db.pool, "2026", Some(2026)).await.unwrap();
    assert_eq!((n.removed, n.kept_newer), (9, 1), "CVE-2026-10140..10148 gone; 10149 is newer than the file, so kept; 10000's newer copy kept");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_nvd_cve WHERE cve_id = 'CVE-2026-10149'").await, 1);

    // The automatic mapping: an installed program NVD knows, by its publisher, compared with all of NVD.
    for q in ["INSERT INTO client (org_id, name, name_key) VALUES (7, 'Alpha Dental', 'alpha dental')",
              "INSERT INTO device (device_id, org_id, name, device_class) VALUES (701, 7, 'DESIGN-1', 'desktop')",
              "INSERT INTO software (device_id, org_id, name, publisher, version) VALUES (701, 7, 'Acme Widget 2.1', 'Acme Inc.', '2.1.0'), (701, 7, 'Widget Helper', 'Nobody', '1.0')"] {
        exec(&db.pool, q).await;
    }
    let o = msp_console::inventory::run(&db.pool).await.unwrap();
    assert_eq!((o.detail["automatic_products"].as_i64(), o.detail["recognised"].as_i64()), (Some(1), Some(1)), "{}", o.detail);
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_software_class WHERE product_key = 'nvd:acme:widget' AND method = 'auto' AND confidence > 0.85").await, 1);
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_pair_cve WHERE product_key = 'nvd:acme:widget' AND version = '2.1.0'").await, 141, "every CVE of the widget before 3.0 that's stored");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_product WHERE product_key = 'nvd:acme:widget' AND source = 'auto'").await, 1);
}
