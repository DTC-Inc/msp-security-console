//! Windows itself: Microsoft's monthly updates against each Windows device's updates. The pure rules (the
//! CVRF document's shape is the real 2026-Oct one's; every id here is made up), then the jobs end to end on both stores against made-up MSRC and NinjaOne stand-ins, and the
//! windows.* ops. The acceptance criterion: a device whose patch level can't be read is never counted as patched.
mod common;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::*;
use msp_console::connectors::msrc::{match_windows, Msrc};
use msp_console::connectors::ninja::Ninja;
use msp_console::connectors::ninja_os::NinjaOs;
use msp_console::contract::EvidenceRequest;
use msp_console::ops::Store;
use msp_console::windows::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

both!(the_jobs_match_every_windows_device_and_the_ops_open_each_count);

// ---------------------------------------------------------------- 1. build strings

#[test]
fn builds_are_read_as_ninjaone_and_microsoft_write_them() {
    assert_eq!(parse_build("22631"), Some(Build { major: 22631, rev: None }), "NinjaOne's bare build: no revision");
    assert_eq!(parse_build("10.0.26100.9711"), Some(Build { major: 26100, rev: Some(9711) }));
    assert_eq!(parse_build("26100.2033"), Some(Build { major: 26100, rev: Some(2033) }));
    assert_eq!(parse_build("10.0.22631"), Some(Build { major: 22631, rev: None }));
    assert_eq!(parse_build("6.3.9600.23470"), Some(Build { major: 9600, rev: Some(23470) }), "Server 2012 R2");
    assert!(parse_build("").is_none() && parse_build("unknown").is_none());
    assert!(windows_fixed_build("23.11.8-1").is_none() && windows_fixed_build("156.0.4314.42").is_none(), "not Windows builds");
    assert_eq!(windows_fixed_build("10.0.20348.5761"), Some(Build { major: 20348, rev: Some(5761) }));
}

// ---------------------------------------------------------------- 2. msrc_fixes

fn rem(kb: &str, fixed: &str, ids: &[&str]) -> Value {
    json!({ "Description": { "Value": kb }, "ProductID": ids, "Type": 2, "SubType": "Security Update", "FixedBuild": fixed })
}
pub fn october() -> Value {
    json!({
        "DocumentTracking": { "Identification": { "ID": { "Value": "2026-Oct" } } },
        "ProductTree": { "FullProductName": [
            { "ProductID": "12390", "Value": "Windows 11 Version 24H2 for x64-based Systems" },
            { "ProductID": "12389", "Value": "Windows 11 Version 24H2 for ARM64-based Systems" },
            { "ProductID": "12436", "Value": "Windows Server 2025" },
            { "ProductID": "12437", "Value": "Windows Server 2025 (Server Core installation)" },
            { "ProductID": "12243", "Value": "Windows 11 Version 23H2 for x64-based Systems" },
            { "ProductID": "17527-17084", "Value": "azl3 dpdk 23.11.3-1 on Azure Linux 3.0" },
            { "ProductID": 11722, "Value": "Skype for Business Server 2015 CU13" } ] },
        "Vulnerability": [
            { "CVE": "CVE-2026-100200", "Title": { "Value": "Windows Update Service Elevation of Privilege Vulnerability" },
              "Notes": [{ "Value": "a long text the console never reads" }],
              "Threats": [
                { "Type": 0, "Description": { "Value": "Elevation of Privilege" }, "ProductID": ["12390"] },
                { "Type": 1, "Description": { "Value": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected" }, "ProductID": ["12390", "12389"] },
                { "Type": 3, "Description": { "Value": "Important" }, "ProductID": ["12390", "12389", "12243"] },
                { "Type": 3, "Description": { "Value": "Critical" }, "ProductID": ["12436", "12437"] } ],
              "Remediations": [
                rem("5127648", "10.0.26100.9711", &["12390", "12389"]),
                rem("5124008", "10.0.26100.9445", &["12390", "12389"]),
                rem("5126646", "10.0.26100.33650", &["12436", "12437"]),
                rem("5126653", "10.0.22631.7652", &["12243"]),
                { "Description": { "Value": "5127648" }, "ProductID": ["12390"], "Type": 3, "SubType": "Release Notes" },
                { "Description": { "Value": "Install the update" }, "ProductID": ["12390"], "Type": 6 },
                rem("Release Notes", "", &["12390"]) ] },
            { "CVE": "CVE-2026-100236", "Title": { "Value": "Dpdk: heap out-of-bounds read/write" },
              "Threats": [{ "Type": 3, "Description": { "Value": "Important" }, "ProductID": ["17527-17084"] }],
              "Remediations": [rem("Release Notes", "23.11.8-1", &["17527-17084"])] },
            { "CVE": "CVE-2026-100300", "Title": { "Value": "Skype for Business Server Spoofing Vulnerability" },
              "Threats": [{ "Type": 3, "Description": { "Value": "Important" }, "ProductID": ["11722"] }],
              "Remediations": [rem("5132779", "6.0.9319.886", &["11722"])] } ] })
}
fn fixes() -> Vec<Fix> { msrc_fixes(&serde_json::from_value(october()).unwrap()) }

#[test]
fn one_row_per_cve_and_windows_product_at_the_earliest_fix() {
    let fx = fixes();
    let f = |cve: &str, pid: &str| fx.iter().find(|r| r.cve == cve && r.product_id == pid).cloned().unwrap();
    assert!(fx.iter().all(|r| r.cve == "CVE-2026-100200"), "Windows rows only: Azure Linux and Skype for Business Server dropped");
    assert_eq!(fx.len(), 5);
    let a = f("CVE-2026-100200", "12390");
    assert_eq!((a.fixed_build.as_str(), a.kb.as_str()), ("10.0.26100.9445", "5124008"), "the first fix, not the later rollup");
    let s = f("CVE-2026-100200", "12436");
    assert_eq!((s.build_major, s.fixed_rev, s.server), (26100, 33650, true));
    assert!(f("CVE-2026-100200", "12437").server && !a.server, "Server Core is a server");
    assert_eq!(f("CVE-2026-100200", "12243").product, "Windows 11 Version 23H2 for x64-based Systems");
    assert_eq!((s.severity.as_deref(), a.severity.as_deref()), (Some("critical"), Some("important")));
    assert!(a.exploited && !s.exploited, "exploited per product");
    assert_eq!(a.title.as_deref(), Some("Windows Update Service Elevation of Privilege Vulnerability"));
    assert!(msrc_fixes(&Cvrf::default()).is_empty());
    assert!(msrc_fixes(&serde_json::from_value(json!({ "Vulnerability": [{ "CVE": "x" }] })).unwrap()).is_empty());
}

// ---------------------------------------------------------------- 3. windows_state

#[test]
fn server_ness_is_part_of_the_key_and_no_revision_is_never_patched() {
    let fx: Vec<Fix> = fixes().into_iter().filter(|r| r.cve == "CVE-2026-100200").collect();
    let ws = |build: Option<&str>, rev: Option<i64>, server: bool| windows_state(true, build, rev, server, &fx);
    assert_eq!(ws(Some("26100"), Some(9445), false).state, "patched");
    assert_eq!(ws(Some("10.0.26100.9711"), None, false).state, "patched");
    let behind = ws(Some("26100"), Some(8875), false);
    assert_eq!((behind.state, behind.kb.as_deref(), behind.fixed_build.as_deref()), ("vulnerable", Some("5124008"), Some("10.0.26100.9445")));
    let srv = ws(Some("26100"), Some(9711), true);
    assert_eq!((srv.state, srv.kb.as_deref()), ("vulnerable", Some("5126646")), "Server 2025 at the client's revision is still vulnerable");
    assert_eq!(ws(Some("26100"), Some(33650), true).state, "patched");
    assert_eq!(ws(Some("10.0.26100.33650"), None, true).state, "patched", "a revision in the build string wins over none");
    assert_eq!(ws(Some("22631"), None, false).state, "unknown", "no revision: unknown, never patched");
    assert_eq!(ws(Some("19045"), Some(7807), false).state, "not_present");
    assert_eq!(windows_state(false, Some("15.1"), None, false, &fx).state, "not_present");
    assert_eq!(ws(None, None, false).state, "unknown");
    assert!(behind.exploited && !srv.exploited);
}

// ---------------------------------------------------------------- 4. months_to_load

#[test]
fn months_are_ordered_by_date_and_read_again_only_when_revised() {
    let e = |id: &str, init: &str, cur: &str| -> IndexEntry { serde_json::from_value(json!({ "ID": id, "InitialReleaseDate": init, "CurrentReleaseDate": cur })).unwrap() };
    let idx = vec![e("2026-May", "2026-05-12T07:00:00Z", "2026-10-24T14:47:55Z"), e("2026-Oct", "2026-10-13T07:00:00Z", "2026-10-26T01:48:59Z"),
                   e("2026-Sep", "2026-09-08T07:00:00Z", "2026-10-25T01:47:42Z"), e("2023-Jan", "2023-01-10T08:00:00Z", "2023-02-01T08:00:00Z")];
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-26T12:00:00Z").unwrap().to_utc();
    assert_eq!(months_to_load(&idx, &BTreeMap::new(), now, 24), ["2026-Oct", "2026-Sep", "2026-May"], "newest first, by date, not by name");
    let loaded: BTreeMap<String, String> = [("2026-Oct", "2026-10-26T01:48:59Z"), ("2026-Sep", "2026-10-24T00:00:00Z"), ("2026-May", "2026-10-24T14:47:55Z")]
        .into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    assert_eq!(months_to_load(&idx, &loaded, now, 24), ["2026-Sep"], "only the month Microsoft revised since");
    assert!(months_to_load(&idx, &BTreeMap::new(), now, 48).contains(&"2023-Jan".to_string()));
}

// ---------------------------------------------------------------- 5. device_revision, and 6. which installs count

#[test]
fn a_devices_revision_comes_from_its_newest_cumulative_update() {
    let kb: BTreeMap<String, Vec<String>> = [("5126653", vec!["10.0.22631.7652"]), ("5099414", vec!["10.0.22631.7376"]), ("5127648", vec!["10.0.26100.9711", "10.0.26200.9711"])]
        .into_iter().map(|(k, v)| (k.to_string(), v.into_iter().map(String::from).collect())).collect();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(device_revision(22631, &s(&["5099414", "5126653"]), &kb), Some(7652));
    assert_eq!(device_revision(26200, &s(&["5127648"]), &kb), Some(9711), "one KB that spans builds gives the device's own");
    assert_eq!(device_revision(19045, &s(&["5126653"]), &kb), None);
    assert_eq!(device_revision(22631, &s(&["KB5126653"]), &kb), Some(7652));
}

#[test]
fn only_windows_cumulative_updates_that_installed_set_a_revision() {
    let at = 1_760_000_000;
    let inst = |name: &str, extra: Value| { let mut p = json!({ "id": "p1", "deviceId": 4242, "name": name, "kbNumber": null, "status": "INSTALLED", "installedAt": at }); for (k, v) in extra.as_object().unwrap() { p[k] = v.clone(); } p };
    let cu = os_update_row(&inst("2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5127648) (26100.9711)", json!({ "kbNumber": "KB5127648" }))).unwrap();
    assert_eq!((cu.0, cu.1.as_str(), cu.2.timestamp()), (4242, "5127648", at));
    assert_eq!(os_update_row(&inst("2026-10 Cumulative Update for Windows Server 2022 for x64-based Systems (KB5126655)", json!({}))).unwrap().1, "5126655", "the KB from the name");
    assert_eq!(os_update_row(&inst("2026-10 Security Monthly Quality Rollup for Windows Server 2012 R2 for x64-based Systems (KB5126836)", json!({}))).unwrap().1, "5126836");
    assert!(os_update_row(&inst("2026-10 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2 for x64 (KB5126001)", json!({}))).is_none());
    assert!(os_update_row(&inst("Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.441.1.0)", json!({}))).is_none());
    assert!(os_update_row(&inst("2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5127648)", json!({ "status": "FAILED" }))).is_none());
    assert!(os_update_row(&inst("2026-10 Cumulative Update for Windows 10 Version 22H2 (KB5126657)", json!({ "deviceId": null }))).is_none());
    assert!(os_update_row(&inst("2026-10 Cumulative Update for Windows 10 Version 22H2 (KB5126657)", json!({ "installedAt": null }))).is_none());
}

// ---------------------------------------------------------------- 8. windows_device

fn fx(cve: &str, rev: i64, kb: &str, server: bool, exploited: bool, severity: &str) -> Fix {
    Fix { cve: cve.into(), product_id: if server { "12436".into() } else { "12390".into() }, product: "Windows".into(), server, build_major: 26100,
          fixed_build: format!("10.0.26100.{rev}"), fixed_rev: rev, kb: kb.into(), severity: Some(severity.into()), exploited, title: Some(cve.into()) }
}
fn all() -> Vec<Fix> { vec![fx("CVE-A", 9445, "5124008", false, false, "important"), fx("CVE-B", 9711, "5127648", false, true, "critical"), fx("CVE-S", 33650, "5126646", true, false, "important")] }
fn dv(family: &str, build: &str, installed: &[&str], pending: &[&str], failed: &[(&str, &str)]) -> (WindowsDevice, Vec<WindowsFinding>) {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    windows_device(&DeviceUpdates { device_id: 7, os_family: family.into(), os_build: build.into(), installed_kbs: s(installed), pending_kbs: s(pending),
        failed: failed.iter().map(|(k, a)| (k.to_string(), a.to_string())).collect() }, &all())
}

#[test]
fn one_device_against_every_windows_cve() {
    let (d, f) = dv("Windows", "26100", &["5101650"], &[], &[]);
    assert_eq!((d.state, f.len()), ("unknown", 0), "a KB Microsoft's data doesn't hold: unknown, no findings, never patched");
    let (d, f) = dv("Windows", "26100", &["5124008"], &[], &[]);
    assert_eq!((d.state, f.iter().map(|x| x.cve.as_str()).collect::<Vec<_>>()), ("vulnerable", vec!["CVE-B"]));
    assert_eq!((d.rev, d.rev_source), (Some(9445), Some("updates")));
    assert_eq!((d.needed_kb.as_deref(), d.needed_build.as_deref(), d.latest_kb.as_deref()), (Some("5127648"), Some("10.0.26100.9711"), Some("5127648")));
    assert_eq!((d.cve_count, d.exploited_count, d.critical_count), (Some(1), Some(1), Some(1)));
    assert_eq!((f[0].kb.as_str(), f[0].severity.as_deref(), f[0].exploited), ("5127648", Some("critical"), true));
    let (d, f) = dv("Windows", "26100", &["5124008", "5127648"], &[], &[]);
    assert_eq!((d.state, f.len(), d.cve_count, d.needed_kb.clone()), ("patched", 0, Some(0), None));
    let (d, _) = dv("Windows", "10.0.26100.9711", &[], &[], &[]);
    assert_eq!((d.state, d.rev_source), ("patched", Some("build")));
    assert_eq!(dv("Windows", "26100", &["5124008"], &["5127648"], &[]).0.update_pending_kb.as_deref(), Some("5127648"), "the needed update pending in NinjaOne");
    let failed = dv("Windows", "26100", &["5124008"], &[], &[("KB5127648", "2026-10-20T03:00:00.000Z")]).0;
    assert_eq!((failed.update_failed_kb.as_deref(), failed.update_failed_at.as_deref()), (Some("5127648"), Some("2026-10-20T03:00:00.000Z")));
    assert!(dv("Windows", "26100", &["5124008"], &["5124008"], &[]).0.update_pending_kb.is_none(), "an older update pending isn't the fix");
    let (srv, _) = dv("Windows Server", "26100", &["5127648"], &[], &[]);
    assert_eq!((srv.state, srv.server), ("unknown", true), "the client's October update isn't a server fix");
    let unk = dv("Windows Server", "26100", &[], &[], &[("KB5126646", "2026-10-20T03:00:00.000Z")]).0;
    assert_eq!((unk.state, unk.update_failed_kb.as_deref()), ("unknown", Some("5126646")), "unknown still says a failed update for its own build");
    assert_eq!(dv("Windows Server", "26100", &[], &["5127648", "5126646"], &[]).0.update_pending_kb.as_deref(), Some("5126646"), "the client's KB is not the server's");
    assert!(srv.update_pending_kb.is_none() && srv.update_failed_kb.is_none());
    assert_eq!(dv("Windows", "7601", &[], &[], &[]).0.state, "untracked");
    assert_eq!(dv("macOS", "15.1", &[], &[], &[]).0.state, "not_windows");
    assert_eq!(os_family("Windows Server 2022 Standard"), "Windows Server");
    assert_eq!(os_family("Windows 11 Pro"), "Windows");
}

// ---------------------------------------------------------------- the jobs, end to end, and the ops

type H = Arc<Mutex<HashMap<String, u32>>>;
fn hit(h: &H, k: &str) { *h.lock().unwrap().entry(k.into()).or_default() += 1; }

/// MSRC and NinjaOne, made up. Windows devices on build 26100: 701 a desktop with only an older update installed
/// (vulnerable to two CVEs, October's exploited one among them, and the update that fixes both failed in NinjaOne), 702 a Server 2025 box with the client's
/// update only (unknown: its patch level can't be read), 703 a desktop with both updates (patched), 704 a laptop with
/// a build Microsoft's data doesn't cover (untracked); and 705 a Mac.
async fn vendors() -> (String, H) {
    let h: H = Default::default();
    let index = json!({ "value": [{ "ID": "2026-Oct", "InitialReleaseDate": "2026-10-13T07:00:00Z", "CurrentReleaseDate": "2026-10-26T01:48:59Z" },
                                  { "ID": "2026-Sep", "InitialReleaseDate": "2026-09-08T07:00:00Z", "CurrentReleaseDate": "2026-09-20T01:47:42Z" }] });
    let sep = json!({ "ProductTree": { "FullProductName": [{ "ProductID": "12390", "Value": "Windows 11 Version 24H2 for x64-based Systems" }] },
        "Vulnerability": [{ "CVE": "CVE-2026-100100", "Title": { "Value": "Windows Kernel Information Disclosure" },
            "Threats": [{ "Type": 3, "Description": { "Value": "Important" }, "ProductID": ["12390"] }], "Remediations": [rem("5124008", "10.0.26100.9445", &["12390"])] },
          { "CVE": "CVE-2026-100050", "Title": { "Value": "Windows Print Spooler Spoofing" },
            "Threats": [{ "Type": 3, "Description": { "Value": "Moderate" }, "ProductID": ["12390"] }], "Remediations": [rem("5119000", "10.0.26100.9000", &["12390"])] }] });
    let at = chrono::Utc::now().timestamp();
    let r = Router::new()
        .route("/msrc/updates", get(move |State(h): State<H>| { let i = index.clone(); async move { hit(&h, "index"); Json(i) } }))
        .route("/msrc/cvrf/{id}", get(move |State(h): State<H>, Path(id): Path<String>| { let s = sep.clone(); async move {
            hit(&h, &format!("month {id}"));
            Json(if id == "2026-Oct" { october() } else { s }) } }))
        .route("/ninja/ws/oauth/token", post(|| async { Json(json!({ "access_token": "b", "expires_in": 3600 })) }))
        .route("/ninja/v2/queries/os-patch-installs", get(move |State(h): State<H>, Query(q): Query<HashMap<String, String>>| async move {
            hit(&h, "installs");
            let cu = |d: i64, kb: &str| json!({ "id": format!("{d}-{kb}"), "deviceId": d, "name": format!("2026-10 Cumulative Update for Windows 11 Version 24H2 (KB{kb})"), "status": "INSTALLED", "installedAt": at });
            if q.get("status").map(String::as_str) == Some("FAILED") {
                return Json(json!({ "results": [{ "id": "f1", "deviceId": 701, "name": "2026-10 Cumulative Update for Windows 11 Version 24H2 (KB5124008)", "kbNumber": "KB5124008", "status": "FAILED", "installedAt": at },
                                                 { "id": "f2", "deviceId": 701, "name": "Cumulative Update (KB5127648)", "kbNumber": "KB5127648", "status": "FAILED", "installedAt": at - 3600 }], "cursor": null }));
            }
            Json(json!({ "results": [cu(701, "5119000"), cu(702, "5127648"), cu(703, "5124008"), cu(703, "5127648"),
                { "id": "x", "deviceId": 703, "name": "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602", "status": "INSTALLED", "installedAt": at }], "cursor": null }))
        }))
        .route("/ninja/v2/queries/os-patches", get(move |State(h): State<H>, Query(q): Query<HashMap<String, String>>| async move {
            hit(&h, "pending");
            Json(json!({ "results": if q.get("status").map(String::as_str) == Some("APPROVED") { json!([{ "id": "a1", "deviceId": 702, "name": "2026-10 Cumulative Update for Windows Server 2025 (KB5126646)", "timestamp": at }]) } else { json!([]) }, "cursor": null }))
        }))
        .with_state(h.clone());
    (serve(r).await, h)
}

async fn seed_devices(pool: &msp_console::db::Pool) {
    msp_console::on_pool!(pool, p, _ => {
        sqlx::query("INSERT INTO client (org_id, name, name_key) VALUES (7, 'Alpha Dental', 'alpha dental'), (8, 'Bravo Ortho', 'bravo ortho')").execute(p).await.unwrap();
        for (id, org, name, class, os, build) in [(701, 7, "DESIGN-1", "desktop", "Windows 11 Pro", "26100"), (702, 7, "ALPHA-DC", "server", "Windows Server 2025 Standard", "26100"),
            (703, 8, "BRAVO-1", "desktop", "Windows 11 Pro", "26100"), (704, 8, "BRAVO-OLD", "laptop", "Windows 11 Pro", "19045"), (705, 8, "BRAVO-MAC", "laptop", "macOS 15", "15.1")] {
            sqlx::query("INSERT INTO device (device_id, org_id, name, device_class, os_name, os_build) VALUES ($1, $2, $3, $4, $5, $6)")
                .bind(id as i64).bind(org as i64).bind(name).bind(class).bind(os).bind(build).execute(p).await.unwrap();
        }
    });
}

async fn op(store: &Store, body: Value) -> Value {
    let (code, a) = store.call(&EvidenceRequest::parse(body.to_string().as_bytes()).unwrap()).await;
    assert_eq!(code, 200, "{a}");
    a
}

async fn the_jobs_match_every_windows_device_and_the_ops_open_each_count(db: TestDb) {
    let (base, h) = vendors().await;
    seed_devices(&db.pool).await;
    // Before Microsoft's data is loaded, nothing is matched: no device reads as untracked or patched by default.
    assert!(match_windows(&db.pool).await.unwrap()["skipped"].is_string());
    let http = msp_console::http_client();
    let ninja = Arc::new(Ninja::new(&format!("{base}/ninja"), "id", "secret", http.clone()));
    let os = NinjaOs::new(ninja).sync(&db.pool).await.unwrap();
    assert_eq!((os.detail["days"].as_i64(), os.detail["cumulative_updates"].as_i64(), os.detail["waiting"].as_i64()), (Some(45), Some(4), Some(1)), "{}", os.detail);
    assert_eq!(count(&db.pool, "SELECT count(*) FROM os_update_installed").await, 4, "the Defender update isn't Windows'");
    let m = Msrc::new(&format!("{base}/msrc"), http.clone());
    let o = m.sync(&db.pool).await.unwrap();
    assert_eq!((o.detail["months_loaded"].as_i64(), o.detail["fixes"].as_i64()), (Some(2), Some(7)), "{}", o.detail);
    assert_eq!(o.detail["match"]["by_state"], json!({ "vulnerable": 1, "unknown": 1, "patched": 1, "untracked": 1 }), "the Mac isn't a Windows device");
    // Read again: nothing changed at Microsoft, so no month is downloaded, and the same states come out.
    let again = m.sync(&db.pool).await.unwrap();
    assert_eq!((again.detail["months_loaded"].as_i64(), h.lock().unwrap().get("month 2026-Oct").copied()), (Some(0), Some(1)));
    assert_eq!(again.detail["match"], o.detail["match"]);
    // October lists the first fix and a later rollup for the same product: the earliest is the threshold.
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_msrc_fix WHERE cve = 'CVE-2026-100200' AND product_id = '12390' AND fixed_rev = 9445").await, 1);

    let store = Store::new(db.pool.clone());
    let a = op(&store, json!({ "op": "windows.devices", "params": {} })).await;
    assert_eq!(a["totals"], json!({ "devices": 4, "vulnerable": 1, "unknown": 1, "patched": 1, "untracked": 1 }), "{a}");
    let rows = a["data"].as_array().unwrap();
    assert_eq!(rows.iter().map(|r| r["device_id"].as_i64().unwrap()).collect::<Vec<_>>(), [701, 702, 704, 703], "worst first: vulnerable, unknown, untracked, patched");
    let v = &rows[0];
    assert_eq!((v["needed_kb"].as_str(), v["update_failed_kb"].as_str(), v["build"].as_str(), v["rev_source"].as_str(), v["cve_count"].as_i64()),
               (Some("5124008"), Some("5124008"), Some("26100.9000"), Some("updates"), Some(2)), "{v}");
    let u = &rows[1];
    assert_eq!((u["state"].as_str(), u["update_pending_kb"].as_str()), (Some("unknown"), Some("5126646")), "unknown, never patched, with the server fix waiting: {u}");
    // Every count opens its rows: a client's vulnerable devices, and a device's open CVEs with the KB for each.
    let a = op(&store, json!({ "op": "windows.devices", "params": { "org_id": 7, "state": "vulnerable" } })).await;
    assert_eq!((a["data"].as_array().unwrap().len(), a["totals"]["vulnerable"].as_i64()), (1, Some(1)));
    let a = op(&store, json!({ "op": "windows.cves", "params": { "device_id": 701 } })).await;
    let cves = a["data"].as_array().unwrap();
    assert_eq!(cves.iter().map(|c| c["cve_id"].as_str().unwrap()).collect::<Vec<_>>(), ["CVE-2026-100200", "CVE-2026-100100"], "exploited first: {a}");
    assert_eq!(cves[0]["kbs"], json!([{ "kb": "5124008", "fixed_build": "10.0.26100.9445", "devices": 1 }]));
    assert_eq!(cves.len() as i64, rows[0]["cve_count"].as_i64().unwrap(), "the device's count is its rows");
    // A CVE's device count opens exactly those devices (windows.devices with cve_id).
    let all = op(&store, json!({ "op": "windows.cves", "params": {} })).await;
    for c in all["data"].as_array().unwrap() {
        let d = op(&store, json!({ "op": "windows.devices", "params": { "cve_id": c["cve_id"] } })).await;
        assert_eq!((d["totals"]["devices"].clone(), d["data"].as_array().map(Vec::len)), (c["devices"].clone(), c["devices"].as_u64().map(|n| n as usize)), "{c} {d}");
    }
    let a = op(&store, json!({ "op": "windows.cves", "params": { "org_id": 8 } })).await;
    assert_eq!((a["data"].as_array().unwrap().len(), a["totals"]["devices"].as_i64()), (0, Some(0)), "Bravo's Windows devices are patched or untracked");
    let (code, a) = store.call(&EvidenceRequest::parse(br#"{"op":"windows.devices","params":{"state":"bogus"}}"#).unwrap()).await;
    assert!(code == 400 && a["error"].as_str().unwrap().contains("state"), "{a}");
    // The evidence model: the msrc source in the drill-down, as Microsoft names the CVEs.
    let a = op(&store, json!({ "op": "cves.list", "params": { "source": ["msrc"] } })).await;
    assert_eq!(a["totals"]["cves"].as_i64(), Some(2), "{a}");
    let a = op(&store, json!({ "op": "cve.get", "params": { "cve_id": "CVE-2026-100200" } })).await;
    assert_eq!(a["data"]["devices_by_source"]["msrc"].as_i64(), Some(1), "{a}");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_evidence WHERE source = 'msrc'").await, 4, "a row per Windows device with a build");
}

