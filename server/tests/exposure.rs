//! Internet exposure, end to end against a made-up NinjaOne and Shodan on both stores: public addresses from
//! NinjaOne's devices pass (servers and desktops; laptops and private addresses left out), each looked up in Shodan's own data, its
//! services rated and matched against NVD, the websites' addresses classified (a CDN attributes nothing; a dedicated
//! server is looked up), edge marks out of every total, scans only under an admin's policy and within the credits,
//! and Shodan's key never in a stored error.
mod common;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{Path, Query, State};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::*;
use http_body_util::BodyExt;
use msp_console::app::{router_with, AppState};
use msp_console::connectors::ninja::Ninja;
use msp_console::connectors::shodan::{scan_due, service_cpe, Shodan, ShodanCfg};
use msp_console::contract::EvidenceRequest;
use msp_console::identity::TrustedHeader;
use msp_console::ops::actions::Actions;
use msp_console::ops::Store;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const KEY: &str = "shodan-key-for-the-test-5a2e";
const WAN: &str = "203.0.113.10";
type Q = Query<HashMap<String, String>>;
fn hit(h: &Hits, k: &str) { *h.lock().unwrap().entry(k.to_string()).or_default() += 1; }

async fn vendors(scan_done: Arc<Mutex<bool>>) -> (String, Hits) {
    let seen: Hits = Default::default();
    let key_ok = |q: &HashMap<String, String>| q.get("key").map(String::as_str) == Some(KEY);
    let r = Router::new()
        .route("/ninja/ws/oauth/token", post(|| async { Json(json!({ "access_token": "ninja-bearer", "expires_in": 3600 })) }))
        .route("/ninja/v2/organizations", get(|State(h): State<Hits>| async move { hit(&h, "ninja_orgs"); Json(json!([{ "id": 1, "name": "Alpha Dental" }, { "id": 2, "name": "Beta Ortho" }])) }))
        .route("/ninja/v2/queries/computer-systems", get(|| async { Json(json!({ "results": [{ "deviceId": 102, "chassisType": "desktop" }, { "deviceId": 201, "chassisType": "laptop" }], "cursor": null })) }))
        .route("/ninja/v2/devices-detailed", get(|State(h): State<Hits>, Query(q): Q| async move {
            hit(&h, "ninja_devices");
            if q.get("after").map(String::as_str) != Some("0") { return Json(json!([])); }
            let d = |id: i64, org: i64, name: &str, node: &str, ip: Option<&str>| { let mut v = json!({ "id": id, "organizationId": org, "systemName": name, "nodeClass": node }); if let Some(ip) = ip { v["publicIP"] = json!(ip); } v };
            Json(json!([d(101, 1, "ALPHA-DC", "WINDOWS_SERVER", Some(WAN)), d(102, 1, "FRONTDESK-1", "WINDOWS_WORKSTATION", Some(WAN)),
                        d(201, 2, "BETA-LT-1", "WINDOWS_WORKSTATION", Some("198.51.100.20")), d(103, 1, "ALPHA-PRINT", "WINDOWS_WORKSTATION", Some("10.0.0.5")),
                        d(104, 1, "ALPHA-CGNAT", "WINDOWS_WORKSTATION", Some("100.64.1.1")), d(105, 1, "ALPHA-NONE", "WINDOWS_WORKSTATION", None)]))
        }))
        .route("/shodan/api-info", get(move |State(h): State<Hits>, Query(q): Q| async move {
            hit(&h, "info");
            if !key_ok(&q) { return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Please provide a valid API key" }))); }
            (StatusCode::OK, Json(json!({ "plan": "dev", "scan_credits": 50, "query_credits": 100 })))
        }))
        .route("/shodan/shodan/host/{ip}", get(move |State(h): State<Hits>, Path(ip): Path<String>, Query(q): Q| async move {
            hit(&h, &format!("host {ip}"));
            if !key_ok(&q) { return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Invalid API key" }))); }
            match ip.as_str() {
                WAN => (StatusCode::OK, Json(json!({ "ip_str": WAN, "ports": [22, 3389], "org": "Example ISP", "isp": "Example ISP", "hostnames": ["gw.alphadental.example"],
                    "last_update": "2026-09-01T00:00:00.000000", "vulns": ["CVE-2026-91000"],
                    "data": [{ "port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2p1", "cpe23": ["cpe:2.3:a:openbsd:openssh:8.2p1"], "timestamp": "2026-11-01T00:00:00.000000" },
                             { "port": 3389, "transport": "tcp", "product": "Remote Desktop Protocol", "timestamp": "2026-11-01T00:00:00.000000" },
                             { "port": 3389, "transport": "tcp", "product": "older banner", "timestamp": "2026-10-01T00:00:00.000000" }] }))),
                "198.51.100.50" => (StatusCode::OK, Json(json!({ "ports": [443], "org": "Example Hosting LLC", "hostnames": ["www.alphadental.example"], "data": [{ "port": 443, "transport": "tcp", "product": "nginx" }] }))),
                "198.51.100.60" => (StatusCode::OK, Json(json!({ "ports": [80, 443], "org": "Cloudflare, Inc.", "asn": "AS13335", "data": [{ "port": 443, "transport": "tcp" }] }))),
                _ => (StatusCode::NOT_FOUND, Json(json!({ "error": "No information available for that IP." }))),
            }
        }))
        .route("/shodan/dns/resolve", get(|State(h): State<Hits>, Query(q): Q| async move {
            hit(&h, "resolve");
            let mut m = serde_json::Map::new();
            for n in q.get("hostnames").cloned().unwrap_or_default().split(',') {
                m.insert(n.into(), match n { "www.alphadental.example" => json!("198.51.100.50"), "alphadental.example" => json!("198.51.100.60"), _ => Value::Null });
            }
            Json(Value::Object(m))
        }))
        .route("/shodan/shodan/scan", post(|State(h): State<Hits>, body: String| async move {
            hit(&h, "scan");
            assert_eq!(body, format!("ips={WAN}"), "only the policy's client's WAN address, never a site's");
            Json(json!({ "id": "scan-1", "count": 1, "credits_left": 49 }))
        }))
        .route("/shodan/shodan/scan/{id}", get(move |State(h): State<Hits>| { let d = scan_done.clone(); async move {
            hit(&h, "scan_status"); Json(json!({ "id": "scan-1", "status": if *d.lock().unwrap() { "DONE" } else { "PROCESSING" } })) } }))
        .with_state(seen.clone());
    (serve(r).await, seen)
}

async fn seed(pool: &msp_console::db::Pool) {
    for q in [
        "INSERT INTO client (org_id, name, name_key, halo_client_id, halo_matched_by) VALUES (1, 'Alpha Dental', 'alpha dental', 10, 'ninjarmm_id')",
        "INSERT INTO client (org_id, name, name_key) VALUES (2, 'Beta Ortho', 'beta ortho')",
        "INSERT INTO halo_client (halo_client_id, name, name_key, ninjarmm_org_id, website_sites) VALUES (10, 'Alpha Dental', 'alpha dental', 1,
            '[{\"url\":\"https://www.alphadental.example/\",\"hostname\":\"www.alphadental.example\",\"apex\":\"alphadental.example\"}]')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (101, 1, 'ALPHA-DC', 'server')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (102, 1, 'FRONTDESK-1', 'desktop')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (201, 2, 'BETA-LT-1', 'laptop')",
        "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, rejected, description) VALUES ('CVE-2026-91000', 7.5, 'HIGH', false, 'A made-up flaw Shodan reports.')",
        "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, rejected) VALUES ('CVE-2026-91001', 9.1, 'CRITICAL', false)",
        "INSERT INTO sec_nvd_cpe (cve_id, cpe, ranges) VALUES ('CVE-2026-91001', 'openbsd:openssh', '[{\"ee\":\"9.0\"}]')",
        "INSERT INTO sec_kev (cve_id, name) VALUES ('CVE-2026-91001', 'Made-up OpenSSH flaw')",
    ] { exec(pool, q).await; }
}

struct Rig { app: Router }
fn rig(pool: msp_console::db::Pool) -> Rig {
    // The console's own admin role (ADMIN_EMAILS behind a proxy) beside SCAN_POLICY_ADMINS: either may set scan policies.
    let proxy = Arc::new(TrustedHeader { header: "x-who".into(), cidrs: vec!["127.0.0.1/32".parse().unwrap()] });
    let identity = Arc::new(msp_console::identity::WithAdmins { inner: proxy, emails: vec!["console-admin@example.com".into()] });
    let state = AppState { identity, store: Store::new(pool), audit: Arc::new(|_| {}) };
    let acts = Arc::new(Actions { halo: None, tickets: None, blackpoint: false, shodan: true, admins: vec!["admin@example.com".into()], everyone_admin: false });
    Rig { app: router_with(state, None, msp_console::ops::actions::routes(acts)).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000)))) }
}
async fn call(r: &Rig, path: &str, body: Value, who: &str) -> (StatusCode, Value) {
    let req = Request::post(path).header("content-type", "application/json").header("x-who", who).body(Body::from(body.to_string())).unwrap();
    let res = r.app.clone().oneshot(req).await.unwrap();
    let st = res.status();
    (st, serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap_or(Value::Null))
}
async fn op(store: &Store, op: &str, params: Value) -> Value {
    let (code, a) = store.call(&EvidenceRequest::parse(json!({ "op": op, "params": params }).to_string().as_bytes()).unwrap()).await;
    assert_eq!(code, 200, "{op}: {a}");
    a
}
fn shodan(base: &str, key: &str) -> Shodan {
    let mut s = Shodan::new(&ShodanCfg { base: format!("{base}/shodan"), key: key.into(), scan_credits: 100, admins: vec![] }, msp_console::http_client());
    s.budget = std::time::Duration::from_secs(60);
    s
}

async fn exposure_end_to_end(db: TestDb) {
    seed(&db.pool).await;
    let done = Arc::new(Mutex::new(false));
    let (base, seen) = vendors(done.clone()).await;
    let store = Store::new(db.pool.clone());

    // 1. NinjaOne's public addresses, public IPv4 only, from the devices job's own pass: no NinjaOne call of their own.
    let ninja = Ninja::new(&format!("{base}/ninja"), "id", "secret", msp_console::http_client());
    let out = ninja.sync_devices(&db.pool).await.unwrap();
    assert_eq!((out.detail["devices"].clone(), out.detail["with_public_ip"].clone()), (json!(6), json!(3)), "{}", out.detail);
    assert_eq!(hits(&seen, "ninja_devices"), 1, "one devices-detailed pass carries the devices and their addresses");
    let wan: Vec<(i64, String)> = msp_console::on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT device_id, public_ip FROM device_wan ORDER BY device_id").fetch_all(p).await.unwrap());
    assert_eq!(wan, vec![(101, WAN.into()), (102, WAN.into()), (201, "198.51.100.20".into())], "private and CGNAT addresses dropped");

    // 2. Shodan: the WAN address (the laptop's left out), and the website's two addresses: a dedicated server,
    //    looked up; a CDN, which attributes nothing.
    let s = shodan(&base, KEY);
    let out = s.sync(&db.pool).await.unwrap();
    assert_eq!((out.detail["addresses"].clone(), out.detail["found"].clone(), out.detail["scan_requested"].clone()), (json!(1), json!(1), json!(0)), "{}", out.detail);
    assert_eq!(out.detail["sites"]["by_class"], json!({ "dedicated": 1, "shared": 1 }), "{}", out.detail);
    assert_eq!((out.detail["scan_credits_left"].clone(), out.detail["query_credits_left"].clone()), (json!(50), json!(100)), "the credits for Status");
    assert_eq!(hits(&seen, "host 198.51.100.20"), 0, "a laptop's address is never looked up");
    let sites: Vec<(String, String, String)> = msp_console::on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT hostname, ip, classification FROM exposure_site ORDER BY hostname").fetch_all(p).await.unwrap());
    assert_eq!(sites, vec![("alphadental.example".into(), "198.51.100.60".into(), "shared".into()), ("www.alphadental.example".into(), "198.51.100.50".into(), "dedicated".into())]);
    assert_eq!(count(&db.pool, "SELECT count(*) FROM exposure_host WHERE ip = '198.51.100.60'").await, 0, "nothing of the CDN's is kept as the client's");

    // 3. The list: the WAN address first (a KEV CVE from NVD's match of OpenSSH 8.2p1), then the website's server.
    let l = op(&store, "exposure.list", json!({})).await;
    assert_eq!(l["totals"], json!({ "addresses": 2, "edge": 0, "looked_up": 2, "kev": 1, "critical": 1, "high": 0, "with_cves": 1, "websites": 1, "clients_kev": 1, "clients_critical": 1 }), "{l}");
    let w = &l["data"][0];
    assert_eq!((w["ip"].clone(), w["severity"].clone(), w["kev_cves"].clone(), w["servers"].clone(), w["desktops"].clone(), w["clients"].clone()),
               (json!(WAN), json!("critical"), json!(["CVE-2026-91001"]), json!(1), json!(1), json!(["Alpha Dental"])), "{w}");
    assert_eq!((l["data"][1]["ip"].clone(), l["data"][1]["website"].clone(), l["data"][1]["sites"].clone(), l["data"][1]["scan"].clone()),
               (json!("198.51.100.50"), json!(true), json!(["www.alphadental.example"]), Value::Null), "a website's server is never scanned: {l}");
    let g = op(&store, "exposure.get", json!({ "ip": WAN })).await["data"].clone();
    let svc: Vec<(Value, Value, Value)> = g["services"].as_array().unwrap().iter().map(|x| (x["port"].clone(), x["rule"]["severity"].clone(), x["product"].clone())).collect();
    assert_eq!(svc, vec![(json!(22), json!("medium"), json!("OpenSSH")), (json!(3389), json!("critical"), json!("Remote Desktop Protocol"))], "the newest banner per port");
    let cves: Vec<(Value, Value, Value)> = g["cves"].as_array().unwrap().iter().map(|c| (c["cve_id"].clone(), c["sources"].clone(), c["kev"].is_object().into())).collect();
    assert_eq!(cves, vec![(json!("CVE-2026-91001"), json!(["nvd"]), json!(true)), (json!("CVE-2026-91000"), json!(["shodan"]), json!(false))]);
    assert_eq!(g["devices"].as_array().unwrap().len(), 2);
    // The CVE's own page names the address it faces the internet on (cve.get's internet_facing), and only for its client.
    let c = op(&store, "cve.get", json!({ "cve_id": "CVE-2026-91001" })).await["data"]["internet_facing"].clone();
    assert_eq!(c.as_array().map(|a| a.iter().map(|x| (x["ip"].clone(), x["sources"].clone(), x["ports"].clone(), x["client_name"].clone())).collect::<Vec<_>>()),
               Some(vec![(json!(WAN), json!(["nvd"]), json!(["22/tcp"]), json!("Alpha Dental"))]), "{c}");
    assert_eq!(op(&store, "cve.get", json!({ "cve_id": "CVE-2026-91001", "org_id": 2 })).await["data"]["internet_facing"], json!([]), "another client's address isn't theirs");
    assert_eq!(op(&store, "cve.get", json!({ "cve_id": "CVE-2026-0404" })).await["data"]["internet_facing"], json!([]), "a CVE on no address faces nothing");

    // 4. An edge entry point: out of every total, out of the list unless asked for, and who marked it is kept.
    let r = rig(db.pool.clone());
    let (st, a) = call(&r, "/api/exposure/edge", json!({ "ip": WAN, "edge": true, "note": "the firewall's VPN portal" }), "tech@example.com").await;
    assert_eq!((st, a["marked_by"].clone()), (StatusCode::OK, json!("tech@example.com")));
    let (st, _) = call(&r, "/api/exposure/edge", json!({ "ip": "192.0.2.99", "edge": true }), "tech@example.com").await;
    assert_eq!(st, StatusCode::NOT_FOUND, "only a current client address can be marked");
    let l = op(&store, "exposure.list", json!({})).await;
    assert_eq!((l["totals"]["addresses"].clone(), l["totals"]["edge"].clone(), l["totals"]["kev"].clone(), l["data"].as_array().unwrap().len()), (json!(1), json!(1), json!(0), 1));
    assert_eq!(op(&store, "exposure.list", json!({ "include_edge": true })).await["data"].as_array().unwrap().len(), 2);
    call(&r, "/api/exposure/edge", json!({ "ip": WAN, "edge": false }), "tech@example.com").await;

    // 5. Scans: off by default; an admin turns Alpha's on; one credit asked for its WAN address, not again inside the
    //    frequency; a finished scan's address is looked up again.
    let (st, a) = call(&r, "/api/exposure/scan-policy", json!({ "org_id": 1, "frequency_days": 30 }), "tech@example.com").await;
    assert_eq!((st, a["error"].as_str().map(|e| e.starts_with("Only an admin"))), (StatusCode::FORBIDDEN, Some(true)));
    let (st, a) = call(&r, "/api/exposure/scan-policy", json!({ "org_id": 1, "frequency_days": 0 }), "console-admin@example.com").await;
    assert_eq!((st, a["error"].clone()), (StatusCode::OK, Value::Null), "a console admin may too, without SCAN_POLICY_ADMINS: {a}");
    let (st, a) = call(&r, "/api/exposure/scan-policy", json!({ "org_id": 1, "frequency_days": 30 }), "Admin@Example.com").await;
    assert_eq!((st, a["set_by"].clone()), (StatusCode::OK, json!("Admin@Example.com")));
    let out = s.sync(&db.pool).await.unwrap();
    assert_eq!((out.detail["scan_requested"].clone(), out.detail["scan_credits_left"].clone()), (json!(1), json!(49)), "{}", out.detail);
    let out = s.sync(&db.pool).await.unwrap();
    assert_eq!(out.detail["scan_requested"], json!(0), "not again inside the frequency: {}", out.detail);
    assert_eq!(op(&store, "exposure.get", json!({ "ip": WAN })).await["data"]["scan"]["pending"], json!("PROCESSING"), "the second run checked the scan: Shodan says it is processing");
    let before = hits(&seen, &format!("host {WAN}"));
    *done.lock().unwrap() = true;
    let out = msp_console::connectors::shodan::Shodan::sync_scans(&s, &db.pool).await.unwrap();
    assert_eq!((out.detail["looked_up"].clone(), hits(&seen, &format!("host {WAN}"))), (json!(1), before + 1), "{}", out.detail);
    assert_eq!(hits(&seen, "scan"), 1);
    // Off again (0): the row goes.
    call(&r, "/api/exposure/scan-policy", json!({ "org_id": 1, "frequency_days": 0 }), "admin@example.com").await;
    assert_eq!(count(&db.pool, "SELECT count(*) FROM scan_policy").await, 0);

    // 6. A wrong key: the run fails with Shodan's status and reason, and the key is nowhere.
    let bad = shodan(&base, "the-wrong-shodan-key-0b7d");
    let e = bad.sync(&db.pool).await.unwrap_err();
    assert_eq!(e, "Shodan: HTTP 401: Please provide a valid API key");
    let errors: Vec<(Option<String>,)> = msp_console::on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT error FROM exposure_host").fetch_all(p).await.unwrap());
    for (x,) in errors { assert!(!x.unwrap_or_default().contains("wrong-shodan-key")); }
}
both!(exposure_end_to_end);

#[test]
fn a_services_cpe_and_version_are_read_as_nvd_names_them() {
    assert_eq!(service_cpe(&["cpe:2.3:a:openbsd:openssh:8.2p1".into()], None), Some(("openbsd:openssh".into(), "8.2".into())));
    assert_eq!(service_cpe(&["cpe:/o:fortinet:fortios".into()], Some("7.2.4")), Some(("o:fortinet:fortios".into(), "7.2.4".into())));
    assert_eq!(service_cpe(&["cpe:/h:vendor:box".into()], Some("1")), None, "hardware isn't matched");
}

#[test]
fn a_scan_is_due_only_outside_its_frequency() {
    let now = chrono::Utc::now();
    let d = |n: i64| Some(now - chrono::Duration::days(n));
    assert!(!scan_due(true, d(40), None, 0, now), "0 is never");
    assert!(scan_due(false, None, None, 30, now), "never seen, never asked: due");
    assert!(!scan_due(false, None, d(5), 30, now), "asked 5 days ago");
    assert!(!scan_due(true, d(10), d(40), 30, now), "Shodan's data is fresh enough");
    assert!(scan_due(true, d(31), d(40), 30, now));
}
