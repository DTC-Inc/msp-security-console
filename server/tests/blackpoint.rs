//! Blackpoint, end to end against a made-up CompassOne on both stores: tenants suggested (by domain, by name) and
//! never applied until a signed-in person confirms; assets tied to devices only inside a confirmed client; open
//! detections, and one no longer open closed; findings as `blackpoint` evidence the CVE list reads; dark-web rows that
//! keep the email, source, date and kind and never the password or hash Blackpoint sent; and the rate budget, which
//! stops a sweep for the next run instead of failing it.
mod common;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use common::*;
use http_body_util::BodyExt;
use msp_console::app::{router_with, AppState};
use msp_console::audit::AuditRecord;
use msp_console::connectors::blackpoint::{darkweb_row, match_key, Blackpoint, BlackpointCfg};
use msp_console::contract::EvidenceRequest;
use msp_console::identity::TrustedHeader;
use msp_console::ops::actions::Actions;
use msp_console::ops::Store;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const TOKEN: &str = "bp-token-for-the-test-31c7";
const PASSWORD: &str = "hunter2-exposed-password-value";
const HASH: &str = "$2b$12$an-exposed-password-hash-value";

type Q = Query<HashMap<String, String>>;
fn hit(h: &Hits, k: &str) { *h.lock().unwrap().entry(k.to_string()).or_default() += 1; }
fn page(data: Value) -> Json<Value> { let n = data.as_array().map_or(0, Vec::len); Json(json!({ "data": data, "meta": { "currentPage": 1, "totalPages": 1, "totalItems": n } })) }

/// Three tenants: Alpha (its domain is a client's website), Beta (its name is a client's, suffixes aside), Gamma (no
/// one). Alpha is licensed for vulnerability detail, with one attacked finding on its front desk and one dark-web
/// exposure that carries a password and a hash. Beta has one open detection the first time, none the second.
async fn compassone(open_beta: Arc<Mutex<bool>>) -> (String, Hits) {
    let seen: Hits = Default::default();
    let ok = |hd: &HeaderMap| hd.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}") as &str);
    let tenant = |hd: &HeaderMap| hd.get("x-tenant-id").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let r = Router::new()
        .route("/bp/v1/tenants", get(move |State(h): State<Hits>, hd: HeaderMap| async move {
            hit(&h, "tenants");
            if !ok(&hd) { return (StatusCode::UNAUTHORIZED, Json(json!({ "message": "Invalid authorization token" }))).into_response(); }
            ([("x-ratelimit-remaining", "3990"), ("x-ratelimit-reset", "60")], page(json!([
                { "id": "t-alpha", "name": "Alpha Clinic Group", "domain": "www.alphadental.example", "accountId": "acc-1" },
                { "id": "t-beta", "name": "Beta Ortho, P.C.", "domain": null },
                { "id": "t-gamma", "name": "Gamma Holdings", "domain": "gamma.example" }]))).into_response()
        }))
        .route("/bp/v1/vulnerability-management/vulnerabilities/stats/count-by-severity", get(move |State(h): State<Hits>, hd: HeaderMap| async move {
            hit(&h, "license");
            if tenant(&hd) == "t-alpha" { (StatusCode::OK, Json(json!({ "data": { "CRITICAL": 1 } }))) } else { (StatusCode::FORBIDDEN, Json(json!({ "message": "Requestor does not have required entitlements" }))) }
        }))
        .route("/bp/v1/assets", get(move |State(h): State<Hits>, hd: HeaderMap, Query(q): Q| async move {
            hit(&h, "assets");
            assert_eq!(q.get("class").map(String::as_str), Some("DEVICE"));
            page(match tenant(&hd).as_str() {
                "t-alpha" => json!([{ "id": "as-1", "hostname": "frontdesk-1", "osName": "Windows 11" }, { "id": "as-9", "hostname": "BETA-LT-1" }]),
                "t-beta" => json!([{ "id": "as-2", "hostname": "BETA-LT-1" }]),
                _ => json!([]),
            })
        }))
        .route("/bp/v1/alert-groups", get(move |State(h): State<Hits>, hd: HeaderMap| { let open_beta = open_beta.clone(); async move {
            hit(&h, "alerts");
            let items = match tenant(&hd).as_str() {
                "t-alpha" => json!([{ "id": "g-1", "riskScore": 92, "alertCount": 3, "alertTypes": ["EDR"], "created": "2026-11-01T10:00:00Z",
                                      "alert": { "hostname": "FRONTDESK-1", "username": "frontdesk", "action": "Suspicious PowerShell", "ruleName": "ps-encoded" } }]),
                "t-beta" if *open_beta.lock().unwrap() => json!([{ "id": "g-2", "riskScore": 40, "alertCount": 1, "alertTypes": ["Identity"], "created": "2026-11-02T10:00:00Z",
                                                                   "alert": { "hostname": "BETA-LT-1", "action": "Impossible travel" } }]),
                _ => json!([]),
            };
            let n = items.as_array().map_or(0, Vec::len);
            Json(json!({ "items": items, "take": 100, "skip": 0, "total": n }))
        } }))
        .route("/bp/v1/vulnerability-management/vulnerabilities", get(move |State(h): State<Hits>, hd: HeaderMap| async move {
            hit(&h, "vulns");
            assert_eq!(tenant(&hd), "t-alpha", "only the licensed tenant's findings are listed");
            page(json!([{ "id": "v-1", "cveId": "CVE-2026-90100", "severity": "CRITICAL", "baseScore": 9.8, "exploitability": "Attacked", "prioritized": true, "assetsAmount": 1,
                          "applicationVendor": "Google", "applicationName": "Chrome", "status": "open" },
                        { "id": "v-2", "cveId": "CVE-2026-90999", "severity": "LOW", "baseScore": 2.0, "assetsAmount": 1, "applicationVendor": "Example", "applicationName": "Tool" }]))
        }))
        .route("/bp/v1/vulnerability-management/vulnerabilities/{id}/assets", get(move |State(h): State<Hits>, axum::extract::Path(id): axum::extract::Path<String>| async move {
            hit(&h, "links");
            assert_eq!(id, "v-1", "only the findings that matter are linked one call each");
            page(json!([{ "id": "as-1", "status": "open", "lastSeenOn": "2026-11-03T00:00:00Z" }]))
        }))
        .route("/bp/v1/vulnerability-management/darkweb/scan/exposures", get(move |State(h): State<Hits>| async move {
            hit(&h, "darkweb");
            page(json!([{ "id": "dw-1", "email": "Pat@AlphaDental.example", "username": "pat", "password": PASSWORD, "passwordHash": HASH, "hash": HASH,
                          "breachName": "Example Breach 2025", "passwordExposed": true, "usernameExposed": true, "breachCreatedAt": "2025-06-01T00:00:00Z", "impactedDomain": "alphadental.example" }]))
        }))
        .with_state(seen.clone());
    (serve(r).await, seen)
}

async fn exec_all(pool: &msp_console::db::Pool, qs: &[&'static str]) { for q in qs { exec(pool, q).await; } }

/// Two clients from NinjaOne (Alpha's Halo link confirmed, with its website), their devices, and an installed Chrome
/// on Alpha's front desk that NVD knows.
async fn seed(pool: &msp_console::db::Pool) {
    exec_all(pool, &[
        "INSERT INTO client (org_id, name, name_key, halo_client_id, halo_matched_by) VALUES (1, 'Alpha Dental', 'alpha dental', 10, 'ninjarmm_id')",
        "INSERT INTO client (org_id, name, name_key) VALUES (2, 'Beta Ortho', 'beta ortho')",
        "INSERT INTO halo_client (halo_client_id, name, name_key, ninjarmm_org_id, website_sites) VALUES (10, 'Alpha Dental', 'alpha dental', 1,
            '[{\"url\":\"https://www.alphadental.example/\",\"hostname\":\"www.alphadental.example\",\"apex\":\"alphadental.example\"}]')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (101, 1, 'FRONTDESK-1', 'desktop')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (201, 2, 'BETA-LT-1', 'laptop')",
        "INSERT INTO sec_evidence (device_id, product_key, version, source) VALUES (101, 'chrome', '120.0', 'ninja_software')",
        "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, rejected) VALUES ('CVE-2026-90100', 9.8, 'CRITICAL', false)",
        "INSERT INTO sec_nvd_cpe (cve_id, cpe, ranges) VALUES ('CVE-2026-90100', 'google:chrome', '[]')",
    ]).await;
}

struct Rig { app: Router, audit: Arc<Mutex<Vec<AuditRecord>>> }
fn rig(pool: msp_console::db::Pool) -> Rig {
    let audit = Arc::new(Mutex::new(Vec::new()));
    let a = audit.clone();
    let state = AppState { identity: Arc::new(TrustedHeader { header: "x-who".into(), cidrs: vec!["127.0.0.1/32".parse().unwrap()] }), store: Store::new(pool),
                           audit: Arc::new(move |r| a.lock().unwrap().push(r)) };
    let acts = Arc::new(Actions { halo: None, tickets: None, blackpoint: true, shodan: false, admins: vec![], everyone_admin: false });
    Rig { app: router_with(state, None, msp_console::ops::actions::routes(acts)).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000)))), audit }
}
async fn call(r: &Rig, path: &str, body: Value, who: Option<&str>) -> (StatusCode, Value) {
    let mut b = Request::post(path).header("content-type", "application/json");
    if let Some(w) = who { b = b.header("x-who", w); }
    let res = r.app.clone().oneshot(b.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let st = res.status();
    (st, serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap_or(Value::Null))
}
async fn op(store: &Store, op: &str, params: Value) -> Value {
    let (code, a) = store.call(&EvidenceRequest::parse(json!({ "op": op, "params": params }).to_string().as_bytes()).unwrap()).await;
    assert_eq!(code, 200, "{op}: {a}");
    a
}

async fn blackpoint_end_to_end(db: TestDb) {
    seed(&db.pool).await;
    let open_beta = Arc::new(Mutex::new(true));
    let (base, seen) = compassone(open_beta.clone()).await;
    let bp = Blackpoint::new(&BlackpointCfg { base: format!("{base}/bp"), token: TOKEN.into() }, msp_console::http_client());
    let store = Store::new(db.pool.clone());

    // 1. Tenants: suggestions only. Alpha by its domain (the client's website), Beta by its name; Gamma nothing.
    let out = bp.sync_tenants(&db.pool).await.unwrap();
    assert_eq!((out.detail["tenants"].clone(), out.detail["suggested"].clone(), out.detail["swept"].clone(), out.detail["licensed"].clone()), (json!(3), json!(2), json!(3), json!(1)), "{}", out.detail);
    let t = op(&store, "blackpoint.tenants", json!({})).await;
    let by: HashMap<String, Value> = t["data"].as_array().unwrap().iter().map(|x| (x["tenant_id"].as_str().unwrap().to_string(), x.clone())).collect();
    assert_eq!((by["t-alpha"]["state"].clone(), by["t-alpha"]["suggested_org_id"].clone(), by["t-alpha"]["suggested_by"].clone()), (json!("suggested"), json!(1), json!("domain")));
    assert_eq!((by["t-beta"]["state"].clone(), by["t-beta"]["suggested_org_id"].clone(), by["t-beta"]["suggested_by"].clone()), (json!("suggested"), json!(2), json!("name")));
    assert_eq!(by["t-gamma"]["state"], json!("unmapped"));
    assert_eq!(t["data"][0]["tenant_id"], json!("t-gamma"), "unmapped first");
    assert_eq!(t["totals"], json!({ "tenants": 3, "confirmed": 0, "suggested": 2, "unmapped": 1, "not_client": 0 }));
    assert_eq!(count(&db.pool, "SELECT count(*) FROM bp_asset WHERE device_id IS NOT NULL").await, 0, "a suggestion ties no asset to a device");

    // 2. Detections, before any tenant is confirmed: they show, as unmapped.
    let out = bp.sync_detections(&db.pool).await.unwrap();
    assert_eq!((out.detail["polled"].clone(), out.detail["open"].clone()), (json!(3), json!(2)), "{}", out.detail);
    let d = op(&store, "detections.list", json!({})).await;
    assert_eq!(d["totals"], json!({ "open": 2, "clients": 0, "high_risk": 1, "unmapped": 2, "without_ticket": 2 }), "{d}");
    assert_eq!(d["data"][0]["detection_id"], json!("g-1"), "the higher risk first");

    // 3. A signed-in person confirms Alpha (the suggestion) and Beta to a client: assets tie to devices at once, inside
    //    the confirmed client only. Without sign-in, nothing.
    let r = rig(db.pool.clone());
    let (st, _) = call(&r, "/api/blackpoint/tenant", json!({ "tenant_id": "t-alpha", "action": "confirm", "org_id": 1 }), None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, a) = call(&r, "/api/blackpoint/tenant", json!({ "tenant_id": "t-alpha", "action": "confirm", "org_id": 1 }), Some("tech@example.com")).await;
    assert_eq!((st, a["assets_matched"].clone()), (StatusCode::OK, json!(1)), "{a}: frontdesk-1 is Alpha's; Alpha's BETA-LT-1 is no device of Alpha's");
    let (st, _) = call(&r, "/api/blackpoint/tenant", json!({ "tenant_id": "t-beta", "action": "confirm", "org_id": 2 }), Some("tech@example.com")).await;
    assert_eq!(st, StatusCode::OK);
    let (st, a) = call(&r, "/api/blackpoint/tenant", json!({ "tenant_id": "t-gamma", "action": "confirm", "org_id": 999 }), Some("tech@example.com")).await;
    assert_eq!((st, a["error"].clone()), (StatusCode::NOT_FOUND, json!("that client isn't in the console")));
    let (st, _) = call(&r, "/api/blackpoint/tenant", json!({ "tenant_id": "t-gamma", "action": "not_client" }), Some("tech@example.com")).await;
    assert_eq!(st, StatusCode::OK);
    let m: Vec<(String, Option<i64>)> = msp_console::on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT asset_id, device_id FROM bp_asset ORDER BY asset_id").fetch_all(p).await.unwrap());
    assert_eq!(m, vec![("as-1".into(), Some(101)), ("as-2".into(), Some(201)), ("as-9".into(), None)]);
    let audit = r.audit.lock().unwrap().clone();
    assert_eq!(audit.iter().map(|x| (x.op.clone().unwrap_or_default(), x.status, x.who.clone())).collect::<Vec<_>>(), vec![
        ("".into(), 401, None),
        ("blackpoint.tenant".into(), 200, Some("tech@example.com".into())), ("blackpoint.tenant".into(), 200, Some("tech@example.com".into())),
        ("blackpoint.tenant".into(), 404, Some("tech@example.com".into())), ("blackpoint.tenant".into(), 200, Some("tech@example.com".into()))]);
    // A re-match keeps every person's decision.
    bp.sync_tenants(&db.pool).await.unwrap();
    let t = op(&store, "blackpoint.tenants", json!({})).await;
    assert_eq!(t["totals"], json!({ "tenants": 3, "confirmed": 2, "suggested": 0, "unmapped": 0, "not_client": 1 }), "{t}");
    let alpha = t["data"].as_array().unwrap().iter().find(|x| x["tenant_id"] == "t-alpha").unwrap().clone();
    assert_eq!((alpha["mapped_by"].clone(), alpha["client"].clone(), alpha["assets"].clone(), alpha["assets_matched"].clone()), (json!("tech@example.com"), json!("Alpha Dental"), json!(2), json!(1)));

    // 4. Detections now belong to clients and devices; one no longer open is closed.
    *open_beta.lock().unwrap() = false;
    bp.sync_detections(&db.pool).await.unwrap();
    let d = op(&store, "detections.list", json!({})).await;
    assert_eq!(d["totals"], json!({ "open": 1, "clients": 1, "high_risk": 1, "unmapped": 0, "without_ticket": 1 }), "{d}");
    assert_eq!((d["data"][0]["client"].clone(), d["data"][0]["device_id"].clone(), d["data"][0]["device_name"].clone()), (json!("Alpha Dental"), json!(101), json!("FRONTDESK-1")));
    let d = op(&store, "detections.list", json!({ "include_closed": true, "org_id": 2 })).await;
    assert_eq!((d["data"].as_array().unwrap().len(), d["data"][0]["status"].clone()), (1, json!("closed")), "{d}");
    let one = op(&store, "detection.get", json!({ "detection_id": "g-1" })).await;
    assert_eq!((one["data"]["finding"].clone(), one["data"]["username"].clone()), (json!("detection:g-1"), json!("frontdesk")));

    // 5. Findings: the attacked one is linked and becomes evidence the CVE list reads; the low one isn't linked.
    let out = bp.sync_vulns(&db.pool).await.unwrap();
    assert_eq!((out.detail["findings"].clone(), out.detail["linked"].clone(), out.detail["darkweb"].clone()), (json!(2), json!(1), json!(1)), "{}", out.detail);
    assert_eq!(out.detail["evidence"]["nvd_match"], json!(1), "Chrome is already known on that device, so the finding is its: {}", out.detail);
    let cves = op(&store, "cves.list", json!({ "org_id": 1, "source": ["blackpoint"] })).await;
    assert_eq!(cves["data"], json!([{ "cve_id": "CVE-2026-90100", "sources": ["blackpoint"], "devices": 1, "running_devices": 0, "kev": false, "exploited": true, "cvss": 9.8 }]), "{cves}");
    let ev: Vec<(String, String, Option<String>)> = msp_console::on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT product_key, version, attribution FROM sec_evidence WHERE source = 'blackpoint'").fetch_all(p).await.unwrap());
    assert_eq!(ev, vec![("chrome".into(), "120.0".into(), Some("nvd-match".into()))]);

    // 6. Dark web: the email, the source, the date and the kind. The password and the hash were never kept anywhere.
    let w = op(&store, "darkweb.list", json!({ "org_id": 1 })).await;
    assert_eq!(w["data"], json!([{ "exposure_id": "dw-1", "email": "pat@alphadental.example", "source": "Example Breach 2025", "found_on": "2025-06-01", "kind": "password",
                                   "tenant_id": "t-alpha", "tenant_name": "Alpha Clinic Group", "org_id": 1, "client": "Alpha Dental" }]));
    assert_eq!(w["totals"], json!({ "exposures": 1, "passwords": 1, "emails": 1 }));
    // Everything the store holds: every row of every table on PostgreSQL; the file and its WAL on SQLite.
    let everything = match &db.pool {
        msp_console::db::Pool::Postgres(p) => {
            let tables: Vec<(String,)> = sqlx::query_as("SELECT table_name::text FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'").fetch_all(p).await.unwrap();
            let mut all = String::new();
            for (t,) in tables {
                let (x,): (String,) = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT coalesce(string_agg(x::text, ' '), '') FROM \"{t}\" x"))).fetch_one(p).await.unwrap();
                all.push_str(&x);
            }
            all
        }
        msp_console::db::Pool::Sqlite(_) => {
            let path = &db.sqlite().path;
            let mut b = std::fs::read(path).unwrap();
            b.extend(std::fs::read(format!("{}-wal", path.display())).unwrap_or_default());
            String::from_utf8_lossy(&b).into_owned()
        }
    };
    for s in [PASSWORD, HASH, "an-exposed-password-hash", "hunter2"] { assert!(!everything.contains(s), "{s} is in the store"); }
    assert!(everything.contains("pat@alphadental.example"), "the search looked at the rows it should have");

    // It really called CompassOne: two tenant lists, three license probes and asset lists each, two detection polls of
    // three tenants, one finding list, one link, one dark-web read.
    assert_eq!([hits(&seen, "tenants"), hits(&seen, "license"), hits(&seen, "assets"), hits(&seen, "alerts"), hits(&seen, "vulns"), hits(&seen, "links"), hits(&seen, "darkweb")],
               [2, 6, 6, 6, 1, 1, 1]);
}
both!(blackpoint_end_to_end, a_dark_web_row_goes_30_days_after_blackpoint_stops_listing_it);

/// Blackpoint's window nearly spent, resetting in an hour: the sweep stops at once and says so, rather than failing
/// tenant after tenant, and the job itself succeeds (the rest is the next run's).
#[tokio::test]
async fn a_spent_rate_window_stops_the_sweep_for_the_next_run() {
    let db = test_db().await;
    let seen: Hits = Default::default();
    let r = Router::new()
        .route("/bp/v1/tenants", get(|State(h): State<Hits>| async move { hit(&h, "tenants");
            ([("x-ratelimit-remaining", "40"), ("x-ratelimit-reset", "3600")], page(json!([{ "id": "t-1", "name": "One" }, { "id": "t-2", "name": "Two" }]))) }))
        .fallback(|State(h): State<Hits>| async move { hit(&h, "other"); page(json!([])) })
        .with_state(seen.clone());
    let base = serve(r).await;
    let bp = Blackpoint::new(&BlackpointCfg { base: format!("{base}/bp"), token: TOKEN.into() }, msp_console::http_client());
    let out = bp.sync_tenants(&db.pool).await.unwrap();
    assert_eq!((out.detail["swept"].clone(), out.detail["deferred"].clone()), (json!(0), json!(2)), "{}", out.detail);
    assert!(out.detail["rate_budget_stop"].as_str().unwrap().contains("40 calls left"), "{}", out.detail);
    assert_eq!((hits(&seen, "tenants"), hits(&seen, "other")), (1, 0), "nothing more was sent once the window was spent");
}

#[test]
fn dark_web_rows_read_only_what_they_keep() {
    let r = darkweb_row(&json!({ "id": 7, "email": " X@Example.COM ", "password": PASSWORD, "passwordHash": HASH, "breachName": "B", "usernameExposed": true, "createdAt": "2026-01-02T03:04:05Z" })).unwrap();
    assert_eq!(r, json!({ "exposure_id": "7", "email": "x@example.com", "source": "B", "found_on": "2026-01-02", "kind": "username" }));
    assert!(!r.to_string().contains("hunter2"));
}

#[test]
fn names_match_with_their_corporate_suffixes_aside() {
    assert_eq!(match_key("Beta Ortho, P.C."), "beta ortho");
    assert_eq!(match_key("Beta Ortho PC"), match_key("beta ortho"));
    assert_eq!(match_key("Smith & Sons LLC"), "smith and sons");
    assert_ne!(match_key("Alpha Clinic Group"), match_key("Alpha Dental"));
}

/// Retention: a dark-web row Blackpoint stopped listing is kept 30 days, soft-deleted, then the purge deletes it; a
/// listed one, and one soft-deleted less than 30 days ago, stay. The job is scheduled whether Blackpoint is on or not.
async fn a_dark_web_row_goes_30_days_after_blackpoint_stops_listing_it(db: TestDb) {
    exec_all(&db.pool, &[
        "INSERT INTO bp_tenant (tenant_id, name, name_key) VALUES ('t-r', 'Retention Example', 'retention example')",
        "INSERT INTO bp_darkweb (exposure_id, tenant_id, email, kind, synced_at, deleted_at) VALUES
           ('listed', 't-r', 'a@example.com', 'email', '2026-11-01T00:00:00.000Z', NULL),
           ('gone-29d', 't-r', 'b@example.com', 'email', '2026-11-01T00:00:00.000Z', '2026-10-08T00:00:00.000Z'),
           ('gone-31d', 't-r', 'c@example.com', 'email', '2026-11-01T00:00:00.000Z', '2026-10-06T00:00:00.000Z')",
    ]).await;
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z").unwrap().with_timezone(&chrono::Utc);
    let out = msp_console::connectors::blackpoint::purge_darkweb(&db.pool, now).await.unwrap();
    assert_eq!(out.detail, json!({ "purged": 1, "keep_days": 30 }));
    let left: Vec<(String,)> = msp_console::on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT exposure_id FROM bp_darkweb ORDER BY exposure_id").fetch_all(p).await.unwrap());
    assert_eq!(left, vec![("gone-29d".to_string(),), ("listed".to_string(),)]);
    assert_eq!(msp_console::connectors::blackpoint::purge_darkweb(&db.pool, now).await.unwrap().detail["purged"], json!(0), "once");
    // Scheduled with no Blackpoint settings at all.
    let Ok(msp_console::config::Startup::Configured(cfg)) = msp_console::config::load(&[("AUTH_MODE".to_string(), "dev_insecure".to_string()), ("MSP_ENV".to_string(), "development".to_string())].into(), &|_| Err(std::io::ErrorKind::NotFound.into())) else { panic!("configured") };
    let names: Vec<&str> = msp_console::jobs(&cfg.connectors, &cfg.db, msp_console::http_client()).iter().map(|j| j.name).collect();
    assert!(names.contains(&"darkweb_purge") && cfg.blackpoint.is_none(), "{names:?}");
}
