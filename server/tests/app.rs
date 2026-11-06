//! The API: sign-in first (failing closed), the contract at the door, answered from the console's own store, one audit
//! line per request that never carries a name, the jobs' status, and the web app's files.
mod common;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use common::*;
use http_body_util::BodyExt;
use msp_console::app::{router, AppState};
use msp_console::audit::AuditRecord;
use msp_console::identity::TrustedHeader;
use msp_console::ops::Store;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

struct Rig { app: axum::Router, audit: Arc<Mutex<Vec<AuditRecord>>> }

fn rig(pool: msp_console::db::Pool, static_dir: Option<std::path::PathBuf>) -> Rig { rig_with(Store::new(pool), static_dir) }
fn rig_with(store: Store, static_dir: Option<std::path::PathBuf>) -> Rig {
    let audit = Arc::new(Mutex::new(Vec::new()));
    let a = audit.clone();
    let state = AppState {
        // The trusted header from loopback stands in for any sign-in: the identity modes have their own tests.
        identity: Arc::new(TrustedHeader { header: "x-who".into(), cidrs: vec!["127.0.0.1/32".parse().unwrap()] }),
        store,
        audit: Arc::new(move |r| a.lock().unwrap().push(r)),
    };
    Rig { app: router(state, static_dir).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000)))), audit }
}
fn post(body: &str, who: Option<&str>) -> Request<Body> {
    let mut b = Request::post("/api/evidence").header("content-type", "application/json");
    if let Some(w) = who { b = b.header("x-who", w); }
    b.body(Body::from(body.to_string())).unwrap()
}
async fn json_of(r: axum::response::Response) -> Value { serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap_or(Value::Null) }

/// One synthetic client with one device carrying one vulnerable install: CVE-2026-0001, KEV-listed.
async fn seed(pool: &msp_console::db::Pool) {
    for q in [
        "INSERT INTO client (org_id, name, name_key) VALUES (7, 'Alpha Dental', 'alpha dental')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (701, 7, 'DESIGN-1', 'desktop')",
        "INSERT INTO sec_evidence (device_id, product_key, version, source) VALUES (701, 'chrome', '120.0', 'ninja_software')",
        "INSERT INTO sec_pair_cve (product_key, version, cve_id, cvss, kev) VALUES ('chrome', '120.0', 'CVE-2026-0001', 9.8, TRUE)",
    ] { msp_console::on_pool!(pool, p, _ => { sqlx::query(q).execute(p).await.unwrap(); }) }
}

#[tokio::test]
async fn without_sign_in_nothing_is_read_and_the_refusal_is_audited() {
    let r = rig(unreachable_pool(), None);
    let res = r.app.clone().oneshot(post(r#"{"op":"cves.list","params":{"org_id":7}}"#, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let a = r.audit.lock().unwrap();
    assert_eq!((a[0].status, a[0].who.clone()), (401, None));
}

#[tokio::test]
async fn a_signed_in_read_is_answered_from_the_consoles_own_store() {
    let db = test_db().await;
    seed(&db.pool).await;
    let r = rig(db.pool.clone(), None);
    let res = r.app.clone().oneshot(post(r#"{"op":"cves.list","params":{"org_id":7,"kev":true}}"#, Some("tech@example.com"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let j = json_of(res).await;
    assert_eq!((j["v"].clone(), j["op"].clone(), j["totals"]["cves"].clone()), (json!(1), json!("cves.list"), json!(1)));
    assert_eq!(j["data"][0]["cve_id"], "CVE-2026-0001");
    let other = r.app.clone().oneshot(post(r#"{"op":"cves.list","params":{"org_id":8}}"#, Some("t@d"))).await.unwrap();
    assert_eq!(json_of(other).await["totals"]["cves"], 0, "another client's CVEs aren't this one's");
}

#[tokio::test]
async fn anything_off_contract_is_a_400_and_never_reaches_the_store() {
    // The pool can't connect: a request that reached the store would be a 503, not a 400.
    let r = rig(unreachable_pool(), None);
    for b in [r#"{"op":"cve.delete","params":{}}"#, r#"{"op":"cves.list","params":{"scope":null}}"#, r#"{"op":"cves.list","params":{},"scope":{"org_id":1}}"#,
        r#"{"op":"cves.list","params":{"org_id":"7; drop"}}"#, r#"{"op":"cves.list","params":{"limit":5000}}"#, r#"{"op":"cves.list","params":{"org_id":-1}}"#,
        r#"{"op":"cve.get","params":{"cve_id":"CVE-12"}}"#, r#"{"op":"cves.list","params":{"source":["telepathy"]}}"#, "{not json", ""] {
        let res = r.app.clone().oneshot(post(b, Some("tech@example.com"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{b}");
    }
    let big = format!(r#"{{"op":"search","params":{{"q":"{}"}}}}"#, "x".repeat(100_000));
    assert_eq!(r.app.clone().oneshot(post(&big, Some("t@d"))).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_audit_line_never_carries_a_name_or_the_search_text() {
    let db = test_db().await;
    seed(&db.pool).await;
    let r = rig(db.pool.clone(), None);
    r.app.clone().oneshot(post(r#"{"op":"search","params":{"q":"DESIGN-1 Alpha Dental"}}"#, Some("tech@example.com"))).await.unwrap();
    r.app.clone().oneshot(post(r#"{"op":"cves.list","params":{"org_id":7,"kev":true}}"#, Some("tech@example.com"))).await.unwrap();
    let a = r.audit.lock().unwrap();
    let all = serde_json::to_string(&*a).unwrap();
    for s in ["DESIGN-1", "Alpha Dental"] { assert!(!all.contains(s), "the audit carries {s}"); }
    assert_eq!(a[0].params, json!({ "q": "[21 chars]" }));
    assert_eq!((a[1].who.as_deref(), a[1].op.as_deref(), a[1].rows, a[1].status), (Some("tech@example.com"), Some("cves.list"), Some(1), 200));
    assert_eq!(a[1].params, json!({ "org_id": 7, "kev": true }));
}

#[tokio::test]
async fn the_store_failing_is_the_contracts_error_not_a_crash_and_not_ready() {
    let r = rig(unreachable_pool(), None);
    let res = r.app.clone().oneshot(post(r#"{"op":"cves.list"}"#, Some("t@d"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_of(res).await["error"], "the console's database didn't answer");
    let ready = r.app.clone().oneshot(Request::get("/readyz").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    // Every op of the evidence API now reads the store, so each fails the same way.
    let later = r.app.clone().oneshot(post(r#"{"op":"product.get","params":{"product_key":"chrome"}}"#, Some("t@d"))).await.unwrap();
    assert_eq!(later.status(), StatusCode::SERVICE_UNAVAILABLE, "the other ops read the store too");
}

both!(ready_and_the_jobs_status_with_a_database);

async fn ready_and_the_jobs_status_with_a_database(db: TestDb) {
    exec(&db.pool, "INSERT INTO job (name, every_secs, last_error) VALUES ('kev', 86400, 'CISA KEV: HTTP 503')").await;
    let r = rig(db.pool.clone(), None);
    assert_eq!(r.app.clone().oneshot(Request::get("/readyz").body(Body::empty()).unwrap()).await.unwrap().status(), StatusCode::OK);
    assert_eq!(r.app.clone().oneshot(Request::get("/api/status").body(Body::empty()).unwrap()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    let s = json_of(r.app.clone().oneshot(Request::get("/api/status").header("x-who", "t@d").body(Body::empty()).unwrap()).await.unwrap()).await;
    assert_eq!((s["jobs"][0]["job"].clone(), s["jobs"][0]["last_error"].clone()), (json!("kev"), json!("CISA KEV: HTTP 503")));
    // And the store: which kind, whether similar-CVE search is on, whose the backups are. Never a path or a URL.
    let kind = match db.backend { Backend::Sqlite => "sqlite", Backend::Postgres => "postgresql" };
    assert_eq!(s["store"]["kind"], json!(kind), "{s}");
    assert!(s["store"]["vectors"]["on"].is_boolean() && s["store"]["backups"].is_string(), "{s}");
    // PostgreSQL's link: the test server's URL sets no sslmode, so the status says TLS isn't required. SQLite has none.
    match db.backend {
        Backend::Postgres => assert!(s["store"]["tls"]["sslmode"] == json!("prefer") && s["store"]["tls"]["note"].as_str().unwrap().contains("TLS isn't required"), "{s}"),
        Backend::Sqlite => assert!(s["store"].get("tls").is_none(), "{s}"),
    }
    // And the embedder: this rig has none, so it's off and says why.
    assert_eq!(s["embedder"], json!({ "on": false, "model": msp_console::embed::MODEL_KEY, "why": msp_console::ops::NO_EMBEDDER }), "{s}");
    let text = s.to_string();
    assert!(!text.contains("console.db") && !text.contains("postgres://"), "{text}");
}

// ---------------------------------------------------------------- cve.similar

#[tokio::test]
async fn similar_cves_off_is_no_rows_and_the_reason_and_still_audited() {
    let db = test_db().await;
    let off = "similar-CVE search is off: the embedder is turned off (EMBEDDER=off)";
    let r = rig_with(Store::new(db.pool.clone()).with_similar(msp_console::embed::State::Off(off.into())), None);
    let res = r.app.clone().oneshot(post(r#"{"op":"cve.similar","params":{"cve_id":"CVE-2026-0001"}}"#, Some("tech@example.com"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let b = json_of(res).await;
    assert_eq!((b["op"].clone(), b["data"].clone(), b["off"].clone()), (json!("cve.similar"), json!([]), json!(off)), "{b}");
    // Nought is refused at the door (the contract's own range), and the op's own range is 1 to 50 even when it's
    // called without the door.
    let res = r.app.clone().oneshot(post(r#"{"op":"cve.similar","params":{"cve_id":"CVE-2026-0001","limit":0}}"#, Some("tech@example.com"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let store = Store::new(db.pool.clone()).with_similar(msp_console::embed::State::Off(off.into()));
    for k in [0u32, 51] {
        let req = msp_console::contract::EvidenceRequest { op: msp_console::contract::ReadOp::CveSimilar,
            params: msp_console::contract::Params { cve_id: Some("CVE-2026-0001".into()), limit: Some(k), ..Default::default() } };
        let (code, a) = store.call(&req).await;
        assert_eq!((code, a["error"].as_str()), (400, Some("limit must be 1 to 50 for cve.similar")), "k={k}");
    }
    // Past 50 is refused, like any out-of-range parameter, and that's audited too.
    let res = r.app.clone().oneshot(post(r#"{"op":"cve.similar","params":{"cve_id":"CVE-2026-0001","limit":51}}"#, Some("tech@example.com"))).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(json_of(res).await["error"].as_str().unwrap().contains("1 to 50"));
    let a = r.audit.lock().unwrap();
    assert_eq!(a.iter().map(|x| (x.op.as_deref(), x.status, x.rows)).collect::<Vec<_>>(), [(Some("cve.similar"), 200, Some(0)), (None, 400, None), (Some("cve.similar"), 400, None)]);
}

both!(similar_cves_on_are_nearest_first_with_devices_scoped_to_the_client);

/// On the real model: the embed job fills the vectors, and cve.similar answers from them, nearest first, each with its
/// score, KEV and how many of the client's devices carry it. A CVE the job hasn't reached says so.
async fn similar_cves_on_are_nearest_first_with_devices_scoped_to_the_client(db: TestDb) {
    let Some(e) = embedder() else { return };
    if msp_console::vectors::available(&db.pool).await.is_err() { eprintln!("this PostgreSQL server has no pgvector: nothing to search"); return; }
    seed(&db.pool).await;
    exec(&db.pool, "INSERT INTO sec_kev (cve_id, name) VALUES ('CVE-2026-0001', 'Chrome V8 type confusion')").await;
    nvd_cve(&db.pool, "CVE-2026-0001", Some("Type Confusion in the V8 JavaScript engine in Google Chrome before 131.0.6778.69 let a remote attacker perform out of bounds memory access through a crafted HTML page."), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1001", Some("Type confusion in V8 in Google Chrome prior to 130.0.6723.91 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page."), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1003", Some("Issue summary: processing a maliciously formatted PKCS12 file may lead OpenSSL to crash, leading to a potential denial of service."), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1004", Some("An SQL injection vulnerability in the login form of the admin panel allows unauthenticated attackers to execute arbitrary SQL commands via the username parameter."), "2026-10-01T00:00:00.000Z", false).await;
    msp_console::embed_job::EmbedJob::new(e.clone()).run(&db.pool).await.unwrap();
    let r = rig_with(Store::new(db.pool.clone()).with_similar(msp_console::embed::State::On(e)), None);
    let ask = |body: &'static str| { let app = r.app.clone(); async move { let res = app.oneshot(post(body, Some("tech@example.com"))).await.unwrap(); (res.status(), json_of(res).await) } };
    let (st, b) = ask(r#"{"op":"cve.similar","params":{"cve_id":"cve-2026-1001","org_id":7,"limit":3}}"#).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let d = b["data"].as_array().unwrap();
    assert_eq!(d.len(), 3, "{b}");
    assert_eq!((d[0]["cve_id"].clone(), d[0]["kev"].clone(), d[0]["devices"].clone(), d[0]["cvss"].clone()), (json!("CVE-2026-0001"), json!(true), json!(1), json!(7.5)), "{b}");
    assert!(d.windows(2).all(|w| w[0]["distance"].as_f64() <= w[1]["distance"].as_f64()), "nearest first: {b}");
    assert!(d.iter().all(|x| x["cve_id"] != "CVE-2026-1001"), "never itself: {b}");
    assert_eq!(b["model"], json!(msp_console::embed::MODEL_KEY));
    // Another client's devices aren't counted.
    let (_, b) = ask(r#"{"op":"cve.similar","params":{"cve_id":"CVE-2026-1001","org_id":8,"limit":1}}"#).await;
    assert_eq!((b["data"][0]["cve_id"].clone(), b["data"][0]["devices"].clone()), (json!("CVE-2026-0001"), json!(0)), "{b}");
    // A CVE with no description in the store has no vector yet: no rows, and a note that says so.
    let (st, b) = ask(r#"{"op":"cve.similar","params":{"cve_id":"CVE-2026-9999"}}"#).await;
    assert_eq!((st, b["data"].clone()), (StatusCode::OK, json!([])), "{b}");
    assert!(b["note"].as_str().unwrap().contains("hasn't been compared yet") && b.get("off").is_none(), "{b}");
    // The audit line names the op and the CVE asked about, never a description.
    let a = r.audit.lock().unwrap();
    assert!(a.iter().all(|x| x.op.as_deref() == Some("cve.similar")));
    assert!(!format!("{:?}", a.iter().map(|x| x.params.to_string()).collect::<Vec<_>>()).contains("Chrome"));
}

#[tokio::test]
async fn me_health_headers_and_the_web_app() {
    let dir = std::env::temp_dir().join(format!("msp-web-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<!doctype html><title>MSP Security Console</title>").unwrap();
    let r = rig(unreachable_pool(), Some(dir));
    let me = r.app.clone().oneshot(Request::get("/api/me").header("x-who", "tech@example.com").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(json_of(me).await, json!({ "email": "tech@example.com", "admin": false, "logout": null }));
    assert_eq!(r.app.clone().oneshot(Request::get("/api/me").body(Body::empty()).unwrap()).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    let health = r.app.clone().oneshot(Request::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(health.headers()["x-content-type-options"], "nosniff");
    assert!(health.headers()["content-security-policy"].to_str().unwrap().contains("frame-ancestors 'none'"));
    assert_eq!(health.headers()["referrer-policy"], "no-referrer");
    let deep = r.app.clone().oneshot(Request::get("/some/view").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(deep.status(), StatusCode::OK, "any other path is the web app's index");
}

#[tokio::test]
async fn an_unknown_api_path_is_a_json_404_behind_sign_in_never_the_web_app() {
    let dir = std::env::temp_dir().join(format!("msp-web-404-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<!doctype html><title>MSP Security Console</title>").unwrap();
    let r = rig(unreachable_pool(), Some(dir));
    for path in ["/api/setup/state", "/api/nope/deeper", "/api"] {
        let anon = r.app.clone().oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(anon.status(), StatusCode::UNAUTHORIZED, "{path}: sign-in first");
        let res = r.app.clone().oneshot(Request::get(path).header("x-who", "pat@example.com").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(res.headers()["content-type"].to_str().unwrap().starts_with("application/json"), "{path}");
        assert_eq!(json_of(res).await, json!({ "error": "there's no such API call" }), "{path}");
    }
    let post = r.app.clone().oneshot(Request::post("/api/setup/save").header("x-who", "pat@example.com").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(post.status(), StatusCode::NOT_FOUND, "any method");
}
