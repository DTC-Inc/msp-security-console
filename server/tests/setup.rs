//! The first-run setup's JSON API: the web app's wizard at /setup and nothing else while unconfigured; a one-time token
//! that unlocks the API with a sealed cookie, ten wrong tries and it locks; state that never shows a secret; each
//! section's live test against stand-in vendors; a save that keeps only the chosen sections' settings, never the
//! environment's, encrypts its secrets and round-trips through start-up; an audit line for every call.
mod common;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use http_body_util::BodyExt;
use msp_console::audit::AuditRecord;
use msp_console::config::{load, AuthConfig, Startup};
use msp_console::setup::{router, Setup, MAX_FAILURES};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

struct Rig { app: axum::Router, s: Arc<Setup>, dir: PathBuf, audit: Arc<Mutex<Vec<AuditRecord>>>, logs: Arc<Mutex<Vec<Value>>>, saved: Arc<AtomicU32> }
impl Rig {
    fn config(&self) -> PathBuf { self.dir.join("config/config.json") }
    fn key(&self) -> PathBuf { self.dir.join("key/master.key") }
    fn db(&self) -> String { self.dir.join("data/console.db").to_str().unwrap().into() }
    fn env(&self) -> HashMap<String, String> { self.s.env.clone() }
    fn ops(&self) -> Vec<(String, u16)> { self.audit.lock().unwrap().iter().map(|r| (r.op.clone().unwrap(), r.status)).collect() }
    async fn send(&self, r: Request<Body>) -> (StatusCode, Value, axum::http::HeaderMap) {
        let res = self.app.clone().oneshot(r).await.unwrap();
        let (st, h) = (res.status(), res.headers().clone());
        let b = res.into_body().collect().await.unwrap().to_bytes();
        (st, serde_json::from_slice(&b).unwrap_or(Value::String(String::from_utf8_lossy(&b).into())), h)
    }
    async fn unlock(&self) -> String {
        let (st, _, h) = self.send(post("/api/setup/unlock", json!({ "token": self.s.token }), None)).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        h["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string()
    }
}

fn rig_with(extra: &[(&str, &str)], static_web: bool) -> Rig { rig_full(extra, static_web, None) }
fn rig_full(extra: &[(&str, &str)], static_web: bool, timeout: Option<Duration>) -> Rig {
    let dir = temp_dir("setup");
    for d in ["config", "data", "web"] { std::fs::create_dir_all(dir.join(d)).unwrap(); }
    std::fs::write(dir.join("web/index.html"), "<!doctype html><title>wizard</title><div id=root></div>").unwrap();
    std::fs::write(dir.join("web/app.js"), "console.log('app')").unwrap();
    let mut env: HashMap<String, String> = [("CONFIG_PATH", dir.join("config/config.json")), ("MASTER_KEY_PATH", dir.join("key/master.key"))]
        .into_iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string())).collect();
    env.insert("MSP_ENV".into(), "development".into());
    if static_web { env.insert("STATIC_DIR".into(), dir.join("web").to_str().unwrap().into()); }
    for (k, v) in extra { env.insert(k.to_string(), v.to_string()); }
    let saved = Arc::new(AtomicU32::new(0));
    let s2 = saved.clone();
    let (audit, logs) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
    let (a, l) = (audit.clone(), logs.clone());
    let mut s = Setup::new(env, msp_console::http_client(), Arc::new(move || { s2.fetch_add(1, Ordering::SeqCst); }));
    s.audit = Arc::new(move |r| a.lock().unwrap().push(r));
    s.log = Arc::new(move |v| l.lock().unwrap().push(v));
    if let Some(t) = timeout { s.test_timeout = t; }
    let s = Arc::new(s);
    Rig { app: router(s.clone()), s, dir, audit, logs, saved }
}
fn rig() -> Rig { rig_with(&[], true) }

fn post(path: &str, body: Value, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::post(path).header("content-type", "application/json");
    if let Some(c) = cookie { b = b.header("cookie", c); }
    b.body(Body::from(body.to_string())).unwrap()
}
fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path);
    if let Some(c) = cookie { b = b.header("cookie", c); }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn while_unconfigured_the_wizard_and_its_assets_are_served_and_nothing_else() {
    let r = rig();
    for p in ["/setup", "/setup/", "/setup/connectors/halo"] {
        let (st, body, _) = r.send(get(p, None)).await;
        assert_eq!(st, StatusCode::OK, "{p}");
        assert!(body.as_str().unwrap().contains("<title>wizard</title>"), "{p}: the app's index.html");
    }
    let (st, body, _) = r.send(get("/app.js", None)).await;
    assert_eq!((st, body.as_str().unwrap()), (StatusCode::OK, "console.log('app')"), "an asset, as it is");
    for req in [get("/", None), get("/api/evidence", None), get("/api/me", None), get("/nope.js", None), post("/api/evidence", json!({}), None), get("/api/setup/nothing", None)] {
        let p = req.uri().to_string();
        let res = r.app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{p}");
        assert_eq!(res.headers()["location"], "/setup", "{p}");
    }
    assert_eq!(r.send(get("/readyz", None)).await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.send(get("/healthz", None)).await.0, StatusCode::OK);
    // Without the web app's files, setup says so rather than serving nothing.
    let bare = rig_with(&[], false);
    assert_eq!(bare.send(get("/setup", None)).await.0, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_token_unlocks_with_a_sealed_cookie_and_ten_wrong_ones_lock_it() {
    let r = rig();
    let (st, body, h) = r.send(post("/api/setup/unlock", json!({ "token": r.s.token }), None)).await;
    assert_eq!(st, StatusCode::NO_CONTENT, "{body}");
    let c = h["set-cookie"].to_str().unwrap();
    assert!(c.starts_with("msp_setup=") && c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Max-Age=1800"), "{c}");
    assert!(!c.contains("Secure"), "plain http outside production: not Secure, so a laptop's http://localhost works ({c})");
    assert!(!c.contains(&r.s.token), "the cookie isn't the token");
    let res = r.app.clone().oneshot(Request::post("/api/setup/unlock").header("content-type", "application/json").header("x-forwarded-proto", "https")
        .body(Body::from(json!({ "token": r.s.token }).to_string())).unwrap()).await.unwrap();
    assert!(res.headers()["set-cookie"].to_str().unwrap().contains("Secure"), "behind https: Secure");
    let prod = rig_with(&[("MSP_ENV", "production")], true);
    let (_, _, h) = prod.send(post("/api/setup/unlock", json!({ "token": prod.s.token }), None)).await;
    assert!(h["set-cookie"].to_str().unwrap().contains("Secure"), "production: always Secure");

    let (st, body, _) = r.send(post("/api/setup/unlock", json!({ "token": "guess" }), None)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().unwrap().contains("setup token"), "{body}");
    for _ in 1..MAX_FAILURES { assert_eq!(r.send(post("/api/setup/unlock", json!({ "token": "guess" }), None)).await.0, StatusCode::UNAUTHORIZED); }
    let (st, body, h) = r.send(post("/api/setup/unlock", json!({ "token": r.s.token }), None)).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS, "the right token after ten wrong ones: {body}");
    assert!(h.get("set-cookie").is_none());
    let ops = r.ops();
    assert_eq!(ops.len(), 2 + MAX_FAILURES as usize + 1, "one audit line per call: {ops:?}");
    assert!(ops.iter().all(|(op, _)| op == "setup.unlock"));
    assert_eq!(ops.iter().filter(|(_, s)| *s == 401).count(), MAX_FAILURES as usize);
    assert_eq!(ops.last().unwrap().1, 429);
    assert!(r.audit.lock().unwrap().iter().all(|a| a.who.as_deref() == Some("setup") && a.params == json!({})));
}

/// Many wrong tokens at once: exactly ten are compared, however they interleave, and the right one then gets 429 too.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_wrong_tokens_never_get_more_than_ten_tries() {
    let r = rig();
    let tasks: Vec<_> = (0..200).map(|i| { let app = r.app.clone(); tokio::spawn(async move {
        app.oneshot(post("/api/setup/unlock", json!({ "token": format!("guess-{i}") }), None)).await.unwrap().status()
    }) }).collect();
    let mut by = HashMap::<u16, usize>::new();
    for t in tasks { *by.entry(t.await.unwrap().as_u16()).or_default() += 1; }
    assert_eq!((by.get(&401).copied(), by.get(&429).copied()), (Some(MAX_FAILURES as usize), Some(200 - MAX_FAILURES as usize)), "{by:?}");
    assert_eq!(r.send(post("/api/setup/unlock", json!({ "token": r.s.token }), None)).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.audit.lock().unwrap().len(), 201, "one audit line each");
}

#[tokio::test]
async fn every_call_but_unlock_needs_the_cookie() {
    let r = rig();
    let other = rig();
    let foreign = other.unlock().await; // sealed by another process's key
    for cookie in [None, Some("msp_setup=forged"), Some(foreign.as_str())] {
        for req in [get("/api/setup/state", cookie), post("/api/setup/test", json!({ "section": "nvd", "values": {} }), cookie),
                    post("/api/setup/save", json!({ "values": { "AUTH_MODE": "proxy" } }), cookie)] {
            let p = req.uri().to_string();
            let (st, body, _) = r.send(req).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{p} with {cookie:?}");
            assert!(body["error"].is_string(), "{body}");
        }
    }
    let ops = r.ops();
    assert_eq!(ops.len(), 9, "{ops:?}");
    assert!(ops.iter().all(|(_, s)| *s == 401));
    assert_eq!(ops.iter().filter(|(o, _)| o == "setup.state").count(), 3);
    assert_eq!(ops.iter().filter(|(o, _)| o == "setup.test.nvd").count(), 3);
    assert_eq!(ops.iter().filter(|(o, _)| o == "setup.save").count(), 3);
    assert!(!r.config().exists() && r.saved.load(Ordering::SeqCst) == 0);
    // And the cookie, once unlocked, is enough.
    let c = r.unlock().await;
    assert_eq!(r.send(get("/api/setup/state", Some(&c))).await.0, StatusCode::OK);
}

#[tokio::test]
async fn state_hides_secrets_and_marks_what_the_environment_sets() {
    let dir = temp_dir("setup-state");
    let ninja_file = dir.join("ninja-secret");
    std::fs::write(&ninja_file, NINJA_SECRET).unwrap();
    let r = rig_with(&[("NINJA_CLIENT_SECRET_FILE", ninja_file.to_str().unwrap()), ("NVD_URL", "https://nvd.example.com/rest"), ("HALO_CLIENT_SECRET", HALO_SECRET)], true);
    // Something already stored: a plain setting and an encrypted secret.
    let k = msp_console::secrets::generate(&r.key()).unwrap();
    std::fs::write(r.config(), json!({ "ACCESS_AUD": "aud-1", "OIDC_CLIENT_SECRET": k.encrypt("OIDC_CLIENT_SECRET", "stored-oidc-secret-c4e1") }).to_string()).unwrap();
    let c = r.unlock().await;
    let (st, body, _) = r.send(get("/api/setup/state", Some(&c))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["sections"], json!(["database", "auth", "ninja", "halo", "nvd", "msrc", "blackpoint", "shodan"]));
    let keys = body["keys"].as_object().unwrap();
    assert_eq!(keys.len(), msp_console::setup::WIZARD.len(), "every key the wizard knows");
    let k = |n: &str| (keys[n]["set"].clone(), keys[n]["env"].clone(), keys[n]["value"].clone());
    assert_eq!(k("NINJA_CLIENT_SECRET"), (json!(true), json!(true), Value::Null), "set by environment, as a file");
    assert_eq!(k("HALO_CLIENT_SECRET"), (json!(true), json!(true), Value::Null));
    assert_eq!(k("NVD_URL"), (json!(true), json!(true), json!("https://nvd.example.com/rest")), "a plain setting shows its value");
    assert_eq!(k("OIDC_CLIENT_SECRET"), (json!(true), json!(false), Value::Null), "stored, never shown");
    assert_eq!(k("ACCESS_AUD"), (json!(true), json!(false), json!("aud-1")));
    assert_eq!(k("NVD_API_KEY"), (json!(false), json!(false), Value::Null));
    assert_eq!(k("DATABASE_PATH"), (json!(false), json!(false), Value::Null));
    assert_eq!((keys["SESSION_KEY"]["secret"].clone(), keys["SESSION_KEY"]["section"].clone()), (json!(true), json!("auth")));
    let text = body.to_string();
    for s in [NINJA_SECRET, HALO_SECRET, "stored-oidc-secret-c4e1", "enc:v1:"] { assert!(!text.contains(s), "{s} in state"); }
    assert_eq!(r.ops(), vec![("setup.unlock".into(), 204), ("setup.state".into(), 200)]);
}

async fn test_call(r: &Rig, c: &str, section: &str, values: Value) -> Value {
    let (st, body, _) = r.send(post("/api/setup/test", json!({ "section": section, "values": values }), Some(c))).await;
    assert_eq!(st, StatusCode::OK, "{section}: {body}");
    for k in ["ok", "message", "status", "detail"] { assert!(body.get(k).is_some(), "{section}: {k} missing from {body}"); }
    let m = body["message"].as_str().unwrap();
    assert!(!m.contains("http://") && !m.contains("https://") && !m.contains('?'), "{section}: a URL in the message: {m}");
    for s in [NINJA_SECRET, HALO_SECRET, NVD_KEY, "wrong-secret-", "bad-key-"] { assert!(!body.to_string().contains(s), "{section}: {s} in {body}"); }
    body
}

#[tokio::test]
async fn ninjaone_is_tested_live_with_a_token_and_one_page_of_organizations() {
    let (v, h) = vendors().await;
    let r = rig();
    let c = r.unlock().await;
    let base = format!("{v}/ninja");
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": base, "NINJA_CLIENT_ID": "client-1", "NINJA_CLIENT_SECRET": NINJA_SECRET })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone(), a["detail"].clone()), (json!(true), json!(200), json!({ "organizations_visible": true, "devices_reporting_processes": 2 })), "{a}");
    assert!(a["message"].as_str().unwrap().contains("2 devices report running processes"), "{a}");
    assert_eq!((hits(&h, "ninja_token"), hits(&h, "ninja_orgs"), hits(&h, "ninja_fields")), (1, 1, 1));
    // Running processes off: no custom-field call. A field nobody reports says to deploy the script.
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": base, "NINJA_CLIENT_ID": "client-1", "NINJA_CLIENT_SECRET": NINJA_SECRET, "NINJA_PROCESS_FIELD": "off" })).await;
    assert_eq!(a["detail"]["processes"], json!("off"), "{a}");
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": base, "NINJA_CLIENT_ID": "client-1", "NINJA_CLIENT_SECRET": NINJA_SECRET, "NINJA_PROCESS_FIELD": "myInventory" })).await;
    assert!(a["ok"] == json!(true) && a["message"].as_str().unwrap().contains("endpoint/README.md"), "{a}");
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": base, "NINJA_CLIENT_ID": "client-1", "NINJA_CLIENT_SECRET": NINJA_SECRET, "NINJA_PROCESS_FIELD": "bad name&x=1" })).await;
    assert_eq!(a["ok"], json!(false), "{a}");
    assert_eq!((hits(&h, "ninja_token"), hits(&h, "ninja_orgs"), hits(&h, "ninja_fields")), (4, 4, 2));
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": base, "NINJA_CLIENT_ID": "client-1", "NINJA_CLIENT_SECRET": "wrong-secret-ninja" })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(401)), "{a}");
    let m = a["message"].as_str().unwrap();
    assert!(m.contains("NinjaOne") && m.contains("401") && !m.contains("no client with secret"), "the status and a short reason, never the vendor's text: {m}");
    assert_eq!((hits(&h, "ninja_token"), hits(&h, "ninja_orgs")), (5, 4), "no organizations call without a token");
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": base })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), Value::Null));
    assert!(a["message"].as_str().unwrap().contains("NINJA_CLIENT_SECRET"));
    let ops = r.ops();
    assert_eq!(ops.iter().filter(|(o, s)| o == "setup.test.ninja" && *s == 200).count(), 6, "{ops:?}");
    for a in r.audit.lock().unwrap().iter() { let t = serde_json::to_string(a).unwrap(); assert!(!t.contains(NINJA_SECRET) && !t.contains("client-1"), "{t}"); }
}

#[tokio::test]
async fn a_secret_left_out_falls_back_only_while_its_addresses_are_unchanged() {
    let (v, h) = vendors().await;
    let dir = temp_dir("setup-fallback");
    std::fs::write(dir.join("ninja"), format!("{NINJA_SECRET}\n")).unwrap();
    // The secret by environment (a mounted file), NinjaOne's address from the store; NVD's key and address both by
    // environment; HaloPSA's secret and address both stored.
    let r = rig_with(&[("NINJA_CLIENT_SECRET_FILE", dir.join("ninja").to_str().unwrap()), ("NVD_API_KEY", NVD_KEY), ("NVD_URL", &format!("{v}/nvd")), ("NVD_FEEDS", "curated")], true);
    let k = msp_console::secrets::generate(&r.key()).unwrap();
    std::fs::write(r.config(), json!({ "NINJA_BASE_URL": format!("{v}/ninja"), "NINJA_CLIENT_ID": "client-1",
        "HALO_BASE_URL": format!("{v}/halo/api"), "HALO_CLIENT_ID": "client-2", "HALO_CLIENT_SECRET": k.encrypt("HALO_CLIENT_SECRET", HALO_SECRET) }).to_string()).unwrap();
    let c = r.unlock().await;
    // Unchanged addresses: left out, or sent as they are (a trailing slash is the same address).
    assert_eq!(test_call(&r, &c, "ninja", json!({})).await["ok"], json!(true));
    assert_eq!(test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": format!("{v}/ninja/") })).await["ok"], json!(true));
    assert_eq!(test_call(&r, &c, "halo", json!({ "HALO_BASE_URL": format!("{v}/halo/api") })).await["ok"], json!(true));
    assert_eq!((hits(&h, "ninja_orgs"), hits(&h, "halo_clients")), (2, 1));
    // A new address with a secret the caller didn't type: refused, and nothing is sent anywhere.
    for (section, values) in [("ninja", json!({ "NINJA_BASE_URL": format!("{v}/evil/ninja") })),
                              ("halo", json!({ "HALO_BASE_URL": format!("{v}/evil/halo/api") })),
                              ("halo", json!({ "HALO_AUTH_URL": format!("{v}/evil/token") })),
                              // The caller's own secret doesn't unlock the environment's: the environment's wins.
                              ("ninja", json!({ "NINJA_BASE_URL": format!("{v}/evil/ninja"), "NINJA_CLIENT_SECRET": "wrong-secret-typed" }))] {
        let a = test_call(&r, &c, section, values.clone()).await;
        assert_eq!(a, json!({ "ok": false, "message": "Enter the secret again to test a new address.", "status": null, "detail": null }), "{values}");
    }
    assert_eq!((hits(&h, "evil"), hits(&h, "ninja_token"), hits(&h, "halo_token")), (0, 2, 1), "no request left for any address");
    // An address the environment sets can't be changed by the caller at all: it's used as it is.
    assert_eq!(test_call(&r, &c, "nvd", json!({ "NVD_URL": format!("{v}/evil/nvd") })).await["detail"], json!({ "total_cves": 250001, "keyed": true, "feeds": "curated" }));
    assert_eq!(hits(&h, "evil"), 0);
    // A secret typed with the new address goes there: the caller already has it.
    let a = test_call(&r, &c, "halo", json!({ "HALO_BASE_URL": format!("{v}/evil/halo/api"), "HALO_CLIENT_SECRET": "wrong-secret-typed-halo" })).await;
    assert_eq!(a["ok"], json!(true), "{a}");
    assert_eq!(hits(&h, "evil"), 5, "the token, the client list, and Halo's three ticket lists");
    // Save keeps the stored secret only with its stored address, by the same rule.
    let save = |values: Value| post("/api/setup/save", json!({ "values": values }), Some(&c));
    let base = json!({ "DATABASE_PATH": r.db(), "AUTH_MODE": "proxy", "PROXY_KIND": "trusted_header", "TRUSTED_HEADER": "X-Email", "TRUSTED_PROXY_CIDRS": "10.0.5.0/24" });
    let mut moved = base.clone(); moved["HALO_BASE_URL"] = json!(format!("{v}/evil/halo/api")); moved["HALO_CLIENT_ID"] = json!("client-2");
    let (st, body, _) = r.send(save(moved)).await;
    assert_eq!((st, body), (StatusCode::BAD_REQUEST, json!({ "error": "Enter the secret again to save a new address.", "section": "halo" })));
    assert_eq!(r.saved.load(Ordering::SeqCst), 0);
    let mut kept = base.clone(); kept["HALO_BASE_URL"] = json!(format!("{v}/halo/api")); kept["HALO_CLIENT_ID"] = json!("client-2");
    kept["NINJA_BASE_URL"] = json!(format!("{v}/ninja")); kept["NINJA_CLIENT_ID"] = json!("client-1");
    let (st, body, _) = r.send(save(kept)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let file: HashMap<String, String> = serde_json::from_str(&std::fs::read_to_string(r.config()).unwrap()).unwrap();
    assert_eq!(k.decrypt("HALO_CLIENT_SECRET", &file["HALO_CLIENT_SECRET"]).unwrap(), HALO_SECRET, "kept, with its address");
    assert!(!file.contains_key("NINJA_CLIENT_SECRET"), "the environment's is never written");
}

#[tokio::test]
async fn a_saved_oidc_secret_is_kept_only_with_its_issuer() {
    let r = rig();
    let k = msp_console::secrets::generate(&r.key()).unwrap();
    std::fs::write(r.config(), json!({ "OIDC_ISSUER": "https://login.example.com/t/v2.0", "OIDC_CLIENT_SECRET": k.encrypt("OIDC_CLIENT_SECRET", "a-stored-oidc-secret") }).to_string()).unwrap();
    let c = r.unlock().await;
    let oidc = |issuer: &str| json!({ "values": { "DATABASE_PATH": r.db(), "AUTH_MODE": "oidc", "OIDC_ISSUER": issuer, "OIDC_CLIENT_ID": "client-1",
        "OIDC_ALLOWED_GROUP": "group-1", "SESSION_KEY": "a-session-key-of-at-least-thirty-two-characters", "PUBLIC_URL": "https://console.example.com" } });
    let (st, body, _) = r.send(post("/api/setup/save", oidc("https://login.example.org/other/v2.0"), Some(&c))).await;
    assert_eq!((st, body["section"].clone()), (StatusCode::BAD_REQUEST, json!("auth")), "{body}");
    let (st, body, _) = r.send(post("/api/setup/save", oidc("https://login.example.com/t/v2.0"), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn halopsa_is_tested_live_with_a_token_and_the_client_count() {
    let (v, h) = vendors().await;
    let r = rig();
    let c = r.unlock().await;
    let vals = json!({ "HALO_BASE_URL": format!("{v}/halo/api"), "HALO_CLIENT_ID": "client-1", "HALO_CLIENT_SECRET": HALO_SECRET });
    let a = test_call(&r, &c, "halo", vals.clone()).await;
    assert_eq!((a["ok"].clone(), a["status"].clone(), a["detail"].clone()), (json!(true), json!(200), json!({ "clients": 3,
        "ticket_types": [{ "id": 31, "name": "Security Alert" }], "statuses": [{ "id": 1, "name": "New" }, { "id": 9, "name": "Closed" }], "priorities": [{ "id": 3, "name": "Medium" }] })),
        "Halo's own lists for the ticket settings, hidden ones left out, priorities by their integer id: {a}");
    let mut with_tenant = vals.clone();
    with_tenant["HALO_TENANT"] = json!(HALO_TENANT);
    assert_eq!(test_call(&r, &c, "halo", with_tenant).await["ok"], json!(true));
    assert_eq!((hits(&h, "halo_token"), hits(&h, "halo_tenant"), hits(&h, "halo_clients")), (2, 1, 2));
    let mut wrong = vals.clone();
    wrong["HALO_CLIENT_SECRET"] = json!("wrong-secret-halo");
    let a = test_call(&r, &c, "halo", wrong).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(401)), "{a}");
    // HALO_AUTH_URL, when it's set, is where the token comes from.
    let mut elsewhere = vals.clone();
    elsewhere["HALO_AUTH_URL"] = json!(format!("{v}/nowhere/token"));
    let a = test_call(&r, &c, "halo", elsewhere).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(404)), "{a}");
    assert_eq!(hits(&h, "halo_token"), 3);
}

#[tokio::test]
async fn nvd_is_tested_with_and_without_a_key_and_a_refused_key_is_named() {
    let (v, h) = vendors().await;
    let r = rig();
    let c = r.unlock().await;
    let url = format!("{v}/nvd");
    let feeds = format!("{v}/feeds");
    let a = test_call(&r, &c, "nvd", json!({ "NVD_URL": url, "NVD_API_KEY": NVD_KEY, "NVD_FEED_URL": feeds })).await;
    assert_eq!((a["ok"].clone(), a["detail"].clone()), (json!(true), json!({ "total_cves": 250001, "keyed": true, "feeds": "full" })), "{a}");
    assert_eq!(hits(&h, "nvd_feeds"), 1, "the full dataset's feed host was checked too");
    let a = test_call(&r, &c, "nvd", json!({ "NVD_URL": url, "NVD_FEEDS": "curated" })).await;
    assert_eq!((a["ok"].clone(), a["detail"].clone()), (json!(true), json!({ "total_cves": 250000, "keyed": false, "feeds": "curated" })), "{a}");
    assert_eq!(hits(&h, "nvd_feeds"), 1, "curated reads no feed");
    let a = test_call(&r, &c, "nvd", json!({ "NVD_URL": url, "NVD_FEED_URL": format!("{v}/nowhere") })).await;
    assert_eq!(a["ok"], json!(false), "a feed host that refuses: {a}");
    let a = test_call(&r, &c, "nvd", json!({ "NVD_URL": url, "NVD_API_KEY": "bad-key-0001" })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(404)), "{a}");
    assert!(a["message"].as_str().unwrap().contains("NVD refused that API key"), "{a}");
    assert_eq!(hits(&h, "nvd"), 4);
}

#[tokio::test]
async fn sign_in_is_tested_for_each_kind() {
    let (v, h) = vendors().await;
    let r = rig_with(&[("ACCESS_CERTS_URL", &format!("{v}/cdn-cgi/access/certs"))], true);
    let c = r.unlock().await;
    let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "proxy", "PROXY_KIND": "cloudflare_access", "ACCESS_TEAM_DOMAIN": "team.example.com", "ACCESS_AUD": "aud" })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(true), json!(200)), "{a}");
    assert!(a["message"].as_str().unwrap().contains("2 signing keys"));
    assert_eq!(hits(&h, "certs"), 1);
    let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "oidc", "OIDC_ISSUER": format!("{v}/idp/v2.0"), "OIDC_CLIENT_SECRET": "an-oidc-secret" })).await;
    assert_eq!(a["ok"], json!(true), "{a}");
    let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "oidc", "OIDC_ISSUER": format!("{v}/idp/v2.0/") })).await;
    assert_eq!(a["ok"], json!(true), "a trailing slash is the same issuer: {a}");
    let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "oidc", "OIDC_ISSUER": format!("{v}/nowhere") })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(404)), "{a}");
    assert_eq!(hits(&h, "discovery"), 2);
    let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "proxy", "PROXY_KIND": "trusted_header", "TRUSTED_HEADER": "X-Forwarded-Email", "TRUSTED_PROXY_CIDRS": "10.0.5.0/24, 10.0.9.4/32" })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(true), Value::Null), "{a}");
    assert!(a["message"].as_str().unwrap().contains("2 proxy address ranges"));
    let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "proxy", "PROXY_KIND": "trusted_header", "TRUSTED_HEADER": "X-Forwarded-Email", "TRUSTED_PROXY_CIDRS": "0.0.0.0/0" })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("whole internet"), "{a}");
    let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "dev_insecure" })).await;
    assert_eq!((a["ok"].clone(), a["message"].clone()), (json!(true), json!(msp_console::setup::NO_SIGN_IN)), "only this computer, outside production: {a}");
    // In production an issuer must be https, before anything is fetched.
    let prod = rig_with(&[("MSP_ENV", "production")], true);
    let pc = prod.unlock().await;
    let a = test_call(&prod, &pc, "auth", json!({ "AUTH_MODE": "oidc", "OIDC_ISSUER": format!("{v}/idp/v2.0") })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("https"), "{a}");
    assert_eq!(hits(&h, "discovery"), 2);
}

#[tokio::test]
async fn the_database_is_tested_without_making_or_migrating_it() {
    let r = rig();
    let c = r.unlock().await;
    let a = test_call(&r, &c, "database", json!({ "DATABASE_PATH": r.db() })).await;
    assert_eq!(a, json!({ "ok": true, "message": "The database file can be created and written.", "status": null, "detail": null }));
    assert!(!PathBuf::from(r.db()).exists(), "the test made no database");
    assert_eq!(std::fs::read_dir(r.dir.join("data")).unwrap().count(), 0, "and left no probe behind");
    let a = test_call(&r, &c, "database", json!({ "DATABASE_PATH": r.dir.join("missing/console.db").to_str().unwrap() })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("doesn't exist"), "{a}");
    let a = test_call(&r, &c, "database", json!({ "DATABASE_PATH": ":memory:" })).await;
    assert_eq!(a["ok"], json!(false));
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let ro = r.dir.join("ro");
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let a = test_call(&r, &c, "database", json!({ "DATABASE_PATH": ro.join("console.db").to_str().unwrap() })).await;
        assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("can't write"), "{a}");
    }
}

#[tokio::test]
async fn a_redirect_is_never_followed_so_no_secret_is_resent_elsewhere() {
    let (v, h) = vendors().await;
    let r = rig();
    let c = r.unlock().await;
    for (section, values) in [("ninja", json!({ "NINJA_BASE_URL": format!("{v}/redir/ninja"), "NINJA_CLIENT_ID": "i", "NINJA_CLIENT_SECRET": NINJA_SECRET })),
                              ("halo", json!({ "HALO_BASE_URL": format!("{v}/redir/halo/api"), "HALO_CLIENT_ID": "i", "HALO_CLIENT_SECRET": HALO_SECRET })),
                              ("nvd", json!({ "NVD_URL": format!("{v}/redir/nvd"), "NVD_API_KEY": NVD_KEY }))] {
        let a = test_call(&r, &c, section, values).await;
        assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(307)), "{a}");
        assert!(a["message"].as_str().unwrap().contains("redirected") && a["message"].as_str().unwrap().contains("final address"), "{a}");
    }
    assert_eq!((hits(&h, "redir"), hits(&h, "evil")), (3, 0), "each asked once, and nothing followed");
    // The connectors use the same client: a redirect is the vendor's failure, never followed.
    let r = msp_console::http_client().post(format!("{v}/redir/x")).send().await.unwrap();
    assert_eq!(r.status(), 307);
    let n = msp_console::connectors::nvd::Nvd::new(&format!("{v}/redir/nvd"), Some(NVD_KEY.into()), msp_console::http_client());
    let pool = test_db().await;
    let e = n.sync_product(&pool.pool, "example:product", None).await.unwrap_err();
    assert!(e.contains("307") && e.contains("redirected"), "{e}");
    assert_eq!(hits(&h, "evil"), 0);
}

#[tokio::test]
async fn an_unreachable_or_slow_vendor_is_a_plain_sentence() {
    let (v, _) = vendors().await;
    let closed = { let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); l.local_addr().unwrap() };
    let r = rig_full(&[], true, Some(Duration::from_millis(300)));
    let c = r.unlock().await;
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": format!("http://{closed}"), "NINJA_CLIENT_ID": "i", "NINJA_CLIENT_SECRET": NINJA_SECRET })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("can't be reached"), "{a}");
    let t0 = std::time::Instant::now();
    let a = test_call(&r, &c, "ninja", json!({ "NINJA_BASE_URL": format!("{v}/slow"), "NINJA_CLIENT_ID": "i", "NINJA_CLIENT_SECRET": NINJA_SECRET })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("didn't answer within"), "{a}");
    assert!(t0.elapsed() < Duration::from_secs(3), "the timeout held: {:?}", t0.elapsed());
    assert_eq!(msp_console::setup::TEST_TIMEOUT, Duration::from_secs(15), "and it's 15 s for real");
}

fn everything(r: &Rig, v: &str) -> Value {
    json!({ "values": {
        "DATABASE_PATH": r.db(), "AUTH_MODE": "proxy", "PROXY_KIND": "cloudflare_access", "ACCESS_TEAM_DOMAIN": "team.example.com", "ACCESS_AUD": "aud-1",
        // From a sign-in mode not chosen: dropped, never stored.
        "OIDC_CLIENT_SECRET": "stray-oidc-secret-for-another-mode", "SESSION_KEY": "stray-session-key-for-another-mode-only",
        "NINJA_BASE_URL": format!("{v}/ninja"), "NINJA_CLIENT_ID": "client-1", "NINJA_CLIENT_SECRET": NINJA_SECRET,
        "HALO_BASE_URL": format!("{v}/halo/api"), "HALO_CLIENT_ID": "client-2", "HALO_CLIENT_SECRET": HALO_SECRET, "HALO_TENANT": HALO_TENANT,
        "NVD_API_KEY": NVD_KEY, "NVD_URL": format!("{v}/nvd"),
        "SETUP_TOKEN": "not-a-setting", "KEV_URL": "http://not.offered.example.com" } })
}

#[tokio::test]
async fn save_encrypts_the_secrets_keeps_only_the_chosen_settings_and_round_trips() {
    let r = rig();
    let c = r.unlock().await;
    let (st, body, _) = r.send(post("/api/setup/save", everything(&r, "http://127.0.0.1:9"), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "restarting": true, "master_key_path": r.key().to_str().unwrap() }));
    assert_eq!(r.saved.load(Ordering::SeqCst), 1, "it exits to restart configured");
    let text = std::fs::read_to_string(r.config()).unwrap();
    let file: HashMap<String, String> = serde_json::from_str(&text).unwrap();
    let mut names: Vec<&str> = file.keys().map(String::as_str).collect();
    names.sort();
    assert_eq!(names, ["ACCESS_AUD", "ACCESS_TEAM_DOMAIN", "AUTH_MODE", "DATABASE_PATH", "HALO_BASE_URL", "HALO_CLIENT_ID", "HALO_CLIENT_SECRET", "HALO_TENANT",
                       "NINJA_BASE_URL", "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET", "NVD_API_KEY", "NVD_URL", "PROXY_KIND"]);
    for k in ["HALO_CLIENT_SECRET", "NINJA_CLIENT_SECRET", "NVD_API_KEY"] { assert!(file[k].starts_with("enc:v1:"), "{k}: {}", file[k]); }
    assert_eq!(text.matches("enc:v1:").count(), 3);
    for s in [NINJA_SECRET, HALO_SECRET, NVD_KEY, "stray-oidc", "stray-session", "not-a-setting"] { assert!(!text.contains(s), "{s} in the file"); }
    assert_eq!(file["ACCESS_AUD"], "aud-1", "plain settings stay plain");
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(r.config()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(r.key()).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Start-up reads it back, the secrets decrypted with the generated key.
    let Startup::Configured(cfg) = load(&r.env(), &|p| std::fs::read_to_string(p)).unwrap() else { panic!("unconfigured") };
    assert!(matches!(cfg.auth, AuthConfig::CloudflareAccess { ref aud, .. } if aud == "aud-1"));
    assert_eq!(cfg.connectors.ninja.as_ref().unwrap().client_secret, NINJA_SECRET);
    assert_eq!(cfg.connectors.halo.as_ref().unwrap().client_secret, HALO_SECRET);
    assert_eq!(cfg.connectors.halo.as_ref().unwrap().tenant.as_deref(), Some(HALO_TENANT));
    assert_eq!(cfg.connectors.nvd_key.as_deref(), Some(NVD_KEY));
    assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    // The wrong key refuses to start, naming a setting and never a value.
    let mut wrong = r.env();
    wrong.insert("CONSOLE_MASTER_KEY".into(), "a-different-master-key-0123456789abcdef".into());
    let e = load(&wrong, &|p| std::fs::read_to_string(p)).unwrap_err();
    assert!(e.contains("HALO_CLIENT_SECRET") && e.contains("can't be decrypted"), "{e}");
    for s in [NINJA_SECRET, HALO_SECRET, NVD_KEY] { assert!(!e.contains(s)); }
    // The audit line names what was saved, never a value; the log says where the key is.
    let a = r.audit.lock().unwrap().last().cloned().unwrap();
    assert_eq!((a.op.as_deref(), a.status, a.who.as_deref()), (Some("setup.save"), 200, Some("setup")));
    assert_eq!(a.params["keys"].as_array().unwrap().len(), 14);
    let logs = serde_json::to_string(&*r.logs.lock().unwrap()).unwrap();
    assert!(logs.contains("generated the master key") && logs.contains("settings saved"), "{logs}");
    for s in [NINJA_SECRET, HALO_SECRET, NVD_KEY, std::fs::read_to_string(r.key()).unwrap().trim()] { assert!(!logs.contains(s) && !serde_json::to_string(&a).unwrap().contains(s)); }
}

/// A leftover temp file (a crash mid-save, or anything put there) is replaced, never reused with its own mode.
#[cfg(unix)]
#[tokio::test]
async fn a_leftover_temp_file_is_replaced_and_the_saved_file_is_0600() {
    use std::os::unix::fs::PermissionsExt;
    let r = rig();
    let tmp = r.dir.join("config/.config.json.tmp");
    std::fs::write(&tmp, "left over").unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
    let elsewhere = r.dir.join("elsewhere.json");
    std::fs::write(&elsewhere, "not the console's").unwrap();
    let c = r.unlock().await;
    let (st, body, _) = r.send(post("/api/setup/save", everything(&r, "http://127.0.0.1:9"), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(std::fs::metadata(r.config()).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(!tmp.exists());
    // A symlink at the temp name is removed, not followed.
    std::fs::remove_file(r.config()).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &tmp).unwrap();
    msp_console::setup::write_config(&r.config(), &[("ACCESS_AUD".to_string(), "aud-1".to_string())].into()).unwrap();
    assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "not the console's");
    assert!(!std::fs::symlink_metadata(r.config()).unwrap().file_type().is_symlink());
    assert_eq!(std::fs::metadata(r.config()).unwrap().permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn values_the_environment_sets_are_never_written() {
    // NinjaOne's secret and its address both by environment: a secret the environment sets goes only to an address it
    // sets too (or the store holds), so the address the wizard sends is ignored rather than refused.
    let r = rig_with(&[("NINJA_CLIENT_SECRET", NINJA_SECRET), ("NINJA_BASE_URL", "https://ninja.example.com"), ("NVD_URL", "https://nvd.example.com/rest"),
                       ("CONSOLE_MASTER_KEY", "an-environment-master-key-0123456789abcd")], true);
    let c = r.unlock().await;
    let (st, body, _) = r.send(post("/api/setup/save", everything(&r, "http://127.0.0.1:9"), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["master_key_path"], Value::Null, "the key is the environment's: there's no file to keep");
    assert!(!r.key().exists(), "and none was generated");
    let file: HashMap<String, String> = serde_json::from_str(&std::fs::read_to_string(r.config()).unwrap()).unwrap();
    assert!(!file.contains_key("NINJA_CLIENT_SECRET") && !file.contains_key("NINJA_BASE_URL") && !file.contains_key("NVD_URL"), "{:?}", file.keys());
    assert!(file.contains_key("NINJA_CLIENT_ID") && file["HALO_CLIENT_SECRET"].starts_with("enc:v1:"));
    let Startup::Configured(cfg) = load(&r.env(), &|p| std::fs::read_to_string(p)).unwrap() else { panic!("unconfigured") };
    assert_eq!((cfg.connectors.ninja.unwrap().client_secret.as_str(), cfg.connectors.nvd_url.as_str()), (NINJA_SECRET, "https://nvd.example.com/rest"));
}

#[tokio::test]
async fn save_refuses_what_start_up_would_and_names_the_section() {
    let r = rig();
    let c = r.unlock().await;
    let base = |extra: Value| { let mut v = json!({ "DATABASE_PATH": r.db(), "AUTH_MODE": "proxy", "PROXY_KIND": "trusted_header", "TRUSTED_HEADER": "X-Forwarded-Email", "TRUSTED_PROXY_CIDRS": "10.0.5.0/24" });
        for (k, x) in extra.as_object().unwrap() { v[k] = x.clone(); } json!({ "values": v }) };
    for (extra, section, says) in [
        (json!({ "NINJA_CLIENT_ID": "client-1" }), json!("ninja"), "NINJA_BASE_URL"),
        (json!({ "HALO_BASE_URL": "https://psa.example.com/api", "HALO_CLIENT_ID": "c", "HALO_CLIENT_SECRET": "s", "HALO_REQUESTS_PER_5MIN": "900" }), json!("halo"), "HALO_REQUESTS_PER_5MIN"),
        (json!({ "TRUSTED_PROXY_CIDRS": "<script>" }), json!("auth"), "isn't a CIDR"),
        (json!({ "AUTH_MODE": "no_such_mode" }), json!("auth"), "Choose how people sign in"),
        (json!({ "BACKUP_KEEP": "0" }), json!("database"), "BACKUP_KEEP"),
        (json!({ "DATABASE_PATH": r.dir.join("missing/console.db").to_str().unwrap() }), json!("database"), "doesn't exist"),
    ] {
        let (st, body, _) = r.send(post("/api/setup/save", base(extra.clone()), Some(&c))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{extra}: {body}");
        assert_eq!(body["section"], section, "{extra}: {body}");
        assert!(body["error"].as_str().unwrap().contains(says), "{extra}: {body}");
    }
    assert!(!r.config().exists() && !r.key().exists() && r.saved.load(Ordering::SeqCst) == 0);
    assert_eq!(r.ops().iter().filter(|(o, s)| o == "setup.save" && *s == 400).count(), 6);
    // And the same settings, whole, save.
    let (st, body, _) = r.send(post("/api/setup/save", base(json!({})), Some(&c))).await;
    assert_eq!((st, body["master_key_path"].clone()), (StatusCode::OK, Value::Null), "no secrets: no key needed: {body}");
    assert!(!r.key().exists());
}

#[tokio::test]
async fn only_this_computer_is_offered_tested_and_saved_outside_production_and_kubernetes() {
    // On a laptop: offered, its test warns, and it saves AUTH_MODE alone (a stray PROXY_KIND or secret is dropped).
    let r = rig();
    let c = r.unlock().await;
    let (_, state, _) = r.send(get("/api/setup/state", Some(&c))).await;
    assert_eq!(state["local_only"], json!(true), "{state}");
    let save = json!({ "values": { "DATABASE_PATH": r.db(), "AUTH_MODE": "dev_insecure", "PROXY_KIND": "trusted_header", "SESSION_KEY": "k".repeat(40) } });
    let (st, body, _) = r.send(post("/api/setup/save", save.clone(), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(r.config()).unwrap()).unwrap();
    assert_eq!(file, json!({ "AUTH_MODE": "dev_insecure", "DATABASE_PATH": r.db() }));
    match load(&r.env(), &|p| std::fs::read_to_string(p)).unwrap() {
        Startup::Configured(cfg) => assert_eq!(cfg.auth, AuthConfig::DevInsecure),
        other => panic!("{other:?}"),
    }
    // In production and on Kubernetes: not offered, its test refuses, and save refuses it with a plain sentence.
    for extra in [("MSP_ENV", "production"), ("KUBERNETES_SERVICE_HOST", "10.0.0.1")] {
        let r = rig_with(&[extra], true);
        let c = r.unlock().await;
        let (_, state, _) = r.send(get("/api/setup/state", Some(&c))).await;
        assert_eq!(state["local_only"], json!(false), "{extra:?}: {state}");
        let a = test_call(&r, &c, "auth", json!({ "AUTH_MODE": "dev_insecure" })).await;
        assert_eq!(a["ok"], json!(false), "{extra:?}: {a}");
        let save = json!({ "values": { "DATABASE_PATH": r.db(), "AUTH_MODE": "dev_insecure" } });
        let (st, body, _) = r.send(post("/api/setup/save", save, Some(&c))).await;
        assert_eq!((st, body["section"].clone()), (StatusCode::BAD_REQUEST, json!("auth")), "{extra:?}: {body}");
        assert_eq!(body["error"], json!(msp_console::setup::NO_SIGN_IN_REFUSED));
        assert!(!r.config().exists() && r.saved.load(Ordering::SeqCst) == 0);
    }
}


// ---------------------------------------------------------------- the database step: PostgreSQL

const DB_PASSWORD: &str = "db-password-never-shown-5d2e8a1c";

#[tokio::test]
async fn a_postgresql_test_that_fails_says_what_failed_and_never_the_url() {
    // Nothing listens on port 1: the Test fails, in a sentence that names neither the password, the user nor the host.
    let r = rig();
    let c = r.unlock().await;
    let url = format!("postgres://console-user:{DB_PASSWORD}@127.0.0.1:1/console");
    let a = test_call(&r, &c, "database", json!({ "DATABASE_URL": url })).await;
    assert_eq!(a["ok"], json!(false), "{a}");
    assert!(a["message"].as_str().unwrap().contains("can't be reached"), "{a}");
    let text = a.to_string();
    for s in [DB_PASSWORD, "console-user", "127.0.0.1"] { assert!(!text.contains(s), "{s} in {text}"); }
    // A URL that isn't PostgreSQL's, or no TLS in production: refused before anything is sent.
    let a = test_call(&r, &c, "database", json!({ "DATABASE_URL": format!("mysql://u:{DB_PASSWORD}@db.example.com/x") })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("postgres:// URL") && !a.to_string().contains(DB_PASSWORD), "{a}");
    let prod = rig_with(&[("MSP_ENV", "production")], true);
    let pc = prod.unlock().await;
    let a = test_call(&prod, &pc, "database", json!({ "DATABASE_URL": format!("postgres://u:{DB_PASSWORD}@db.example.com/x") })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("set sslmode=verify-full"), "{a}");
    let a = test_call(&prod, &pc, "database", json!({ "DATABASE_URL": format!("postgres://u:{DB_PASSWORD}@db.example.com/x?sslmode=require") })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("accepts any certificate"), "require is refused in production: {a}");
    // The URL is a secret: state says it's set or not, never its value, and it belongs to the database step.
    let (_, state, _) = r.send(get("/api/setup/state", Some(&c))).await;
    assert_eq!(state["keys"]["DATABASE_URL"], json!({ "set": false, "env": false, "value": null, "secret": true, "section": "database" }));
    // Every audit line is the setting-free kind.
    assert!(r.audit.lock().unwrap().iter().all(|x| !serde_json::to_string(x).unwrap().contains(DB_PASSWORD)));
}

#[tokio::test]
async fn the_postgresql_test_connects_checks_create_and_pgvector_and_migrates_nothing() {
    let Some(db) = pg_role_db(true).await else { return };
    let r = rig();
    let c = r.unlock().await;
    let a = test_call(&r, &c, "database", json!({ "DATABASE_URL": db.url })).await;
    assert_eq!(a["ok"], json!(true), "{a}");
    assert!(a["message"].as_str().unwrap().contains("can make its tables there"), "{a}");
    let want = if pg_has_vector().await { "available" } else { "absent" };
    assert_eq!((a["detail"]["pgvector"].clone(), a["detail"]["sslmode"].clone()), (json!(want), json!("prefer")), "{a}");
    assert!(!a.to_string().contains(&db.password), "{a}");
    assert!(a["message"].as_str().unwrap().contains("TLS isn't required"), "no sslmode is said: {a}");
    // Nothing was made: no migrations table, no probe table, no extension.
    let p = sqlx::PgPool::connect(&db.url).await.unwrap();
    let tables: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'").fetch_one(&p).await.unwrap();
    let ext: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_extension WHERE extname = 'vector'").fetch_one(&p).await.unwrap();
    p.close().await;
    assert_eq!((tables, ext), (0, 0), "the test made nothing");
    // The wrong password: refused, said plainly.
    let wrong = db.url.replace(&db.password, "pw-not-the-right-one-0000");
    let a = test_call(&r, &c, "database", json!({ "DATABASE_URL": wrong })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("refused the user or password") && !a.to_string().contains("pw-not-the-right"), "{a}");
    // TLS, when the server speaks it: sslmode=require connects outside production and says the certificate wasn't
    // checked; verify-full checks it, and a self-signed one that no root signs is refused.
    if pg_has_tls().await {
        let a = test_call(&r, &c, "database", json!({ "DATABASE_URL": format!("{}?sslmode=require", db.url) })).await;
        assert_eq!((a["ok"].clone(), a["detail"]["sslmode"].clone()), (json!(true), json!("require")), "{a}");
        assert!(a["message"].as_str().unwrap().contains("TLS without certificate check"), "{a}");
        let a = test_call(&r, &c, "database", json!({ "DATABASE_URL": format!("{}?sslmode=verify-full", db.url) })).await;
        assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("TLS handshake failed"), "the certificate is checked: {a}");
    }
}

#[tokio::test]
async fn a_role_that_may_not_create_tables_is_told_so_at_test_and_save() {
    let Some(db) = pg_role_db(false).await else { return };
    let r = rig();
    let c = r.unlock().await;
    let a = test_call(&r, &c, "database", json!({ "DATABASE_URL": db.url })).await;
    assert!(a["ok"] == json!(false) && a["message"].as_str().unwrap().contains("may not create tables"), "{a}");
    let save = json!({ "values": { "DATABASE_URL": db.url, "AUTH_MODE": "dev_insecure" } });
    let (st, body, _) = r.send(post("/api/setup/save", save, Some(&c))).await;
    assert_eq!((st, body["section"].clone()), (StatusCode::BAD_REQUEST, json!("database")), "{body}");
    assert!(body["error"].as_str().unwrap().contains("may not create tables") && !body.to_string().contains(&db.password), "{body}");
    assert!(!r.config().exists() && r.saved.load(Ordering::SeqCst) == 0);
}

#[tokio::test]
async fn saving_postgresql_keeps_the_url_encrypted_and_switching_back_drops_it() {
    let Some(db) = pg_role_db(true).await else { return };
    let r = rig();
    let c = r.unlock().await;
    let read_file = || -> HashMap<String, String> { serde_json::from_str(&std::fs::read_to_string(r.config()).unwrap()).unwrap() };
    // PostgreSQL chosen: the URL is kept, encrypted; a stray SQLite setting from the other choice is not.
    let save = json!({ "values": { "DATABASE_URL": db.url, "BACKUP_KEEP": "5", "AUTH_MODE": "dev_insecure" } });
    let (st, body, _) = r.send(post("/api/setup/save", save, Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let file = read_file();
    assert_eq!(file.keys().cloned().collect::<std::collections::BTreeSet<_>>(), ["AUTH_MODE", "DATABASE_URL"].map(String::from).into());
    assert!(file["DATABASE_URL"].starts_with("enc:v1:"));
    let text = std::fs::read_to_string(r.config()).unwrap();
    assert!(!text.contains(&db.password) && !text.contains("msp_role_"), "{text}");
    let Startup::Configured(cfg) = load(&r.env(), &|p| std::fs::read_to_string(p)).unwrap() else { panic!("unconfigured") };
    assert!(matches!(cfg.db, msp_console::db::DbConfig::Postgres(_)), "{:?}", cfg.db);
    let (_, state, _) = r.send(get("/api/setup/state", Some(&c))).await;
    assert_eq!((state["keys"]["DATABASE_URL"]["set"].clone(), state["keys"]["DATABASE_URL"]["value"].clone()), (json!(true), Value::Null), "{state}");
    // Saved again without retyping it: still PostgreSQL, the URL kept as it was.
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": { "AUTH_MODE": "dev_insecure" } }), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert!(read_file().contains_key("DATABASE_URL"));
    // The SQLite file chosen instead: the saved URL goes, so start-up doesn't find both.
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": { "DATABASE_PATH": r.db(), "AUTH_MODE": "dev_insecure" } }), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(read_file(), HashMap::from([("AUTH_MODE".to_string(), "dev_insecure".to_string()), ("DATABASE_PATH".to_string(), r.db())]));
    assert!(matches!(load(&r.env(), &|p| std::fs::read_to_string(p)).unwrap(), Startup::Configured(ref c) if c.db.sqlite().is_some()));
}

#[tokio::test]
async fn a_database_url_from_the_environment_is_shown_set_and_wins() {
    let Some(db) = pg_role_db(true).await else { return };
    let r = rig_with(&[("DATABASE_URL", db.url.as_str())], true);
    let c = r.unlock().await;
    let (_, state, _) = r.send(get("/api/setup/state", Some(&c))).await;
    assert_eq!(state["keys"]["DATABASE_URL"], json!({ "set": true, "env": true, "value": null, "secret": true, "section": "database" }));
    assert!(!state.to_string().contains(&db.password));
    // Its Test uses the environment's URL; a SQLite path typed beside it is dropped at save, not stored beside it.
    let a = test_call(&r, &c, "database", json!({})).await;
    assert_eq!(a["ok"], json!(true), "{a}");
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": { "DATABASE_PATH": r.db(), "AUTH_MODE": "dev_insecure" } }), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(r.config()).unwrap()).unwrap();
    assert_eq!(file, json!({ "AUTH_MODE": "dev_insecure" }), "the environment's URL is never written, and the path isn't kept beside it");
}

/// Blackpoint's and Shodan's sections: a live, read-only Test each, a refusal that never echoes the token or
/// key back, Shodan's credits in the answer, and the BOUND rule: a stored secret never goes to a new address.
#[tokio::test]
async fn blackpoint_and_shodan_are_tested_live_and_their_secrets_stay_bound() {
    let (v, h) = vendors().await;
    let r = rig();
    let c = r.unlock().await;
    let bp = json!({ "BLACKPOINT_BASE_URL": format!("{v}/blackpoint"), "BLACKPOINT_API_TOKEN": BLACKPOINT_TOKEN });
    let a = test_call(&r, &c, "blackpoint", bp.clone()).await;
    assert_eq!((a["ok"].clone(), a["detail"].clone()), (json!(true), json!({ "tenants": 1 })), "{a}");
    let mut wrong = bp.clone(); wrong["BLACKPOINT_API_TOKEN"] = json!("wrong-bp-token-in-a-test");
    let a = test_call(&r, &c, "blackpoint", wrong).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(401)), "{a}");
    assert!(!a.to_string().contains("wrong-bp-token"), "the vendor's echo never comes back: {a}");
    let sh = json!({ "SHODAN_URL": format!("{v}/shodan"), "SHODAN_API_KEY": SHODAN_KEY });
    let a = test_call(&r, &c, "shodan", sh.clone()).await;
    assert_eq!((a["ok"].clone(), a["detail"].clone()), (json!(true), json!({ "plan": "dev", "scan_credits": 95, "query_credits": 200 })), "{a}");
    assert!(a["message"].as_str().unwrap().contains("95 scan credits"), "{a}");
    let mut wrong = sh.clone(); wrong["SHODAN_API_KEY"] = json!("wrong-shodan-key-in-a-test");
    let a = test_call(&r, &c, "shodan", wrong).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(401)), "{a}");
    assert!(!a.to_string().contains("wrong-shodan-key"), "{a}");
    assert_eq!((hits(&h, "blackpoint_tenants"), hits(&h, "shodan_info")), (2, 2), "each Test really called the vendor");
    // Saved, then a new address without the secret typed again: refused at Test and at save, nothing sent.
    let base = json!({ "DATABASE_PATH": r.db(), "AUTH_MODE": "proxy", "PROXY_KIND": "trusted_header", "TRUSTED_HEADER": "X-Email", "TRUSTED_PROXY_CIDRS": "10.0.5.0/24" });
    let mut all = base.clone();
    for part in [&bp, &sh] { for (k, x) in part.as_object().unwrap() { all[k] = x.clone(); } }
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": all }), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let text = std::fs::read_to_string(r.config()).unwrap();
    assert_eq!(text.matches("enc:v1:").count(), 2, "{text}");
    for s in [BLACKPOINT_TOKEN, SHODAN_KEY] { assert!(!text.contains(s)); }
    for (section, values) in [("blackpoint", json!({ "BLACKPOINT_BASE_URL": format!("{v}/evil/bp") })), ("shodan", json!({ "SHODAN_URL": format!("{v}/evil/shodan") }))] {
        let a = test_call(&r, &c, section, values).await;
        assert_eq!(a["message"], json!("Enter the secret again to test a new address."), "{a}");
    }
    let mut moved = base.clone(); moved["SHODAN_URL"] = json!(format!("{v}/evil/shodan"));
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": moved }), Some(&c))).await;
    assert_eq!((st, body), (StatusCode::BAD_REQUEST, json!({ "error": "Enter the secret again to save a new address.", "section": "shodan" })));
    assert_eq!(hits(&h, "evil"), 0, "no request left for another address");
}

/// Halo's ticket settings: all three or none, and only with Halo; start-up's rule, at save.
#[tokio::test]
async fn halo_ticket_settings_come_together_and_need_halo() {
    let r = rig();
    let c = r.unlock().await;
    let base = json!({ "DATABASE_PATH": r.db(), "AUTH_MODE": "proxy", "PROXY_KIND": "trusted_header", "TRUSTED_HEADER": "X-Email", "TRUSTED_PROXY_CIDRS": "10.0.5.0/24" });
    let mut some = base.clone(); some["HALO_BASE_URL"] = json!("https://halo.example.com/api"); some["HALO_CLIENT_ID"] = json!("c"); some["HALO_CLIENT_SECRET"] = json!(HALO_SECRET);
    some["HALO_TICKET_TYPE_ID"] = json!("31");
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": some.clone() }), Some(&c))).await;
    assert_eq!((st, body["section"].clone()), (StatusCode::BAD_REQUEST, json!("halo")), "{body}");
    let mut no_halo = base.clone();
    for (k, x) in [("HALO_TICKET_TYPE_ID", "31"), ("HALO_TICKET_STATUS_ID", "1"), ("HALO_TICKET_PRIORITY_ID", "3")] { no_halo[k] = json!(x); some[k] = json!(x); }
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": no_halo }), Some(&c))).await;
    assert_eq!((st, body["section"].clone()), (StatusCode::BAD_REQUEST, json!("halo")), "{body}");
    let (st, body, _) = r.send(post("/api/setup/save", json!({ "values": some }), Some(&c))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let Startup::Configured(cfg) = load(&r.env(), &|p| std::fs::read_to_string(p)).unwrap() else { panic!("unconfigured") };
    assert_eq!(cfg.tickets, Some(msp_console::ops::tickets::TicketCfg { type_id: 31, status_id: 1, priority_id: 3 }));
}

#[tokio::test]
async fn microsofts_updates_are_tested_live_and_off_is_said() {
    let (v, h) = vendors().await;
    let r = rig();
    let c = r.unlock().await;
    let a = test_call(&r, &c, "msrc", json!({ "MSRC_URL": format!("{v}/msrc") })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone(), a["detail"].clone()), (json!(true), json!(200), json!({ "months": 2 })), "{a}");
    let a = test_call(&r, &c, "msrc", json!({ "MSRC": "off" })).await;
    assert_eq!((a["ok"].clone(), a["detail"].clone()), (json!(true), json!({ "msrc": "off" })), "{a}");
    let a = test_call(&r, &c, "msrc", json!({ "MSRC_URL": format!("{v}/nowhere") })).await;
    assert_eq!((a["ok"].clone(), a["status"].clone()), (json!(false), json!(404)), "{a}");
    assert_eq!(hits(&h, "msrc"), 1, "off made no call");
}
