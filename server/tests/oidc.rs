//! AUTH_MODE=oidc against a stand-in provider on a real local port: discovery, its keys, and a token endpoint that
//! checks the client secret and the PKCE verifier against the challenge, as Entra does. The whole flow (login, the
//! provider, the callback, the session) and every way it should refuse.
mod common;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use common::*;
use http_body_util::BodyExt;
use msp_console::app::{router, AppState};
use msp_console::ops::Store;
use msp_console::oidc::{routes, safe_return, Oidc, OidcSettings, LOGIN_COOKIE, SESSION_COOKIE};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

#[derive(Default)]
struct Provider { challenge: String, claims: Value, key_pem: String, issuer_says: Option<String> }
type P = Arc<Mutex<Provider>>;

async fn provider() -> (String, P) {
    let p: P = Arc::new(Mutex::new(Provider::default()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let b2 = base.clone();
    let r = Router::new()
        .route("/tenant/v2.0/.well-known/openid-configuration", get(move |State(p): State<P>| { let b = b2.clone(); async move {
            let iss = p.lock().unwrap().issuer_says.clone().unwrap_or(format!("{b}/tenant/v2.0"));
            Json(json!({ "issuer": iss, "authorization_endpoint": format!("{b}/authorize"), "token_endpoint": format!("{b}/token"),
                "jwks_uri": format!("{b}/keys"), "end_session_endpoint": format!("{b}/logout") })) } }))
        .route("/keys", get(|| async { Json(json!({ "keys": [keys().a_jwk.clone()] })) }))
        .route("/token", post(|State(p): State<P>, Form(f): Form<HashMap<String, String>>| async move {
            let p = p.lock().unwrap();
            let verifier_ok = f.get("code_verifier").is_some_and(|v| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())) == p.challenge);
            if f.get("code").map(String::as_str) != Some("good-code") || f.get("client_secret").map(String::as_str) != Some("s3cret") || !verifier_ok
                || f.get("grant_type").map(String::as_str) != Some("authorization_code") || f.get("redirect_uri").map(String::as_str) != Some("https://console.test/auth/callback") {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" })));
            }
            (StatusCode::OK, Json(json!({ "id_token": sign(p.claims.clone(), &p.key_pem, "kid-a"), "token_type": "Bearer" })))
        }))
        .with_state(p.clone());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    (base, p)
}

fn settings(base: &str, session_key: &str) -> OidcSettings {
    OidcSettings { issuer: format!("{base}/tenant/v2.0"), client_id: "client-123".into(), client_secret: "s3cret".into(), allowed_group: "group-techs".into(),
        session_key: session_key.into(), public_url: "https://console.test".into() }
}
const SK: &str = "a-session-key-of-at-least-thirty-two-chars";

struct Rig { app: Router, p: P, base: String, o: Arc<Oidc> }
async fn rig() -> Rig {
    let (base, p) = provider().await;
    let o = Arc::new(Oidc::new(settings(&base, SK), msp_console::http_client()));
    let state = AppState { identity: o.clone(), store: Store::new(unreachable_pool()), audit: Arc::new(|_| {}) };
    let app = router(state, None).merge(routes(o.clone())).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
    Rig { app, p, base, o }
}
fn id_claims(base: &str, nonce: &str, extra: Value) -> Value {
    let mut c = json!({ "iss": format!("{base}/tenant/v2.0"), "aud": "client-123", "exp": now() + 600, "iat": now(), "nonce": nonce,
        "email": "tech@example.com", "groups": ["group-other", "group-techs"] });
    for (k, v) in extra.as_object().unwrap() { if v.is_null() { c.as_object_mut().unwrap().remove(k); } else { c[k] = v.clone(); } }
    c
}
fn set_cookie_value(r: &axum::response::Response, name: &str) -> Option<String> {
    r.headers().get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).find(|v| v.starts_with(&format!("{name}=")))
        .map(|v| v[name.len() + 1..].split(';').next().unwrap().to_string())
}
fn qs(url: &str) -> HashMap<String, String> { serde_urlencoded::from_str(url.split_once('?').map(|x| x.1).unwrap_or("")).unwrap() }
async fn body(r: axum::response::Response) -> String { String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap() }

/// Start a sign-in; returns the authorize query and the login cookie.
async fn start(r: &Rig, return_to: &str) -> (HashMap<String, String>, String) {
    let res = r.app.clone().oneshot(Request::get(format!("/auth/login?return_to={}", urlencode(return_to))).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = res.headers()[header::LOCATION].to_str().unwrap().to_string();
    assert!(loc.starts_with(&format!("{}/authorize?", r.base)), "{loc}");
    (qs(&loc), set_cookie_value(&res, LOGIN_COOKIE).expect("a login cookie"))
}
fn urlencode(s: &str) -> String { serde_urlencoded::to_string([("x", s)]).unwrap()[2..].to_string() }
async fn callback(r: &Rig, state: &str, login: &str) -> axum::response::Response {
    r.app.clone().oneshot(Request::get(format!("/auth/callback?code=good-code&state={}", urlencode(state))).header(header::COOKIE, format!("{LOGIN_COOKIE}={login}")).body(Body::empty()).unwrap()).await.unwrap()
}
/// The whole flow with the provider's id_token shaped by `extra` (and signed by `key_pem`).
async fn flow(r: &Rig, extra: Value, key_pem: &str, return_to: &str) -> axum::response::Response {
    let (q, login) = start(r, return_to).await;
    { let mut p = r.p.lock().unwrap(); p.challenge = q["code_challenge"].clone(); p.claims = id_claims(&r.base, &q["nonce"], extra); p.key_pem = key_pem.into(); }
    callback(r, &q["state"], &login).await
}
async fn me(r: &Rig, session: &str) -> StatusCode {
    r.app.clone().oneshot(Request::get("/api/me").header(header::COOKIE, format!("{SESSION_COOKIE}={session}")).body(Body::empty()).unwrap()).await.unwrap().status()
}

#[tokio::test]
async fn the_authorize_request_carries_pkce_state_nonce_and_our_callback() {
    let r = rig().await;
    let (q, _) = start(&r, "/").await;
    assert_eq!((q["response_type"].as_str(), q["client_id"].as_str(), q["code_challenge_method"].as_str()), ("code", "client-123", "S256"));
    assert_eq!(q["redirect_uri"], "https://console.test/auth/callback");
    assert!(q["scope"].contains("openid") && q["state"].len() >= 20 && q["nonce"].len() >= 20 && q["code_challenge"].len() == 43);
}

#[tokio::test]
async fn a_member_of_the_group_signs_in_and_lands_where_they_were_going() {
    let r = rig().await;
    let res = flow(&r, json!({}), &keys().a_pem, "/#v=client&org=7").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()[header::LOCATION], "/#v=client&org=7");
    let all: Vec<_> = res.headers().get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).collect();
    assert!(all.iter().any(|c| c.starts_with(SESSION_COOKIE) && c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Lax") && c.contains("Max-Age=28800")), "{all:?}");
    assert!(all.iter().any(|c| c.starts_with(&format!("{LOGIN_COOKIE}=;")) && c.contains("Max-Age=0")), "the login cookie is cleared");
    let s = set_cookie_value(&res, SESSION_COOKIE).unwrap();
    let who = r.app.clone().oneshot(Request::get("/api/me").header(header::COOKIE, format!("other=1; {SESSION_COOKIE}={s}")).body(Body::empty()).unwrap()).await.unwrap();
    let who: Value = serde_json::from_str(&body(who).await).unwrap();
    assert_eq!((who["email"].as_str(), who["logout"].as_str()), (Some("tech@example.com"), Some("/auth/logout")));
    // An app role does as well as a group.
    let res = flow(&r, json!({ "groups": null, "roles": ["group-techs"] }), &keys().a_pem, "/").await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn outside_the_group_or_with_too_many_groups_is_refused_and_says_why() {
    let r = rig().await;
    let res = flow(&r, json!({ "groups": ["group-other"] }), &keys().a_pem, "/").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie_value(&res, SESSION_COOKIE).is_none());
    let res = flow(&r, json!({ "groups": null, "_claim_names": { "groups": "src1" } }), &keys().a_pem, "/").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(body(res).await.contains("too many groups"));
}

#[tokio::test]
async fn a_token_that_isnt_good_gets_no_session() {
    let r = rig().await;
    for (what, extra, key) in [
        ("another audience", json!({ "aud": "someone-else" }), keys().a_pem.as_str()),
        ("another issuer", json!({ "iss": "https://evil.example/v2.0" }), keys().a_pem.as_str()),
        ("expired", json!({ "exp": now() - 600 }), keys().a_pem.as_str()),
        ("not yet valid", json!({ "nbf": now() + 600 }), keys().a_pem.as_str()),
        ("another nonce", json!({ "nonce": "replayed" }), keys().a_pem.as_str()),
        ("no nonce", json!({ "nonce": null }), keys().a_pem.as_str()),
        ("a stranger's key", json!({}), keys().b_pem.as_str()),
        ("names no one", json!({ "email": null }), keys().a_pem.as_str()),
    ] {
        let res = flow(&r, extra, key, "/").await;
        assert!(res.status().is_client_error(), "{what}: {}", res.status());
        assert!(set_cookie_value(&res, SESSION_COOKIE).is_none(), "{what} got a session");
    }
}

#[tokio::test]
async fn a_callback_that_didnt_start_here_is_refused() {
    let r = rig().await;
    let (q, login) = start(&r, "/").await;
    { let mut p = r.p.lock().unwrap(); p.challenge = q["code_challenge"].clone(); p.claims = id_claims(&r.base, &q["nonce"], json!({})); p.key_pem = keys().a_pem.clone(); }
    assert_eq!(callback(&r, "another-state", &login).await.status(), StatusCode::BAD_REQUEST, "state");
    let none = r.app.clone().oneshot(Request::get(format!("/auth/callback?code=good-code&state={}", urlencode(&q["state"]))).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(none.status(), StatusCode::BAD_REQUEST, "no login cookie");
    let err = r.app.clone().oneshot(Request::get("/auth/callback?error=%3Cscript%3Ex").header(header::COOKIE, format!("{LOGIN_COOKIE}={login}")).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    assert!(!body(err).await.contains("<script>"), "the provider's error echoed unescaped");
    assert_eq!(callback(&r, &q["state"], &login).await.status(), StatusCode::SEE_OTHER, "and the real one still works");
}

#[tokio::test]
async fn a_cookie_that_isnt_ours_or_isnt_a_session_is_no_one() {
    let r = rig().await;
    let s = set_cookie_value(&flow(&r, json!({}), &keys().a_pem, "/").await, SESSION_COOKIE).unwrap();
    assert_eq!(me(&r, &s).await, StatusCode::OK);
    let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&s).unwrap();
    let n = bytes.len() - 5; bytes[n] ^= 1;
    assert_eq!(me(&r, &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)).await, StatusCode::UNAUTHORIZED, "tampered");
    let other = Oidc::new(settings(&r.base, "another-session-key-also-thirty-two-chars!"), msp_console::http_client());
    assert_eq!(me(&r, &other.seal("session", json!({ "email": "ceo@example.com" }), Duration::from_secs(3600))).await, StatusCode::UNAUTHORIZED, "another key");
    assert_eq!(me(&r, &r.o.seal("session", json!({ "email": "x@y" }), Duration::from_secs(0))).await, StatusCode::UNAUTHORIZED, "expired");
    let (_, login) = start(&r, "/").await;
    assert_eq!(me(&r, &login).await, StatusCode::UNAUTHORIZED, "a pending sign-in is not a session");
    assert_eq!(me(&r, "junk").await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_api_says_where_to_sign_in_and_sign_out_ends_both_sessions() {
    let r = rig().await;
    let res = r.app.clone().oneshot(Request::post("/api/evidence").header("content-type", "application/json").body(Body::from(r#"{"op":"cves.list"}"#)).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(serde_json::from_str::<Value>(&body(res).await).unwrap()["login"], "/auth/login");
    let out = r.app.clone().oneshot(Request::post("/auth/logout").header(header::ORIGIN, "https://console.test").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(out.status(), StatusCode::OK);
    let clears = out.headers().get_all(header::SET_COOKIE).iter().any(|v| v.to_str().unwrap().starts_with(&format!("{SESSION_COOKIE}=;")) && v.to_str().unwrap().contains("Max-Age=0"));
    let loc = serde_json::from_str::<Value>(&body(out).await).unwrap()["to"].as_str().unwrap().to_string();
    assert!(loc.starts_with(&format!("{}/logout?", r.base)) && qs(&loc)["post_logout_redirect_uri"] == "https://console.test", "{loc}");
    assert!(clears, "the session cookie isn't cleared");
}

#[tokio::test]
async fn only_the_console_itself_can_sign_someone_out() {
    let r = rig().await;
    let s = set_cookie_value(&flow(&r, json!({}), &keys().a_pem, "/").await, SESSION_COOKIE).unwrap();
    let out = |b: axum::http::request::Builder| { let app = r.app.clone(); let s = s.clone(); async move {
        app.oneshot(b.header(header::COOKIE, format!("{SESSION_COOKIE}={s}")).body(Body::empty()).unwrap()).await.unwrap() } };
    for (what, b) in [
        ("another site", Request::post("/auth/logout").header(header::ORIGIN, "https://evil.example")),
        ("a look-alike host", Request::post("/auth/logout").header(header::ORIGIN, "https://console.test.evil.example")),
        ("plain http", Request::post("/auth/logout").header(header::ORIGIN, "http://console.test")),
        ("cross-site, no Origin", Request::post("/auth/logout").header("sec-fetch-site", "cross-site")),
        ("no word of where from", Request::post("/auth/logout")),
    ] {
        let res = out(b).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{what}");
        assert!(set_cookie_value(&res, SESSION_COOKIE).is_none(), "{what} cleared the session");
    }
    assert_eq!(out(Request::get("/auth/logout")).await.status(), StatusCode::METHOD_NOT_ALLOWED, "a link can't sign out");
    assert_eq!(out(Request::post("/auth/logout").header("sec-fetch-site", "same-origin")).await.status(), StatusCode::OK, "same-origin, no Origin");
    assert_eq!(me(&r, &s).await, StatusCode::OK, "the session cookie itself is still good until the browser drops it");
}

#[tokio::test]
async fn a_provider_calling_itself_by_another_issuer_is_not_trusted() {
    let r = rig().await;
    r.p.lock().unwrap().issuer_says = Some("https://login.evil.example/v2.0".into());
    let res = r.app.clone().oneshot(Request::get("/auth/login").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}

#[test]
fn after_sign_in_only_a_path_on_this_site() {
    for (given, want) in [(Some("/#v=cve&id=CVE-2026-1"), "/#v=cve&id=CVE-2026-1"), (Some("//evil.example"), "/"), (Some("https://evil.example"), "/"),
        (Some("/\\evil.example"), "/"), (Some("/\r\nSet-Cookie:x"), "/"), (None, "/")] {
        assert_eq!(safe_return(given), want, "{given:?}");
    }
}

async fn admin_of(r: &Rig, extra: Value) -> Value {
    let res = flow(r, extra, &keys().a_pem, "/").await;
    let s = set_cookie_value(&res, SESSION_COOKIE).expect("signed in");
    let who = r.app.clone().oneshot(Request::get("/api/me").header(header::COOKIE, format!("{SESSION_COOKIE}={s}")).body(Body::empty()).unwrap()).await.unwrap();
    serde_json::from_str::<Value>(&body(who).await).unwrap()["admin"].clone()
}

/// OIDC_ADMIN_GROUP: a member of the allowed group who is also in the admin group (or holds it as a role) is an admin;
/// anyone else isn't, and a console with no admin group has none.
#[tokio::test]
async fn the_admin_group_in_the_token_makes_an_admin() {
    let (base, p) = provider().await;
    let o = Arc::new(Oidc::new(settings(&base, SK), msp_console::http_client()).with_admin_group(Some("group-admins".into())));
    let state = AppState { identity: o.clone(), store: Store::new(unreachable_pool()), audit: Arc::new(|_| {}) };
    let app = router(state, None).merge(routes(o.clone())).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
    let r = Rig { app, p, base, o };
    assert_eq!(admin_of(&r, json!({ "groups": ["group-techs", "group-admins"] })).await, json!(true));
    assert_eq!(admin_of(&r, json!({ "roles": ["group-admins"] })).await, json!(true), "an app role does as well");
    assert_eq!(admin_of(&r, json!({})).await, json!(false));
    let plain = rig().await;
    assert_eq!(admin_of(&plain, json!({ "groups": ["group-techs", "group-admins"] })).await, json!(false), "no admin group: no admins");
}
