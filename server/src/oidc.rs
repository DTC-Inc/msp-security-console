//! The console's own sign-in (design rev 3.1, AUTH_MODE=oidc): OpenID Connect against Entra ID in any tenant, or any
//! provider that puts groups or roles in its id_token. Authorization code with PKCE (S256), state and nonce. The pending
//! sign-in and the session are each an authenticated, encrypted cookie (XChaCha20-Poly1305, its key derived from
//! SESSION_KEY with HKDF), so replicas share nothing and a cookie can be neither read nor altered. The id_token is
//! checked against the provider's keys, its issuer, our client id as audience, its expiry and our nonce; access needs
//! OIDC_ALLOWED_GROUP in the token's groups or roles. Fails closed throughout.

use crate::app::security_headers;
use crate::identity::{IdFuture, Identity, Refusal, Who};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use crate::seal::{random, Sealer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub const SESSION_COOKIE: &str = "__Host-msp_session";
pub const LOGIN_COOKIE: &str = "__Host-msp_login";
pub const SESSION_HOURS: u64 = 8;
const LOGIN_MINUTES: u64 = 10;

#[derive(Clone)]
pub struct OidcSettings { pub issuer: String, pub client_id: String, pub client_secret: String, pub allowed_group: String, pub session_key: String, pub public_url: String }
// By hand, so the client secret and the session key never reach a Debug form.
impl std::fmt::Debug for OidcSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcSettings").field("issuer", &self.issuer).field("client_id", &self.client_id).field("allowed_group", &self.allowed_group)
            .field("public_url", &self.public_url).field("client_secret", &"[redacted]").field("session_key", &"[redacted]").finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Meta { issuer: String, authorization_endpoint: String, token_endpoint: String, jwks_uri: String, end_session_endpoint: Option<String> }

pub struct Oidc {
    s: OidcSettings,
    /// OIDC_ADMIN_GROUP: a group (or app role) in the token that makes the person an admin. None: no one is.
    admin_group: Option<String>,
    http: reqwest::Client,
    sealer: Sealer,
    meta: RwLock<Option<(Meta, Instant)>>,
    keys: RwLock<(HashMap<String, DecodingKey>, Option<Instant>)>,
}

#[derive(Serialize, Deserialize)]
struct Pending { state: String, nonce: String, verifier: String, return_to: String }
#[derive(Serialize, Deserialize)]
struct Session { email: String, #[serde(default)] admin: bool }

fn same(a: &str, b: &str) -> bool { a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |x, (p, q)| x | (p ^ q)) == 0 }
fn esc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;") }

/// Where to go after signing in: a path on this site only, never another host (no open redirect).
pub fn safe_return(r: Option<&str>) -> String {
    match r {
        Some(p) if p.starts_with('/') && !p.starts_with("//") && !p.contains('\\') && !p.chars().any(char::is_control) && p.len() <= 512 => p.to_string(),
        _ => "/".into(),
    }
}

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
}

fn set_cookie(name: &str, value: &str, max_age: u64) -> HeaderValue {
    HeaderValue::from_str(&format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}")).expect("a cookie")
}

impl Oidc {
    pub fn new(s: OidcSettings, http: reqwest::Client) -> Self {
        let sealer = Sealer::new(b"msp-security-console session v1", s.session_key.as_bytes());
        Self { s, http, sealer, admin_group: None, meta: RwLock::new(None), keys: RwLock::new((HashMap::new(), None)) }
    }

    /// Admins are the people whose token carries this group or role (OIDC_ADMIN_GROUP), read once at sign-in and kept
    /// in the session: a change in the group takes effect at the next sign-in, as membership itself does.
    pub fn with_admin_group(mut self, g: Option<String>) -> Self { self.admin_group = g.filter(|g| !g.trim().is_empty()); self }

    /// An authenticated, encrypted cookie value: the kind is bound in as associated data, so a pending sign-in can't be
    /// replayed as a session, and the expiry is inside (crate::seal).
    pub fn seal<T: Serialize>(&self, kind: &str, d: T, ttl: Duration) -> String { self.sealer.seal(kind, d, ttl) }

    pub fn open<T: DeserializeOwned>(&self, kind: &str, v: &str) -> Option<T> { self.sealer.open(kind, v) }

    async fn meta(&self) -> Result<Meta, String> {
        if let Some((m, t)) = self.meta.read().await.as_ref() && t.elapsed() < Duration::from_secs(3600) { return Ok(m.clone()); }
        let url = format!("{}/.well-known/openid-configuration", self.s.issuer.trim_end_matches('/'));
        let m: Meta = self.http.get(&url).timeout(Duration::from_secs(10)).send().await.map_err(|_| "the provider's discovery document can't be fetched")?
            .error_for_status().map_err(|_| "the provider's discovery document can't be fetched")?.json().await.map_err(|_| "the provider's discovery document isn't valid")?;
        // The provider must call itself by the issuer we were configured with (Entra: the tenant's v2.0 issuer).
        if m.issuer.trim_end_matches('/') != self.s.issuer.trim_end_matches('/') { return Err("the provider's issuer isn't the configured OIDC_ISSUER".into()); }
        *self.meta.write().await = Some((m.clone(), Instant::now()));
        Ok(m)
    }

    async fn key(&self, jwks_uri: &str, kid: &str) -> Option<DecodingKey> {
        if let Some(k) = self.keys.read().await.0.get(kid) { return Some(k.clone()); }
        let mut w = self.keys.write().await;
        if let Some(k) = w.0.get(kid) { return Some(k.clone()); }
        if w.1.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) { return None; }
        w.1 = Some(Instant::now());
        let set: JwkSet = self.http.get(jwks_uri).timeout(Duration::from_secs(10)).send().await.ok()?.error_for_status().ok()?.json().await.ok()?;
        w.0 = set.keys.iter().filter_map(|j| Some((j.common.key_id.clone()?, DecodingKey::from_jwk(j).ok()?))).collect();
        w.0.get(kid).cloned()
    }

    fn redirect_uri(&self) -> String { format!("{}/auth/callback", self.s.public_url.trim_end_matches('/')) }

    /// The person in an id_token, if the token is good and they're in the allowed group or role; and whether they're
    /// an admin (OIDC_ADMIN_GROUP among the same groups or roles).
    async fn person(&self, m: &Meta, id_token: &str, nonce: &str) -> Result<(String, bool), (StatusCode, String)> {
        let bad = |w: &str| (StatusCode::UNAUTHORIZED, format!("The sign-in couldn't be verified ({w})."));
        let h = decode_header(id_token).map_err(|_| bad("unreadable token"))?;
        if h.alg != Algorithm::RS256 { return Err(bad("not RS256")); }
        let key = self.key(&m.jwks_uri, &h.kid.ok_or_else(|| bad("no key id"))?).await.ok_or_else(|| bad("a key the provider doesn't publish"))?;
        let mut v = Validation::new(Algorithm::RS256);
        v.set_audience(&[&self.s.client_id]);
        v.set_issuer(&[&m.issuer]);
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        v.validate_nbf = true;
        let c: serde_json::Value = decode(id_token, &key, &v).map_err(|_| bad("token refused"))?.claims;
        if !c.get("nonce").and_then(|n| n.as_str()).is_some_and(|n| same(n, nonce)) { return Err(bad("nonce")); }
        let email = ["email", "preferred_username", "upn"].iter().find_map(|k| c.get(*k).and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
            .ok_or_else(|| bad("names no one"))?.to_string();
        let has = |claim: &str, want: &str| c.get(claim).and_then(|g| g.as_array()).is_some_and(|a| a.iter().any(|x| x.as_str() == Some(want)));
        if has("groups", &self.s.allowed_group) || has("roles", &self.s.allowed_group) {
            let admin = self.admin_group.as_deref().is_some_and(|g| has("groups", g) || has("roles", g));
            return Ok((email, admin));
        }
        if c.get("_claim_names").and_then(|n| n.get("groups")).is_some() {
            return Err((StatusCode::FORBIDDEN, "You're in too many groups for Entra to list in the sign-in token. Ask your administrator to give you the console's app role instead.".into()));
        }
        Err((StatusCode::FORBIDDEN, "You're signed in, but not in the group allowed to use this console.".into()))
    }
}

impl Identity for Oidc {
    fn mode(&self) -> &'static str { "oidc" }
    fn login_url(&self) -> Option<&'static str> { Some("/auth/login") }
    fn identify<'a>(&'a self, headers: &'a HeaderMap, _peer: IpAddr) -> IdFuture<'a> {
        Box::pin(async move {
            let v = cookie(headers, SESSION_COOKIE).ok_or(Refusal("not signed in".into()))?;
            let s: Session = self.open("session", &v).ok_or(Refusal("the session isn't valid".into()))?;
            Ok(Who { email: s.email, admin: s.admin })
        })
    }
}

pub fn routes(o: Arc<Oidc>) -> Router {
    security_headers(Router::new().route("/auth/login", get(login)).route("/auth/callback", get(callback)).route("/auth/logout", post(logout)).with_state(o))
}

fn page(status: StatusCode, msg: &str) -> Response {
    (status, Html(format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign-in</title></head><body style=\"font:15px system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px\"><h1>MSP Security Console</h1><p>{}</p><p><a href=\"/auth/login\">Try again</a></p></body></html>", esc(msg)))).into_response()
}

#[derive(Deserialize)]
struct LoginQ { return_to: Option<String> }

async fn login(State(o): State<Arc<Oidc>>, Query(q): Query<LoginQ>) -> Response {
    let m = match o.meta().await { Ok(m) => m, Err(e) => return page(StatusCode::BAD_GATEWAY, &e) };
    let p = Pending { state: B64.encode(random(16)), nonce: B64.encode(random(16)), verifier: B64.encode(random(32)), return_to: safe_return(q.return_to.as_deref()) };
    let challenge = B64.encode(Sha256::digest(p.verifier.as_bytes()));
    let query = serde_urlencoded::to_string([("response_type", "code"), ("client_id", o.s.client_id.as_str()), ("redirect_uri", o.redirect_uri().as_str()),
        ("scope", "openid email profile"), ("state", p.state.as_str()), ("nonce", p.nonce.as_str()), ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"), ("response_mode", "query")]).expect("a query");
    let to = format!("{}{}{query}", m.authorization_endpoint, if m.authorization_endpoint.contains('?') { "&" } else { "?" });
    let sealed = o.seal("login", p, Duration::from_secs(LOGIN_MINUTES * 60));
    let mut r = (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response();
    r.headers_mut().append(header::SET_COOKIE, set_cookie(LOGIN_COOKIE, &sealed, LOGIN_MINUTES * 60));
    r
}

#[derive(Deserialize)]
struct CallbackQ { code: Option<String>, state: Option<String>, error: Option<String> }
#[derive(Deserialize)]
struct TokenAnswer { id_token: Option<String> }

async fn callback(State(o): State<Arc<Oidc>>, headers: HeaderMap, Query(q): Query<CallbackQ>) -> Response {
    if let Some(e) = q.error { return page(StatusCode::UNAUTHORIZED, &format!("The sign-in was refused by the provider: {e}.")); }
    let Some(p) = cookie(&headers, LOGIN_COOKIE).and_then(|v| o.open::<Pending>("login", &v)) else {
        return page(StatusCode::BAD_REQUEST, "This sign-in has expired or didn't start here.");
    };
    if !q.state.as_deref().is_some_and(|s| same(s, &p.state)) { return page(StatusCode::BAD_REQUEST, "This sign-in didn't start here."); }
    let Some(code) = q.code else { return page(StatusCode::BAD_REQUEST, "The provider sent no code."); };
    let m = match o.meta().await { Ok(m) => m, Err(e) => return page(StatusCode::BAD_GATEWAY, &e) };
    let redirect_uri = o.redirect_uri();
    let form = [("grant_type", "authorization_code"), ("code", code.as_str()), ("redirect_uri", redirect_uri.as_str()), ("client_id", o.s.client_id.as_str()),
        ("client_secret", o.s.client_secret.as_str()), ("code_verifier", p.verifier.as_str())];
    let body = serde_urlencoded::to_string(form).expect("a form");
    let ans = o.http.post(&m.token_endpoint).timeout(Duration::from_secs(15)).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(body).send().await;
    let tok: Option<TokenAnswer> = match ans { Ok(r) if r.status().is_success() => r.json().await.ok(), _ => None };
    let Some(id_token) = tok.and_then(|t| t.id_token) else { return page(StatusCode::BAD_GATEWAY, "The provider didn't complete the sign-in."); };
    match o.person(&m, &id_token, &p.nonce).await {
        Err((st, msg)) => page(st, &msg),
        Ok((email, admin)) => {
            let session = o.seal("session", Session { email, admin }, Duration::from_secs(SESSION_HOURS * 3600));
            let mut r = (StatusCode::SEE_OTHER, [(header::LOCATION, p.return_to)]).into_response();
            r.headers_mut().append(header::SET_COOKIE, set_cookie(SESSION_COOKIE, &session, SESSION_HOURS * 3600));
            r.headers_mut().append(header::SET_COOKIE, set_cookie(LOGIN_COOKIE, "", 0));
            r
        }
    }
}

/// Sign-out is a POST from the console's own page (Origin, or Sec-Fetch-Site where a browser sends no Origin), so a
/// page elsewhere can't sign someone out. It answers where to go next rather than redirecting: the CSP's
/// `form-action 'self'` would block a form's redirect on to the provider.
async fn logout(State(o): State<Arc<Oidc>>, headers: HeaderMap) -> Response {
    if !from_this_site(&headers, &o.s.public_url) { return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "sign out from the console itself" }))).into_response(); }
    // Back to the provider to end its session too, when it says how; otherwise home.
    let to = match o.meta().await.ok().and_then(|m| m.end_session_endpoint) {
        Some(end) => format!("{end}{}{}", if end.contains('?') { "&" } else { "?" },
            serde_urlencoded::to_string([("post_logout_redirect_uri", o.s.public_url.as_str()), ("client_id", o.s.client_id.as_str())]).expect("a query")),
        None => "/".into(),
    };
    let mut r = Json(serde_json::json!({ "to": to })).into_response();
    r.headers_mut().append(header::SET_COOKIE, set_cookie(SESSION_COOKIE, "", 0));
    r
}

/// Whether a request came from a page on `public_url`'s own origin.
pub fn from_this_site(headers: &HeaderMap, public_url: &str) -> bool {
    let rest = public_url.split_once("://").map_or("", |x| x.1);
    let origin = format!("{}://{}", public_url.split_once("://").map_or("", |x| x.0), rest.split('/').next().unwrap_or(""));
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    match h("origin") {
        Some(o) => o.eq_ignore_ascii_case(&origin),
        None => h("sec-fetch-site") == Some("same-origin"),
    }
}
