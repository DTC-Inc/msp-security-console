//! What only an admin may do, once the console is set up: Settings → Connectors (see each connector's settings,
//! test them live, change them) and the advisories entered ahead of NVD. Admins are chosen by sign-in mode
//! (src/config.rs, `Admins`); anyone else signed in gets a 403, and nobody signed in a 401 that says where to sign in.
//!
//! Settings → Connectors is the setup wizard's own logic on a configured console: the same sections, the same live,
//! read-only Test, the same rule that a stored or environment secret is never sent to an address the caller changed
//! (setup's BOUND), the same read-only display of what the environment sets, and the same config file, its secrets
//! encrypted under the master key (saving re-encrypts any secret still stored in plaintext). The database and sign-in
//! sections aren't here: changing either is a new setup or the environment, never a click.
//!
//! A saved change applies the way setup's does: the console restarts with it. Its settings are read in one place, at
//! start-up (config::load), with every refusal there; a connector's jobs, rate limiters and leases are built from them
//! once, and a restart is the one way all of them change together. A hot reload would mean a second path for settings,
//! a running job holding the old credentials under its lease, and, with several replicas on PostgreSQL, one replica on
//! the new settings and the rest on the old. The jobs' cursors live in the store, so a restart resumes where they were.
//!
//! Every call is an audit line naming who, and for a change which settings changed: their names, never their values.

use crate::audit::{now, AuditRecord, AuditSink};
use crate::config::{self, KEYS};
use crate::db::Pool;
use crate::identity::{Identity, Who};
use crate::secrets;
use crate::setup::{self, Answer, WIZARD};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Admin {
    pub identity: Arc<dyn Identity>,
    pub audit: AuditSink,
    /// The process's environment: what it sets is shown read-only and never written to the file.
    pub env: HashMap<String, String>,
    pub config_path: PathBuf,
    pub http: reqwest::Client,
    pub pool: Pool,
    /// After a saved change: the process restarts with it (main.rs exits for its supervisor to start it again).
    pub on_saved: Arc<dyn Fn() + Send + Sync>,
    pub test_timeout: Duration,
}

impl Admin {
    pub fn new(identity: Arc<dyn Identity>, env: HashMap<String, String>, http: reqwest::Client, pool: Pool, on_saved: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self { identity, audit: crate::audit::stdout_sink(), config_path: config::config_path(&env), env, http, pool, on_saved, test_timeout: setup::TEST_TIMEOUT }
    }
    fn production(&self) -> bool { self.env.get("MSP_ENV").map(String::as_str) == Some("production") }
    fn kubernetes(&self) -> bool { self.env.contains_key("KUBERNETES_SERVICE_HOST") }
    fn record(&self, who: &Who, op: &str, status: StatusCode, t0: Instant, params: Value) {
        (self.audit)(AuditRecord { at: now(), who: Some(who.email.clone()), op: Some(op.into()), params, rows: None, status: status.as_u16(), ms: t0.elapsed().as_millis() });
    }
    /// What the config file holds now, decrypted. A file that can't be read (or a secret that won't decrypt) is a
    /// refusal naming the setting, never a guess.
    fn stored(&self) -> Result<HashMap<String, String>, String> { config::read_file(&self.env, &|p| std::fs::read_to_string(p)).map(|f| f.values) }
}

pub const NOT_ADMIN: &str = "Only an admin can change the console's settings and advisories. Everyone signed in can read them.";

pub fn router(a: Arc<Admin>) -> Router {
    crate::app::security_headers(Router::new()
        .route("/api/admin/connectors", get(connectors))
        .route("/api/admin/connectors/test", post(test))
        .route("/api/admin/connectors/save", post(save))
        .route("/api/admin/advisories", post(advisory))
        .layer(middleware::from_fn_with_state(a.clone(), admins_only))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(a))
}

/// Signed in (401 otherwise, with where to sign in) and an admin (403 otherwise); both refusals are audited.
async fn admins_only(State(a): State<Arc<Admin>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    let t0 = Instant::now();
    let op = format!("admin.{}", req.uri().path().trim_start_matches("/api/admin/").replace('/', "."));
    match a.identity.identify(req.headers(), peer.ip()).await {
        Err(_) => {
            (a.audit)(AuditRecord { at: now(), who: None, op: Some(op), params: json!({}), rows: None, status: 401, ms: t0.elapsed().as_millis() });
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": "sign in first", "login": a.identity.login_url() }))).into_response()
        }
        Ok(who) if !who.admin => {
            a.record(&who, &op, StatusCode::FORBIDDEN, t0, json!({}));
            (StatusCode::FORBIDDEN, Json(json!({ "error": NOT_ADMIN }))).into_response()
        }
        Ok(who) => { req.extensions_mut().insert(who); next.run(req).await }
    }
}

fn error(status: StatusCode, msg: &str) -> Response { (status, Json(json!({ "error": msg }))).into_response() }

/// The body as a JSON object. JSON only: a page elsewhere can't send it without the browser asking first.
fn body_json(headers: &HeaderMap, body: &Bytes) -> Result<Value, (StatusCode, &'static str)> {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.trim_start().to_ascii_lowercase().starts_with("application/json") { return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "send JSON")); }
    serde_json::from_slice::<Value>(body).ok().filter(Value::is_object).ok_or((StatusCode::BAD_REQUEST, "the body isn't a JSON object"))
}

fn section_of(b: &Value) -> Result<&'static str, String> {
    let secs = setup::connector_sections();
    let want = b.get("section").and_then(Value::as_str).unwrap_or("");
    secs.iter().copied().find(|s| *s == want).ok_or_else(|| format!("section must be one of {}", secs.join(", ")))
}

/// Each connector's settings as the screens show them: set or not, read-only where the environment sets them, and a
/// plain setting's value in effect (a secret's never), plus which secrets the file still holds unencrypted.
async fn connectors(State(a): State<Arc<Admin>>, Extension(who): Extension<Who>) -> Response {
    let t0 = Instant::now();
    let stored = match a.stored() { Ok(s) => s, Err(e) => { a.record(&who, "admin.connectors", StatusCode::SERVICE_UNAVAILABLE, t0, json!({})); return error(StatusCode::SERVICE_UNAVAILABLE, &e); } };
    let secs = setup::connector_sections();
    let keys = setup::key_states(&a.env, &stored, &secs);
    let plaintext = plaintext_secrets(&a.config_path);
    a.record(&who, "admin.connectors", StatusCode::OK, t0, json!({}));
    Json(json!({ "sections": secs, "keys": keys, "plaintext_secrets": plaintext })).into_response()
}

async fn test(State(a): State<Arc<Admin>>, Extension(who): Extension<Who>, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let b = match body_json(&headers, &body) { Ok(b) => b, Err((st, why)) => { a.record(&who, "admin.connectors.test", st, t0, json!({})); return error(st, why); } };
    let section = match section_of(&b) { Ok(s) => s, Err(e) => { a.record(&who, "admin.connectors.test", StatusCode::BAD_REQUEST, t0, json!({})); return error(StatusCode::BAD_REQUEST, &e); } };
    let op = format!("admin.connectors.test.{section}");
    let stored = match a.stored() { Ok(s) => s, Err(e) => { a.record(&who, &op, StatusCode::SERVICE_UNAVAILABLE, t0, json!({})); return error(StatusCode::SERVICE_UNAVAILABLE, &e); } };
    let given = only_section(section, setup::given_values(b.get("values")));
    if setup::moves_secret(&a.env, section, &given, &stored) {
        a.record(&who, &op, StatusCode::OK, t0, json!({ "ok": false, "vendor_status": null }));
        return Json(json!({ "ok": false, "message": setup::NEW_ADDRESS_TEST, "status": null, "detail": null })).into_response();
    }
    // What's stored, then what was sent, then the environment over both: what the console would run with.
    let mut values = stored.clone();
    values.extend(given);
    for k in KEYS { if let Some(v) = a.env.get(*k) && !v.trim().is_empty() { values.insert(k.to_string(), v.clone()); } }
    let ans: Answer = setup::test_section(section, &values, &a.http, a.production(), a.kubernetes(), a.test_timeout).await;
    a.record(&who, &op, StatusCode::OK, t0, json!({ "ok": ans.ok, "vendor_status": ans.status }));
    Json(json!({ "ok": ans.ok, "message": ans.message, "status": ans.status, "detail": ans.detail })).into_response()
}

/// The settings sent that belong to this section, and no others: a save for NinjaOne can't change HaloPSA.
fn only_section(section: &str, given: HashMap<String, String>) -> HashMap<String, String> {
    given.into_iter().filter(|(k, _)| setup::section_of(k) == Some(section)).collect()
}

/// The secrets the config file holds unencrypted (a hand-edited file, or one from before encryption): names only.
fn plaintext_secrets(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    let Ok(v) = serde_json::from_str::<serde_json::Map<String, Value>>(&text) else { return vec![] };
    let mut out: Vec<String> = v.iter().filter(|(k, x)| secrets::is_secret(k) && x.as_str().is_some_and(|s| !s.trim().is_empty() && !secrets::is_encrypted(s))).map(|(k, _)| k.clone()).collect();
    out.sort();
    out
}

async fn save(State(a): State<Arc<Admin>>, Extension(who): Extension<Who>, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let (r, section, changed, reencrypted) = save_inner(&a, &headers, &body);
    let restarting = r.status() == StatusCode::OK && !(changed.is_empty() && reencrypted.is_empty());
    a.record(&who, &format!("admin.connectors.save{}", section.map(|s| format!(".{s}")).unwrap_or_default()), r.status(), t0,
        json!({ "changed": changed, "reencrypted": reencrypted, "restarting": restarting }));
    if restarting { (a.on_saved)(); }
    r
}

/// The answer, the section, the settings that changed and the secrets re-encrypted (names, never values).
fn save_inner(a: &Admin, headers: &HeaderMap, body: &Bytes) -> (Response, Option<&'static str>, Vec<String>, Vec<String>) {
    let b = match body_json(headers, body) { Ok(b) => b, Err((st, why)) => return (error(st, why), None, vec![], vec![]) };
    let section = match section_of(&b) { Ok(s) => s, Err(e) => return (error(StatusCode::BAD_REQUEST, &e), None, vec![], vec![]) };
    let stored = match a.stored() { Ok(s) => s, Err(e) => return (error(StatusCode::SERVICE_UNAVAILABLE, &e), Some(section), vec![], vec![]) };
    let given = only_section(section, setup::given_values(b.get("values")));
    let off = b.get("off").and_then(Value::as_bool).unwrap_or(false);
    if !off && setup::moves_secret(&a.env, section, &given, &stored) {
        return ((StatusCode::BAD_REQUEST, Json(json!({ "error": setup::NEW_ADDRESS_SAVE, "section": section }))).into_response(), Some(section), vec![], vec![]);
    }
    // The file as it is, with this section's settings replaced: a setting sent is set, a plain one not sent is cleared,
    // a secret not sent is kept. `off` clears the whole section, turning the connector off. What the environment sets is
    // never written.
    let mut file: BTreeMap<String, String> = stored.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for (k, _) in WIZARD.iter().filter(|(_, s)| *s == section) {
        if setup::env_sets(&a.env, k) { continue; }
        match (off, given.get(*k)) {
            (true, _) => { file.remove(*k); }
            (false, Some(v)) => { file.insert(k.to_string(), v.clone()); }
            (false, None) if !secrets::is_secret(k) => { file.remove(*k); }
            (false, None) => {}
        }
    }
    let changed: Vec<String> = file.keys().chain(stored.keys()).collect::<BTreeSet<_>>().into_iter()
        .filter(|k| file.get(*k) != stored.get(*k)).cloned().collect();
    let plain = plaintext_secrets(&a.config_path);
    if changed.is_empty() && plain.is_empty() {
        return (Json(json!({ "restarting": false, "changed": [], "reencrypted": [] })).into_response(), Some(section), vec![], vec![]);
    }
    // The same rules as start-up, on exactly this file under this environment: a half-filled connector refuses here.
    let text = serde_json::to_string(&file).expect("json");
    let path = a.config_path.clone();
    let read = |p: &Path| if p == path { Ok(text.clone()) } else { std::fs::read_to_string(p) };
    match config::load(&a.env, &read) {
        Ok(config::Startup::Configured(_)) => {}
        Ok(_) => return (error(StatusCode::BAD_REQUEST, "That would leave the console unconfigured."), Some(section), changed, vec![]),
        Err(e) => return ((StatusCode::BAD_REQUEST, Json(json!({ "error": e, "section": section }))).into_response(), Some(section), changed, vec![]),
    }
    // Every secret in the file encrypted under the master key, the ones that were plaintext included.
    if file.keys().any(|k| secrets::is_secret(k)) {
        let key = match secrets::find(&a.env, &|p| std::fs::read_to_string(p)) {
            Ok(Some(k)) => k,
            Ok(None) => match secrets::generate(&secrets::key_path(&a.env)) { Ok(k) => k, Err(e) => return (error(StatusCode::INTERNAL_SERVER_ERROR, &e), Some(section), changed, vec![]) },
            Err(e) => return (error(StatusCode::BAD_REQUEST, &e), Some(section), changed, vec![]),
        };
        for (k, v) in file.iter_mut() { if secrets::is_secret(k) { *v = key.encrypt(k, v); } }
    }
    let reencrypted: Vec<String> = plain.into_iter().filter(|k| file.contains_key(k)).collect();
    if let Err(e) = setup::write_config(&a.config_path, &file) { return (error(StatusCode::INTERNAL_SERVER_ERROR, &e), Some(section), changed, vec![]); }
    (Json(json!({ "restarting": true, "changed": changed, "reencrypted": reencrypted })).into_response(), Some(section), changed, reencrypted)
}

/// Add, change, supersede or reactivate an advisory (src/advisory.rs), as the signed-in admin; it applies at once.
async fn advisory(State(a): State<Arc<Admin>>, Extension(who): Extension<Who>, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let b = match body_json(&headers, &body) { Ok(b) => b, Err((st, why)) => { a.record(&who, "admin.advisories", st, t0, json!({})); return error(st, why); } };
    let Some(action) = b.get("action").and_then(Value::as_str).and_then(crate::advisory::Action::parse) else {
        a.record(&who, "admin.advisories", StatusCode::BAD_REQUEST, t0, json!({}));
        return error(StatusCode::BAD_REQUEST, "action must be save, supersede or reactivate");
    };
    let op = format!("admin.advisories.{}", action.as_str());
    let adv = b.get("advisory").cloned().unwrap_or(json!({}));
    // The audit line names the advisory and its CVE, ids only: never its title, rules or notes.
    let ids = json!({ "advisory_id": adv.get("advisory_id").and_then(Value::as_str).map(|s| s.chars().take(120).collect::<String>()),
                      "cve_id": adv.get("cve_id").and_then(Value::as_str).map(|s| s.chars().take(30).collect::<String>()) });
    let reason = b.get("reason").and_then(Value::as_str).unwrap_or("");
    let (st, ans) = match crate::advisory::save(&a.pool, action, &adv, reason, &who.email).await {
        Ok(v) => (StatusCode::OK, v),
        Err(crate::advisory::SaveError::Bad(m)) => (StatusCode::BAD_REQUEST, json!({ "error": m })),
        Err(crate::advisory::SaveError::NotFound) => (StatusCode::NOT_FOUND, json!({ "error": "There's no such advisory." })),
        Err(crate::advisory::SaveError::Db(_)) => (StatusCode::SERVICE_UNAVAILABLE, json!({ "error": "the console's database didn't answer" })),
    };
    a.record(&who, &op, st, t0, ids);
    (st, Json(ans)).into_response()
}
