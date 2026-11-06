//! The first-run setup (docs/design.md, "Configuration"). Only while unconfigured: the server prints a one-time token
//! to its log at boot, serves the web app's wizard at /setup and the JSON setup API under /api/setup, and nothing else.
//! The token unlocks the API for 30 minutes (a sealed cookie); ten wrong tokens lock it until a restart. Each section
//! (the database, sign-in, NinjaOne, HaloPSA, NVD, Blackpoint, Shodan) can be tested live and read-only before saving; the save checks the
//! whole configuration with start-up's own rules, and that the store can be reached and written, writes the config
//! file (mode 0600, its secrets encrypted under the master key: crate::secrets), and the process exits so its
//! supervisor restarts it configured. Every call writes an audit line (who "setup"), never a value.

mod checks;

use crate::app::security_headers;
use crate::audit::{now, stdout_sink, AuditRecord, AuditSink};
use crate::config::{self, KEYS};
use crate::db::DbConfig;
use crate::oidc::cookie;
use crate::seal::Sealer;
use crate::secrets;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::handler::HandlerWithoutStateExt;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_http::services::{ServeDir, ServeFile};

pub use checks::{Answer, NO_SIGN_IN};

pub const MAX_FAILURES: u32 = 10;
pub const COOKIE: &str = "msp_setup";
pub const UNLOCK_MINUTES: u64 = 30;
pub const TEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The wizard's sections, in its order.
pub const SECTIONS: &[&str] = &["database", "auth", "ninja", "halo", "nvd", "msrc", "blackpoint", "shodan"];

/// Every setting the wizard knows, and its section. The rest of KEYS (the `_FILE` paths, KEV_URL, SCHEDULER,
/// ACCESS_CERTS_URL, and the embedder's EMBEDDER, MODEL_DIR and EMBED_THREADS) are set by environment only, and still
/// honoured when they are.
pub const WIZARD: &[(&str, &str)] = &[
    ("DATABASE_PATH", "database"), ("BACKUP_KEEP", "database"), ("DATABASE_URL", "database"),
    ("AUTH_MODE", "auth"), ("PROXY_KIND", "auth"), ("ACCESS_TEAM_DOMAIN", "auth"), ("ACCESS_AUD", "auth"),
    ("TRUSTED_HEADER", "auth"), ("TRUSTED_PROXY_CIDRS", "auth"),
    ("OIDC_ISSUER", "auth"), ("OIDC_CLIENT_ID", "auth"), ("OIDC_CLIENT_SECRET", "auth"), ("OIDC_ALLOWED_GROUP", "auth"), ("SESSION_KEY", "auth"),
    ("PUBLIC_URL", "auth"), ("OIDC_ADMIN_GROUP", "auth"), ("ADMIN_EMAILS", "auth"),
    ("NINJA_BASE_URL", "ninja"), ("NINJA_CLIENT_ID", "ninja"), ("NINJA_CLIENT_SECRET", "ninja"), ("NINJA_PROCESS_FIELD", "ninja"),
    ("HALO_BASE_URL", "halo"), ("HALO_AUTH_URL", "halo"), ("HALO_TENANT", "halo"), ("HALO_CLIENT_ID", "halo"), ("HALO_CLIENT_SECRET", "halo"),
    ("HALO_REQUESTS_PER_5MIN", "halo"), ("HALO_DETAIL_BUDGET", "halo"),
    ("HALO_TICKET_TYPE_ID", "halo"), ("HALO_TICKET_STATUS_ID", "halo"), ("HALO_TICKET_PRIORITY_ID", "halo"),
    ("NVD_API_KEY", "nvd"), ("NVD_URL", "nvd"), ("NVD_FEEDS", "nvd"), ("NVD_FEED_URL", "nvd"),
    ("MSRC", "msrc"), ("MSRC_URL", "msrc"),
    ("BLACKPOINT_BASE_URL", "blackpoint"), ("BLACKPOINT_API_TOKEN", "blackpoint"),
    ("SHODAN_API_KEY", "shodan"), ("SHODAN_URL", "shodan"), ("SHODAN_SCAN_CREDITS_PER_MONTH", "shodan"), ("SCAN_POLICY_ADMINS", "shodan"),
];

pub fn section_of(k: &str) -> Option<&'static str> { WIZARD.iter().find(|(n, _)| *n == k).map(|(_, s)| *s) }

/// The sign-in settings each mode keeps; anything else sent for sign-in is dropped, so no stray secret is stored. No
/// sign-in at all (dev_insecure) is kept only where start-up would allow it: on one computer, never in production or
/// Kubernetes.
fn auth_keys(mode: &str, kind: &str, local_only: bool) -> &'static [&'static str] {
    match (mode, kind) {
        ("dev_insecure", _) if local_only => &["AUTH_MODE"],
        ("proxy", "cloudflare_access") => &["AUTH_MODE", "PROXY_KIND", "ACCESS_TEAM_DOMAIN", "ACCESS_AUD", "PUBLIC_URL", "ADMIN_EMAILS"],
        ("proxy", "trusted_header") => &["AUTH_MODE", "PROXY_KIND", "TRUSTED_HEADER", "TRUSTED_PROXY_CIDRS", "PUBLIC_URL", "ADMIN_EMAILS"],
        ("oidc", _) => &["AUTH_MODE", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_ALLOWED_GROUP", "SESSION_KEY", "PUBLIC_URL", "OIDC_ADMIN_GROUP"],
        _ => &[],
    }
}

/// Each secret, and every address it's sent to: by a Test, and by the console once it's saved. A secret the caller
/// didn't type (the stored one, or the environment's) goes only to addresses that also come, unchanged, from the store
/// or the environment. Otherwise anyone holding the setup token could send it to a host of their own.
///
/// DATABASE_URL is the address and the secret at once: the password is in the URL, so a stored URL is only ever used
/// whole, and pointing it at a new host means typing the whole URL again, password included. It has no other address
/// to move it to; it's listed so that stays true if one is ever added.
const BOUND: &[(&str, &str, &[&str])] = &[
    ("database", "DATABASE_URL", &[]),
    ("ninja", "NINJA_CLIENT_SECRET", &["NINJA_BASE_URL"]),
    ("halo", "HALO_CLIENT_SECRET", &["HALO_BASE_URL", "HALO_AUTH_URL"]),
    ("nvd", "NVD_API_KEY", &["NVD_URL"]),
    ("blackpoint", "BLACKPOINT_API_TOKEN", &["BLACKPOINT_BASE_URL"]),
    ("shodan", "SHODAN_API_KEY", &["SHODAN_URL"]),
    ("auth", "OIDC_CLIENT_SECRET", &["OIDC_ISSUER"]),
];
pub const NEW_ADDRESS_TEST: &str = "Enter the secret again to test a new address.";
pub const NEW_ADDRESS_SAVE: &str = "Enter the secret again to save a new address.";

/// Structured log lines (stdout in the process; captured in tests).
pub type LogSink = Arc<dyn Fn(Value) + Send + Sync>;
pub fn stdout_log() -> LogSink { Arc::new(|v: Value| println!("{v}")) }

pub struct Setup {
    pub token: String,
    pub config_path: PathBuf,
    /// The process's environment: what it sets is shown read-only and never written to the file.
    pub env: HashMap<String, String>,
    pub http: reqwest::Client,
    /// The web app's files; the wizard is its /setup view.
    pub static_dir: Option<PathBuf>,
    pub on_saved: Arc<dyn Fn() + Send + Sync>,
    pub audit: AuditSink,
    pub log: LogSink,
    /// How long a section's live test may take (15 s; shorter only in tests).
    pub test_timeout: Duration,
    failures: AtomicU32,
    sealer: Sealer,
}

impl Setup {
    pub fn new(env: HashMap<String, String>, http: reqwest::Client, on_saved: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            token: new_token(), config_path: config::config_path(&env), static_dir: env.get("STATIC_DIR").filter(|s| !s.is_empty()).map(PathBuf::from),
            env, http, on_saved, audit: stdout_sink(), log: stdout_log(), test_timeout: TEST_TIMEOUT, failures: AtomicU32::new(0),
            sealer: Sealer::ephemeral(b"msp-security-console setup v1"),
        }
    }

    fn production(&self) -> bool { self.env.get("MSP_ENV").map(String::as_str) == Some("production") }
    fn kubernetes(&self) -> bool { self.env.contains_key("KUBERNETES_SERVICE_HOST") }
    /// Whether "only this computer" (no sign-in) may be chosen: outside production and outside Kubernetes, as start-up
    /// allows dev_insecure.
    pub fn local_only(&self) -> bool { !self.production() && !self.kubernetes() }

    /// Whether the environment sets this setting (itself, or as NAME_FILE).
    pub fn env_sets(&self, k: &str) -> bool { env_sets(&self.env, k) }

    /// What the file holds now, decrypted. Unconfigured, that's usually nothing.
    fn stored(&self) -> HashMap<String, String> {
        config::read_file(&self.env, &|p| std::fs::read_to_string(p)).map(|f| f.values).unwrap_or_default()
    }

    fn record(&self, op: &str, status: StatusCode, t0: Instant, params: Value) {
        (self.audit)(AuditRecord { at: now(), who: Some("setup".into()), op: Some(op.into()), params, rows: None, status: status.as_u16(), ms: t0.elapsed().as_millis() });
    }

    fn unlocked(&self, headers: &HeaderMap) -> bool {
        cookie(headers, COOKIE).and_then(|v| self.sealer.open::<u8>("setup", &v)).is_some()
    }

    /// The request's settings: known ones only, trimmed, empty meaning "not given".
    fn given(values: Option<&Value>) -> HashMap<String, String> {
        values.and_then(Value::as_object).into_iter().flatten()
            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.trim().to_string())))
            .filter(|(k, v)| section_of(k).is_some() && !v.is_empty()).collect()
    }

    /// Whether `section` would send a secret the caller didn't type to an address the caller changed (BOUND).
    fn moves_secret(&self, section: &str, given: &HashMap<String, String>, stored: &HashMap<String, String>) -> bool { moves_secret(&self.env, section, given, stored) }

    /// The settings a test runs with: what's stored, then what was sent, then the environment over both. For the
    /// database, only the chosen store's settings (store_keys), so a test of the SQLite file isn't read as PostgreSQL
    /// because a URL was saved before, or the other way round.
    fn effective(&self, given: &HashMap<String, String>) -> HashMap<String, String> {
        let mut m = self.stored();
        m.extend(given.clone());
        for k in KEYS { if let Some(v) = self.env.get(*k) && !v.trim().is_empty() { m.insert(k.to_string(), v.clone()); } }
        let keep = self.store_keys(given, &self.stored());
        m.retain(|k, _| section_of(k.strip_suffix("_FILE").unwrap_or(k)) != Some("database") || keep.contains(&k.strip_suffix("_FILE").unwrap_or(k)));
        m
    }

    /// The database settings to keep, for the store the person chose. The environment's choice wins, as it does at
    /// start-up. Then what was sent: DATABASE_PATH means the SQLite file (the wizard always sends it for that choice,
    /// the default path included), DATABASE_URL means PostgreSQL, and both are kept, for start-up's rules to refuse.
    /// Then a saved DATABASE_URL means PostgreSQL still. Otherwise, the SQLite file at its default path.
    pub fn store_keys(&self, given: &HashMap<String, String>, stored: &HashMap<String, String>) -> &'static [&'static str] {
        const SQLITE: &[&str] = &["DATABASE_PATH", "BACKUP_KEEP"];
        const POSTGRES: &[&str] = &["DATABASE_URL"];
        const BOTH: &[&str] = &["DATABASE_PATH", "BACKUP_KEEP", "DATABASE_URL"];
        match (self.env_sets("DATABASE_URL"), self.env_sets("DATABASE_PATH")) {
            (true, true) => return BOTH,
            (true, false) => return POSTGRES,
            (false, true) => return SQLITE,
            _ => {}
        }
        match (given.contains_key("DATABASE_URL"), given.contains_key("DATABASE_PATH")) {
            (true, true) => BOTH,
            (true, false) => POSTGRES,
            (false, true) => SQLITE,
            _ if stored.contains_key("DATABASE_URL") || stored.contains_key("DATABASE_URL_FILE") => POSTGRES,
            _ => SQLITE,
        }
    }
}

/// Whether the environment sets this setting (itself, or as NAME_FILE): shown read-only, never written.
pub fn env_sets(env: &HashMap<String, String>, k: &str) -> bool {
    [k.to_string(), format!("{k}_FILE")].iter().any(|n| KEYS.contains(&n.as_str()) && env.get(n).is_some_and(|v| !v.trim().is_empty()))
}

/// Whether `section` would send a secret the caller didn't type (the stored one, or the environment's) to an address
/// the caller changed (BOUND). Setup and Settings → Connectors share it.
pub fn moves_secret(env: &HashMap<String, String>, section: &str, given: &HashMap<String, String>, stored: &HashMap<String, String>) -> bool {
    let norm = |v: &str| v.trim().trim_end_matches('/').to_string();
    BOUND.iter().filter(|(sec, _, _)| *sec == section).any(|(_, secret, urls)| {
        let borrowed = env_sets(env, secret)
            || (!given.contains_key(*secret) && (stored.contains_key(*secret) || stored.contains_key(&format!("{secret}_FILE"))));
        borrowed && urls.iter().any(|u| !env_sets(env, u) && given.get(*u).is_some_and(|v| Some(norm(v)) != stored.get(*u).map(|x| norm(x))))
    })
}

/// The settings a request sent: known ones only, trimmed, empty meaning "not given".
pub fn given_values(values: Option<&Value>) -> HashMap<String, String> { Setup::given(values) }

/// Each wizard setting of these sections as the screens show it: set or not, set by environment (read-only), and a
/// plain setting's value in effect (a secret's never).
pub fn key_states(env: &HashMap<String, String>, stored: &HashMap<String, String>, sections: &[&str]) -> Map<String, Value> {
    let mut keys = Map::new();
    for (k, sec) in WIZARD.iter().filter(|(_, s)| sections.contains(s)) {
        let by_env = env_sets(env, k);
        let secret = secrets::is_secret(k);
        let set = by_env || stored.contains_key(*k) || stored.contains_key(&format!("{k}_FILE"));
        let value = if secret { None } else { env.get(*k).filter(|v| !v.trim().is_empty()).or_else(|| stored.get(*k)).cloned() };
        keys.insert(k.to_string(), json!({ "set": set, "env": by_env, "value": value, "secret": secret, "section": sec }));
    }
    keys
}

/// A section's live, read-only Test with these settings, cut off at `timeout`.
pub async fn test_section(section: &str, values: &HashMap<String, String>, http: &reqwest::Client, production: bool, kubernetes: bool, timeout: Duration) -> Answer {
    match tokio::time::timeout(timeout, checks::run(section, values, http, production, kubernetes, timeout)).await {
        Ok(a) => a,
        Err(_) => Answer::fail(&format!("{} didn't answer within {} seconds.", checks::vendor(section), timeout.as_secs().max(1)), None),
    }
}

/// The connectors' sections: every one of the wizard's but the database and sign-in, which change only by a new setup
/// or the environment.
pub fn connector_sections() -> Vec<&'static str> { SECTIONS.iter().copied().filter(|s| *s != "database" && *s != "auth").collect() }

pub fn new_token() -> String { crate::seal::random(24).iter().map(|x| format!("{x:02x}")).collect() }

fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn error(status: StatusCode, msg: &str) -> Response { (status, Json(json!({ "error": msg }))).into_response() }

pub fn router(s: Arc<Setup>) -> Router {
    let api = Router::new()
        .route("/api/setup/unlock", post(unlock))
        .route("/api/setup/state", get(state))
        .route("/api/setup/test", post(test))
        .route("/api/setup/save", post(save))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(s.clone());
    let to_setup = || async { Redirect::to("/setup") };
    let mut r = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "unconfigured: finish /setup") }))
        .merge(api);
    match &s.static_dir {
        Some(dir) => {
            // The wizard is the web app's own view; its assets are served as they are; anything else goes to /setup.
            let index = ServeFile::new(dir.join("index.html"));
            r = r.route_service("/setup", index.clone()).route_service("/setup/", index.clone()).route_service("/setup/{*rest}", index)
                .fallback_service(ServeDir::new(dir).append_index_html_on_directories(false).call_fallback_on_method_not_allowed(true).fallback(to_setup.into_service()));
        }
        None => {
            let missing = || async { (StatusCode::SERVICE_UNAVAILABLE, "The web app isn't in this build: set STATIC_DIR to its files, or configure by environment.") };
            r = r.route("/setup", get(missing)).route("/setup/", get(missing)).route("/setup/{*rest}", get(missing)).fallback(to_setup);
        }
    }
    security_headers(r)
}

/// The body as a JSON object, or the status and reason to refuse it with.
fn json_body(headers: &HeaderMap, body: &Bytes) -> Result<Value, (StatusCode, &'static str)> {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.trim_start().to_ascii_lowercase().starts_with("application/json") { return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "send JSON")); }
    serde_json::from_slice::<Value>(body).ok().filter(Value::is_object).ok_or((StatusCode::BAD_REQUEST, "the body isn't a JSON object"))
}

async fn unlock(State(s): State<Arc<Setup>>, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let r = unlock_inner(&s, &headers, &body);
    s.record("setup.unlock", r.status(), t0, json!({}));
    r
}

fn unlock_inner(s: &Setup, headers: &HeaderMap, body: &Bytes) -> Response {
    let b = match json_body(headers, body) { Ok(b) => b, Err((st, why)) => return error(st, why) };
    // A try is reserved before the token is compared, in one atomic step, so however many arrive at once no more than
    // MAX_FAILURES are ever compared; the right token gives its try back.
    if s.failures.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < MAX_FAILURES).then_some(n + 1)).is_err() {
        return error(StatusCode::TOO_MANY_REQUESTS, "Too many wrong setup tokens. Restart the console for a new token (it prints to the log).");
    }
    if !same(b.get("token").and_then(Value::as_str).unwrap_or("").trim(), &s.token) {
        return error(StatusCode::UNAUTHORIZED, "That isn't the setup token. It's in the console's log, printed once at start-up.");
    }
    s.failures.fetch_sub(1, Ordering::SeqCst);
    // Secure, unless this is plain http outside production (a laptop's http://localhost).
    let https = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).is_some_and(|p| p.split(',').next().unwrap_or("").trim().eq_ignore_ascii_case("https"));
    let secure = if s.production() || https { "; Secure" } else { "" };
    let v = s.sealer.seal("setup", 1u8, Duration::from_secs(UNLOCK_MINUTES * 60));
    let c = format!("{COOKIE}={v}; Path=/api/setup; HttpOnly; SameSite=Strict; Max-Age={}{secure}", UNLOCK_MINUTES * 60);
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&c).expect("a cookie"));
    r
}

pub const NO_SIGN_IN_REFUSED: &str = "No sign-in is only for trying the console on one computer, and isn't allowed in production or on Kubernetes. Choose how people sign in: Cloudflare Access, a trusted header, or OIDC.";

const LOCKED: &str = "unlock setup first, with the token from the console's log";

async fn state(State(s): State<Arc<Setup>>, headers: HeaderMap) -> Response {
    let t0 = Instant::now();
    if !s.unlocked(&headers) { s.record("setup.state", StatusCode::UNAUTHORIZED, t0, json!({})); return error(StatusCode::UNAUTHORIZED, LOCKED); }
    let stored = s.stored();
    // A secret is only ever set or not; a plain setting shows what's in effect.
    let keys = key_states(&s.env, &stored, SECTIONS);
    s.record("setup.state", StatusCode::OK, t0, json!({}));
    Json(json!({ "keys": keys, "sections": SECTIONS, "local_only": s.local_only() })).into_response()
}

async fn test(State(s): State<Arc<Setup>>, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    let parsed = json_body(&headers, &body);
    let section = parsed.as_ref().ok().and_then(|b| b.get("section")).and_then(Value::as_str).filter(|x| SECTIONS.contains(x)).map(String::from);
    let op = format!("setup.test.{}", section.as_deref().unwrap_or("unknown"));
    if !s.unlocked(&headers) { s.record(&op, StatusCode::UNAUTHORIZED, t0, json!({})); return error(StatusCode::UNAUTHORIZED, LOCKED); }
    let b = match parsed { Ok(b) => b, Err((st, why)) => { s.record(&op, st, t0, json!({})); return error(st, why); } };
    let Some(section) = section else {
        s.record(&op, StatusCode::BAD_REQUEST, t0, json!({}));
        return error(StatusCode::BAD_REQUEST, &format!("section must be one of {}", SECTIONS.join(", ")));
    };
    let given = Setup::given(b.get("values"));
    // The sign-in test sends no secret anywhere (discovery, certs); the vendors' tests do.
    if section != "auth" && s.moves_secret(&section, &given, &s.stored()) {
        s.record(&op, StatusCode::OK, t0, json!({ "ok": false, "vendor_status": null }));
        return Json(json!({ "ok": false, "message": NEW_ADDRESS_TEST, "status": null, "detail": null })).into_response();
    }
    let values = s.effective(&given);
    let a = test_section(&section, &values, &s.http, s.production(), s.kubernetes(), s.test_timeout).await;
    s.record(&op, StatusCode::OK, t0, json!({ "ok": a.ok, "vendor_status": a.status }));
    Json(json!({ "ok": a.ok, "message": a.message, "status": a.status, "detail": a.detail })).into_response()
}

/// The section a start-up error is about: the one owning the setting it names first.
fn section_in(msg: &str) -> Option<&'static str> {
    let mut best: Option<(usize, usize, &'static str)> = None;
    for k in KEYS {
        if let Some(at) = msg.find(k) {
            let base = k.strip_suffix("_FILE").unwrap_or(k);
            if let Some(sec) = section_of(base) && best.is_none_or(|(a, l, _)| at < a || (at == a && k.len() > l)) { best = Some((at, k.len(), sec)); }
        }
    }
    best.map(|b| b.2)
}

fn refuse(status: StatusCode, msg: &str, section: Option<&str>) -> Response { (status, Json(json!({ "error": msg, "section": section }))).into_response() }

async fn save(State(s): State<Arc<Setup>>, headers: HeaderMap, body: Bytes) -> Response {
    let t0 = Instant::now();
    if !s.unlocked(&headers) { s.record("setup.save", StatusCode::UNAUTHORIZED, t0, json!({})); return error(StatusCode::UNAUTHORIZED, LOCKED); }
    let (r, names) = save_inner(&s, &headers, &body).await;
    s.record("setup.save", r.status(), t0, json!({ "keys": names }));
    r
}

/// The answer, and the names of the settings written (for the audit line; never their values).
async fn save_inner(s: &Setup, headers: &HeaderMap, body: &Bytes) -> (Response, Vec<String>) {
    let b = match json_body(headers, body) { Ok(b) => b, Err((st, why)) => return (error(st, why), vec![]) };
    let given = Setup::given(b.get("values"));
    // Sign-in decides which of its settings are kept; the environment's choice wins, as it does at start-up.
    let pick = |k: &str| s.env.get(k).filter(|v| !v.trim().is_empty()).or_else(|| given.get(k)).cloned().unwrap_or_default();
    if pick("AUTH_MODE") == "dev_insecure" && !s.local_only() {
        return (refuse(StatusCode::BAD_REQUEST, NO_SIGN_IN_REFUSED, Some("auth")), vec![]);
    }
    let auth = auth_keys(&pick("AUTH_MODE"), &pick("PROXY_KIND"), s.local_only());
    if auth.is_empty() { return (refuse(StatusCode::BAD_REQUEST, "Choose how people sign in: behind a proxy (Cloudflare Access, or a trusted header), or OIDC.", Some("auth")), vec![]); }
    let stored = s.stored();
    // The chosen store's settings only: a saved URL isn't kept beside a SQLite file chosen now, nor a path beside a URL.
    let store = s.store_keys(&given, &stored);
    let keep = |k: &str| match section_of(k) { Some("auth") => auth.contains(&k), Some("database") => store.contains(&k), Some(_) => true, None => false };
    // A kept or environment secret goes nowhere new (BOUND): sign-in's only when its mode keeps it.
    for (sec, secret, _) in BOUND {
        if keep(secret) && s.moves_secret(sec, &given, &stored) { return (refuse(StatusCode::BAD_REQUEST, NEW_ADDRESS_SAVE, Some(sec)), vec![]); }
    }
    // What goes in the file: the chosen sections' settings, never one the environment sets. A secret left out keeps
    // the stored one.
    let mut file: BTreeMap<String, String> = BTreeMap::new();
    for (k, _) in WIZARD {
        if !keep(k) || s.env_sets(k) { continue; }
        let v = given.get(*k).or_else(|| if secrets::is_secret(k) { stored.get(*k) } else { None });
        if let Some(v) = v { file.insert(k.to_string(), v.clone()); }
    }
    let names: Vec<String> = file.keys().cloned().collect();
    // The same rules as start-up, on exactly this file under this environment.
    let text = serde_json::to_string(&file).expect("json");
    let path = s.config_path.clone();
    let read = |p: &Path| if p == path { Ok(text.clone()) } else { std::fs::read_to_string(p) };
    let cfg = match config::load(&s.env, &read) {
        Ok(config::Startup::Configured(c)) => c,
        Ok(_) => return (refuse(StatusCode::BAD_REQUEST, "Nothing was filled in.", None), names),
        Err(e) => return (refuse(StatusCode::BAD_REQUEST, &e, section_in(&e)), names),
    };
    // Its store must be somewhere it can reach and write, or it restarts into a refusal with no setup to fix it from.
    let db = match &cfg.db {
        DbConfig::Sqlite(c) => checks::database_at(&c.path),
        DbConfig::Postgres(c) => match tokio::time::timeout(s.test_timeout, checks::postgres_at(c, s.test_timeout)).await {
            Ok(a) => a,
            Err(_) => Answer::fail(&format!("The database didn't answer within {} seconds.", s.test_timeout.as_secs().max(1)), None),
        },
    };
    if !db.ok { return (refuse(StatusCode::BAD_REQUEST, &db.message, Some("database")), names); }
    // Secrets encrypted under the master key: the environment's, or the one on the key's volume, made on first use.
    let mut key_path: Option<String> = None;
    if file.keys().any(|k| secrets::is_secret(k)) {
        let key = match secrets::find(&s.env, &|p| std::fs::read_to_string(p)) {
            Ok(Some(k)) => k,
            Ok(None) => match secrets::generate(&secrets::key_path(&s.env)) {
                Ok(k) => { (s.log)(json!({ "msg": "setup: generated the master key that encrypts the config file's secrets; keep it with the config volume's backups", "master_key_path": k.source.path() })); k }
                Err(e) => return (refuse(StatusCode::INTERNAL_SERVER_ERROR, &e, None), names),
            },
            Err(e) => return (refuse(StatusCode::BAD_REQUEST, &e, None), names),
        };
        key_path = key.source.path().map(|p| p.display().to_string());
        for (k, v) in file.iter_mut() { if secrets::is_secret(k) { *v = key.encrypt(k, v); } }
    }
    if let Err(e) = write_config(&s.config_path, &file) { return (refuse(StatusCode::INTERNAL_SERVER_ERROR, &e, None), names); }
    (s.log)(json!({ "msg": "setup: settings saved; restarting configured", "config_path": s.config_path, "keys": names }));
    (s.on_saved)();
    (Json(json!({ "restarting": true, "master_key_path": key_path })).into_response(), names)
}

/// Written beside itself and renamed into place, readable by the console alone.
pub fn write_config(path: &Path, settings: &BTreeMap<String, String>) -> Result<(), String> {
    use std::io::Write;
    let dir = path.parent().ok_or("the config path has no directory")?;
    let tmp = dir.join(".config.json.tmp");
    let text = serde_json::to_string_pretty(settings).map_err(|_| "the settings couldn't be written")?;
    // Always a new file, so it's always 0600: a leftover from a crash (or anything else at that name) would keep its
    // own mode through a truncate, and a symlink there would be followed.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(format!("can't replace {} in {}", tmp.display(), dir.display())),
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
    let mut fh = o.open(&tmp).map_err(|_| format!("can't write in {}: mount a writable volume there, or configure by environment instead", dir.display()))?;
    fh.write_all(text.as_bytes()).and_then(|_| fh.sync_all()).map_err(|_| "the settings couldn't be written")?;
    std::fs::rename(&tmp, path).map_err(|_| "the settings couldn't be put in place")?;
    Ok(())
}
