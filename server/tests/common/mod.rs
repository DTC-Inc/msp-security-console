#![allow(dead_code)]
//! Stand-ins on real local ports (a team's Access certs endpoint, the vendors), and a fresh store per test, on SQLite or
//! PostgreSQL.
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub async fn serve(r: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    format!("http://{addr}")
}

/// Two RSA key pairs, made once per test run and never written down: A is the team's (served from its certs
/// endpoint), B a stranger's.
pub struct Keys { pub a_pem: String, pub b_pem: String, pub a_jwk: Value }
pub fn keys() -> &'static Keys {
    use base64::Engine;
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    static K: std::sync::OnceLock<Keys> = std::sync::OnceLock::new();
    K.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let a = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let b = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let b64 = |x: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        let jwk = json!({ "kty": "RSA", "kid": "kid-a", "alg": "RS256", "use": "sig", "n": b64(a.n().to_bytes_be()), "e": b64(a.e().to_bytes_be()) });
        Keys { a_pem: a.to_pkcs1_pem(LineEnding::LF).unwrap().to_string(), b_pem: b.to_pkcs1_pem(LineEnding::LF).unwrap().to_string(), a_jwk: jwk }
    })
}

/// The team's certs endpoint, counting how often it is asked.
pub async fn certs() -> (String, Arc<Mutex<u32>>) {
    let n = Arc::new(Mutex::new(0u32));
    let jwks = json!({ "keys": [keys().a_jwk.clone()] });
    let c = n.clone();
    let r = Router::new().route("/cdn-cgi/access/certs", get(move || { let j = jwks.clone(); let c = c.clone(); async move { *c.lock().unwrap() += 1; Json(j) } }));
    (format!("{}/cdn-cgi/access/certs", serve(r).await), n)
}

pub fn sign(claims: Value, key_pem: &str, kid: &str) -> String {
    let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    h.kid = Some(kid.into());
    jsonwebtoken::encode(&h, &claims, &jsonwebtoken::EncodingKey::from_rsa_pem(key_pem.as_bytes()).unwrap()).unwrap()
}
pub const TEAM: &str = "example.cloudflareaccess.com";
pub const AUD: &str = "aud-tag-123";
pub fn now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }
pub fn claims(extra: Value) -> Value {
    let mut c = json!({ "iss": format!("https://{TEAM}"), "aud": AUD, "exp": now() + 300, "iat": now(), "email": "tech@example.com" });
    for (k, v) in extra.as_object().unwrap() { if v.is_null() { c.as_object_mut().unwrap().remove(k); } else { c[k] = v.clone(); } }
    c
}

/// A pool on a file that never opens: for routes that must not reach the store at all, and for the store failing.
pub fn unreachable_pool() -> msp_console::db::Pool { msp_console::db::unopenable() }

/// Which store a test runs on. The store's own tests run on both: `both!` makes a `sqlite` and a `postgres` test of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend { Sqlite, Postgres }

/// A fresh store, migrated, removed with the guard: a SQLite file in its own temporary directory, or a database of its
/// own on the PostgreSQL server TEST_DATABASE_URL names (dropped afterwards). SQLite always runs. PostgreSQL without
/// TEST_DATABASE_URL is skipped LOUDLY, unless REQUIRE_DB is set (CI), where it fails: a database test that didn't run
/// must never pass quietly.
pub struct TestDb { pub pool: msp_console::db::Pool, pub cfg: msp_console::db::DbConfig, pub backend: Backend, guard: Guard }
enum Guard { Dir(std::path::PathBuf), Pg(PgDb) }
impl TestDb {
    /// The SQLite store's settings (its tests that are about the file).
    pub fn sqlite(&self) -> &msp_console::db::SqliteConfig { self.cfg.sqlite().expect("a SQLite store") }
    /// The PostgreSQL database's URL, for a test that connects again.
    pub fn url(&self) -> Option<&str> { match &self.guard { Guard::Pg(d) => Some(&d.url), Guard::Dir(_) => None } }
}
impl Drop for TestDb {
    fn drop(&mut self) { if let Guard::Dir(d) = &self.guard { let _ = std::fs::remove_dir_all(d); } }
}

/// A fresh SQLite store: the default for tests that aren't about which store.
pub async fn test_db() -> TestDb { test_db_on(Backend::Sqlite).await.expect("SQLite always runs") }

pub async fn test_db_on(b: Backend) -> Option<TestDb> {
    match b {
        Backend::Sqlite => {
            let dir = temp_dir("console-test");
            let cfg = msp_console::db::DbConfig::Sqlite(msp_console::db::SqliteConfig { path: dir.join("console.db"), backup_keep: 7 });
            let pool = msp_console::db::connect(&cfg).await.expect("migrated");
            Some(TestDb { pool, cfg, backend: b, guard: Guard::Dir(dir) })
        }
        Backend::Postgres => {
            let d = pg_db().await?;
            let cfg = msp_console::db::DbConfig::Postgres(msp_console::db::PgConfig::new(&d.url, false).unwrap());
            let pool = msp_console::db::connect(&cfg).await.expect("migrated");
            Some(TestDb { pool, cfg, backend: b, guard: Guard::Pg(d) })
        }
    }
}

/// The PostgreSQL server's admin URL from TEST_DATABASE_URL; None (and SKIPPED said) when it isn't set, a failure under
/// REQUIRE_DB.
pub fn pg_admin() -> Option<String> {
    match std::env::var("TEST_DATABASE_URL").ok().filter(|u| !u.trim().is_empty()) {
        Some(u) => Some(u),
        None => {
            if std::env::var("REQUIRE_DB").is_ok_and(|v| !v.is_empty()) { panic!("REQUIRE_DB is set but TEST_DATABASE_URL isn't: the PostgreSQL tests must run here"); }
            eprintln!("SKIPPED: no TEST_DATABASE_URL, so this PostgreSQL test did not run");
            None
        }
    }
}

/// A fresh, empty database on the test server (nothing migrated), dropped when it goes.
pub struct PgDb { pub url: String, pub admin: String, pub name: String }
impl Drop for PgDb {
    fn drop(&mut self) {
        let (admin, name) = (self.admin.clone(), self.name.clone());
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async { if let Ok(p) = sqlx::PgPool::connect(&admin).await { let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))).execute(&p).await; } });
        }).join();
    }
}
pub async fn pg_db() -> Option<PgDb> {
    let admin = pg_admin()?;
    let name = format!("msp_test_{}", hex(6));
    let p = sqlx::PgPool::connect(&admin).await.expect("TEST_DATABASE_URL reachable");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&p).await.unwrap();
    p.close().await;
    Some(PgDb { url: with_database(&admin, &name), admin, name })
}
/// The same server and credentials, another database (the URL's query, such as sslmode, kept).
pub fn with_database(url: &str, name: &str) -> String {
    let (base, query) = match url.split_once('?') { Some((b, q)) => (b, Some(q)), None => (url, None) };
    let at = base.rfind('/').filter(|i| *i > "postgres://".len()).expect("TEST_DATABASE_URL needs a /database");
    match query { Some(q) => format!("{}/{name}?{q}", &base[..at]), None => format!("{}/{name}", &base[..at]) }
}
/// A database owned by a role of its own, whose password is long and made up here: for tests that look for the
/// password everywhere it mustn't be. Both go when the guard does.
pub struct PgRole { pub url: String, pub password: String, db: PgDb, role: String }
impl Drop for PgRole {
    fn drop(&mut self) {
        let (admin, name, role) = (self.db.admin.clone(), self.db.name.clone(), self.role.clone());
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async { if let Ok(p) = sqlx::PgPool::connect(&admin).await {
                let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))).execute(&p).await;
                let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP ROLE IF EXISTS {role}"))).execute(&p).await;
            } });
        }).join();
    }
}
pub async fn pg_role_db(can_create: bool) -> Option<PgRole> {
    let admin = pg_admin()?;
    let (role, password, name) = (format!("msp_role_{}", hex(6)), format!("pw-{}", hex(16)), format!("msp_test_{}", hex(6)));
    let p = sqlx::PgPool::connect(&admin).await.expect("TEST_DATABASE_URL reachable");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE ROLE {role} LOGIN PASSWORD '{password}'"))).execute(&p).await.unwrap();
    // The database's owner may create in its public schema (PostgreSQL 15 and later give PUBLIC no CREATE there).
    let owner = if can_create { format!(" OWNER {role}") } else { String::new() };
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}{owner}"))).execute(&p).await.unwrap();
    p.close().await;
    let base = with_database(&admin, &name);
    let at = base.find('@').expect("TEST_DATABASE_URL has user@host");
    let url = format!("postgres://{role}:{password}{}", &base[at..]);
    Some(PgRole { url, password, role, db: PgDb { url: base, admin, name } })
}
/// Whether the test server speaks TLS (the CI service doesn't; a local one may).
pub async fn pg_has_tls() -> bool {
    let Ok(admin) = std::env::var("TEST_DATABASE_URL") else { return false };
    let p = sqlx::PgPool::connect(&admin).await.unwrap();
    let on: String = sqlx::query_scalar("SHOW ssl").fetch_one(&p).await.unwrap();
    p.close().await;
    on == "on"
}

/// Whether the test server carries pgvector (CI's image does; plain postgres doesn't).
pub async fn pg_has_vector() -> bool {
    let Ok(admin) = std::env::var("TEST_DATABASE_URL") else { return false };
    let p = sqlx::PgPool::connect(&admin).await.unwrap();
    let has: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vector')").fetch_one(&p).await.unwrap();
    p.close().await;
    has
}

pub fn hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One statement with no arguments, on either store.
pub async fn exec(pool: &msp_console::db::Pool, sql: &'static str) {
    msp_console::on_pool!(pool, p, _ => { sqlx::query(sql).execute(p).await.unwrap(); })
}
/// One count, on either store.
pub async fn count(pool: &msp_console::db::Pool, sql: &'static str) -> i64 {
    msp_console::on_pool!(pool, p, _ => sqlx::query_scalar::<_, i64>(sql).fetch_one(p).await.unwrap())
}

/// `both!(name, ...)`: for each `async fn name(db: TestDb)`, a test of it on a fresh SQLite store (`name::sqlite`) and
/// one on a fresh PostgreSQL database (`name::postgres`, skipped without TEST_DATABASE_URL, a failure under REQUIRE_DB).
#[macro_export]
macro_rules! both {
    ($($name:ident),* $(,)?) => { $(
        mod $name {
            #[tokio::test] async fn sqlite() { super::$name(super::common::test_db_on(super::common::Backend::Sqlite).await.unwrap()).await }
            #[tokio::test] async fn postgres() { if let Some(db) = super::common::test_db_on(super::common::Backend::Postgres).await { super::$name(db).await } }
        }
    )* };
}

// Stand-in vendors for setup's live tests, on one local port: NinjaOne, HaloPSA, NVD, a team's Access certs and an
// OIDC provider's discovery. Every credential here is made up. A refusal echoes what it was sent, as some vendors do,
// so a test can prove the console never relays a vendor's own text.
pub const NINJA_SECRET: &str = "ninja-secret-7d41c0a9e2";
pub const HALO_SECRET: &str = "halo-secret-3b9f62d7c1";
pub const NVD_KEY: &str = "nvd-key-58c2e4a1f0b6";
pub const HALO_TENANT: &str = "example-tenant";
pub const BLACKPOINT_TOKEN: &str = "blackpoint-token-9e3a71c5d2";
pub const SHODAN_KEY: &str = "shodan-key-4b8f02e6a9c1";
pub type Hits = Arc<Mutex<std::collections::HashMap<String, u32>>>;

pub async fn vendors() -> (String, Hits) {
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::Form;
    use std::collections::HashMap;
    let hits: Hits = Arc::new(Mutex::new(HashMap::new()));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    fn hit(h: &Hits, k: &str) { *h.lock().unwrap().entry(k.to_string()).or_default() += 1; }
    fn bearer(h: &HeaderMap) -> String { h.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string() }
    type F = Form<HashMap<String, String>>;
    type Q = Query<HashMap<String, String>>;
    let refuse = |f: &HashMap<String, String>| (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid_client", "error_description": format!("no client with secret {}", f.get("client_secret").cloned().unwrap_or_default()) })));
    let b2 = base.clone();
    let b3 = base.clone();
    let r = Router::new()
        .route("/ninja/ws/oauth/token", post(move |State(h): State<Hits>, Form(f): F| async move {
            hit(&h, "ninja_token");
            if f.get("client_secret").map(String::as_str) == Some(NINJA_SECRET) && f.get("scope").map(String::as_str) == Some("monitoring") && f.get("grant_type").map(String::as_str) == Some("client_credentials") {
                (StatusCode::OK, Json(json!({ "access_token": "ninja-bearer", "expires_in": 3600 })))
            } else { refuse(&f) }
        }))
        .route("/ninja/v2/organizations", get(|State(h): State<Hits>, hd: HeaderMap, Query(q): Q| async move {
            hit(&h, "ninja_orgs");
            if bearer(&hd) != "Bearer ninja-bearer" || q.get("pageSize").map(String::as_str) != Some("1") { return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))); }
            (StatusCode::OK, Json(json!([{ "id": 1, "name": "Example Org" }])))
        }))
        .route("/halo/auth/token", post(move |State(h): State<Hits>, Form(f): F| async move {
            hit(&h, "halo_token");
            let tenant_ok = f.get("tenant").is_none_or(|t| t == HALO_TENANT);
            if f.get("client_secret").map(String::as_str) == Some(HALO_SECRET) && f.get("scope").map(String::as_str) == Some("all") && tenant_ok {
                if f.contains_key("tenant") { hit(&h, "halo_tenant"); }
                (StatusCode::OK, Json(json!({ "access_token": "halo-bearer", "expires_in": 3600 })))
            } else { refuse(&f) }
        }))
        .route("/halo/api/Client", get(|State(h): State<Hits>, hd: HeaderMap, Query(q): Q| async move {
            hit(&h, "halo_clients");
            if bearer(&hd) != "Bearer halo-bearer" || q.get("page_size").map(String::as_str) != Some("1") || q.get("count").map(String::as_str) != Some("1") {
                return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" })));
            }
            (StatusCode::OK, Json(json!({ "record_count": 3, "clients": [{ "id": 10, "name": "Alpha Example" }] })))
        }))
        .route("/nvd", get(|State(h): State<Hits>, hd: HeaderMap, Query(q): Q| async move {
            hit(&h, "nvd");
            if q.get("resultsPerPage").map(String::as_str) != Some("1") { return (StatusCode::BAD_REQUEST, Json(json!({ "message": "resultsPerPage" }))); }
            match hd.get("apiKey").and_then(|v| v.to_str().ok()) {
                None => (StatusCode::OK, Json(json!({ "totalResults": 250000, "vulnerabilities": [] }))),
                Some(NVD_KEY) => (StatusCode::OK, Json(json!({ "totalResults": 250001, "vulnerabilities": [] }))),
                Some(other) => (StatusCode::NOT_FOUND, Json(json!({ "message": format!("apiKey {other} not found") }))),
            }
        }))
        // Halo's lists for the ticket settings (Halo's priorities carry a GUID id and the integer priorityid).
        .route("/halo/api/TicketType", get(|State(h): State<Hits>, hd: HeaderMap| async move { hit(&h, "halo_lists");
            if bearer(&hd) != "Bearer halo-bearer" { return (StatusCode::UNAUTHORIZED, Json(json!({}))); }
            (StatusCode::OK, Json(json!([{ "id": 31, "name": "Security Alert" }, { "id": 32, "name": "Hidden", "ishidden": true }]))) }))
        .route("/halo/api/Status", get(|State(h): State<Hits>| async move { hit(&h, "halo_lists"); Json(json!([{ "id": 1, "name": "New" }, { "id": 9, "name": "Closed" }])) }))
        .route("/halo/api/Priority", get(|State(h): State<Hits>| async move { hit(&h, "halo_lists"); Json(json!([{ "id": "5f0c-guid", "priorityid": 3, "name": "Medium" }])) }))
        // Blackpoint and Shodan: a wrong token or key is refused with an answer that echoes it, as some vendors do.
        .route("/blackpoint/v1/tenants", get(|State(h): State<Hits>, hd: HeaderMap| async move {
            hit(&h, "blackpoint_tenants");
            if bearer(&hd) != format!("Bearer {BLACKPOINT_TOKEN}") { return (StatusCode::UNAUTHORIZED, Json(json!({ "message": format!("Invalid authorization token {}", bearer(&hd)) }))); }
            (StatusCode::OK, Json(json!({ "data": [{ "id": "tenant-1", "name": "Alpha Example" }], "meta": { "totalItems": 1, "totalPages": 1 } })))
        }))
        .route("/shodan/api-info", get(|State(h): State<Hits>, Query(q): Q| async move {
            hit(&h, "shodan_info");
            let key = q.get("key").cloned().unwrap_or_default();
            if key != SHODAN_KEY { return (StatusCode::UNAUTHORIZED, Json(json!({ "error": format!("Invalid API key {key}") }))); }
            (StatusCode::OK, Json(json!({ "plan": "dev", "scan_credits": 95, "query_credits": 200 })))
        }))
        // The endpoint script's field (running processes): two devices report it.
        .route("/ninja/v2/queries/custom-fields-detailed", get(|State(h): State<Hits>, hd: HeaderMap, Query(q): Q| async move {
            hit(&h, "ninja_fields");
            if bearer(&hd) != "Bearer ninja-bearer" { return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))); }
            let f = q.get("fields").cloned().unwrap_or_default();
            if f != "processInventoryCollectedAt" { return (StatusCode::OK, Json(json!({ "results": [], "cursor": null }))); }
            (StatusCode::OK, Json(json!({ "results": [{ "deviceId": 1, "fields": [] }, { "deviceId": 2, "fields": [] }], "cursor": null })))
        }))
        .route("/feeds/nvdcve-2.0-modified.meta", get(|State(h): State<Hits>| async move { hit(&h, "nvd_feeds");
            "lastModifiedDate:2026-11-06T03:00:00-05:00\r\nsize:100\r\ngzSize:50\r\nsha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\r\n" }))
        .route("/msrc/updates", get(|State(h): State<Hits>| async move { hit(&h, "msrc");
            Json(json!({ "value": [{ "ID": "2026-Oct", "InitialReleaseDate": "2026-10-13T07:00:00Z", "CurrentReleaseDate": "2026-10-26T01:48:59Z" },
                                   { "ID": "2026-Sep", "InitialReleaseDate": "2026-09-08T07:00:00Z", "CurrentReleaseDate": "2026-10-25T01:47:42Z" }] })) }))
        .route("/cdn-cgi/access/certs", get(|State(h): State<Hits>| async move { hit(&h, "certs"); Json(json!({ "keys": [{ "kid": "k1", "kty": "RSA" }, { "kid": "k2", "kty": "RSA" }] })) }))
        .route("/idp/v2.0/.well-known/openid-configuration", get(move |State(h): State<Hits>| { let b = b2.clone(); async move { hit(&h, "discovery"); Json(json!({ "issuer": format!("{b}/idp/v2.0") })) } }))
        // Someone else's host: anything sent here is counted, and it answers as a vendor would, so a test proves no
        // request reached it rather than that one failed.
        .route("/evil/{*rest}", axum::routing::any(|State(h): State<Hits>| async move { hit(&h, "evil");
            Json(json!({ "access_token": "evil-bearer", "expires_in": 3600, "record_count": 1, "totalResults": 1 })) }))
        // A redirect to someone else's host, keeping the method and body (307) or permanently (308).
        .route("/redir/{*rest}", axum::routing::any(move |State(h): State<Hits>, axum::extract::Path(rest): axum::extract::Path<String>| { let b = b3.clone(); async move {
            hit(&h, "redir");
            (StatusCode::TEMPORARY_REDIRECT, [("location", format!("{b}/evil/{rest}"))]) } }))
        .route("/slow", get(|| async { tokio::time::sleep(std::time::Duration::from_secs(5)).await; "late" }))
        .route("/slow/ws/oauth/token", post(|| async { tokio::time::sleep(std::time::Duration::from_secs(5)).await; "late" }))
        .with_state(hits.clone());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    (base, hits)
}
pub fn hits(h: &Hits, k: &str) -> u32 { h.lock().unwrap().get(k).copied().unwrap_or(0) }

/// A fresh empty directory, removed by nobody: the OS's temp area is cleaned on its own.
pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).unwrap();
    let d = std::env::temp_dir().join(format!("msp-{tag}-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The real embedding model, for the tests that run it: MODEL_DIR, or the cache scripts/fetch-model.sh fills
/// (`~/.cache/msp-console/models/bge-small-en-v1.5-int8`). Loaded once per test binary and shared. Absent, the test is
/// skipped LOUDLY, unless REQUIRE_MODEL is set (CI), where it fails: a model test that didn't run must never pass
/// quietly. Never a stand-in: these tests run ONNX Runtime on the pinned model, or they don't run.
pub fn embedder() -> Option<std::sync::Arc<msp_console::embed::Embedder>> {
    static E: std::sync::OnceLock<Result<std::sync::Arc<msp_console::embed::Embedder>, String>> = std::sync::OnceLock::new();
    let dir = model_dir();
    let got = E.get_or_init(|| {
        if !dir.join("model.onnx").exists() { return Err(format!("no model in {}", dir.display())); }
        // A model that's there but won't load is a failure, never a skip.
        Ok(std::sync::Arc::new(msp_console::embed::Embedder::load(&dir, 2).unwrap_or_else(|e| panic!("the model in {} doesn't load: {e}", dir.display()))))
    });
    match got {
        Ok(e) => Some(e.clone()),
        Err(why) => {
            if std::env::var("REQUIRE_MODEL").is_ok_and(|v| !v.is_empty()) { panic!("REQUIRE_MODEL is set but there's {why}: run scripts/fetch-model.sh"); }
            eprintln!("SKIPPED: {why} (scripts/fetch-model.sh fetches it), so this embedder test did not run");
            None
        }
    }
}
pub fn model_dir() -> std::path::PathBuf {
    if let Some(d) = std::env::var_os("MODEL_DIR").filter(|d| !d.is_empty()) { return d.into(); }
    let cache = std::env::var_os("XDG_CACHE_HOME").filter(|d| !d.is_empty()).map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache"));
    cache.join("msp-console/models/bge-small-en-v1.5-int8")
}

/// An NVD row, as the NVD connector writes one (its times in the store's one form).
pub async fn nvd_cve(pool: &msp_console::db::Pool, cve_id: &str, description: Option<&str>, last_modified: &str, rejected: bool) {
    let t = msp_console::db::Ts(chrono::DateTime::parse_from_rfc3339(last_modified).unwrap().with_timezone(&chrono::Utc));
    msp_console::on_pool!(pool, p, _ => { sqlx::query(
        "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, published, last_modified, rejected, description) VALUES ($1, 7.5, 'HIGH', $2, $2, $3, $4)
         ON CONFLICT (cve_id) DO UPDATE SET last_modified = excluded.last_modified, rejected = excluded.rejected, description = excluded.description")
        .bind(cve_id).bind(t).bind(rejected).bind(description).execute(p).await.unwrap(); })
}
