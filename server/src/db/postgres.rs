//! The PostgreSQL store: a database the installer runs, named by DATABASE_URL (or DATABASE_URL_FILE). For an MSP that
//! wants more than one replica, or its own managed database. The URL carries the password, so it's a secret as a whole:
//! it's never logged or shown, its Debug form is redacted, and every error here names DATABASE_URL and the kind of
//! failure, never the host, the user or anything the driver echoes back.
//!
//! TLS: the URL's `sslmode` decides, as libpq's does. In production (MSP_ENV=production) the console must check the
//! server's certificate, since the link carries the clients' data: `verify-full` (the certificate, and that it's for
//! the host in the URL), or `verify-ca` with the CA named in `sslrootcert`. Everything else is refused there,
//! `require` included: sqlx's `require` encrypts but accepts any certificate for any host, so it can't tell the
//! database from something in between. Managed PostgreSQL (Azure, RDS, Cloud SQL) publishes its CA for this; the
//! platform's roots are used when `sslrootcert` isn't given. Outside production anything goes (a database on the same
//! laptop), and anything short of a checked certificate is said at start and on /api/status.
//!
//! One source of truth, the URL. sqlx, like libpq, fills in what a URL leaves out from PGHOST, PGUSER, PGPASSWORD,
//! PGSSLMODE, PGSSLROOTCERT and the rest of libpq's variables, and it has no way to parse without them. So the console
//! refuses to start while any of them is set in its environment, naming the variable, and production also wants
//! sslmode written in the URL itself.

use super::Pool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::str::FromStr;
use std::time::Duration;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

/// The database's address and credentials, checked. Only this module reads the URL.
#[derive(Clone, PartialEq)]
pub struct PgConfig { url: String, tls: &'static str }

impl std::fmt::Debug for PgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("PgConfig").field("url", &"[redacted]").field("sslmode", &self.tls).finish() }
}

impl PgConfig {
    /// DATABASE_URL as start-up takes it, against the process's own environment (which is what sqlx reads).
    pub fn new(url: &str, production: bool) -> Result<Self, String> { Self::new_in(url, production, &|k| std::env::var(k).ok()) }

    /// DATABASE_URL as start-up takes it: a postgres:// URL that parses, none of libpq's variables in `env`, and in
    /// production an sslmode in the URL that checks the certificate. The error names the setting, never what it holds.
    pub fn new_in(url: &str, production: bool, env: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        if let Some(k) = LIBPQ_ENV.iter().find(|k| env(k).is_some_and(|v| !v.trim().is_empty())) {
            return Err(format!("{k} is set in the console's environment: the console takes PostgreSQL's settings from DATABASE_URL alone (host, port, user, password, database, sslmode, sslrootcert), so unset {k} and put what it says in the URL"));
        }
        let url = url.trim();
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err("DATABASE_URL must be a postgres:// URL (for a SQLite file on the console's volume, set DATABASE_PATH instead)".into());
        }
        let o = PgConnectOptions::from_str(url).map_err(|_| "DATABASE_URL isn't a PostgreSQL URL that can be read: check its form, and its sslmode if it sets one".to_string())?;
        let tls = o.get_ssl_mode();
        let root = param(url, &["sslrootcert", "ssl-root-cert", "ssl-ca"]).is_some();
        if production && param(url, &["sslmode", "ssl-mode"]).is_none() { return Err(format!("{TLS_IN_PRODUCTION} (it sets no sslmode)")); }
        if production {
            let ok = match tls { PgSslMode::VerifyFull => true, PgSslMode::VerifyCa => root, _ => false };
            if !ok {
                let now = match tls {
                    PgSslMode::VerifyCa => "sslmode=verify-ca without sslrootcert".to_string(),
                    PgSslMode::Require => "sslmode=require, which encrypts but accepts any certificate".to_string(),
                    m => format!("sslmode={}", sslmode(m)),
                };
                return Err(format!("{TLS_IN_PRODUCTION} (it has {now})"));
            }
        }
        Ok(Self { url: url.to_string(), tls: sslmode(tls) })
    }

    /// The sslmode in effect, by name.
    pub fn sslmode(&self) -> &'static str { self.tls }

    /// What to say about the link when its certificate isn't checked (outside production only): None when it is.
    pub fn tls_note(&self) -> Option<&'static str> { tls_note(self.tls) }

    pub fn options(&self) -> PgConnectOptions {
        PgConnectOptions::from_str(&self.url).expect("checked in PgConfig::new").application_name("msp-security-console")
    }
}

/// libpq's environment variables that sqlx reads when it parses a URL. None may be set: the URL is the one source.
pub const LIBPQ_ENV: &[&str] = &["PGHOST", "PGHOSTADDR", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE", "PGSSLROOTCERT",
                                 "PGSSLCERT", "PGSSLKEY", "PGAPPNAME", "PGOPTIONS"];

pub const TLS_IN_PRODUCTION: &str = "DATABASE_URL must check the database's certificate in production (MSP_ENV=production): set sslmode=verify-full (with sslrootcert=<path to the CA's certificate>, unless the platform's roots sign it), or sslmode=verify-ca with sslrootcert=<path>";

/// The link's word for start-up and /api/status, by sslmode: nothing when the certificate is checked.
pub fn tls_note(sslmode: &str) -> Option<&'static str> {
    match sslmode {
        "verify-full" | "verify-ca" => None,
        "require" => Some("TLS without certificate check: the link is encrypted, but any certificate is accepted (sslmode=require); production refuses it"),
        _ => Some("TLS isn't required: the link may be plain text (sslmode=disable, allow or prefer); production refuses it"),
    }
}

/// A query parameter of the URL, by any of its names (libpq's and sqlx's spellings), decoded.
pub(crate) fn param(url: &str, names: &[&str]) -> Option<String> {
    let q = url.split_once('?')?.1.split('#').next().unwrap_or("");
    q.split('&').filter_map(|kv| kv.split_once('=').or(Some((kv, "")))).find(|(k, _)| names.contains(k)).map(|(_, v)| v.to_string())
}

pub fn sslmode_of(o: &PgConnectOptions) -> &'static str { sslmode(o.get_ssl_mode()) }

fn sslmode(m: PgSslMode) -> &'static str {
    match m { PgSslMode::Disable => "disable", PgSslMode::Allow => "allow", PgSslMode::Prefer => "prefer", PgSslMode::Require => "require",
              PgSslMode::VerifyCa => "verify-ca", PgSslMode::VerifyFull => "verify-full" }
}

/// Connect and migrate. sqlx holds a PostgreSQL advisory lock around the migrations, so replicas starting together
/// apply each one once. Then the vector table, if pgvector has been installed since (0003_vectors.sql).
pub async fn connect(c: &PgConfig) -> Result<Pool, String> {
    let pool = PgPoolOptions::new().max_connections(10).acquire_timeout(Duration::from_secs(15)).connect_with(c.options()).await
        .map_err(|e| format!("the database DATABASE_URL names can't be reached: {}", reach(&e)))?;
    MIGRATOR.run(&pool).await.map_err(|e| format!("the database migrations failed: {}", migrate(&e)))?;
    // Never a refusal: without it, similar-CVE search is off, and /api/status says why (vectors::available).
    let _ = sqlx::query("SELECT msp_console_vectors()").execute(&pool).await;
    Ok(Pool::Postgres(pool))
}

/// Why a connection failed, in words an installer can act on: no host, user, database name or driver text.
pub fn reach(e: &sqlx::Error) -> String {
    match e {
        sqlx::Error::Tls(_) => "the TLS handshake failed (check sslmode, and sslrootcert for verify-ca or verify-full)".into(),
        // A refused certificate reaches here as I/O (rustls's error inside an InvalidData), not as sqlx's Tls.
        sqlx::Error::Io(io) if io.kind() == std::io::ErrorKind::InvalidData || io.get_ref().is_some_and(|e| e.is::<rustls::Error>()) =>
            "the TLS handshake failed: the server's certificate wasn't accepted (it must be signed by the CA in sslrootcert, or by the platform's roots, and name the URL's host for verify-full)".into(),
        sqlx::Error::Io(io) => format!("the network said no ({}): check the host and port, and that the console can reach them", io.kind()),
        sqlx::Error::PoolTimedOut => "it didn't answer in time: check the host and port, and that the console can reach them".into(),
        sqlx::Error::Configuration(_) => "DATABASE_URL can't be used as it is: check its form".into(),
        sqlx::Error::Database(d) => match d.code().as_deref() {
            Some("28P01") | Some("28000") => "it refused the user or password".into(),
            Some("3D000") => "the database in the URL doesn't exist".into(),
            Some("42501") => "the user may not connect to that database".into(),
            Some("53300") => "it has no free connections".into(),
            Some(c) => format!("it refused (SQLSTATE {c}, {})", class_of(c)),
            None => "it refused".into(),
        },
        _ => "the connection failed".into(),
    }
}

fn migrate(e: &sqlx::migrate::MigrateError) -> String {
    match e {
        sqlx::migrate::MigrateError::Execute(e) | sqlx::migrate::MigrateError::ExecuteMigration(e, _) => match e.as_database_error().and_then(|d| d.code()) {
            Some(c) if c == "42501" => "the user may not create tables there: grant it CREATE on its schema (or make it the schema's owner)".into(),
            Some(c) if c == "3F000" => "there's no schema to create tables in: check the user's search_path".into(),
            Some(c) => format!("SQLSTATE {c} ({})", class_of(&c)),
            None => reach(e),
        },
        other => other.to_string(),
    }
}

/// SQLSTATE's class, by its first two characters: what a failure was, without the message, which can quote values.
pub fn class_of(code: &str) -> &'static str {
    match code.get(..2).unwrap_or("") {
        "08" => "the connection", "0A" => "a feature the server lacks", "22" => "a value that didn't fit", "23" => "a constraint",
        "25" | "40" => "a transaction conflict", "28" => "the user or password", "3D" => "no such database", "3F" => "no such schema",
        "42" => "the schema or a permission", "53" => "the server's resources", "54" => "a limit", "55" => "the object's state",
        "57" => "the server stopped the work", "58" => "the server's system", "XX" => "an internal error", _ => "the database",
    }
}

/// What the setup wizard's Test learns about a database, read-only: it answers, the user may create tables where the
/// migrations will, and whether pgvector is installed, could be, or isn't there. Nothing is migrated or kept.
pub async fn probe(c: &PgConfig, timeout: Duration) -> Result<Probe, String> {
    use sqlx::{Connection, Row};
    let o = c.options();
    let mut conn = tokio::time::timeout(timeout, sqlx::PgConnection::connect_with(&o)).await
        .map_err(|_| "it didn't answer in time: check the host and port, and that the console can reach them".to_string())?
        .map_err(|e| reach(&e))?;
    sqlx::query("SELECT 1").execute(&mut conn).await.map_err(|e| reach(&e))?;
    // The migrations make ordinary tables in the first schema on the search_path. Making one inside a transaction that
    // is rolled back proves exactly that (a temporary table would pass for a user without CREATE on the schema, the
    // usual gap since PostgreSQL 15), and leaves nothing behind.
    let mut tx = conn.begin().await.map_err(|e| reach(&e))?;
    let name = format!("msp_console_setup_probe_{}", crate::seal::random(6).iter().map(|b| format!("{b:02x}")).collect::<String>());
    let made = sqlx::query(sqlx::AssertSqlSafe(format!("CREATE TABLE {name} (x integer)"))).execute(&mut *tx).await;
    let _ = tx.rollback().await;
    let can_create = match made {
        Ok(_) => Ok(()),
        Err(e) => Err(match e.as_database_error().and_then(|d| d.code()).as_deref() {
            Some("42501") => "the user may not create tables in its schema: grant it CREATE there (or make it the schema's owner)".to_string(),
            Some("3F000") => "there's no schema to create tables in: check the user's search_path".to_string(),
            _ => format!("making a table failed ({})", super::why(&e)),
        }),
    };
    let row = sqlx::query("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector'), EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vector')")
        .fetch_one(&mut conn).await.map_err(|e| reach(&e))?;
    let pgvector = match (row.get::<bool, _>(0), row.get::<bool, _>(1)) { (true, _) => "installed", (false, true) => "available", _ => "absent" };
    let _ = conn.close().await;
    Ok(Probe { can_create, pgvector })
}

pub struct Probe { pub can_create: Result<(), String>, pub pgvector: &'static str }
