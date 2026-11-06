//! The console's own store: a SQLite file on the console's own volume (the default, one replica), or a PostgreSQL
//! database the installer runs (more than one replica, or a managed database). DATABASE_URL picks PostgreSQL;
//! otherwise it's the file at DATABASE_PATH. Either way the schema is migrations embedded in the binary and applied at
//! start, and the store holds client data (docs/design.md, "Data handling").
//!
//! One `Pool` over the two drivers, not sqlx's `Any`: `Any` can't carry JSON, times or arrays faithfully, and every
//! query here reads one or the other. A query whose SQL is the same on both is written once inside `on_pool!`, which
//! compiles its body once per driver, so it binds and decodes through each driver's own types; where the dialects
//! differ (reading JSON in bulk, an `IN` list, case-insensitive search, vectors, backups) the body picks its SQL by
//! dialect, or the module has a small arm for each.
//!
//! **Values on both stores** (so a query reads the same Rust types from either):
//!   - a time is `chrono::DateTime<Utc>`. SQLite keeps it as ISO-8601 text with milliseconds (`ts`), so text order is
//!     time order; PostgreSQL as timestamptz. It's bound as `Ts`, which writes each store's own form;
//!   - a list bound for `IN` is `List`: a JSON array on SQLite (`IN (SELECT value FROM json_each($1))`), an array on
//!     PostgreSQL (`= ANY($1)`);
//!   - JSON is `serde_json::Value`, a boolean `bool`, an id or count `i64`, a score `f64`, a date `NaiveDate`.
//!   - Placeholders are `$1`, `$2` ... on both (SQLite reads `$N` as the Nth argument).

pub mod fold;
pub mod postgres;
pub mod sqlite;

pub use postgres::PgConfig;
pub use sqlite::{open, register_vec, unopenable, vec_version, SqliteConfig, DEFAULT_PATH};

use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::{Database, Encode, Postgres, Sqlite, Type};

/// The store's connections: one driver or the other, chosen at start.
#[derive(Clone, Debug)]
pub enum Pool { Sqlite(sqlx::SqlitePool), Postgres(sqlx::PgPool) }

/// Which store, for /api/status and the start log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind { Sqlite, Postgresql }

impl Pool {
    pub fn kind(&self) -> Kind { match self { Pool::Sqlite(_) => Kind::Sqlite, Pool::Postgres(_) => Kind::Postgresql } }
    pub async fn close(&self) { match self { Pool::Sqlite(p) => p.close().await, Pool::Postgres(p) => p.close().await } }
}

/// Run `$body` with `$p` the driver's own pool and `$pg` true on PostgreSQL. The body is compiled once per driver, so
/// the same text binds and decodes through each one's types; `if $pg { .. } else { .. }` picks SQL that differs.
#[macro_export]
macro_rules! on_pool {
    ($pool:expr, $p:ident, $pg:pat => $body:expr) => {
        match $pool {
            $crate::db::Pool::Sqlite($p) => { let $pg = false; $body }
            $crate::db::Pool::Postgres($p) => { let $pg = true; $body }
        }
    };
}

/// Where the store is: a SQLite file, or a PostgreSQL database.
#[derive(Debug, Clone, PartialEq)]
pub enum DbConfig { Sqlite(SqliteConfig), Postgres(PgConfig) }

impl DbConfig {
    pub fn sqlite(&self) -> Option<&SqliteConfig> { match self { DbConfig::Sqlite(s) => Some(s), DbConfig::Postgres(_) => None } }
    pub fn kind(&self) -> Kind { match self { DbConfig::Sqlite(_) => Kind::Sqlite, DbConfig::Postgres(_) => Kind::Postgresql } }
}

/// Open the store (a SQLite file is made the first time) and migrate it. Refuses with a plain reason, which names a
/// setting and never what a secret one holds.
pub async fn connect(c: &DbConfig) -> Result<Pool, String> {
    match c {
        DbConfig::Sqlite(s) => { register_vec(); fold::register(); sqlite::open(s).await }
        DbConfig::Postgres(p) => postgres::connect(p).await,
    }
}

/// Ready means the database answers.
pub async fn ping(pool: &Pool) -> bool {
    on_pool!(pool, p, _ => sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(p).await.is_ok())
}

/// What the store can do, for /api/status and the start log: which kind, whether vector search is on (and why not),
/// and whose the backups are. Never a path's or a URL's contents beyond the kind.
pub async fn describe(pool: &Pool) -> serde_json::Value {
    let vectors = crate::vectors::available(pool).await;
    let backups = match pool {
        Pool::Sqlite(_) => "the console's own: a daily copy of the file in backup/ beside it (the backup job), on the same volume, so snapshot the volume too",
        Pool::Postgres(_) => "yours: the console makes no copies of a PostgreSQL database, so back it up with pg_dump or your provider's snapshots",
    };
    let mut d = serde_json::json!({ "kind": pool.kind(), "vectors": match vectors { Ok(()) => serde_json::json!({ "on": true }), Err(why) => serde_json::json!({ "on": false, "why": why }) },
        "backups": backups });
    // PostgreSQL's link: its sslmode, and a note when the certificate isn't checked (only possible outside production).
    if let Pool::Postgres(p) = pool {
        let mode = postgres::sslmode_of(&p.connect_options());
        d["tls"] = match postgres::tls_note(mode) { Some(note) => serde_json::json!({ "sslmode": mode, "note": note }), None => serde_json::json!({ "sslmode": mode }) };
    }
    d
}

/// Now, in the store's one time form.
pub fn now() -> Ts { Ts(chrono::Utc::now()) }
/// A time as SQLite's store writes it: ISO-8601 UTC with milliseconds, the same text strftime('%Y-%m-%dT%H:%M:%fZ')
/// writes. Also the form a time takes inside JSON handed to either store.
pub fn ts(t: chrono::DateTime<chrono::Utc>) -> String { t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string() }
/// A vendor's timestamp (RFC 3339, or NVD's zone-less UTC) in that form; None when it isn't one.
pub fn ts_text(s: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&chrono::Utc))
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").map(|t| t.and_utc()))
        .ok().map(ts)
}
/// A client's name for the name suggestion (a vendor's link confirms, a name only suggests): lowercased, every run of anything but a-z and 0-9 made one space
/// (what regexp_replace(lower(name), '[^a-z0-9]+', ' ', 'g') makes of it).
pub fn name_key(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut gap = false;
    for c in name.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() { out.push(c); gap = false; } else if !gap { out.push(' '); gap = true; }
    }
    out
}

/// A time to bind: SQLite's ISO text (`ts`) on SQLite, timestamptz on PostgreSQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ts(pub chrono::DateTime<chrono::Utc>);

impl Ts {
    pub fn after(self, d: std::time::Duration) -> Ts { Ts(self.0 + chrono::Duration::from_std(d).unwrap_or_default()) }
}

impl Type<Sqlite> for Ts { fn type_info() -> <Sqlite as Database>::TypeInfo { <String as Type<Sqlite>>::type_info() } }
impl<'q> Encode<'q, Sqlite> for Ts {
    fn encode_by_ref(&self, buf: &mut <Sqlite as Database>::ArgumentBuffer) -> Result<IsNull, BoxDynError> { <String as Encode<'q, Sqlite>>::encode(ts(self.0), buf) }
}
impl Type<Postgres> for Ts { fn type_info() -> <Postgres as Database>::TypeInfo { <chrono::DateTime<chrono::Utc> as Type<Postgres>>::type_info() } }
impl<'q> Encode<'q, Postgres> for Ts {
    fn encode_by_ref(&self, buf: &mut <Postgres as Database>::ArgumentBuffer) -> Result<IsNull, BoxDynError> { <chrono::DateTime<chrono::Utc> as Encode<'q, Postgres>>::encode_by_ref(&self.0, buf) }
}

/// A list to bind where a query asks "is it one of these": a JSON array on SQLite, read with
/// `IN (SELECT value FROM json_each($n))`, and an array on PostgreSQL, read with `= ANY($n)`.
#[derive(Debug, Clone, PartialEq)]
pub struct List<T>(pub Vec<T>);

pub fn list<T: Clone>(items: &[T]) -> List<T> { List(items.to_vec()) }

impl<T: serde::Serialize> Type<Sqlite> for List<T> { fn type_info() -> <Sqlite as Database>::TypeInfo { <String as Type<Sqlite>>::type_info() } }
impl<'q, T: serde::Serialize> Encode<'q, Sqlite> for List<T> {
    fn encode_by_ref(&self, buf: &mut <Sqlite as Database>::ArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <String as Encode<'q, Sqlite>>::encode(serde_json::to_string(&self.0)?, buf)
    }
}
impl<T> Type<Postgres> for List<T> where Vec<T>: Type<Postgres> { fn type_info() -> <Postgres as Database>::TypeInfo { <Vec<T> as Type<Postgres>>::type_info() } }
impl<'q, T> Encode<'q, Postgres> for List<T> where Vec<T>: Encode<'q, Postgres> {
    fn encode_by_ref(&self, buf: &mut <Postgres as Database>::ArgumentBuffer) -> Result<IsNull, BoxDynError> { <Vec<T> as Encode<'q, Postgres>>::encode_by_ref(&self.0, buf) }
}

/// A database error as a job's last_error or a refusal can carry it: SQLite's message (it names tables and columns,
/// never values), PostgreSQL's SQLSTATE and its class (its messages can quote the value that failed).
pub fn why(e: &sqlx::Error) -> String {
    match e.as_database_error() {
        Some(d) => match d.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
            Some(pg) => format!("SQLSTATE {} ({})", pg.code(), postgres::class_of(pg.code())),
            None => d.message().to_string(),
        },
        None => match e {
            sqlx::Error::Io(e) => format!("I/O: {}", e.kind()),
            sqlx::Error::PoolTimedOut => "timed out".into(),
            sqlx::Error::Tls(_) => "TLS".into(),
            _ => "error".into(),
        },
    }
}
