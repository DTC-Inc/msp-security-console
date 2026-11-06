//! The SQLite store: one file on the console's own volume, DATABASE_PATH (default /data/console.db). One process
//! writes it: on SQLite the console runs as one replica by design. The file holds client data, so it lives on an
//! encrypted volume and is readable by the console's user alone.

use super::Pool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Transactions: `pool.begin()` is a deferred BEGIN, which takes the write lock at its first write. Every transaction
/// here opens with a write (a DELETE or an INSERT), and the scheduler runs one job at a time, so none can hit
/// SQLITE_BUSY when it upgrades from reading to writing, a wait the busy timeout can't cover under WAL. Keep it so:
/// a transaction that must read before it writes opens with `BEGIN IMMEDIATE`
/// (`pool.begin_with("BEGIN IMMEDIATE")`).
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

pub const DEFAULT_PATH: &str = "/data/console.db";

/// Where the file lives and how many nightly copies of it to keep.
#[derive(Debug, Clone, PartialEq)]
pub struct SqliteConfig { pub path: PathBuf, pub backup_keep: usize }

impl SqliteConfig {
    /// Nightly copies go beside the database, in backup/.
    pub fn backup_dir(&self) -> PathBuf { self.path.parent().unwrap_or(Path::new(".")).join("backup") }
}

/// The connection: WAL (readers never wait for the writer), foreign keys on, a writer waits up to 5 s for another,
/// NORMAL sync (safe under WAL: a power cut can lose the last commits, never corrupt the file), and temporary tables
/// in memory, because the root filesystem is read-only.
fn options(path: &Path, create: bool) -> SqliteConnectOptions {
    SqliteConnectOptions::new().filename(path).create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal).foreign_keys(true).busy_timeout(Duration::from_secs(5))
        .synchronous(SqliteSynchronous::Normal).pragma("temp_store", "MEMORY")
}

/// Open and migrate on connections as they come. Refuses when the directory isn't writable, and, before any migration
/// runs, when sqlite-vec isn't in the connection: the schema has a vec0 table, and a store that migrates half-way is
/// worse than none. `db::connect` registers the extension first; this is the half that doesn't, so a build without it
/// can be tested.
pub async fn open(c: &SqliteConfig) -> Result<Pool, String> {
    let dir = c.path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    writable(dir).map_err(|e| format!("DATABASE_PATH's directory {} isn't writable ({e}): mount the console's volume there", dir.display()))?;
    create_private(&c.path).map_err(|e| format!("the database {} can't be created ({e})", c.path.display()))?;
    let pool = SqlitePoolOptions::new().max_connections(8).acquire_timeout(Duration::from_secs(15))
        .connect_with(options(&c.path, true)).await
        .map_err(|e| format!("the database {} can't be opened ({})", c.path.display(), super::why(&e)))?;
    let pool = Pool::Sqlite(pool);
    vec_version(&pool).await
        .map_err(|e| format!("refusing to open the store: the sqlite-vec extension isn't in the connection ({e}); this build is broken"))?;
    let Pool::Sqlite(p) = &pool else { unreachable!() };
    MIGRATOR.run(p).await.map_err(|e| format!("the database migrations failed: {e}"))?;
    Ok(pool)
}

/// sqlite-vec, compiled into the binary, registered once per process as an auto-extension: SQLite runs its init on
/// every connection opened after this, the pool's included. Nothing is loaded from disk.
pub fn register_vec() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: sqlite3_vec_init is the extension's entry point with SQLite's xEntryPoint signature; the crate
        // declares it without arguments, hence the transmute, as sqlite-vec's own Rust docs do.
        let rc = unsafe {
            libsqlite3_sys::sqlite3_auto_extension(Some(std::mem::transmute::<*const (), unsafe extern "C" fn(
                *mut libsqlite3_sys::sqlite3, *mut *mut std::os::raw::c_char, *const libsqlite3_sys::sqlite3_api_routines) -> std::os::raw::c_int>(
                sqlite_vec::sqlite3_vec_init as *const ())))
        };
        // Only SQLITE_NOMEM can fail it; the open that follows then refuses with a plain reason.
        let _ = rc;
    });
}

/// The vector extension's version on a connection of a SQLite pool ("v0.1.9"), or why it isn't there.
pub async fn vec_version(pool: &Pool) -> Result<String, String> {
    match pool {
        Pool::Sqlite(p) => sqlx::query_scalar::<_, String>("SELECT vec_version()").fetch_one(p).await.map_err(|e| super::why(&e)),
        Pool::Postgres(_) => Err("sqlite-vec is SQLite's".into()),
    }
}

/// A pool on a file that never opens: for the routes that must not reach the store, and for the store failing.
pub fn unopenable() -> Pool {
    Pool::Sqlite(SqlitePoolOptions::new().acquire_timeout(Duration::from_millis(500)).connect_lazy_with(options(Path::new("/nonexistent/msp-console/none.db"), false)))
}

/// Create and remove a probe file: a read-only or missing volume is found at start, not at the first write.
fn writable(dir: &Path) -> std::io::Result<()> {
    let mut b = [0u8; 6];
    let _ = getrandom::fill(&mut b);
    let probe = dir.join(format!(".write-probe-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()));
    std::fs::write(&probe, b"")?;
    std::fs::remove_file(&probe)
}

/// The database file is made 0600 before SQLite first opens it, so its -wal and -shm files (which SQLite creates with
/// the database's own mode) are the console user's alone too. An empty file is an empty database.
fn create_private(path: &Path) -> std::io::Result<()> {
    if path.exists() { return Ok(()); }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    match o.open(path) { Ok(_) => Ok(()), Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()), Err(e) => Err(e) }
}

/// A file of the store's (a backup) is the console user's alone.
pub fn private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}
