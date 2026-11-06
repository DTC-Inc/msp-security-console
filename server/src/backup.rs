//! The daily copy of the SQLite store: `VACUUM INTO` a dated file beside the database, in backup/, keeping the
//! newest BACKUP_KEEP (default 7). VACUUM INTO writes a consistent, compacted copy while the console keeps serving; it's
//! written under a temporary name and renamed, so a copy that's there is a whole one. The copies are on the same volume
//! as the database: they undo a bad write or a broken file, not the loss of the volume, which is the volume's own
//! snapshots' job (docs/design.md, "Data handling").
//!
//! SQLite only. On PostgreSQL the job isn't scheduled, and backups are the operator's (pg_dump, or the provider's
//! snapshots), as /api/status says (db::describe).

use crate::db::{sqlite, Pool, SqliteConfig};
use crate::scheduler::{Job, Outcome};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Backup { pub dir: PathBuf, pub keep: usize }

impl Backup {
    pub fn new(c: &SqliteConfig) -> Self { Self { dir: c.backup_dir(), keep: c.backup_keep.max(1) } }

    pub async fn run(&self, pool: &Pool) -> Result<Outcome, String> {
        let Pool::Sqlite(pool) = pool else { return Err("backup: the console copies only a SQLite store; a PostgreSQL database's backups are yours".into()) };
        let io = |what: &str, e: std::io::Error| format!("backup: {what} ({})", e.kind());
        std::fs::create_dir_all(&self.dir).map_err(|e| io("the backup directory can't be made", e))?;
        let name = format!("console-{}.db", chrono::Utc::now().format("%Y-%m-%d"));
        let (file, partial) = (self.dir.join(&name), self.dir.join(format!("{name}.partial")));
        // VACUUM INTO refuses a file that exists: a partial copy a crash left behind goes first.
        if partial.exists() { std::fs::remove_file(&partial).map_err(|e| io("an old partial copy can't be removed", e))?; }
        let target = partial.to_str().ok_or("backup: the backup directory's path isn't UTF-8")?.to_string();
        sqlx::query("VACUUM INTO $1").bind(target).execute(pool).await.map_err(crate::connectors::ninja::db)?;
        sqlite::private(&partial);
        std::fs::rename(&partial, &file).map_err(|e| io("the copy can't be renamed into place", e))?;
        let bytes = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        let (kept, removed) = self.prune().map_err(|e| io("old copies can't be listed or removed", e))?;
        Ok(Outcome { detail: json!({ "file": name, "bytes": bytes, "kept": kept, "removed": removed }), cursor: None })
    }

    /// Keep the newest `keep` copies (their names sort by date), remove the rest and any stray partial copies.
    pub fn prune(&self) -> std::io::Result<(usize, usize)> {
        let mut copies = Vec::new();
        let mut removed = 0;
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name().to_string_lossy().to_string();
            if is_copy(&name) { copies.push(name); }
            // One backup runs at a time, and this one has renamed its copy: a partial copy here is a dead run's.
            else if name.starts_with("console-") && name.ends_with(".db.partial") { std::fs::remove_file(self.dir.join(&name))?; removed += 1; }
        }
        copies.sort();
        let drop = copies.len().saturating_sub(self.keep);
        for name in &copies[..drop] { std::fs::remove_file(self.dir.join(name))?; removed += 1; }
        Ok((copies.len() - drop, removed))
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        vec![Job { name: "backup", every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, _| { let b = self.clone(); Box::pin(async move { b.run(&pool).await }) }) }]
    }
}

/// console-YYYY-MM-DD.db, and nothing else: prune never touches a file it didn't make.
fn is_copy(name: &str) -> bool {
    name.strip_prefix("console-").and_then(|r| r.strip_suffix(".db")).is_some_and(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok())
}
