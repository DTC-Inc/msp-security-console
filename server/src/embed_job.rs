//! The `embed` job: NVD's descriptions into vectors for similar-CVE search, inside the console (src/embed.rs). Each
//! run takes out the vectors of CVEs that lost their description (rejected, or gone), then embeds, batch by batch,
//! every CVE with a description and no vector of the current model yet, and every CVE whose description changed. It
//! stops when there's nothing left or its time budget is spent, and says how many remain; the next run carries on.
//!
//! Under the scheduler's lease like every job, so on PostgreSQL one replica embeds at a time. Cancellable at any
//! await: a batch's vectors and records are one transaction (vectors::put_embedded), so a run cancelled mid-batch
//! leaves the batches before it whole and nothing of that one. Idempotent: a second run over the same descriptions
//! makes nothing.
//!
//! "Changed" is NVD's word for it first: a CVE is looked at again only when its lastModified moved since its vector was
//! made. Then the description's SHA-256 decides: a new score or a new CPE moves lastModified without changing what the
//! description means, and that CVE keeps its vector (only the lastModified it was checked at is updated).
//!
//! A description that can't be embedded fails alone: it's recorded in `cve_embed_failed` with the class of the failure
//! (never the text), its old vector taken out, and the run carries on. It's tried again only when its description
//! changes, by the same test as above. /api/status counts this run's failures and every failure on record.

use crate::db::Pool;
use crate::embed::{self, sha256_hex, Embedder, MODEL_KEY};
use crate::scheduler::{Job, Outcome};
use crate::vectors::{self, Batch, Read};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Every two minutes: a run with nothing to do is one query (0.07 s over all of NVD's 400,000 CVEs, measured on
/// SQLite), and a large first load (all of NVD: about 400,000 descriptions, some 40 minutes of CPU)
/// goes on in budget-sized runs, between which the other jobs get their turn.
pub const EVERY: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct EmbedJob {
    pub embedder: Arc<Embedder>,
    /// Descriptions per inference and per transaction.
    pub batch: usize,
    /// When a run stops starting new batches.
    pub budget: Duration,
}

/// A CVE to look at: its id, description and lastModified, and the hash of the description its vector was made from,
/// or that last failed, if either.
type Candidate = (String, String, Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<String>);

impl EmbedJob {
    /// 32 descriptions a batch, and a run stops starting batches after 30 seconds: with the Kubernetes base's half a
    /// core, a longer run would hold the CPU from the other jobs and from the API.
    pub fn new(embedder: Arc<Embedder>) -> Self { Self { embedder, batch: 32, budget: Duration::from_secs(30) } }

    /// CVEs with a description that have no vector of this model, or whose lastModified moved since theirs was made
    /// (or since theirs failed); in id order after `after`, at most `limit`. A rejected CVE is no one's, so it's never
    /// embedded.
    async fn candidates(pool: &Pool, after: &str, limit: usize) -> Result<Vec<Candidate>, String> {
        crate::on_pool!(pool, p, pg => sqlx::query_as(if pg {
            "SELECT n.cve_id, n.description, n.last_modified, r.text_sha256, f.text_sha256
               FROM sec_nvd_cve n LEFT JOIN cve_embedded r ON r.model = $1 AND r.cve_id = n.cve_id
                    LEFT JOIN cve_embed_failed f ON f.model = $1 AND f.cve_id = n.cve_id
              WHERE NOT n.rejected AND n.description IS NOT NULL AND n.description <> '' AND n.cve_id > $2
                AND (r.cve_id IS NULL OR r.nvd_modified IS DISTINCT FROM n.last_modified)
                AND (f.cve_id IS NULL OR f.nvd_modified IS DISTINCT FROM n.last_modified)
              ORDER BY n.cve_id LIMIT $3"
        } else {
            // Times are TEXT in one form (db::ts) on SQLite, so equal times are equal text.
            "SELECT n.cve_id, n.description, n.last_modified, r.text_sha256, f.text_sha256
               FROM sec_nvd_cve n LEFT JOIN cve_embedded r ON r.model = $1 AND r.cve_id = n.cve_id
                    LEFT JOIN cve_embed_failed f ON f.model = $1 AND f.cve_id = n.cve_id
              WHERE NOT n.rejected AND n.description IS NOT NULL AND n.description <> '' AND n.cve_id > $2
                AND (r.cve_id IS NULL OR r.nvd_modified IS NOT n.last_modified)
                AND (f.cve_id IS NULL OR f.nvd_modified IS NOT n.last_modified)
              ORDER BY n.cve_id LIMIT $3"
        }).bind(MODEL_KEY).bind(after).bind(limit as i64).fetch_all(p).await).map_err(|e| format!("embed: {}", crate::db::why(&e)))
    }

    /// How many CVEs are still to look at.
    async fn remaining(pool: &Pool) -> Result<i64, String> {
        crate::on_pool!(pool, p, pg => sqlx::query_scalar(if pg {
            "SELECT count(*) FROM sec_nvd_cve n LEFT JOIN cve_embedded r ON r.model = $1 AND r.cve_id = n.cve_id
                    LEFT JOIN cve_embed_failed f ON f.model = $1 AND f.cve_id = n.cve_id
              WHERE NOT n.rejected AND n.description IS NOT NULL AND n.description <> ''
                AND (r.cve_id IS NULL OR r.nvd_modified IS DISTINCT FROM n.last_modified)
                AND (f.cve_id IS NULL OR f.nvd_modified IS DISTINCT FROM n.last_modified)"
        } else {
            "SELECT count(*) FROM sec_nvd_cve n LEFT JOIN cve_embedded r ON r.model = $1 AND r.cve_id = n.cve_id
                    LEFT JOIN cve_embed_failed f ON f.model = $1 AND f.cve_id = n.cve_id
              WHERE NOT n.rejected AND n.description IS NOT NULL AND n.description <> ''
                AND (r.cve_id IS NULL OR r.nvd_modified IS NOT n.last_modified)
                AND (f.cve_id IS NULL OR f.nvd_modified IS NOT n.last_modified)"
        }).bind(MODEL_KEY).fetch_one(p).await).map_err(|e| format!("embed: {}", crate::db::why(&e)))
    }

    /// One run. Its detail on /api/status is counts only: the model, what it embedded, what it found unchanged, what
    /// failed this run and how many failures are on record, what it removed, what's left, and how long it took.
    pub async fn run(&self, pool: &Pool) -> Result<Outcome, String> {
        let t0 = Instant::now();
        let removed = vectors::remove_stale(pool, MODEL_KEY).await.map_err(|e| format!("embed: {e}"))?;
        let (mut embedded, mut unchanged, mut failed) = (0usize, 0usize, 0usize);
        let mut classes: std::collections::BTreeMap<&'static str, usize> = Default::default();
        // Keyset through the ids, so a run always moves forward, whatever it finds.
        let mut after = String::new();
        loop {
            let rows = Self::candidates(pool, &after, self.batch.max(1)).await?;
            let Some(last) = rows.last() else { break };
            after = last.0.clone();
            let mut b = Batch::default();
            let mut todo = Vec::new();
            for (cve_id, description, nvd_modified, made_from, failed_on) in rows {
                let text_sha256 = sha256_hex(description.as_bytes());
                let read = Read { cve_id, nvd_modified, text_sha256 };
                if made_from.as_deref() == Some(read.text_sha256.as_str()) { b.unchanged.push(read) }
                else if failed_on.as_deref() == Some(read.text_sha256.as_str()) { b.still_failing.push(read) }
                else { todo.push((read, description)) }
            }
            if !todo.is_empty() {
                let texts = todo.iter().map(|(_, d)| d.clone()).collect();
                let results = embed::embed(self.embedder.clone(), texts).await.map_err(|e| format!("embed: {e}"))?;
                for ((read, _), r) in todo.into_iter().zip(results) {
                    match r {
                        Ok(v) => b.made.push((read, v)),
                        Err(f) => {
                            println!("{}", json!({ "msg": "a description couldn't be embedded; skipped until it changes", "job": "embed", "cve_id": read.cve_id, "class": f.class }));
                            *classes.entry(f.class).or_default() += 1;
                            b.failed.push((read, f.class));
                        }
                    }
                }
            }
            vectors::put_embedded(pool, MODEL_KEY, &b).await.map_err(|e| format!("embed: {e}"))?;
            embedded += b.made.len();
            unchanged += b.unchanged.len() + b.still_failing.len();
            failed += b.failed.len();
            if t0.elapsed() >= self.budget { break; }
        }
        let remaining = Self::remaining(pool).await?;
        let failing = vectors::failing(pool, MODEL_KEY).await.map_err(|e| format!("embed: {e}"))?;
        Ok(Outcome { detail: json!({ "model": MODEL_KEY, "embedded": embedded, "unchanged": unchanged, "failed": failed, "failed_by_class": classes,
            "failing": failing, "removed": removed, "remaining": remaining, "seconds": (t0.elapsed().as_millis() as f64 / 1000.0) }), cursor: None })
    }

    pub fn jobs(self) -> Vec<Job> {
        let me = Arc::new(self);
        vec![Job { name: "embed", every: EVERY, run: Arc::new(move |pool, _| { let j = me.clone(); Box::pin(async move { j.run(&pool).await }) }) }]
    }
}
