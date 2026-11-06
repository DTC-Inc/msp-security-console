//! Jobs inside the server ("The scheduler"). Each job is a row in `job`; a process runs it only after claiming
//! its lease with one conditional UPDATE, renews the lease while it runs, and releases it with the result and the
//! job's cursor. On SQLite the console is one replica, and the lease keeps a job from running twice at once; on
//! PostgreSQL several replicas share the jobs through it. Two claims at the same moment can't both win: PostgreSQL
//! locks the row for the first UPDATE and checks the second's WHERE again against what the first wrote (SQLite has one
//! writer at a time). A process that dies mid-run holds nothing for longer than the lease, so another process (or the
//! same one restarted) runs the job again from its last cursor. Nothing outside the store: no leader election.
//!
//! The lease's clock: on PostgreSQL it's the database's (`now()`), so replicas whose clocks disagree still agree on
//! when a lease ends; on SQLite, with one process, it's that process's.
//!
//! Keeping the lease: it's renewed every third of its length while the job runs. A renewal that fails (the database
//! didn't answer) is retried, backing off, while the lease can still be ours; a renewal that finds the lease gone (it
//! changed no row: another process holds it now) is final. Either way, a run that has lost its lease is cancelled,
//! its future dropped at its next await (an open transaction rolls back), and its result is never recorded: the
//! process that holds the lease now is the one running the job.

use serde_json::{json, Value};
use crate::db::{self, Pool};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// What a run returns: a detail for /api/status (counts, never data), and the job's resume point for next time.
#[derive(Debug)]
pub struct Outcome { pub detail: Value, pub cursor: Option<Value> }
pub type RunFuture = Pin<Box<dyn Future<Output = Result<Outcome, String>> + Send>>;
pub type RunFn = Arc<dyn Fn(Pool, Option<Value>) -> RunFuture + Send + Sync>;

#[derive(Clone)]
pub struct Job { pub name: &'static str, pub every: Duration, pub run: RunFn }

#[derive(Clone)]
pub struct Scheduler { pub pool: Pool, pub holder: String, pub jobs: Vec<Job>, pub lease: Duration, pub tick: Duration }

impl Scheduler {
    pub fn new(pool: Pool, jobs: Vec<Job>) -> Self {
        let mut b = [0u8; 6];
        let _ = getrandom::fill(&mut b);
        let holder = b.iter().map(|x| format!("{x:02x}")).collect();
        Self { pool, holder, jobs, lease: Duration::from_secs(120), tick: Duration::from_secs(15) }
    }

    /// Make sure every job has its row (a new job is due at once; an existing one keeps its schedule).
    pub async fn register(&self) -> Result<(), sqlx::Error> {
        for j in &self.jobs {
            crate::on_pool!(&self.pool, p, _ => sqlx::query("INSERT INTO job (name, every_secs) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET every_secs = excluded.every_secs")
                .bind(j.name).bind(j.every.as_secs() as i32).execute(p).await.map(|_| ()))?;
        }
        Ok(())
    }

    /// Claim a due job's lease; Some(cursor) when this process now holds it.
    pub async fn claim(&self, name: &str) -> Result<Option<Option<Value>>, sqlx::Error> {
        let row: Option<(Option<Value>,)> = match &self.pool {
            Pool::Sqlite(p) => {
                let now = db::now();
                sqlx::query_as(
                    "UPDATE job SET lease_holder = $2, lease_until = $4, last_started_at = $3
                      WHERE name = $1 AND next_run_at <= $3 AND (lease_until IS NULL OR lease_until < $3)
                      RETURNING cursor")
                    .bind(name).bind(&self.holder).bind(now).bind(now.after(self.lease)).fetch_optional(p).await?
            }
            Pool::Postgres(p) => sqlx::query_as(
                "UPDATE job SET lease_holder = $2, lease_until = now() + make_interval(secs => $3), last_started_at = now()
                  WHERE name = $1 AND next_run_at <= now() AND (lease_until IS NULL OR lease_until < now())
                  RETURNING cursor")
                .bind(name).bind(&self.holder).bind(self.lease.as_secs_f64()).fetch_optional(p).await?,
        };
        Ok(row.map(|r| r.0))
    }

    /// Ok(true): renewed. Ok(false): the lease is someone else's now. Err: the database didn't answer.
    async fn renew(&self, name: &str) -> Result<bool, sqlx::Error> {
        let r = match &self.pool {
            Pool::Sqlite(p) => sqlx::query("UPDATE job SET lease_until = $3 WHERE name = $1 AND lease_holder = $2")
                .bind(name).bind(&self.holder).bind(db::now().after(self.lease)).execute(p).await.map(|r| r.rows_affected()),
            Pool::Postgres(p) => sqlx::query("UPDATE job SET lease_until = now() + make_interval(secs => $3) WHERE name = $1 AND lease_holder = $2")
                .bind(name).bind(&self.holder).bind(self.lease.as_secs_f64()).execute(p).await.map(|r| r.rows_affected()),
        };
        r.map(|n| n == 1)
    }

    /// Keep `name`'s lease while a run holds it; returns only when it's lost.
    async fn keep_lease(&self, name: &str) -> Lost {
        let mut held = tokio::time::Instant::now();
        // Give up a little before the lease could have ended, so no two runs overlap even then.
        let window = self.lease - self.lease / 10;
        loop {
            tokio::time::sleep(self.lease / 3).await;
            let mut wait = (self.lease / 20).max(Duration::from_millis(10));
            loop {
                match self.renew(name).await {
                    Ok(true) => { held = tokio::time::Instant::now(); break; }
                    Ok(false) => return Lost::Taken,
                    // Retried, backing off, up to the end of the window (the last try at its very end), then given up.
                    Err(_) => {
                        let left = (held + window).saturating_duration_since(tokio::time::Instant::now());
                        if left.is_zero() { return Lost::Unrenewable; }
                        tokio::time::sleep(wait.min(left)).await;
                        wait *= 2;
                    }
                }
            }
        }
    }

    /// Let go of a lease this process can't renew, if the database will hear it: the job is then due again at once.
    async fn release(&self, name: &str) {
        let _ = crate::on_pool!(&self.pool, p, _ => sqlx::query("UPDATE job SET lease_holder = NULL, lease_until = NULL WHERE name = $1 AND lease_holder = $2")
            .bind(name).bind(&self.holder).execute(p).await.map(|_| ()));
    }

    async fn finish(&self, job: &Job, res: &Result<Outcome, String>) {
        let name = job.name;
        let (ok, err, detail, cursor) = match res {
            Ok(o) => (true, None, Some(o.detail.clone()), o.cursor.clone()),
            Err(e) => (false, Some(e.chars().take(300).collect::<String>()), None, None),
        };
        // A failed run keeps its cursor and is retried sooner (at most every 15 minutes), never later than usual.
        let wait = if ok { job.every } else { job.every.min(Duration::from_secs(900)) };
        let r = match &self.pool {
            Pool::Sqlite(p) => {
                let now = db::now();
                sqlx::query(
                    "UPDATE job SET lease_holder = NULL, lease_until = NULL, next_run_at = $3,
                            last_ok_at = CASE WHEN $4 THEN $7 ELSE last_ok_at END, last_error = $5,
                            last_detail = CASE WHEN $4 THEN $6 ELSE last_detail END, cursor = CASE WHEN $4 THEN $8 ELSE cursor END
                      WHERE name = $1 AND lease_holder = $2")
                    .bind(name).bind(&self.holder).bind(now.after(wait)).bind(ok).bind(err).bind(detail).bind(now).bind(cursor).execute(p).await.map(|r| r.rows_affected())
            }
            Pool::Postgres(p) => sqlx::query(
                "UPDATE job SET lease_holder = NULL, lease_until = NULL, next_run_at = now() + make_interval(secs => $3),
                        last_ok_at = CASE WHEN $4 THEN now() ELSE last_ok_at END, last_error = $5,
                        last_detail = CASE WHEN $4 THEN $6 ELSE last_detail END, cursor = CASE WHEN $4 THEN $7 ELSE cursor END
                  WHERE name = $1 AND lease_holder = $2")
                .bind(name).bind(&self.holder).bind(wait.as_secs_f64()).bind(ok).bind(err).bind(detail).bind(cursor).execute(p).await.map(|r| r.rows_affected()),
        };
        if !matches!(r, Ok(1)) {
            println!("{}", json!({ "msg": "a job's lease was lost before it finished; its result is not recorded", "job": name }));
        }
    }

    /// Run one job now if it's due and unclaimed; true when it ran here (to the end, or until its lease was lost).
    pub async fn run_if_due(&self, job: &Job) -> bool {
        let cursor = match self.claim(job.name).await { Ok(Some(c)) => c, _ => return false };
        let run = (job.run)(self.pool.clone(), cursor);
        // The run and the lease side by side: the run ending first is recorded; the lease lost first drops the run.
        let res = tokio::select! {
            res = run => res,
            lost = self.keep_lease(job.name) => {
                if lost == Lost::Unrenewable { self.release(job.name).await; }
                let why = match lost { Lost::Taken => "another process holds its lease now", Lost::Unrenewable => "its lease couldn't be renewed before it ran out" };
                println!("{}", json!({ "msg": "job cancelled", "job": job.name, "why": why }));
                return true;
            }
        };
        self.finish(job, &res).await;
        let line = match &res { Ok(o) => json!({ "msg": "job finished", "job": job.name, "detail": o.detail }), Err(e) => json!({ "msg": "job failed", "job": job.name, "error": e }) };
        println!("{line}");
        true
    }

    /// The loop: every tick, each due job, one at a time in this process (the vendors' rate limits are per process; with
    /// several replicas, a job runs on whichever claims it).
    pub async fn run_forever(self) {
        if let Err(e) = self.register().await { println!("{}", json!({ "msg": "the scheduler can't register its jobs", "error": e.to_string() })); }
        loop {
            for j in &self.jobs { self.run_if_due(j).await; }
            tokio::time::sleep(self.tick).await;
        }
    }
}

/// How a run lost its lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lost { Taken, Unrenewable }

/// /api/status: every job's state, without data.
pub async fn status(pool: &Pool) -> Result<Value, sqlx::Error> {
    type Row = (String, Option<chrono::DateTime<chrono::Utc>>, Option<String>, chrono::DateTime<chrono::Utc>, bool, Option<Value>);
    let rows: Vec<Row> = match pool {
        Pool::Sqlite(p) => sqlx::query_as(
            "SELECT name, last_ok_at, last_error, next_run_at, (lease_until IS NOT NULL AND lease_until > $1) AS running, last_detail FROM job ORDER BY name")
            .bind(db::now()).fetch_all(p).await?,
        Pool::Postgres(p) => sqlx::query_as(
            "SELECT name, last_ok_at, last_error, next_run_at, (lease_until IS NOT NULL AND lease_until > now()) AS running, last_detail FROM job ORDER BY name")
            .fetch_all(p).await?,
    };
    Ok(Value::Array(rows.into_iter().map(|(name, ok, err, next, running, detail)| json!({
        "job": name, "last_ok_at": ok, "last_error": err, "next_run_at": next, "running": running, "detail": detail })).collect()))
}
