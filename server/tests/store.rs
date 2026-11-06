//! The console's own store, on both stores it can be: a SQLite file, and a PostgreSQL database (TEST_DATABASE_URL;
//! skipped LOUDLY without it, a failure under REQUIRE_DB). Migrations once and only once, the connection's settings,
//! the scheduler single-writer and resuming (and one claim among several processes at once), the daily backup (SQLite's
//! alone), Halo's shared limit kept, and the tracer end to end. Synthetic vendors on local ports stand in for NinjaOne,
//! HaloPSA, CISA KEV and NVD; every client, device and CVE here is made up.
mod common;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::*;
use msp_console::config::{Connectors, HaloCfg, NinjaCfg};
use msp_console::connectors::halo::{Halo, HaloSettings};
use msp_console::connectors::{Backoff, Limiter};
use msp_console::contract::EvidenceRequest;
use msp_console::db::{Pool, Ts};
use msp_console::on_pool;
use msp_console::ops::Store;
use msp_console::scheduler::{Job, Outcome, Scheduler};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

both!(
    migrations_apply_once_and_two_processes_starting_together_apply_nothing_new,
    two_schedulers_on_one_store_never_run_the_same_job_at_once,
    of_many_processes_claiming_one_due_job_at_the_same_moment_exactly_one_wins,
    a_crashed_holders_lease_expires_and_another_process_takes_the_job,
    a_run_whose_lease_is_taken_is_cancelled_and_never_recorded,
    a_run_that_cant_renew_keeps_trying_for_the_lease_window_then_is_cancelled,
    a_failed_run_keeps_its_cursor_says_why_and_retries_sooner,
    a_restart_mid_run_resumes_from_the_last_cursor,
    the_tracer_one_clients_cves_from_the_consoles_own_data,
    nothing_is_matched_or_deleted_before_the_inventory_exists_and_a_bad_answer_deletes_nothing,
    search_orders_names_the_same_on_both_stores,
);

// ---------------------------------------------------------------- migrations

async fn migrations_apply_once_and_two_processes_starting_together_apply_nothing_new(db: TestDb) {
    // test_db migrated it once; two more starts at the same moment (two replicas, on PostgreSQL) are both fine, and
    // apply nothing new.
    let (a, b) = tokio::join!(msp_console::db::connect(&db.cfg), msp_console::db::connect(&db.cfg));
    assert!(a.is_ok() && b.is_ok(), "{:?} {:?}", a.err(), b.err());
    let n = count(&db.pool, "SELECT count(*) FROM _sqlx_migrations WHERE success").await;
    let expected = match db.backend { Backend::Sqlite => msp_console::db::sqlite::MIGRATOR.iter().count(), Backend::Postgres => msp_console::db::postgres::MIGRATOR.iter().count() };
    assert_eq!(n as usize, expected);
    assert_eq!(expected, 12, "the first five, the advisories (0010), Windows, processes and the full NVD (0020 to 0022), and Blackpoint, exposure and tickets (0030 to 0032)");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_product").await, 22, "the seed applied once, not three times");
}

/// Every migration is pinned by its checksum: sqlx refuses a store whose applied migration changed, so a change to one
/// (even a comment) is a decision, made here: an applied migration is never edited, a change is a new migration.
#[test]
fn the_sqlite_migrations_are_the_ones_an_existing_store_already_has() {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    // Every one is pinned: a store that has run one must find it unchanged.
    let got: Vec<(i64, String, String)> = msp_console::db::sqlite::MIGRATOR.iter().map(|m| (m.version, m.description.to_string(), hex(&m.checksum))).collect();
    assert_eq!(got, vec![
        (1, "store".to_string(), "e3420e7617f2ffb2b78dcda885e1988bc2b309be865493776fe92716ecfe2888756dbb668500a1ee3cb603d33c928c70".to_string()),
        (2, "products".into(), "587b8bef07a965735978f6b1b7a42d55f513cdc668b00d5cd690b89f357b1caae02ab107a830ddcf97b077abf396924b".into()),
        (3, "vectors".into(), "d697c9896384cf8e7d2af37e408e7a46b442c427219b942cb9ba231c0a017656eac8612fa7317f6d17f722a506f23e44".into()),
        (4, "embedded".into(), "1684ecffdf29610d135333c2f7fc563c1653bba4d0eb0e6295263742dffc40ec4cfafe5d84ec3cdc688c8eb3dd89d3f9".into()),
        (5, "embed failed".into(), "0e7ce54e174aad34257ff003fbcac96a6fade90054ac04a77ac2a45fb7bc931b3eab856300c514f974cba4f65fefd0b9".into()),
        (10, "advisories".into(), "12911a217d8d8eb954fc503f5826fbf93dd123d792ccfc048a463199ed5991b78c5764b13dc1eacc1c2673d4bba35363".into()),
        (20, "windows".into(), "4266f20340c0606d79321551c358cc99e93f90a31ac014b10301633fb82b8556fb758304ae599282704c927e71ad6ed7".into()),
        (21, "processes".into(), "e380017d018c1b3d46f6cc84e62191042d01b0c84f83f11ce517ed58a6c42563622d449eb230b9d81f0aa949e1a9ead8".into()),
        (22, "nvd full".into(), "677723a454eec7c21f27375f9089d8b874014479722fd04df324e018a674d483cbd6792c3c07bf8a1aab1185ea9c81f9".into()),
        (30, "blackpoint".into(), "dd2f902e3f572aaca04d7906220ded20d7ca4ff552e42a7b15d3307491ae76d44794d7565bf222719b9d8301167f6f01".into()),
        (31, "exposure".into(), "fcc8937371b9f5eb36a6320617a104326def406ee2eb2d494a0e1879db14bfe2b11622e3671cfe560a3261e4b69cd25f".into()),
        (32, "tickets".into(), "4f5c0cd43f9dd89fc58a11eab3e73d4ce0b6acdd65eb04704f951126eb255f5e07ad2f8541780b4a2dfb8910b19921fd".into()),
    ]);
    // And both stores are seeded with the same products: SQLite's literals read as written, PostgreSQL's E'' ones with
    // their escapes (the only escapes they use are doubled backslashes).
    let rows = |store: &str| -> Vec<Vec<String>> {
        let text = std::fs::read_to_string(format!("{}/migrations/{store}/0002_products.sql", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let lit = regex::Regex::new(r"(E?)'((?:[^']|'')*)'").unwrap();
        text.lines().filter(|l| l.trim_start().starts_with("('")).map(|l| lit.captures_iter(l).map(|c| {
            let v = c[2].replace("''", "'");
            if &c[1] == "E" { assert!(!v.replace("\\\\", "").contains('\\'), "only doubled backslashes: {v}"); v.replace("\\\\", "\\") } else { v }
        }).collect()).collect()
    };
    let (sqlite, postgres) = (rows("sqlite"), rows("postgres"));
    assert_eq!(sqlite.len(), 22);
    assert_eq!(sqlite, postgres);
    assert!(sqlite.iter().any(|r| r[2] == "notepad-plus-plus:notepad\\+\\+"), "the escapes NVD writes survive");
}

/// PostgreSQL's seed reads the same with standard_conforming_strings off, where a plain '...' would eat its
/// backslashes: every product, rule and CPE as SQLite's store holds them.
#[tokio::test]
async fn the_postgresql_seed_doesnt_depend_on_standard_conforming_strings() {
    let Some(d) = pg_db().await else { return };
    let admin = sqlx::PgPool::connect(&d.admin).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("ALTER DATABASE {} SET standard_conforming_strings = off", d.name))).execute(&admin).await.unwrap();
    admin.close().await;
    let pool = msp_console::db::connect(&msp_console::db::DbConfig::Postgres(msp_console::db::PgConfig::new(&d.url, false).unwrap())).await.unwrap();
    let Pool::Postgres(p) = &pool else { unreachable!() };
    let off: String = sqlx::query_scalar("SHOW standard_conforming_strings").fetch_one(p).await.unwrap();
    assert_eq!(off, "off", "the migrations really ran with it off");
    type Product = (String, String, String, Value, i64);
    let pg: Vec<Product> = sqlx::query_as("SELECT product_key, label, cpe, match, sort_order::bigint FROM sec_product ORDER BY product_key").fetch_all(p).await.unwrap();
    let lite = test_db().await;
    let sqlite: Vec<Product> = on_pool!(&lite.pool, p, _ => sqlx::query_as("SELECT product_key, label, cpe, match, sort_order FROM sec_product ORDER BY product_key").fetch_all(p).await.unwrap());
    assert_eq!(pg.len(), 22);
    assert_eq!(pg, sqlite);
    assert_eq!(pg.iter().find(|r| r.0 == "firefox_esr").unwrap().3["name_re"], "^Mozilla Firefox.*\\bESR\\b");
    // And search, whose SQL holds no backslash on PostgreSQL, still escapes a pattern's own _ there.
    let store = Store::new(pool.clone());
    let (_, a) = store.call(&EvidenceRequest::parse(br#"{"op":"search","params":{"q":"veeam_"}}"#).unwrap()).await;
    assert_eq!(a["data"].as_array().map(Vec::len), Some(1), "{a}");
    let (_, a) = store.call(&EvidenceRequest::parse(br#"{"op":"search","params":{"q":"7_zip"}}"#).unwrap()).await;
    assert_eq!(a["data"], json!([]), "_ is a character, not a wildcard: {a}");
    pool.close().await;
}

/// Search orders as SQLite's NOCASE does on both stores: ASCII letters folded, then byte order.
async fn search_orders_names_the_same_on_both_stores(db: TestDb) {
    for (id, name) in [(1, "beta Clinic"), (2, "Alpha Dental"), (3, "alpha dental"), (4, "_Annex"), (5, "Zeta"), (6, "ALPHA ortho")] {
        on_pool!(&db.pool, p, _ => { sqlx::query("INSERT INTO client (org_id, name, name_key) VALUES ($1, $2, $3)").bind(id as i64).bind(name).bind(msp_console::db::name_key(name)).execute(p).await.unwrap(); });
    }
    let store = Store::new(db.pool.clone());
    let (_, a) = store.call(&EvidenceRequest::parse(br#"{"op":"search","params":{"q":"a"}}"#).unwrap()).await;
    let names: Vec<&str> = a["data"].as_array().unwrap().iter().filter(|x| x["type"] == "client").map(|x| x["label"].as_str().unwrap()).collect();
    // Folded to lower case and compared by byte ('_' is 0x5F, below 'a'); a tie broken by the name's bytes ('A' before 'a').
    assert_eq!(names, ["_Annex", "Alpha Dental", "alpha dental", "ALPHA ortho", "beta Clinic", "Zeta"]);
}

#[tokio::test]
async fn the_connection_is_wal_with_foreign_keys_a_busy_timeout_and_normal_sync() {
    let db = test_db().await;
    let Pool::Sqlite(pool) = &db.pool else { unreachable!() };
    let mut c = pool.acquire().await.unwrap();
    let one = |q: &'static str| sqlx::query_scalar::<_, String>(q);
    let (mode, fk, busy, sync, temp) = (one("PRAGMA journal_mode").fetch_one(&mut *c).await.unwrap(), sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys").fetch_one(&mut *c).await.unwrap(),
        sqlx::query_scalar::<_, i64>("PRAGMA busy_timeout").fetch_one(&mut *c).await.unwrap(), sqlx::query_scalar::<_, i64>("PRAGMA synchronous").fetch_one(&mut *c).await.unwrap(),
        sqlx::query_scalar::<_, i64>("PRAGMA temp_store").fetch_one(&mut *c).await.unwrap());
    assert_eq!((mode.as_str(), fk, busy, sync, temp), ("wal", 1, 5000, 1, 2), "WAL, foreign keys on, 5 s, NORMAL, temp in memory");
}

#[cfg(unix)]
#[tokio::test]
async fn the_database_and_its_wal_are_the_console_users_alone() {
    use std::os::unix::fs::PermissionsExt;
    let db = test_db().await;
    exec(&db.pool, "INSERT INTO sec_kev (cve_id) VALUES ('CVE-2026-0001')").await;
    for f in [db.sqlite().path.clone(), db.sqlite().path.with_extension("db-wal")] {
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600, "{}", f.display());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn it_refuses_to_start_when_the_directory_isnt_writable() {
    use msp_console::db::{DbConfig, SqliteConfig};
    use std::os::unix::fs::PermissionsExt;
    let db = test_db().await;
    let ro = db.sqlite().path.parent().unwrap().join("read-only");
    std::fs::create_dir(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    let e = msp_console::db::connect(&DbConfig::Sqlite(SqliteConfig { path: ro.join("console.db"), backup_keep: 7 })).await.unwrap_err();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(e.contains("isn't writable") && e.contains("mount the console's volume"), "{e}");
    let e = msp_console::db::connect(&DbConfig::Sqlite(SqliteConfig { path: "/nonexistent/msp-console/console.db".into(), backup_keep: 7 })).await.unwrap_err();
    assert!(e.contains("isn't writable"), "{e}");
}

// ---------------------------------------------------------------- the scheduler

fn slow_job(name: &'static str, log: Arc<Mutex<Vec<(Instant, Instant)>>>, takes: Duration) -> Job {
    Job { name, every: Duration::ZERO, run: Arc::new(move |_pool, _| {
        let log = log.clone();
        Box::pin(async move { let t0 = Instant::now(); tokio::time::sleep(takes).await; log.lock().unwrap().push((t0, Instant::now())); Ok(Outcome { detail: json!({}), cursor: None }) })
    }) }
}

/// Another process on the same store: its own connections (a second replica, on PostgreSQL).
async fn another_process(db: &TestDb) -> Pool { msp_console::db::connect(&db.cfg).await.unwrap() }

async fn two_schedulers_on_one_store_never_run_the_same_job_at_once(db: TestDb) {
    let log = Arc::new(Mutex::new(Vec::new()));
    // A short lease that the runner must keep renewing: the job takes longer than one lease. Each scheduler has its own
    // pool, as two processes would.
    let mk = |pool: Pool| { let mut s = Scheduler::new(pool, vec![slow_job("slow", log.clone(), Duration::from_millis(700))]); s.lease = Duration::from_millis(300); s.tick = Duration::from_millis(20); s };
    let (a, b) = (mk(db.pool.clone()), mk(another_process(&db).await));
    assert_ne!(a.holder, b.holder);
    a.register().await.unwrap();
    let (ta, tb) = (tokio::spawn(a.run_forever()), tokio::spawn(b.run_forever()));
    tokio::time::sleep(Duration::from_millis(3500)).await;
    ta.abort(); tb.abort();
    let mut runs = log.lock().unwrap().clone();
    runs.sort();
    assert!(runs.len() >= 3, "it ran: {} runs", runs.len());
    for w in runs.windows(2) { assert!(w[1].0 >= w[0].1, "two runs overlapped"); }
}

async fn of_many_processes_claiming_one_due_job_at_the_same_moment_exactly_one_wins(db: TestDb) {
    // Eight processes, each with its own connections, claim the same due job at once, twenty times over. The claim is
    // one UPDATE ... WHERE (due and unleased) ... RETURNING: PostgreSQL locks the row for the first and checks the
    // others' WHERE again against what it wrote; SQLite lets one writer in at a time. Either way, one winner a round.
    let job = slow_job("contended", Default::default(), Duration::ZERO);
    let mut procs = Vec::new();
    for _ in 0..8 { procs.push(Arc::new(Scheduler::new(another_process(&db).await, vec![job.clone()]))); }
    procs[0].register().await.unwrap();
    for round in 0..20 {
        on_pool!(&db.pool, p, _ => { sqlx::query("UPDATE job SET lease_holder = NULL, lease_until = NULL, next_run_at = $1 WHERE name = 'contended'")
            .bind(Ts(chrono::Utc::now() - chrono::Duration::seconds(1))).execute(p).await.unwrap(); });
        let start = Arc::new(tokio::sync::Barrier::new(procs.len()));
        let tasks: Vec<_> = procs.iter().map(|s| { let (s, start) = (s.clone(), start.clone()); tokio::spawn(async move { start.wait().await; s.claim("contended").await.unwrap().is_some() }) }).collect();
        let mut won = 0;
        for t in tasks { won += usize::from(t.await.unwrap()); }
        assert_eq!(won, 1, "round {round}: {won} processes hold the one lease");
        let holder: Option<String> = on_pool!(&db.pool, p, _ => sqlx::query_scalar("SELECT lease_holder FROM job WHERE name = 'contended'").fetch_one(p).await.unwrap());
        assert!(procs.iter().any(|s| Some(&s.holder) == holder.as_ref()), "the winner's name is on the lease");
    }
}

async fn a_crashed_holders_lease_expires_and_another_process_takes_the_job(db: TestDb) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let s = Scheduler::new(another_process(&db).await, vec![slow_job("orphan", log.clone(), Duration::from_millis(10))]);
    s.register().await.unwrap();
    let until = Ts(chrono::Utc::now() + chrono::Duration::milliseconds(800));
    on_pool!(&db.pool, p, _ => { sqlx::query("UPDATE job SET lease_holder = 'dead-process', lease_until = $1 WHERE name = 'orphan'").bind(until).execute(p).await.unwrap(); });
    assert!(!s.run_if_due(&s.jobs[0]).await, "held by the process that died");
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(s.run_if_due(&s.jobs[0]).await, "the lease expired: taken over");
    assert_eq!(log.lock().unwrap().len(), 1);
}

/// A job that takes three seconds unless it's stopped: `stopped` is set when its future is dropped before it ends,
/// `ended` when it runs to the end.
fn long_job(name: &'static str, ended: Arc<std::sync::atomic::AtomicBool>, stopped: Arc<std::sync::atomic::AtomicBool>) -> Job {
    use std::sync::atomic::Ordering;
    struct OnDrop(Arc<std::sync::atomic::AtomicBool>, Arc<std::sync::atomic::AtomicBool>);
    impl Drop for OnDrop { fn drop(&mut self) { if !self.1.load(Ordering::SeqCst) { self.0.store(true, Ordering::SeqCst); } } }
    Job { name, every: Duration::from_secs(3600), run: Arc::new(move |_p, _c| {
        let (ended, stopped) = (ended.clone(), stopped.clone());
        Box::pin(async move {
            let _guard = OnDrop(stopped, ended.clone());
            tokio::time::sleep(Duration::from_secs(3)).await;
            ended.store(true, Ordering::SeqCst);
            Ok(Outcome { detail: json!({ "ran": "to the end" }), cursor: Some(json!({ "page": 9 })) })
        })
    }) }
}

async fn a_run_whose_lease_is_taken_is_cancelled_and_never_recorded(db: TestDb) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (ended, stopped) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let mut s = Scheduler::new(another_process(&db).await, vec![long_job("taken", ended.clone(), stopped.clone())]);
    s.lease = Duration::from_millis(300);
    s.register().await.unwrap();
    let t0 = Instant::now();
    let run = tokio::spawn(async move { let j = s.jobs[0].clone(); s.run_if_due(&j).await });
    // Another process takes the lease while the job runs (as after a pause longer than the lease, on a replica).
    tokio::time::sleep(Duration::from_millis(150)).await;
    on_pool!(&db.pool, p, _ => { sqlx::query("UPDATE job SET lease_holder = 'another-process', lease_until = $1 WHERE name = 'taken'")
        .bind(Ts(chrono::Utc::now() + chrono::Duration::minutes(5))).execute(p).await.unwrap(); });
    assert!(run.await.unwrap(), "it ran here, until it lost the lease");
    assert!(t0.elapsed() < Duration::from_millis(1500), "cancelled at the next renewal, not left to finish: {:?}", t0.elapsed());
    assert!(stopped.load(Ordering::SeqCst) && !ended.load(Ordering::SeqCst), "the run was dropped mid-way");
    // Nothing of it was recorded, and the lease is still the other process's.
    let (holder, ok, cursor): (Option<String>, Option<chrono::DateTime<chrono::Utc>>, Option<Value>) = on_pool!(&db.pool, p, _ => sqlx::query_as(
        "SELECT lease_holder, last_ok_at, cursor FROM job WHERE name = 'taken'").fetch_one(p).await.unwrap());
    assert_eq!((holder.as_deref(), ok, cursor), (Some("another-process"), None, None));
}

async fn a_run_that_cant_renew_keeps_trying_for_the_lease_window_then_is_cancelled(db: TestDb) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (ended, stopped) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let pool = another_process(&db).await;
    let mut s = Scheduler::new(pool.clone(), vec![long_job("unreachable", ended.clone(), stopped.clone())]);
    s.lease = Duration::from_millis(600);
    s.register().await.unwrap();
    let t0 = Instant::now();
    let run = tokio::spawn(async move { let j = s.jobs[0].clone(); s.run_if_due(&j).await });
    // Renewed once at 200 ms; then this process loses its database (its pool closes), so the renewal at 400 ms fails.
    tokio::time::sleep(Duration::from_millis(300)).await;
    pool.close().await;
    assert!(run.await.unwrap());
    let took = t0.elapsed();
    // A failed renewal isn't the end: it's retried until the lease could have run out (540 ms after the last
    // renewal at about 200 ms), and only then is the run cancelled. Giving up at the first failure would be ~400 ms.
    assert!(took >= Duration::from_millis(650) && took < Duration::from_millis(1500), "{took:?}");
    assert!(stopped.load(Ordering::SeqCst) && !ended.load(Ordering::SeqCst), "the run was dropped mid-way");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM job WHERE name = 'unreachable' AND last_ok_at IS NOT NULL").await, 0, "and not recorded");
}

async fn a_failed_run_keeps_its_cursor_says_why_and_retries_sooner(db: TestDb) {
    let job = Job { name: "flaky", every: Duration::from_secs(86_400), run: Arc::new(|_p, cur| Box::pin(async move {
        if cur.is_none() { Ok(Outcome { detail: json!({ "n": 1 }), cursor: Some(json!({ "page": 2 })) }) } else { Err("NinjaOne: HTTP 503".into()) }
    })) };
    let s = Scheduler::new(db.pool.clone(), vec![job]);
    s.register().await.unwrap();
    assert!(s.run_if_due(&s.jobs[0]).await);
    on_pool!(&db.pool, p, _ => { sqlx::query("UPDATE job SET next_run_at = $1").bind(Ts(chrono::Utc::now() - chrono::Duration::seconds(1))).execute(p).await.unwrap(); });
    assert!(s.run_if_due(&s.jobs[0]).await);
    let (cursor, err, ok, next): (Option<Value>, Option<String>, bool, chrono::DateTime<chrono::Utc>) = on_pool!(&db.pool, p, _ => sqlx::query_as(
        "SELECT cursor, last_error, last_ok_at IS NOT NULL, next_run_at FROM job WHERE name = 'flaky'").fetch_one(p).await.unwrap());
    assert_eq!((cursor, err.as_deref(), ok), (Some(json!({ "page": 2 })), Some("NinjaOne: HTTP 503"), true));
    let wait = (next - chrono::Utc::now()).num_seconds();
    assert!((890..=900).contains(&wait), "retried in 15 minutes, not tomorrow: {wait}");
    // The next run gets the cursor the last good run left, as it would after a restart.
    let (cur,): (Option<Value>,) = on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT cursor FROM job WHERE name = 'flaky'").fetch_one(p).await.unwrap());
    assert_eq!(cur, Some(json!({ "page": 2 })));
}

async fn a_restart_mid_run_resumes_from_the_last_cursor(db: TestDb) {
    let seen: Arc<Mutex<Vec<Option<Value>>>> = Default::default();
    let s2 = seen.clone();
    let job = Job { name: "pages", every: Duration::from_secs(86_400), run: Arc::new(move |_p, cur| { let s = s2.clone(); Box::pin(async move {
        s.lock().unwrap().push(cur.clone());
        Ok(Outcome { detail: json!({}), cursor: Some(json!({ "done": [7] })) })
    }) }) };
    let a = Scheduler::new(db.pool.clone(), vec![job.clone()]);
    a.register().await.unwrap();
    assert!(a.run_if_due(&a.jobs[0]).await);
    // The process dies holding the next run's lease; a new process (a new holder) starts once the lease is gone.
    let past = Ts(chrono::Utc::now() - chrono::Duration::seconds(1));
    on_pool!(&db.pool, p, _ => { sqlx::query("UPDATE job SET next_run_at = $1, lease_holder = 'the-old-process', lease_until = $1 WHERE name = 'pages'").bind(past).execute(p).await.unwrap(); });
    let b = Scheduler::new(another_process(&db).await, vec![job]);
    assert!(b.run_if_due(&b.jobs[0]).await);
    assert_eq!(*seen.lock().unwrap(), vec![None, Some(json!({ "done": [7] }))]);
}

// ---------------------------------------------------------------- the daily backup

#[tokio::test]
async fn the_backup_is_a_whole_private_copy_and_keeps_only_the_newest() {
    let db = test_db().await;
    exec(&db.pool, "INSERT INTO client (org_id, name, name_key) VALUES (7, 'Alpha Dental', 'alpha dental')").await;
    let dir = db.sqlite().backup_dir();
    std::fs::create_dir_all(&dir).unwrap();
    // Nine older copies, a dead run's partial copy, and a file that isn't the backup's to touch.
    for d in 1..=9 { std::fs::write(dir.join(format!("console-2026-01-0{d}.db")), b"old").unwrap(); }
    std::fs::write(dir.join("console-2026-01-10.db.partial"), b"dead").unwrap();
    std::fs::write(dir.join("notes.txt"), b"mine").unwrap();
    let b = msp_console::backup::Backup { dir: dir.clone(), keep: 3 };
    let o = b.run(&db.pool).await.unwrap();
    let today = format!("console-{}.db", chrono::Utc::now().format("%Y-%m-%d"));
    assert_eq!((o.detail["file"].as_str(), o.detail["kept"].as_u64(), o.detail["removed"].as_u64()), (Some(today.as_str()), Some(3), Some(8)), "{}", o.detail);
    let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    left.sort();
    assert_eq!(left, vec!["console-2026-01-08.db".to_string(), "console-2026-01-09.db".into(), today.clone(), "notes.txt".into()]);
    // Run again the same day (a retry): the day's copy is replaced, not refused.
    exec(&db.pool, "INSERT INTO client (org_id, name, name_key) VALUES (8, 'Bravo Ortho', 'bravo ortho')").await;
    b.run(&db.pool).await.unwrap();
    // The copy is a database of its own, with everything committed when it was made.
    let copy = msp_console::db::connect(&msp_console::db::DbConfig::Sqlite(msp_console::db::SqliteConfig { path: dir.join(&today), backup_keep: 7 })).await.unwrap();
    let names: Vec<(String,)> = on_pool!(&copy, p, _ => sqlx::query_as("SELECT name FROM client ORDER BY org_id").fetch_all(p).await.unwrap());
    assert_eq!(names, vec![("Alpha Dental".to_string(),), ("Bravo Ortho".to_string(),)]);
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(dir.join(&today)).unwrap().permissions().mode() & 0o777, 0o600); }
    // And the job is on /api/status like every other.
    let s = Scheduler::new(db.pool.clone(), Arc::new(msp_console::backup::Backup::new(db.sqlite())).jobs());
    s.register().await.unwrap();
    assert!(s.run_if_due(&s.jobs[0]).await);
    let status = msp_console::scheduler::status(&db.pool).await.unwrap();
    assert_eq!((status[0]["job"].as_str(), status[0]["last_error"].is_null(), status[0]["detail"]["file"].as_str()), (Some("backup"), true, Some(today.as_str())));
}

#[tokio::test]
async fn on_postgresql_there_is_no_backup_job_and_the_status_says_backups_are_yours() {
    let Some(db) = test_db_on(Backend::Postgres).await else { return };
    let c = Connectors { ninja: None, halo: None, nvd_url: "https://nvd.example.com".into(), nvd_key: None, kev_url: "https://kev.example.com".into(), msrc_url: None, nvd_feed_url: None, ninja_process_field: None };
    let names: Vec<&str> = msp_console::jobs(&c, &db.cfg, msp_console::http_client()).iter().map(|j| j.name).collect();
    assert_eq!(names, ["kev", "nvd_products", "match", "darkweb_purge"], "no backup job on PostgreSQL");
    let e = msp_console::backup::Backup { dir: std::env::temp_dir().join("never-made"), keep: 1 }.run(&db.pool).await.unwrap_err();
    assert!(e.contains("PostgreSQL") && e.contains("yours"), "{e}");
    let d = msp_console::db::describe(&db.pool).await;
    assert_eq!(d["kind"], "postgresql");
    assert!(d["backups"].as_str().unwrap().contains("pg_dump"), "{d}");
}

// ---------------------------------------------------------------- Halo's shared limit

#[tokio::test]
async fn halo_never_takes_more_than_its_share_and_waits_after_a_429() {
    let calls: Arc<Mutex<Vec<Instant>>> = Default::default();
    let first429 = Arc::new(Mutex::new(true));
    let (c2, f2) = (calls.clone(), first429.clone());
    let base = serve(Router::new()
        .route("/auth/token", post(|| async { Json(json!({ "access_token": "t", "expires_in": 3600 })) }))
        .route("/api/Client/{id}", get(move || { let (c, f) = (c2.clone(), f2.clone()); async move {
            c.lock().unwrap().push(Instant::now());
            if std::mem::replace(&mut *f.lock().unwrap(), false) { return (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "0")], Json(json!({}))).into_response(); }
            Json(json!({ "id": 1 })).into_response()
        } }))).await;
    let mut h = Halo::new(HaloSettings { base: format!("{base}/api"), auth_url: None, client_id: "i".into(), client_secret: "s".into(), tenant: None, per_5min: 150, detail_budget: 150 }, msp_console::http_client());
    assert_eq!((h.backoff.floor, h.limiter_window()), (Duration::from_secs(60), Duration::from_secs(300)), "Halo's real settings: a minute after a 429, a 5-minute window");
    // Scaled down so the test is quick: 3 calls a 400 ms window, a 250 ms floor after a 429.
    h.limiter = Limiter::new(3, Duration::from_millis(400));
    h.backoff = Backoff { floor: Duration::from_millis(250), tries: 3 };
    let t0 = Instant::now();
    for i in 0..8 { h.get(&format!("/Client/{i}")).await.unwrap(); }
    let seen = calls.lock().unwrap().clone();
    assert_eq!(seen.len(), 9, "8 reads, one of them retried after the 429");
    assert!(seen[1].duration_since(seen[0]) >= Duration::from_millis(250), "the 429 waited at least the floor, though Retry-After said 0");
    for (i, t) in seen.iter().enumerate() {
        let in_window = seen.iter().filter(|u| **u >= *t && u.duration_since(*t) < Duration::from_millis(390)).count();
        assert!(in_window <= 3, "call {i}: {in_window} calls inside one window");
    }
    assert!(t0.elapsed() >= Duration::from_millis(800));
}

// ---------------------------------------------------------------- the tracer, end to end

/// NinjaOne, HaloPSA, CISA KEV and NVD, made up. Alpha Dental (org 7, Halo 100, linked by ninjarmmid) has a desktop
/// with Chrome 120 (vulnerable to CVE-2026-0001, which CISA lists as used by ransomware) and Firefox ESR; Bravo Ortho
/// (org 8) has a laptop with Chrome 122 (fixed). Two Halo clients both link to org 8 and neither's name is its, so Bravo
/// stays unlinked: an ambiguous link confirms nothing, and a different name suggests nothing. Charlie's Clinic (org 9)
/// has no link at all, and Halo's "CHARLIE S  CLINIC" is the same name once case and punctuation go: a suggestion.
type S = Arc<Mutex<Vec<(String, HashMap<String, String>)>>>;
async fn vendors() -> (String, S) {
    let seen: S = Default::default();
    fn note(s: &S, what: &str, h: &HeaderMap) { s.lock().unwrap().push((what.into(), h.iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect())); }
    let r = Router::new()
        .route("/ninja/ws/oauth/token", post(|| async { Json(json!({ "access_token": "ninja-bearer", "expires_in": 3600 })) }))
        .route("/ninja/v2/organizations", get(|State(s): State<S>, h: HeaderMap| async move { note(&s, "orgs", &h);
            Json(json!([{ "id": 7, "name": "Alpha Dental" }, { "id": 8, "name": "Bravo Ortho" }, { "id": 9, "name": "Charlie's Clinic" }])) }))
        .route("/ninja/v2/queries/computer-systems", get(|| async { Json(json!({ "results": [{ "deviceId": 701, "chassisType": "desktop" }, { "deviceId": 801, "chassisType": "laptop" }], "cursor": null })) }))
        .route("/ninja/v2/devices-detailed", get(|Query(q): Query<HashMap<String, String>>| async move {
            if q.get("after").map(String::as_str) != Some("0") { return Json(json!([])); }
            Json(json!([{ "id": 701, "organizationId": 7, "systemName": "DESIGN-1", "nodeClass": "WINDOWS_WORKSTATION", "os": { "name": "Windows 11 Pro" }, "lastContact": 1761552000.5 },
                        { "id": 801, "organizationId": 8, "systemName": "BRAVO-LT", "nodeClass": "WINDOWS_WORKSTATION", "os": { "name": "Windows 11 Pro" }, "lastContact": 1761552000 },
                        { "id": 702, "organizationId": 7, "systemName": "ALPHA-DC", "nodeClass": "WINDOWS_SERVER", "os": { "name": "Windows Server 2022" } }]))
        }))
        .route("/ninja/v2/queries/software", get(|Query(q): Query<HashMap<String, String>>| async move {
            let org = q.get("df").cloned().unwrap_or_default();
            let rows = match org.as_str() {
                "org=7" => json!([{ "deviceId": 701, "name": "Google Chrome", "publisher": "Google LLC", "version": "120.0.6099.71" },
                                  { "deviceId": 701, "name": "Mozilla Firefox ESR 115.4.0 (x64 en-US)", "publisher": "Mozilla", "version": "115.4.0" },
                                  { "deviceId": 702, "name": "Microsoft Edge", "publisher": "Microsoft", "version": "141.0" }]),
                "org=8" => json!([{ "deviceId": 801, "name": "Google Chrome", "publisher": "Google LLC", "version": "122.0.6261.57" }]),
                _ => json!([]),
            };
            Json(json!({ "results": rows, "cursor": null }))
        }))
        .route("/halo/auth/token", post(|| async { Json(json!({ "access_token": "halo-bearer", "expires_in": 3600 })) }))
        .route("/halo/api/Client", get(|| async { Json(json!({ "clients": [{ "id": 100, "name": "Alpha Dental" }, { "id": 200, "name": "Bravo Orthodontics" }, { "id": 201, "name": "Bravo Ortho East" },
                                                                             { "id": 300, "name": "CHARLIE S  CLINIC" }] })) }))
        .route("/halo/api/Client/{id}", get(|axum::extract::Path(id): axum::extract::Path<i64>| async move {
            Json(match id { 100 => json!({ "id": 100, "ninjarmmid": 7, "website": "http://www.alphadental.example/", "domain": "N/A" }), 300 => json!({ "id": 300 }),
                            _ => json!({ "id": id, "ninjarmmid": "8" }) })
        }))
        .route("/kev.json", get(|| async { Json(json!({ "vulnerabilities": [
            { "cveID": "CVE-2026-0001", "vendorProject": "Google", "product": "Chromium", "vulnerabilityName": "Synthetic Chromium flaw", "dateAdded": "2026-10-01", "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known" },
            { "cveID": "CVE-2026-0999", "vendorProject": "Other", "product": "Other", "vulnerabilityName": "Unrelated", "dateAdded": "2026-10-02", "knownRansomwareCampaignUse": "Unknown" }] })) }))
        .route("/nvd", get(|State(s): State<S>, h: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
            note(&s, "nvd", &h);
            if q.get("virtualMatchString").map(String::as_str) != Some("cpe:2.3:a:google:chrome") { return Json(json!({ "totalResults": 0, "vulnerabilities": [] })); }
            Json(json!({ "totalResults": 2, "vulnerabilities": [
                { "cve": { "id": "CVE-2026-0001", "published": "2026-09-30T10:00:00.000", "lastModified": "2026-10-01T10:00:00.000", "vulnStatus": "Analyzed",
                    "descriptions": [{ "lang": "en", "value": "A synthetic use-after-free in Chrome before 121." }],
                    "metrics": { "cvssMetricV31": [{ "type": "Primary", "cvssData": { "baseScore": 8.8, "baseSeverity": "HIGH" } }] },
                    "configurations": [{ "nodes": [{ "cpeMatch": [{ "vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "121.0.6167.85" }] }] }] } },
                { "cve": { "id": "CVE-2026-0002", "published": "2026-09-01T10:00:00.000", "vulnStatus": "Rejected",
                    "configurations": [{ "nodes": [{ "cpeMatch": [{ "vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "999" }] }] }] } } ] }))
        }))
        .with_state(seen.clone());
    (serve(r).await, seen)
}

async fn the_tracer_one_clients_cves_from_the_consoles_own_data(db: TestDb) {
    let (base, seen) = vendors().await;
    let connectors = Connectors {
        ninja: Some(NinjaCfg { base: format!("{base}/ninja"), client_id: "ninja-id".into(), client_secret: "ninja-secret-value".into() }),
        halo: Some(HaloCfg { base: format!("{base}/halo/api"), auth_url: None, tenant: None, client_id: "halo-id".into(), client_secret: "halo-secret-value".into(), per_5min: 150, detail_budget: 150 }),
        nvd_url: format!("{base}/nvd"), nvd_key: Some("nvd-key-value".into()), kev_url: format!("{base}/kev.json"),
        msrc_url: None, nvd_feed_url: None, ninja_process_field: None,
    };
    let jobs = msp_console::jobs(&connectors, &db.cfg, msp_console::http_client());
    let mut names = vec!["ninja_devices", "ninja_software", "halo_clients", "kev", "nvd_products", "match", "darkweb_purge"];
    if db.backend == Backend::Sqlite { names.push("backup"); }
    assert_eq!(jobs.iter().map(|j| j.name).collect::<Vec<_>>(), names, "the backup job is the SQLite store's alone");
    let s = Scheduler::new(db.pool.clone(), jobs);
    s.register().await.unwrap();
    for j in &s.jobs { assert!(s.run_if_due(j).await, "{} ran", j.name); }
    let status = msp_console::scheduler::status(&db.pool).await.unwrap();
    for j in status.as_array().unwrap() { assert!(j["last_error"].is_null(), "{j}"); }

    // The vendors saw their own bearer, and NVD the key, in headers: never a secret in a URL.
    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls.iter().find(|c| c.0 == "orgs").unwrap().1["authorization"], "Bearer ninja-bearer");
    assert_eq!(calls.iter().find(|c| c.0 == "nvd").unwrap().1["apikey"], "nvd-key-value");

    let store = Store::new(db.pool.clone());
    let ask = |b: &str| EvidenceRequest::parse(b.as_bytes()).unwrap();
    let (code, a) = store.call(&ask(r#"{"op":"cves.list","params":{"org_id":7}}"#)).await;
    assert_eq!(code, 200, "{a}");
    assert_eq!(a["totals"]["cves"], 1, "{a}");
    assert_eq!((a["data"][0]["cve_id"].clone(), a["data"][0]["kev"].clone(), a["data"][0]["cvss"].clone(), a["data"][0]["devices"].clone(), a["data"][0]["sources"].clone()),
               (json!("CVE-2026-0001"), json!(true), json!(8.8), json!(1), json!(["ninja_software"])));
    assert!(!a["as_of"]["inventory"].is_null());
    let (_, b) = store.call(&ask(r#"{"op":"cves.list","params":{"org_id":8}}"#)).await;
    assert_eq!(b["totals"]["cves"], 0, "Chrome 122 is past the fix");
    let (_, c) = store.call(&ask(r#"{"op":"cve.get","params":{"cve_id":"CVE-2026-0001","org_id":7}}"#)).await;
    assert_eq!((c["data"]["nvd"]["cvss"].clone(), c["data"]["kev"]["ransomware"].clone(), c["data"]["devices"].clone(), c["data"]["devices_by_source"]["ninja_software"].clone()),
               (json!(8.8), json!(true), json!(1), json!(1)), "{c}");
    let (_, r) = store.call(&ask(r#"{"op":"cves.list","params":{}}"#)).await;
    assert!(r["data"].as_array().unwrap().iter().all(|x| x["cve_id"] != "CVE-2026-0002"), "a rejected CVE is no one's");
    let (_, q) = store.call(&ask(r#"{"op":"search","params":{"q":"alpha"}}"#)).await;
    assert_eq!(q["data"][0], json!({ "type": "client", "id": 7, "label": "Alpha Dental" }));

    // What the connectors stored: classes, the Halo link by Halo's own id, the website normalised.
    let classes: Vec<(i64, String)> = on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT device_id, device_class FROM device ORDER BY device_id").fetch_all(p).await.unwrap());
    assert_eq!(classes, vec![(701, "desktop".into()), (702, "server".into()), (801, "laptop".into())]);
    let contact: Option<chrono::DateTime<chrono::Utc>> = on_pool!(&db.pool, p, _ => sqlx::query_scalar("SELECT last_contact FROM device WHERE device_id = 701").fetch_one(p).await.unwrap());
    assert_eq!(contact.map(msp_console::db::ts).as_deref(), Some("2025-10-27T08:00:00.500Z"), "NinjaOne's epoch seconds, the same time on either store");
    let links: Vec<(i64, Option<i64>, Option<String>)> = on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT org_id, halo_client_id, halo_matched_by FROM client ORDER BY org_id").fetch_all(p).await.unwrap());
    assert_eq!(links, vec![(7, Some(100), Some("ninjarmm_id".into())), (8, None, None), (9, Some(300), Some("name".into()))],
               "two Halo clients claim org 8: not confirmed, and no name is its; org 9's name matches, a suggestion");
    let (sites,): (Value,) = on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT website_sites FROM halo_client WHERE halo_client_id = 100").fetch_one(p).await.unwrap());
    assert_eq!(sites, json!([{ "url": "http://www.alphadental.example/", "hostname": "www.alphadental.example", "apex": "alphadental.example" }]));
    let kev: (Option<chrono::NaiveDate>, bool) = on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT date_added, ransomware FROM sec_kev WHERE cve_id = 'CVE-2026-0001'").fetch_one(p).await.unwrap());
    assert_eq!(kev, (chrono::NaiveDate::from_ymd_opt(2026, 10, 1), true));

    let secrets = ["ninja-secret-value", "halo-secret-value", "nvd-key-value", "ninja-bearer", "halo-bearer"];
    if db.backend == Backend::Postgres {
        // No secret in any table: every row of every table, as text. The scan reads real data: the client's name is there.
        let tables: Vec<String> = on_pool!(&db.pool, p, _ => sqlx::query_scalar("SELECT table_name::text FROM information_schema.tables WHERE table_schema = current_schema() ORDER BY 1").fetch_all(p).await.unwrap());
        assert!(tables.len() >= 14, "{tables:?}");
        let mut all = String::new();
        for t in &tables {
            let rows: Option<String> = on_pool!(&db.pool, p, _ => sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT string_agg(row_to_json(t)::text, ' ') FROM \"{t}\" t"))).fetch_one(p).await.unwrap());
            all.push_str(&rows.unwrap_or_default());
        }
        assert!(all.contains("Alpha Dental"));
        for secret in secrets { assert!(!all.contains(secret), "{secret} stored in the database"); }
        return;
    }

    // The backup ran with the rest, and no secret is anywhere on the volume: the database, its WAL, or the copy.
    let backup = status.as_array().unwrap().iter().find(|j| j["job"] == "backup").unwrap().clone();
    assert!(!backup["last_ok_at"].is_null() && backup["detail"]["bytes"].as_u64().unwrap() > 0, "{backup}");
    let mut files = vec![db.sqlite().path.clone(), db.sqlite().path.with_extension("db-wal")];
    files.extend(std::fs::read_dir(db.sqlite().backup_dir()).unwrap().map(|e| e.unwrap().path()));
    assert_eq!(files.len(), 3, "{files:?}");
    let has = |b: &[u8], s: &str| b.windows(s.len()).any(|w| w == s.as_bytes());
    let read: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
    // The scan reads real data: the client's name is in the live store (file or WAL) and in the copy.
    assert!(has(&[read[0].clone(), read[1].clone()].concat(), "Alpha Dental") && has(&read[2], "Alpha Dental"));
    for (f, bytes) in files.iter().zip(&read) {
        for secret in secrets {
            assert!(!has(bytes, secret), "{secret} stored in {}", f.display());
        }
    }
}

async fn nothing_is_matched_or_deleted_before_the_inventory_exists_and_a_bad_answer_deletes_nothing(db: TestDb) {
    let o = msp_console::inventory::run(&db.pool).await.unwrap();
    assert_eq!(o.detail["skipped"], "no software inventory yet");
    // KEV answering almost nothing is a broken answer, not a purge.
    for n in 1..=10 { on_pool!(&db.pool, p, _ => { sqlx::query("INSERT INTO sec_kev (cve_id) VALUES ($1)").bind(format!("CVE-2026-{n:04}")).execute(p).await.unwrap(); }); }
    let base = serve(Router::new().route("/kev.json", get(|| async { Json(json!({ "vulnerabilities": [{ "cveID": "CVE-2026-0001" }] })) }))).await;
    let e = msp_console::connectors::kev::Kev::new(&format!("{base}/kev.json"), msp_console::http_client()).sync(&db.pool).await.unwrap_err();
    assert!(e.contains("kept what we have"), "{e}");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_kev").await, 10);
}
