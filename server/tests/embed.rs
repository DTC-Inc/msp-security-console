//! The embedder and the `embed` job, on the real model through ONNX Runtime (src/embed.rs, src/embed_job.rs): no
//! stand-in. The model tests need the pinned files (scripts/fetch-model.sh fetches them once, outside the repo) and are
//! skipped LOUDLY without them, or fail under REQUIRE_MODEL (CI). The descriptions are made up, in NVD's style.
mod common;
use common::*;
use msp_console::embed::{self, Embedder, EmbedConfig, State, DIMS, MODEL_KEY};
use msp_console::embed_job::EmbedJob;
use msp_console::vectors;
use std::sync::Arc;
use std::time::Duration;

both!(
    the_job_embeds_what_has_a_description_once_and_nothing_twice,
    a_changed_description_is_embedded_again_and_a_rescored_one_is_not,
    a_rejected_or_emptied_cve_loses_its_vector,
    cancelling_a_run_mid_batch_leaves_whole_batches_or_nothing,
    the_job_runs_under_the_scheduler_and_reports_counts_on_status,
    a_description_that_fails_is_recorded_and_skipped_and_the_rest_are_embedded,
);

const V8_A: &str = "Type confusion in V8 in Google Chrome prior to 130.0.6723.91 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.";
const V8_B: &str = "Type Confusion in the V8 JavaScript engine in Google Chrome before 131.0.6778.69 let a remote attacker perform out of bounds memory access through a crafted HTML page.";
const CHROME_UI: &str = "Inappropriate implementation in the Downloads UI of Google Chrome prior to 128.0 allowed a remote attacker to spoof the contents of the address bar via a crafted HTML page.";
const OPENSSL: &str = "Issue summary: processing a maliciously formatted PKCS12 file may lead OpenSSL to crash, leading to a potential denial of service.";
const SQLI: &str = "An SQL injection vulnerability in the login form of the admin panel allows unauthenticated attackers to execute arbitrary SQL commands via the username parameter.";

fn dot(a: &[f32], b: &[f32]) -> f32 { a.iter().zip(b).map(|(x, y)| x * y).sum() }
fn dist(a: &[f32], b: &[f32]) -> f32 { 1.0 - dot(a, b) }

#[test]
fn the_pins_in_the_code_are_the_pins_the_fetch_script_downloads_by() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/fetch-model.sh")).unwrap();
    for (name, sha) in embed::FILES {
        assert!(script.lines().any(|l| l.starts_with(&format!("{name}|")) && l.ends_with(&format!("|{sha}"))), "{name} {sha} isn't the script's pin");
    }
    assert!(script.contains(embed::DEFAULT_DIR.rsplit('/').next().unwrap()), "the script's default cache is named for the model");
}

#[test]
fn vectors_are_384_long_unit_length_and_the_same_alone_or_among_others() {
    let Some(e) = embedder() else { return };
    let texts: Vec<String> = [V8_A, OPENSSL, "Windows Kernel Elevation of Privilege Vulnerability."].map(String::from).to_vec();
    let vs = e.embed_blocking(&texts).unwrap();
    assert_eq!(vs.len(), 3);
    for v in &vs {
        assert_eq!(v.len(), DIMS);
        let n = dot(v, v).sqrt();
        assert!((n - 1.0).abs() < 1e-5, "norm {n}");
    }
    // A vector is its own text's alone: the same embedded alone, again, or after other texts (the int8 model's
    // activation scale would move it inside a padded batch, which is why the embedder never batches).
    let alone = e.embed_blocking(&texts[2..]).unwrap();
    assert_eq!(alone[0], vs[2], "the same text, the same vector, whatever came before it");
    assert_eq!(e.embed_blocking(&texts[2..]).unwrap(), alone);
    // Nothing in, nothing out.
    assert!(e.embed_blocking(&[]).unwrap().is_empty());
}

#[test]
fn two_descriptions_of_one_v8_type_confusion_are_nearer_than_a_chrome_bug_and_an_openssl_bug() {
    let Some(e) = embedder() else { return };
    let v = e.embed_blocking(&[V8_A, V8_B, CHROME_UI, OPENSSL, SQLI].map(String::from)).unwrap();
    let (v8, chrome_openssl) = (dist(&v[0], &v[1]), dist(&v[2], &v[3]));
    assert!(v8 < chrome_openssl, "V8/V8 {v8} should be nearer than Chrome/OpenSSL {chrome_openssl}");
    // And each V8 description's nearest is the other one, not the other Chrome bug or anything else.
    for (i, j) in [(0, 1), (1, 0)] {
        let nearest = (0..v.len()).filter(|k| *k != i).min_by(|a, b| dist(&v[i], &v[*a]).total_cmp(&dist(&v[i], &v[*b]))).unwrap();
        assert_eq!(nearest, j, "nearest to {i}");
    }
    println!("cosine distance: V8/V8 {v8:.3}, Chrome/OpenSSL {chrome_openssl:.3}, V8/SQLi {:.3}", dist(&v[0], &v[4]));
}

#[test]
fn a_description_past_512_tokens_is_cut_not_refused() {
    let Some(e) = embedder() else { return };
    let long = format!("{V8_A} ").repeat(60);
    let v = e.embed_blocking(&[long]).unwrap();
    assert_eq!(v[0].len(), DIMS);
}

#[test]
fn a_giant_description_is_cut_to_16_kb_on_a_character_boundary_before_tokenising() {
    assert_eq!(embed::capped("short"), "short");
    // "é" is two bytes: 16 KB falls in the middle of one, and the cut steps back to the boundary before it.
    let s = format!("a{}", "é".repeat(10_000));
    let c = embed::capped(&s);
    assert!(c.len() <= embed::MAX_TEXT_BYTES && c.len() >= embed::MAX_TEXT_BYTES - 1 && s.starts_with(c), "{}", c.len());
    let Some(e) = embedder() else { return };
    // Past 512 tokens either way, so the cut changes nothing the model would have seen.
    let huge = format!("{V8_A} ").repeat(1000);
    assert!(huge.len() > 100_000);
    assert_eq!(e.embed_blocking(std::slice::from_ref(&huge)).unwrap(), e.embed_blocking(&[embed::capped(&huge).to_string()]).unwrap());
}

// ---------------------------------------------------------------- off, and why

#[tokio::test]
async fn off_by_setting_or_with_a_missing_or_wrong_model_the_console_still_serves_and_says_why() {
    let db = test_db().await;
    let off = |on: bool, dir: std::path::PathBuf| EmbedConfig { on, model_dir: dir, threads: 2 };
    let State::Off(why) = embed::start(&off(false, model_dir()), &db.pool).await else { panic!("EMBEDDER=off is off") };
    assert_eq!(why, embed::OFF_BY_SETTING);
    let missing = temp_dir("no-model");
    let State::Off(why) = embed::start(&off(true, missing.clone()), &db.pool).await else { panic!("no model is off") };
    assert!(why.starts_with("similar-CVE search is off: the embedding model didn't load") && why.contains("model.onnx can't be read") && why.contains("MODEL_DIR"), "{why}");
    // Files that are there but aren't the pinned ones are refused, before ONNX Runtime ever reads them.
    std::fs::write(missing.join("model.onnx"), b"not a model").unwrap();
    std::fs::write(missing.join("tokenizer.json"), b"{}").unwrap();
    let State::Off(why) = embed::start(&off(true, missing.clone()), &db.pool).await else { panic!("a wrong model is off") };
    assert!(why.contains("isn't the pinned bge-small-en-v1.5-int8 file"), "{why}");
    assert_eq!(State::Off(why.clone()).describe(), serde_json::json!({ "on": false, "model": MODEL_KEY, "why": why }));
    let _ = std::fs::remove_dir_all(&missing);
}

#[tokio::test]
async fn on_postgresql_without_pgvector_the_embedder_is_off_in_the_stores_own_words() {
    let Some(role) = pg_role_db(true).await else { return };
    let cfg = msp_console::db::DbConfig::Postgres(msp_console::db::PgConfig::new(&role.url, false).unwrap());
    let pool = msp_console::db::connect(&cfg).await.unwrap();
    // This role can't create the extension, so the database has none (tests/vectors.rs says why).
    let State::Off(why) = embed::start(&EmbedConfig::default(), &pool).await else { panic!("no pgvector, no embedder") };
    assert_eq!(why, vectors::EXTENSION_MISSING);
    pool.close().await;
}

// ---------------------------------------------------------------- the job, on both stores

fn job(e: Arc<Embedder>) -> EmbedJob { EmbedJob { embedder: e, batch: 2, budget: Duration::from_secs(600) } }

async fn seed(db: &TestDb) {
    nvd_cve(&db.pool, "CVE-2026-1001", Some(V8_A), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1002", Some(V8_B), "2026-10-02T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1003", Some(OPENSSL), "2026-10-03T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1004", Some(SQLI), "2026-10-04T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1005", Some("Rejected reason: this candidate was withdrawn by its CNA."), "2026-10-05T00:00:00.000Z", true).await;
    nvd_cve(&db.pool, "CVE-2026-1006", None, "2026-10-06T00:00:00.000Z", false).await;
}

/// Whether this store holds vectors; PostgreSQL without pgvector has nothing for the job to do.
async fn vectors_on(db: &TestDb) -> bool {
    if vectors::available(&db.pool).await.is_ok() { return true; }
    assert_eq!(db.backend, Backend::Postgres, "only PostgreSQL may lack vectors");
    eprintln!("this PostgreSQL server has no pgvector: the embed job doesn't run here");
    false
}

async fn counts(db: &TestDb) -> (i64, i64) {
    (count(&db.pool, "SELECT count(*) FROM vec_cve_description").await, count(&db.pool, "SELECT count(*) FROM cve_embedded").await)
}

async fn the_job_embeds_what_has_a_description_once_and_nothing_twice(db: TestDb) {
    let Some(e) = embedder() else { return };
    if !vectors_on(&db).await { return; }
    seed(&db).await;
    let o = job(e.clone()).run(&db.pool).await.unwrap();
    assert_eq!((o.detail["embedded"].as_u64(), o.detail["unchanged"].as_u64(), o.detail["remaining"].as_i64(), o.detail["model"].as_str()),
               (Some(4), Some(0), Some(0), Some(MODEL_KEY)), "{}", o.detail);
    assert_eq!(counts(&db).await, (4, 4), "the rejected CVE and the one without a description have no vector");
    // Similar to the first V8 type confusion: the other one first.
    let near = vectors::similar_cves(&db.pool, "CVE-2026-1001", MODEL_KEY, 3).await.unwrap();
    assert_eq!(near[0].0, "CVE-2026-1002", "{near:?}");
    assert!(near[0].1 < near[1].1, "{near:?}");
    // Idempotent: run again, nothing made, the vectors byte for byte the same.
    let before: Vec<(String, String)> = msp_console::on_pool!(&db.pool, p, pg => sqlx::query_as(if pg { "SELECT cve_id, embedding::text FROM vec_cve_description ORDER BY cve_id" }
        else { "SELECT cve_id, hex(embedding) FROM vec_cve_description ORDER BY cve_id" }).fetch_all(p).await.unwrap());
    let again = job(e).run(&db.pool).await.unwrap();
    assert_eq!((again.detail["embedded"].as_u64(), again.detail["unchanged"].as_u64(), again.detail["removed"].as_u64()), (Some(0), Some(0), Some(0)), "{}", again.detail);
    let after: Vec<(String, String)> = msp_console::on_pool!(&db.pool, p, pg => sqlx::query_as(if pg { "SELECT cve_id, embedding::text FROM vec_cve_description ORDER BY cve_id" }
        else { "SELECT cve_id, hex(embedding) FROM vec_cve_description ORDER BY cve_id" }).fetch_all(p).await.unwrap());
    assert_eq!(before, after);
}

async fn a_changed_description_is_embedded_again_and_a_rescored_one_is_not(db: TestDb) {
    let Some(e) = embedder() else { return };
    if !vectors_on(&db).await { return; }
    seed(&db).await;
    job(e.clone()).run(&db.pool).await.unwrap();
    // NVD rescored 1003 (lastModified moved, the words didn't), and rewrote 1004 as another V8 type confusion.
    nvd_cve(&db.pool, "CVE-2026-1003", Some(OPENSSL), "2026-11-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-1004", Some(V8_B), "2026-11-02T00:00:00.000Z", false).await;
    let o = job(e.clone()).run(&db.pool).await.unwrap();
    assert_eq!((o.detail["embedded"].as_u64(), o.detail["unchanged"].as_u64(), o.detail["remaining"].as_i64()), (Some(1), Some(1), Some(0)), "{}", o.detail);
    assert_eq!(counts(&db).await, (4, 4));
    let near = vectors::similar_cves(&db.pool, "CVE-2026-1004", MODEL_KEY, 1).await.unwrap();
    assert_eq!(near[0].0, "CVE-2026-1002", "its new words are what it's compared by: {near:?}");
    // The record moved with it: the next run has nothing to look at.
    let o = job(e).run(&db.pool).await.unwrap();
    assert_eq!((o.detail["embedded"].as_u64(), o.detail["unchanged"].as_u64()), (Some(0), Some(0)), "{}", o.detail);
}

async fn a_rejected_or_emptied_cve_loses_its_vector(db: TestDb) {
    let Some(e) = embedder() else { return };
    if !vectors_on(&db).await { return; }
    seed(&db).await;
    job(e.clone()).run(&db.pool).await.unwrap();
    nvd_cve(&db.pool, "CVE-2026-1003", Some("Rejected reason: a duplicate of another CVE."), "2026-11-01T00:00:00.000Z", true).await;
    nvd_cve(&db.pool, "CVE-2026-1004", None, "2026-11-01T00:00:00.000Z", false).await;
    let o = job(e).run(&db.pool).await.unwrap();
    assert_eq!((o.detail["removed"].as_u64(), o.detail["embedded"].as_u64()), (Some(2), Some(0)), "{}", o.detail);
    assert_eq!(counts(&db).await, (2, 2));
    let near = vectors::similar_cves(&db.pool, "CVE-2026-1001", MODEL_KEY, 5).await.unwrap();
    assert_eq!(near.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), ["CVE-2026-1002"]);
}

async fn cancelling_a_run_mid_batch_leaves_whole_batches_or_nothing(db: TestDb) {
    let Some(e) = embedder() else { return };
    if !vectors_on(&db).await { return; }
    // 24 descriptions, 4 to a batch: six batches, so a cancelled run has somewhere in the middle to stop.
    let words = [V8_A, V8_B, CHROME_UI, OPENSSL, SQLI, "Windows Kernel Elevation of Privilege Vulnerability."];
    for i in 0..24 { nvd_cve(&db.pool, &format!("CVE-2026-2{i:03}"), Some(&format!("{} (variant {i})", words[i % words.len()])), "2026-10-01T00:00:00.000Z", false).await; }
    let j = EmbedJob { embedder: e.clone(), batch: 4, budget: Duration::from_secs(600) };
    // After every cut: each vector has its record and each record its vector, in whole batches.
    let whole = |v: i64, r: i64, paired: i64| { assert_eq!((v, r, paired), (v, v, v), "a vector without its record, or the reverse"); assert_eq!(v % 4, 0, "{v} isn't whole batches of 4"); };
    let paired = "SELECT count(*) FROM cve_embedded r WHERE EXISTS (SELECT 1 FROM vec_cve_description v WHERE v.model = r.model AND v.cve_id = r.cve_id)";
    // Cut before the first batch lands: nothing at all.
    assert!(tokio::time::timeout(Duration::from_millis(1), j.run(&db.pool)).await.is_err(), "a run can't finish in a millisecond");
    let (v, r) = counts(&db).await;
    whole(v, r, count(&db.pool, paired).await);
    // Then, three times: a run that's cancelled (its future dropped, as the scheduler does when the lease is lost)
    // as soon as a batch has landed, so the cut falls in the next batch.
    let mut mid = 0;
    for _ in 0..3 {
        let (before, _) = counts(&db).await;
        let (pool, jj) = (db.pool.clone(), j.clone());
        let run = tokio::spawn(async move { jj.run(&pool).await });
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            if counts(&db).await.0 > before || run.is_finished() { break; }
        }
        run.abort();
        let _ = run.await;
        let (v, r) = counts(&db).await;
        whole(v, r, count(&db.pool, paired).await);
        if v > before && v < 24 { mid += 1; }
    }
    assert!(mid > 0, "no cut landed mid-run, so cancellation wasn't tested");
    // A clean run finishes what the cut ones left, and then there's nothing more to do.
    j.run(&db.pool).await.unwrap();
    assert_eq!(counts(&db).await, (24, 24));
    let o = j.run(&db.pool).await.unwrap();
    assert_eq!((o.detail["embedded"].as_u64(), o.detail["remaining"].as_i64()), (Some(0), Some(0)), "{}", o.detail);
}

/// One description that fails (a failure injected into the real embedder, in the middle of a batch) is recorded with
/// its class and skipped: the rest of its batch and the batches after it are embedded, the next run makes progress
/// rather than failing on it again, and it's tried again only when its description changes.
async fn a_description_that_fails_is_recorded_and_skipped_and_the_rest_are_embedded(db: TestDb) {
    if embedder().is_none() { return; }
    if !vectors_on(&db).await { return; }
    let e = Arc::new(Embedder::load(&model_dir(), 2).unwrap().fail_on("POISON"));
    let j = EmbedJob { embedder: e, batch: 3, budget: Duration::from_secs(600) };
    nvd_cve(&db.pool, "CVE-2026-3001", Some(V8_A), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-3002", Some("POISON: a description the embedder can't take."), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-3003", Some(OPENSSL), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-3004", Some(SQLI), "2026-10-01T00:00:00.000Z", false).await;
    nvd_cve(&db.pool, "CVE-2026-3005", Some(V8_B), "2026-10-01T00:00:00.000Z", false).await;
    let d = |o: &msp_console::scheduler::Outcome, k: &str| o.detail[k].as_i64().unwrap_or(-1);
    let o = j.run(&db.pool).await.expect("one bad description doesn't fail the run");
    assert_eq!((d(&o, "embedded"), d(&o, "failed"), d(&o, "failing"), d(&o, "remaining")), (4, 1, 1, 0), "{}", o.detail);
    assert_eq!(o.detail["failed_by_class"], serde_json::json!({ "injected": 1 }));
    assert_eq!(counts(&db).await, (4, 4));
    let rows: Vec<(String, String)> = msp_console::on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT cve_id, error_class FROM cve_embed_failed").fetch_all(p).await.unwrap());
    assert_eq!(rows, [("CVE-2026-3002".to_string(), "injected".to_string())], "its class, never its text");
    assert!(!vectors::has_cve(&db.pool, "CVE-2026-3002", MODEL_KEY).await.unwrap());
    // The next run doesn't try it again: nothing to do, nothing failed.
    let o = j.run(&db.pool).await.unwrap();
    assert_eq!((d(&o, "embedded"), d(&o, "failed"), d(&o, "failing")), (0, 0, 1), "{}", o.detail);
    // NVD touched it without changing the words: still not tried.
    nvd_cve(&db.pool, "CVE-2026-3002", Some("POISON: a description the embedder can't take."), "2026-11-01T00:00:00.000Z", false).await;
    let o = j.run(&db.pool).await.unwrap();
    assert_eq!((d(&o, "embedded"), d(&o, "failed"), d(&o, "unchanged"), d(&o, "remaining")), (0, 0, 1, 0), "{}", o.detail);
    // New words: tried again, embedded, and the failure is gone.
    nvd_cve(&db.pool, "CVE-2026-3002", Some(CHROME_UI), "2026-11-02T00:00:00.000Z", false).await;
    let o = j.run(&db.pool).await.unwrap();
    assert_eq!((d(&o, "embedded"), d(&o, "failed"), d(&o, "failing")), (1, 0, 0), "{}", o.detail);
    assert_eq!(counts(&db).await, (5, 5));
    // A CVE that had a vector and is rewritten into words that fail loses the old vector: it described other words.
    nvd_cve(&db.pool, "CVE-2026-3001", Some("POISON again."), "2026-11-03T00:00:00.000Z", false).await;
    let o = j.run(&db.pool).await.unwrap();
    assert_eq!((d(&o, "embedded"), d(&o, "failed"), d(&o, "failing")), (0, 1, 1), "{}", o.detail);
    assert_eq!(counts(&db).await, (4, 4));
    assert!(!vectors::has_cve(&db.pool, "CVE-2026-3001", MODEL_KEY).await.unwrap());
    // And a failed CVE NVD rejects is cleared like any other.
    nvd_cve(&db.pool, "CVE-2026-3001", Some("Rejected reason: withdrawn."), "2026-11-04T00:00:00.000Z", true).await;
    let o = j.run(&db.pool).await.unwrap();
    assert_eq!((d(&o, "removed"), d(&o, "failing")), (1, 0), "{}", o.detail);
}

async fn the_job_runs_under_the_scheduler_and_reports_counts_on_status(db: TestDb) {
    let Some(e) = embedder() else { return };
    if !vectors_on(&db).await { return; }
    seed(&db).await;
    let s = msp_console::scheduler::Scheduler::new(db.pool.clone(), EmbedJob::new(e).jobs());
    s.register().await.unwrap();
    assert!(s.run_if_due(&s.jobs[0]).await, "due at once, and claimed");
    assert!(!s.run_if_due(&s.jobs[0]).await, "not due again for two minutes");
    let status = msp_console::scheduler::status(&db.pool).await.unwrap();
    let j = &status[0];
    assert_eq!((j["job"].as_str(), j["last_error"].is_null(), j["detail"]["embedded"].as_u64(), j["detail"]["remaining"].as_i64()), (Some("embed"), true, Some(4), Some(0)), "{j}");
    // Counts only: never a description on /api/status.
    assert!(!j.to_string().contains("Chrome"), "{j}");
}
