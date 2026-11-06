//! Vector search on the store (sqlite-vec, statically linked, on SQLite; pgvector on PostgreSQL when the server has it):
//! its first use, "similar to this CVE" by the meaning of NVD's description. The vectors here are made up and small in
//! meaning (a few hot dimensions out of 384), so the right neighbours are known before the query runs. On a PostgreSQL
//! server without pgvector, the search is off and says so, and the store still works.
mod common;
use common::*;
use msp_console::on_pool;
use msp_console::vectors::{self, CVE_DIMS};

both!(
    similar_cves_come_back_nearest_first_without_the_cve_itself_or_another_models,
    putting_a_cve_again_replaces_its_vector,
    a_vector_of_the_wrong_size_or_not_a_number_is_refused,
    two_models_vectors_for_one_cve_coexist_and_each_answers_alone,
);

/// Whether this store does vector search; on PostgreSQL without pgvector, it must say it's off, and refuse.
async fn on(db: &TestDb) -> bool {
    match vectors::available(&db.pool).await {
        Ok(()) => true,
        Err(why) => {
            assert_eq!((db.backend, why.as_str()), (Backend::Postgres, vectors::EXTENSION_MISSING), "only PostgreSQL may lack it");
            let x = v(&[(0, 1.0)]);
            assert_eq!(vectors::put_cve(&db.pool, "CVE-2026-0001", M, &x).await.unwrap_err(), vectors::EXTENSION_MISSING);
            assert_eq!(vectors::similar_cves(&db.pool, "CVE-2026-0001", M, 3).await.unwrap_err(), vectors::EXTENSION_MISSING);
            false
        }
    }
}

/// A unit-ish vector with weight on the given dimensions and nothing elsewhere.
fn v(hot: &[(usize, f32)]) -> Vec<f32> {
    let mut x = vec![0.0f32; CVE_DIMS];
    for &(i, w) in hot { x[i] = w; }
    x
}
const M: &str = "test-model-384";

#[tokio::test]
async fn the_extension_is_in_every_connection() {
    let db = test_db().await;
    let mut seen = Vec::new();
    // More connections than the pool keeps idle, so this isn't one lucky connection.
    let msp_console::db::Pool::Sqlite(pool) = &db.pool else { unreachable!() };
    let mut held = Vec::new();
    for _ in 0..4 { held.push(pool.acquire().await.unwrap()); }
    for c in held.iter_mut() { seen.push(sqlx::query_scalar::<_, String>("SELECT vec_version()").fetch_one(&mut **c).await.unwrap()); }
    assert!(seen.iter().all(|s| s == "v0.1.9"), "{seen:?}");
    assert_eq!(msp_console::db::describe(&db.pool).await["vectors"], serde_json::json!({ "on": true }));
}

async fn similar_cves_come_back_nearest_first_without_the_cve_itself_or_another_models(db: TestDb) {
    if !on(&db).await { return; }
    // A: the one asked about. B nearly the same; C half-way; D unrelated. E would be nearest of all, but another model made it.
    for (id, model, x) in [
        ("CVE-2026-0001", M, v(&[(0, 1.0)])),
        ("CVE-2026-0002", M, v(&[(0, 1.0), (1, 0.1)])),
        ("CVE-2026-0003", M, v(&[(0, 1.0), (1, 1.0)])),
        ("CVE-2026-0004", M, v(&[(7, 1.0)])),
        ("CVE-2026-0005", "another-model-384", v(&[(0, 1.0)])),
    ] { vectors::put_cve(&db.pool, id, model, &x).await.unwrap(); }
    let got = vectors::similar_cves(&db.pool, "CVE-2026-0001", M, 10).await.unwrap();
    let ids: Vec<&str> = got.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"]);
    // Cosine distance: about 0.005 to B, about 0.29 to C, 1 to the orthogonal D.
    let d: Vec<f64> = got.iter().map(|(_, d)| *d).collect();
    assert!(d[0] < 0.01 && (0.28..0.30).contains(&d[1]) && (d[2] - 1.0).abs() < 1e-6, "{d:?}");
    // k is honoured.
    assert_eq!(vectors::similar_cves(&db.pool, "CVE-2026-0001", M, 1).await.unwrap().len(), 1);
    // A CVE with no vector has no neighbours, rather than an error.
    assert!(vectors::similar_cves(&db.pool, "CVE-2026-9999", M, 5).await.unwrap().is_empty());
}

async fn putting_a_cve_again_replaces_its_vector(db: TestDb) {
    if !on(&db).await { return; }
    vectors::put_cve(&db.pool, "CVE-2026-0001", M, &v(&[(0, 1.0)])).await.unwrap();
    vectors::put_cve(&db.pool, "CVE-2026-0002", M, &v(&[(0, 1.0)])).await.unwrap();
    vectors::put_cve(&db.pool, "CVE-2026-0003", M, &v(&[(5, 1.0)])).await.unwrap();
    // Its description changed upstream: B now means what C means.
    vectors::put_cve(&db.pool, "CVE-2026-0002", M, &v(&[(5, 1.0)])).await.unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM vec_cve_description").await, 3, "replaced, not added");
    let got = vectors::similar_cves(&db.pool, "CVE-2026-0003", M, 1).await.unwrap();
    assert_eq!(got[0].0, "CVE-2026-0002");
}

async fn a_vector_of_the_wrong_size_or_not_a_number_is_refused(db: TestDb) {
    // Refused before the store is asked, so on any store.
    let e = vectors::put_cve(&db.pool, "CVE-2026-0001", M, &[1.0; 383]).await.unwrap_err();
    assert!(e.contains("384"), "{e}");
    let mut x = v(&[(0, 1.0)]);
    x[3] = f32::NAN;
    assert!(vectors::put_cve(&db.pool, "CVE-2026-0001", M, &x).await.unwrap_err().contains("finite"));
    assert!(vectors::put_cve(&db.pool, "CVE-2026-0001", M, &v(&[])).await.unwrap_err().contains("zero"), "cosine of a zero vector means nothing");
}

#[tokio::test]
async fn the_daily_backup_carries_the_vectors() {
    let db = test_db().await;
    vectors::put_cve(&db.pool, "CVE-2026-0001", M, &v(&[(0, 1.0)])).await.unwrap();
    vectors::put_cve(&db.pool, "CVE-2026-0002", M, &v(&[(0, 1.0), (1, 0.2)])).await.unwrap();
    let dir = db.sqlite().backup_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let o = msp_console::backup::Backup { dir: dir.clone(), keep: 2 }.run(&db.pool).await.unwrap();
    let copy = msp_console::db::DbConfig::Sqlite(msp_console::db::SqliteConfig { path: dir.join(o.detail["file"].as_str().unwrap()), backup_keep: 2 });
    let restored = msp_console::db::connect(&copy).await.unwrap();
    let got = vectors::similar_cves(&restored, "CVE-2026-0001", M, 5).await.unwrap();
    assert_eq!(got.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), ["CVE-2026-0002"]);
}

async fn two_models_vectors_for_one_cve_coexist_and_each_answers_alone(db: TestDb) {
    if !on(&db).await { return; }
    // A reviewer's probe: 0001/a, 0002/a, then 0001/b. B's vector for 0001 must not replace A's.
    vectors::put_cve(&db.pool, "CVE-2026-0001", "model-a", &v(&[(0, 1.0)])).await.unwrap();
    vectors::put_cve(&db.pool, "CVE-2026-0002", "model-a", &v(&[(0, 1.0), (1, 0.1)])).await.unwrap();
    vectors::put_cve(&db.pool, "CVE-2026-0001", "model-b", &v(&[(9, 1.0)])).await.unwrap();
    let rows: Vec<(String, String)> = on_pool!(&db.pool, p, _ => sqlx::query_as("SELECT model, cve_id FROM vec_cve_description ORDER BY model, cve_id").fetch_all(p).await.unwrap());
    assert_eq!(rows, [("model-a".to_string(), "CVE-2026-0001".to_string()), ("model-a".into(), "CVE-2026-0002".into()), ("model-b".into(), "CVE-2026-0001".into())]);
    assert_eq!(vectors::similar_cves(&db.pool, "CVE-2026-0002", "model-a", 5).await.unwrap().iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(), ["CVE-2026-0001"]);
    // Model B has only 0001 so far, so no neighbours; its vector isn't compared with A's.
    assert!(vectors::similar_cves(&db.pool, "CVE-2026-0001", "model-b", 5).await.unwrap().is_empty());
    // Putting 0001/b again replaces B's row only.
    vectors::put_cve(&db.pool, "CVE-2026-0001", "model-b", &v(&[(8, 1.0)])).await.unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM vec_cve_description").await, 3);
}

/// On PostgreSQL: with pgvector, the migration made the table and the search is on; without it, the migrations still
/// ran whole, the search is off, and /api/status's store says why. And a database that gets pgvector after the console
/// first ran gets the table at the next start (msp_console_vectors()).
#[tokio::test]
async fn on_postgresql_vector_search_follows_pgvector_and_never_stops_the_store() {
    let Some(db) = test_db_on(Backend::Postgres).await else { return };
    assert_eq!(count(&db.pool, "SELECT count(*) FROM _sqlx_migrations WHERE success").await as usize, msp_console::db::postgres::MIGRATOR.iter().count(), "every migration ran, with or without pgvector");
    let status = msp_console::db::describe(&db.pool).await;
    if !pg_has_vector().await {
        eprintln!("this PostgreSQL server has no pgvector: the off path");
        assert_eq!(status["vectors"], serde_json::json!({ "on": false, "why": vectors::EXTENSION_MISSING }));
        assert!(!on(&db).await);
        return;
    }
    assert_eq!(status["vectors"], serde_json::json!({ "on": true }));
    let dims: i32 = on_pool!(&db.pool, p, _ => sqlx::query_scalar("SELECT atttypmod FROM pg_attribute WHERE attrelid = 'vec_cve_description'::regclass AND attname = 'embedding'").fetch_one(p).await.unwrap());
    assert_eq!(dims, 384);
    // As if pgvector arrived after the first start: no table, so the search is off and says so ...
    exec(&db.pool, "DROP TABLE vec_cve_description").await;
    assert_eq!(vectors::available(&db.pool).await.unwrap_err(), vectors::TABLE_MISSING, "the extension is there, the table isn't: said so");
    // ... and the next start makes it, and it works.
    let again = msp_console::db::connect(&db.cfg).await.unwrap();
    vectors::available(&again).await.unwrap();
    vectors::put_cve(&again, "CVE-2026-0001", M, &v(&[(0, 1.0)])).await.unwrap();
    vectors::put_cve(&again, "CVE-2026-0002", M, &v(&[(0, 1.0), (1, 1.0)])).await.unwrap();
    let got = vectors::similar_cves(&again, "CVE-2026-0001", M, 5).await.unwrap();
    assert!(got.len() == 1 && got[0].0 == "CVE-2026-0002" && (0.28..0.30).contains(&got[0].1), "{got:?}");
}

/// On PostgreSQL with pgvector, similar-CVE search is served by the HNSW index: the query orders by distance to a
/// constant (the CVE's own vector, fetched first), so on a table the size of a real catalogue the planner's own choice
/// is the index. And a model with few vectors among many still gets k answers (the filter can't starve the index's
/// candidates: hnsw.iterative_scan, hnsw.ef_search).
#[tokio::test]
async fn on_postgresql_similar_search_uses_the_index_and_a_small_model_still_gets_k() {
    let Some(db) = test_db_on(Backend::Postgres).await else { return };
    if !pg_has_vector().await { eprintln!("this PostgreSQL server has no pgvector: nothing to plan"); return; }
    let msp_console::db::Pool::Postgres(p) = &db.pool else { unreachable!() };
    // 10,000 vectors of one model (built without the index, then the index made once: quicker than 10,000 inserts
    // into it), 30 of another, and one of that other model that sits among the first model's vectors.
    exec(&db.pool, "DROP INDEX ix_vec_cve_description").await;
    exec(&db.pool, "INSERT INTO vec_cve_description (model, cve_id, embedding)
                    SELECT 'big', 'CVE-2026-' || lpad(g::text, 5, '0'), (SELECT array_agg((random() + i * 0 + g * 0)::float4) FROM generate_series(1, 384) i)::vector
                      FROM generate_series(1, 10000) g").await;
    exec(&db.pool, "INSERT INTO vec_cve_description (model, cve_id, embedding)
                    SELECT 'small', 'CVE-2027-' || lpad(g::text, 5, '0'), (SELECT array_agg((CASE WHEN i = 2 THEN 5.0 ELSE random() * 0.1 END + g * 0)::float4) FROM generate_series(1, 384) i)::vector
                      FROM generate_series(1, 30) g").await;
    exec(&db.pool, "INSERT INTO vec_cve_description (model, cve_id, embedding) SELECT 'small', 'CVE-2027-AMONG', embedding FROM vec_cve_description WHERE cve_id = 'CVE-2026-00001'").await;
    exec(&db.pool, "CREATE INDEX ix_vec_cve_description ON vec_cve_description USING hnsw (embedding vector_cosine_ops)").await;
    exec(&db.pool, "ANALYZE vec_cve_description").await;
    // The plan, for the search's own SQL with its own settings.
    let mine: String = sqlx::query_scalar("SELECT embedding::text FROM vec_cve_description WHERE cve_id = 'CVE-2026-00002'").fetch_one(p).await.unwrap();
    let mut tx = p.begin().await.unwrap();
    vectors::pg_search_settings(&mut tx, 10).await.unwrap();
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("EXPLAIN (COSTS OFF) {}", vectors::PG_SIMILAR)))
        .bind(&mine).bind("big").bind("CVE-2026-00002").bind(10i64).fetch_all(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(plan.iter().any(|l| l.contains("Index Scan using ix_vec_cve_description")), "{}", plan.join("\n"));
    // The answers: ten, nearest first, the CVE itself left out, only the model asked about.
    let got = vectors::similar_cves(&db.pool, "CVE-2026-00002", "big", 10).await.unwrap();
    assert!(got.len() == 10 && got.windows(2).all(|w| w[0].1 <= w[1].1) && got.iter().all(|(id, _)| id != "CVE-2026-00002" && id.starts_with("CVE-2026-")), "{got:?}");
    // The small model's CVE that sits among the big model's vectors: its nearest neighbours overall are all the other
    // model's, and it still gets ten of its own.
    let got = vectors::similar_cves(&db.pool, "CVE-2027-AMONG", "small", 10).await.unwrap();
    assert!(got.len() == 10 && got.iter().all(|(id, _)| id.starts_with("CVE-2027-") && id != "CVE-2027-AMONG"), "{got:?}");
}

/// The console's usual PostgreSQL role: not a superuser, the owner of its own database, and so unable to CREATE
/// EXTENSION vector (pgvector isn't a trusted extension; on a server without pgvector there's nothing to create).
/// 0003_vectors.sql's WHEN OTHERS branch takes it: every migration still runs, the store opens, and similar-CVE search
/// is off with the right reason.
#[tokio::test]
async fn as_a_role_that_cant_create_the_extension_the_store_opens_with_similar_search_off() {
    let Some(role) = pg_role_db(true).await else { return };
    let cfg = msp_console::db::DbConfig::Postgres(msp_console::db::PgConfig::new(&role.url, false).unwrap());
    let pool = msp_console::db::connect(&cfg).await.expect("the store opens without pgvector");
    let msp_console::db::Pool::Postgres(p) = &pool else { unreachable!() };
    let (superuser, can_create_ext): (bool, bool) = sqlx::query_as(
        "SELECT rolsuper, EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') FROM pg_roles WHERE rolname = current_user").fetch_one(p).await.unwrap();
    assert_eq!((superuser, can_create_ext), (false, false), "an ordinary role, and no extension was made");
    assert_eq!(count(&pool, "SELECT count(*) FROM _sqlx_migrations WHERE success").await as usize, msp_console::db::postgres::MIGRATOR.iter().count(), "every migration ran, the vectors one included");
    assert!(!sqlx::query_scalar::<_, bool>("SELECT msp_console_vectors()").fetch_one(p).await.unwrap(), "and the table waits for the extension");
    assert_eq!(vectors::available(&pool).await.unwrap_err(), vectors::EXTENSION_MISSING);
    assert_eq!(msp_console::db::describe(&pool).await["vectors"], serde_json::json!({ "on": false, "why": vectors::EXTENSION_MISSING }));
    // The rest of the store works: the scheduler's table, the seed.
    assert_eq!(count(&pool, "SELECT count(*) FROM sec_product").await, 22);
    pool.close().await;
}
