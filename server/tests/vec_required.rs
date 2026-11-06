//! Without sqlite-vec the store refuses to open, before any migration runs. Its own test binary (its own process) on
//! purpose: the extension is registered process-wide by db::connect, and nothing here calls it, so these connections
//! are the ones a build without the extension would make.
use msp_console::db;

#[tokio::test]
async fn the_store_refuses_to_open_without_the_vector_extension_and_migrates_nothing() {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    let dir = std::env::temp_dir().join(format!("msp-console-novec-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = db::SqliteConfig { path: dir.join("console.db"), backup_keep: 7 };
    let e = db::open(&cfg).await.unwrap_err();
    assert!(e.contains("sqlite-vec") && e.contains("refus"), "{e}");
    // Nothing was migrated: a half-built store is worse than none.
    let raw = sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&cfg.path)).await.unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM sqlite_schema").fetch_one(&raw).await.unwrap();
    assert_eq!(n, 0, "no tables, not even _sqlx_migrations");
    raw.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}
