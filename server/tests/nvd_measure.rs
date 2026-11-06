//! The first load of the whole of NVD, measured against NVD itself ("measure and document the time and size of the
//! first load"). Not run by default: it downloads about 400 MB from nvd.nist.gov. Run it on purpose, in release (the
//! image's build), with a scratch SQLite file:
//!
//!     NVD_MEASURE_DB=/tmp/nvd-measure.db cargo test --release --locked --test nvd_measure -- --ignored --nocapture
//!
//! It prints each feed's time and size, the store's size, and the process's peak memory. docs/design.md has the numbers.
mod common;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "downloads the whole of NVD"]
async fn the_first_full_nvd_load_measured() {
    let path = std::path::PathBuf::from(std::env::var("NVD_MEASURE_DB").expect("NVD_MEASURE_DB, a scratch file to load into"));
    let cfg = msp_console::db::DbConfig::Sqlite(msp_console::db::SqliteConfig { path: path.clone(), backup_keep: 1 });
    let pool = msp_console::db::connect(&cfg).await.unwrap();
    let mut feed = msp_console::connectors::nvd_feed::NvdFeed::new(msp_console::connectors::nvd_feed::DEFAULT_URL, msp_console::http_client());
    feed.budget = std::time::Duration::from_secs(4 * 3600);
    let t0 = std::time::Instant::now();
    let o = feed.sync(&pool).await.unwrap();
    let secs = t0.elapsed().as_secs();
    let size = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    msp_console::on_pool!(&pool, p, _ => { sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(p).await.unwrap(); });
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage writes into the struct it's given.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let peak = if cfg!(target_os = "macos") { u.ru_maxrss as u64 } else { u.ru_maxrss as u64 * 1024 };
    println!("{}", serde_json::json!({ "seconds": secs, "store_mb": size(&path) / 1_000_000, "peak_rss_mb": peak >> 20, "detail": o.detail }));
}
