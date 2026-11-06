//! The full NVD seed in bounded memory: a feed whose JSON is larger than the Kubernetes
//! base's 512 MiB limit streams through the reader, and what it holds stays one network chunk's worth and the CVE in
//! progress. Its own test file, so the process's peak memory is this test's alone. The feed is made up and made here:
//! a few thousand synthetic CVEs with long descriptions, compressed as they're written, so nothing holds it whole on
//! this side either.
mod common;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::*;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::Arc;

const TARGET: usize = 560 * 1024 * 1024;

fn peak_rss() -> u64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage writes into the struct it's given.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let v = u.ru_maxrss as u64;
    if cfg!(target_os = "macos") { v } else { v * 1024 }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_feed_larger_than_the_memory_limit_streams_in_bounded_memory() {
    // The feed: its gzip and the SHA-256 of its JSON, made in one pass.
    let filler = "x".repeat(256 * 1024);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut sha = Sha256::new();
    let mut put = |s: &[u8], gz: &mut flate2::write::GzEncoder<Vec<u8>>| { sha.update(s); gz.write_all(s).unwrap(); };
    put(br#"{"resultsPerPage":0,"format":"NVD_CVE","version":"2.0","vulnerabilities":["#, &mut gz);
    let (mut written, mut n) = (0usize, 0usize);
    while written < TARGET {
        let item = format!(r#"{}{{"cve":{{"id":"CVE-2026-{}","lastModified":"2026-01-01T00:00:00.000","descriptions":[{{"lang":"en","value":"{{ [ {filler} ] }}"}}]}}}}"#, if n > 0 { "," } else { "" }, 100000 + n);
        put(item.as_bytes(), &mut gz);
        written += item.len(); n += 1;
    }
    put(b"]}", &mut gz);
    let body = Arc::new(gz.finish().unwrap());
    let sha: String = sha.finalize().iter().map(|b| format!("{b:02X}")).collect();
    let meta = format!("lastModifiedDate:2026-11-06T03:00:00-05:00\r\ngzSize:{}\r\nsha256:{sha}\r\n", body.len());
    let r = Router::new()
        .route("/feeds/nvdcve-2.0-2026.meta", get(move || { let m = meta.clone(); async move { m } }))
        .route("/feeds/nvdcve-2.0-2026.json.gz", get(|State(b): State<Arc<Vec<u8>>>| async move { b.as_ref().clone().into_response() }))
        .with_state(body.clone());
    let base = serve(r).await;
    let before = peak_rss();
    let feed = msp_console::connectors::nvd_feed::NvdFeed::new(&format!("{base}/feeds"), msp_console::http_client());
    let mut seen = 0usize;
    let (_, l) = feed.stream("2026", |cves, _| { seen += cves.len(); async { Ok(()) } }).await.unwrap();
    assert!(l.bytes as usize > 512 * 1024 * 1024, "the feed is larger than the limit: {} bytes", l.bytes);
    assert_eq!((l.cves, seen), (n, n), "every CVE was handed over");
    // What the reader held at once: about one decoded network chunk and the CVE in progress, never the feed.
    assert!(l.high_water < 8 * 1024 * 1024, "the reader held {} bytes at once", l.high_water);
    let grew = peak_rss().saturating_sub(before);
    assert!(peak_rss() < 512 * 1024 * 1024, "the process's peak was {} MiB", peak_rss() >> 20);
    println!("streamed {} MiB of JSON ({} CVEs, {} KiB gzipped); the reader held at most {} KiB; peak memory grew {} MiB while streaming",
             l.bytes >> 20, n, body.len() >> 10, l.high_water >> 10, grew >> 20);
}
