//! The whole NVD dataset, from NVD's JSON 2.0 feeds, kept current: NVD_FEEDS=full (the default; curated turns it off), and then the console
//! compares every installed program and running binary with all of NVD, not only the curated products.
//!
//!   {NVD_FEED_URL}/nvdcve-2.0-<YYYY>.json.gz    every CVE with that id year (2002 to now: about 25 files, ~400 MB
//!                                               gzipped, ~3 GB of JSON)
//!   {NVD_FEED_URL}/nvdcve-2.0-modified.json.gz  everything changed in the last 8 days
//!   ... and a .meta beside each: lastModifiedDate, gzSize, and the SHA-256 of the UNCOMPRESSED JSON.
//!
//! **Memory stays bounded.** Nothing is parsed whole: the download is fed through a gzip decoder 4 KB at a time, and a
//! small splitter (FeedReader) hands over one CVE object at a time, tracking strings and escapes so braces inside a
//! description don't count. What it holds at once is one network chunk's worth of decoded text and the CVE it's in.
//! The test streams a feed larger than the Kubernetes base's 512 MiB and checks what the reader held.
//!
//! **Nothing half-written.** A feed streams into the staging tables (nvd_stage_cve, nvd_stage_cpe) in small
//! transactions, so no other write waits on a download. Only once the download is whole (the .meta's gzSize, the
//! gzip trailer's CRC, the .meta's SHA-256 of the JSON) is it swapped into sec_nvd_cve and sec_nvd_cpe, in one
//! transaction. A corrupt, short or tampered download is refused, and what was there stays.
//!
//! **Guards:** a year whose CVE count falls below half of what's stored is refused; a stored copy newer
//! than the feed's (applied from the modified feed since the yearly file was built) is kept; a CVE a yearly file no
//! longer lists is removed only when it's no newer than the file. A dropped download resumes with a Range request.
//!
//! **Order.** Never-loaded years first, then the oldest-loaded. A year is read again when the modified chain has a gap
//! (the modified feed not applied for 7 days, so changes could have been missed), and weekly as a safety net. A run
//! starts no new year after 15 minutes, and the next run (hourly) carries on, so a first load spreads over a few runs
//! while the other jobs get their turns. The modified feed is applied after any year loads, and at least every 12
//! hours.

use crate::connectors::ninja::db;
use crate::db::{self as store, Pool};
use crate::matching::{cvss_of, nvd_all_ranges, severity_of};
use crate::scheduler::{Job, Outcome};
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
pub const FIRST_YEAR: i32 = 2002;
/// The modified feed covers 8 days; a gap longer than this re-reads every year.
pub const MODIFIED_WINDOW_DAYS: i64 = 7;
pub const RESEED_DAYS: i64 = 7;
/// The modified feed is applied at least this often.
pub const MODIFIED_EVERY: Duration = Duration::from_secs(12 * 3600);
pub const MIN_KEEP: f64 = 0.5;
pub const MAX_RESUMES: usize = 6;
/// No new year starts after this; the next run carries on.
pub const BUDGET: Duration = Duration::from_secs(15 * 60);
/// CVEs per staging transaction.
const CHUNK: usize = 500;
/// Compressed bytes fed to the decoder at once, its CVEs taken before the next: what the reader holds is about this,
/// decoded (NVD's feeds compress about 12 to 1; the memory test's made-up one, far more).
const FEED_STEP: usize = 4 * 1024;

// ---------------------------------------------------------------- the reader

/// The CVE objects of a feed's top-level "vulnerabilities" array, one at a time, from its JSON text as it arrives.
/// Every byte also goes into the SHA-256 the .meta is checked against. Never holds more than the CVE it's in and the
/// CVEs completed in the text written since the last `next`.
#[derive(Default)]
pub struct FeedReader {
    state: u8, // 0 seeking the array, 1 in it, 2 done
    seek: Vec<u8>,
    depth: u32,
    in_str: bool,
    esc: bool,
    cur: Vec<u8>,
    done: VecDeque<Vec<u8>>,
    queued: usize,
    hasher: Sha256,
    /// Bytes of JSON seen.
    pub bytes: u64,
    /// The most this reader held at once (the CVE in progress and the ones not yet taken): the memory bound, measured.
    pub high_water: usize,
}

impl std::io::Write for FeedReader {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.feed(buf); Ok(buf.len()) }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl FeedReader {
    pub fn new() -> Self { Self::default() }

    pub fn feed(&mut self, buf: &[u8]) {
        self.hasher.update(buf);
        self.bytes += buf.len() as u64;
        let mut i = 0;
        if self.state == 0 {
            self.seek.extend_from_slice(buf);
            let key = b"\"vulnerabilities\"";
            let Some(k) = find(&self.seek, key) else {
                if self.seek.len() > 4096 { let keep = self.seek.split_off(self.seek.len() - 64); self.seek = keep; }
                return;
            };
            let Some(b) = self.seek[k..].iter().position(|c| *c == b'[') else { return };
            // Where the array starts within `buf`: the seek buffer ends with buf.
            let start_in_seek = k + b + 1;
            let before = self.seek.len() - buf.len();
            if start_in_seek < before {
                // The '[' was in an earlier write: replay the rest of the seek buffer.
                let rest = self.seek[start_in_seek..].to_vec();
                self.seek.clear();
                self.state = 1;
                self.scan(&rest);
                return;
            }
            i = start_in_seek - before;
            self.seek.clear();
            self.state = 1;
        }
        if self.state == 1 { let tail = &buf[i..]; self.scan_owned(tail); }
    }

    fn scan(&mut self, s: &[u8]) { self.scan_owned(s) }

    fn scan_owned(&mut self, s: &[u8]) {
        let mut start: Option<usize> = if self.depth > 0 { Some(0) } else { None };
        let mut j = 0;
        while j < s.len() {
            let c = s[j];
            if self.in_str {
                // Inside a string: skip to the next quote or backslash.
                if self.esc { self.esc = false; j += 1; continue; }
                match s[j..].iter().position(|b| *b == b'"' || *b == b'\\') {
                    None => { j = s.len(); continue; }
                    Some(p) => { j += p; if s[j] == b'\\' { self.esc = true; } else { self.in_str = false; } j += 1; continue; }
                }
            }
            match c {
                b'"' if self.depth > 0 => self.in_str = true,
                b'{' => { if self.depth == 0 { start = Some(j); self.cur.clear(); } self.depth += 1; }
                b'}' if self.depth > 0 => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        self.cur.extend_from_slice(&s[start.unwrap_or(0)..=j]);
                        let item = std::mem::take(&mut self.cur);
                        self.queued += item.len();
                        self.done.push_back(item);
                        start = None;
                    }
                }
                b']' if self.depth == 0 => { self.state = 2; break; }
                _ => {}
            }
            j += 1;
        }
        if self.state == 1 && self.depth > 0 { self.cur.extend_from_slice(&s[start.unwrap_or(0)..]); }
        self.high_water = self.high_water.max(self.cur.len() + self.queued);
    }

    /// The next whole CVE object, as JSON text.
    pub fn take(&mut self) -> Option<Vec<u8>> { let x = self.done.pop_front()?; self.queued -= x.len(); Some(x) }

    /// Whether the array was seen to its end.
    pub fn complete(&self) -> bool { self.state == 2 }

    /// The SHA-256 of every byte written, lower-case hex.
    pub fn sha256(&self) -> String { self.hasher.clone().finalize().iter().map(|b| format!("{b:02x}")).collect() }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> { h.windows(n.len()).position(|w| w == n) }

// ---------------------------------------------------------------- rows

/// One CVE's row and its product rows, as stored. None for a record that isn't a CVE.
pub fn rows_for(item: &Value) -> Option<(Value, Vec<Value>)> {
    let c = item.get("cve")?;
    let id = c.get("id").and_then(Value::as_str)?;
    let year: i32 = id.strip_prefix("CVE-")?.split('-').next()?.parse().ok()?;
    if !id.split('-').nth(2).is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) { return None; }
    let desc = c.get("descriptions").and_then(Value::as_array).and_then(|d| d.iter().find(|x| x.get("lang").and_then(Value::as_str) == Some("en")))
        .and_then(|x| x.get("value")).and_then(Value::as_str).map(|s| s.chars().take(2000).collect::<String>()).filter(|s| !s.is_empty());
    let when = |k: &str| c.get(k).and_then(Value::as_str).and_then(store::ts_text);
    let rejected = c.get("vulnStatus").and_then(Value::as_str).is_some_and(|s| s.eq_ignore_ascii_case("rejected"));
    let cve = json!({ "cve_id": id, "year": year, "cvss": cvss_of(c), "severity": severity_of(c), "published": when("published"), "last_modified": when("lastModified"),
                      "rejected": rejected, "description": desc });
    let cpes = if rejected { vec![] } else {
        nvd_all_ranges(c).into_iter().map(|(key, ranges)| json!({ "cve_id": id, "cpe": key, "part": if key.starts_with("o:") { "o" } else { "a" }, "ranges": ranges })).collect()
    };
    Some((cve, cpes))
}

/// A feed's .meta: when NVD built it, its gzip size, and the SHA-256 of the JSON inside.
#[derive(Debug, Clone, PartialEq)]
pub struct Meta { pub last_modified: Option<String>, pub sha256: Option<String>, pub gz_size: Option<u64> }
pub fn parse_meta(text: &str) -> Meta {
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix(':')).map(|v| v.trim().to_string()));
    Meta { last_modified: get("lastModifiedDate"), sha256: get("sha256").map(|s| s.to_lowercase()), gz_size: get("gzSize").and_then(|s| s.parse().ok()) }
}

/// Which years to (re)load this run, oldest-loaded first: never loaded, a gap in the modified chain, or due weekly.
pub fn years_to_load(now: chrono::DateTime<chrono::Utc>, loaded: &BTreeMap<String, chrono::DateTime<chrono::Utc>>, modified_at: Option<chrono::DateTime<chrono::Utc>>, all: bool) -> Vec<i32> {
    use chrono::Datelike;
    let gap = modified_at.is_none_or(|m| now - m > chrono::Duration::days(MODIFIED_WINDOW_DAYS));
    let mut due: Vec<i32> = (FIRST_YEAR..=now.year()).filter(|y| {
        let at = loaded.get(&y.to_string());
        all || gap || at.is_none_or(|t| now - *t > chrono::Duration::days(RESEED_DAYS))
    }).collect();
    due.sort_by_key(|y| (loaded.get(&y.to_string()).map(|t| t.timestamp_millis()).unwrap_or(0), *y));
    due
}

// ---------------------------------------------------------------- the connector

#[derive(Clone)]
pub struct NvdFeed { pub url: String, http: reqwest::Client, pub budget: Duration }

impl std::fmt::Debug for NvdFeed { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("NvdFeed").field("url", &self.url).finish_non_exhaustive() } }

/// What one feed held.
#[derive(Debug, Clone, Default)]
pub struct Loaded { pub cves: usize, pub cpe_rows: usize, pub applied: i64, pub kept_newer: i64, pub removed: i64, pub resumes: usize, pub bytes: u64, pub gz_bytes: u64, pub high_water: usize }

impl NvdFeed {
    pub fn new(url: &str, http: reqwest::Client) -> Self { Self { url: url.trim_end_matches('/').into(), http, budget: BUDGET } }

    fn file(&self, name: &str, ext: &str) -> String { format!("{}/nvdcve-2.0-{name}.{ext}", self.url) }

    async fn meta(&self, name: &str) -> Result<Meta, String> {
        let r = self.http.get(self.file(name, "meta")).header(reqwest::header::ACCEPT_ENCODING, "identity").timeout(Duration::from_secs(60)).send().await
            .map_err(|e| if e.is_timeout() { "timed out".to_string() } else { "unreachable".to_string() })?;
        if !r.status().is_success() { return Err(format!("{name}.meta: HTTP {}", r.status().as_u16())); }
        let m = parse_meta(&r.text().await.map_err(|_| format!("{name}.meta was cut off"))?);
        if m.sha256.is_none() { return Err(format!("{name}.meta has no sha256")); }
        if m.gz_size.is_none() { return Err(format!("{name}.meta has no gzSize")); }
        Ok(m)
    }

    /// Download one feed, check it against its .meta, and hand over its CVEs `CHUNK` at a time. Returns the reader's
    /// measurements; an error means the feed is refused, whatever was handed over.
    pub async fn stream<F, Fut>(&self, name: &str, mut sink: F) -> Result<(Meta, Loaded), String>
    where F: FnMut(Vec<Value>, Vec<Value>) -> Fut, Fut: std::future::Future<Output = Result<(), String>> {
        let meta = self.meta(name).await?;
        let expected = meta.gz_size.unwrap_or(0);
        let mut dec = flate2::write::GzDecoder::new(FeedReader::new());
        let (mut got, mut resumes, mut first) = (0u64, 0usize, true);
        let (mut cves, mut cpes): (Vec<Value>, Vec<Value>) = (Vec::new(), Vec::new());
        let mut n = Loaded::default();
        loop {
            let mut req = self.http.get(self.file(name, "json.gz")).header(reqwest::header::ACCEPT_ENCODING, "identity").timeout(Duration::from_secs(30 * 60));
            if got > 0 { req = req.header(reqwest::header::RANGE, format!("bytes={got}-")); }
            let mut r = req.send().await.map_err(|e| if e.is_timeout() { format!("{name}: timed out") } else { format!("{name}: unreachable") })?;
            let st = r.status();
            if got == 0 && !st.is_success() { return Err(format!("{name}.json.gz: HTTP {}", st.as_u16())); }
            if got > 0 && st != StatusCode::PARTIAL_CONTENT { return Err(format!("{name}.json.gz: resuming at {got} answered HTTP {}", st.as_u16())); }
            // The bytes on the wire must be the .gz file itself: a server that gzips it again (Content-Encoding) would
            // make sizes, ranges and the hash stop lining up.
            if r.headers().get(reqwest::header::CONTENT_ENCODING).is_some_and(|v| v.as_bytes() != b"identity") {
                return Err(format!("{name}.json.gz: the server applied a Content-Encoding although identity was asked for"));
            }
            let mut why = "ended early";
            loop {
                let chunk = match tokio::time::timeout(Duration::from_secs(120), r.chunk()).await {
                    Err(_) => { why = "stalled"; break; }
                    Ok(Err(_)) => { why = "the connection dropped"; break; }
                    Ok(Ok(None)) => break,
                    Ok(Ok(Some(c))) => c,
                };
                if first && !chunk.is_empty() {
                    if chunk.len() < 2 || chunk[0] != 0x1f || chunk[1] != 0x8b { return Err(format!("{name}.json.gz: the body isn't a gzip file")); }
                    first = false;
                }
                got += chunk.len() as u64;
                if got > expected { return Err(format!("{name}.json.gz: more bytes than the .meta's gzSize ({expected})")); }
                for piece in chunk.chunks(FEED_STEP) {
                    dec.write_all(piece).map_err(|_| format!("{name}.json.gz: not a gzip stream that decodes"))?;
                    while let Some(item) = dec.get_mut().take() {
                        let Ok(v) = serde_json::from_slice::<Value>(&item) else { return Err(format!("{name}: a CVE record isn't JSON")) };
                        let Some((c, p)) = rows_for(&v) else { continue };
                        n.cpe_rows += p.len(); n.cves += 1;
                        cves.push(c); cpes.extend(p);
                        if cves.len() >= CHUNK { sink(std::mem::take(&mut cves), std::mem::take(&mut cpes)).await?; }
                    }
                }
            }
            if got == expected { break; }
            resumes += 1;
            if resumes > MAX_RESUMES { return Err(format!("{name}.json.gz: stopped at {got} of {expected} bytes after {MAX_RESUMES} resumes ({why})")); }
            println!("{}", json!({ "msg": "an NVD download stopped part-way; resuming", "feed": name, "at": got, "of": expected, "why": why }));
        }
        dec.try_finish().map_err(|_| format!("{name}.json.gz: the gzip stream is truncated or corrupt"))?;
        let reader = dec.finish().map_err(|_| format!("{name}.json.gz: the gzip stream is truncated or corrupt"))?;
        let mut tail = reader;
        while let Some(item) = tail.take() {
            if let Ok(v) = serde_json::from_slice::<Value>(&item) && let Some((c, p)) = rows_for(&v) { n.cpe_rows += p.len(); n.cves += 1; cves.push(c); cpes.extend(p); }
        }
        if !cves.is_empty() { sink(cves, cpes).await?; }
        if !tail.complete() { return Err(format!("{name}: the vulnerabilities array never ended")); }
        let sha = tail.sha256();
        if Some(&sha) != meta.sha256.as_ref() { return Err(format!("{name}: its SHA-256 doesn't match the .meta's (changed mid-download?)")); }
        n.resumes = resumes; n.bytes = tail.bytes; n.gz_bytes = got; n.high_water = tail.high_water;
        Ok((meta, n))
    }

    /// Load one feed: `year` for a yearly file (its guards apply), None for the modified feed.
    pub async fn load(&self, pool: &Pool, name: &str, year: Option<i32>) -> Result<Loaded, String> {
        clear_stage(pool).await?;
        let r = self.stream(name, |cves, cpes| { let pool = pool.clone(); async move {
            let cves: Vec<Value> = match year { Some(y) => cves.into_iter().filter(|c| c["year"].as_i64() == Some(y as i64)).collect(), None => cves };
            let ids: std::collections::HashSet<&str> = cves.iter().filter_map(|c| c["cve_id"].as_str()).collect();
            let cpes: Vec<Value> = cpes.into_iter().filter(|p| p["cve_id"].as_str().is_some_and(|i| ids.contains(i))).collect();
            stage(&pool, &cves, &cpes).await
        } }).await;
        let (meta, mut n) = match r { Ok(x) => x, Err(e) => { let _ = clear_stage(pool).await; return Err(e); } };
        let r = swap(pool, name, year, &meta, &mut n).await;
        let _ = clear_stage(pool).await;
        r.map(|_| n)
    }

    pub async fn sync(&self, pool: &Pool) -> Result<Outcome, String> {
        let t0 = Instant::now();
        let rows: Vec<(String, chrono::DateTime<chrono::Utc>)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT feed, loaded_at FROM sec_nvd_feed").fetch_all(p).await).map_err(db)?;
        let loaded: BTreeMap<String, chrono::DateTime<chrono::Utc>> = rows.into_iter().collect();
        let now = chrono::Utc::now();
        let modified_at = loaded.get("modified").copied();
        let years = years_to_load(now, &loaded, modified_at, false);
        let (mut done, mut deferred, mut failed): (Vec<Value>, usize, Vec<String>) = (vec![], 0, vec![]);
        // Each year's time and size, for the start log and the first load's measurement.
        for y in years {
            // At least one year a run, so a seed always moves forward.
            if (!done.is_empty() || !failed.is_empty()) && t0.elapsed() > self.budget { deferred += 1; continue; }
            let t = Instant::now();
            // NVD's host drops connections; a second try usually completes. A refusal that kept the stored rows isn't retried.
            let mut r = self.load(pool, &y.to_string(), Some(y)).await;
            if let Err(e) = &r && !e.contains("kept what's stored") { r = self.load(pool, &y.to_string(), Some(y)).await; }
            match r {
                Ok(n) => {
                    let row = json!({ "year": y, "cves": n.cves, "removed": n.removed, "seconds": t.elapsed().as_secs(), "mb": n.bytes / 1_000_000, "gz_mb": n.gz_bytes / 1_000_000 });
                    println!("{}", json!({ "msg": "an NVD feed loaded", "feed": row }));
                    done.push(row);
                }
                Err(e) => failed.push(e),
            }
        }
        let mut modified = Value::Null;
        if !done.is_empty() || modified_at.is_none_or(|m| (now - m).to_std().unwrap_or_default() > MODIFIED_EVERY) {
            let mut r = self.load(pool, "modified", None).await;
            if r.is_err() { r = self.load(pool, "modified", None).await; }
            match r { Ok(n) => modified = json!({ "applied": n.applied, "kept_newer": n.kept_newer }), Err(e) => failed.push(e) }
        }
        let (cves, cpe_rows, years_loaded): (i64, i64, i64) = crate::on_pool!(pool, p, pg => sqlx::query_as(if pg {
            "SELECT (SELECT count(*) FROM sec_nvd_cve), (SELECT count(*) FROM sec_nvd_cpe), (SELECT count(*) FROM sec_nvd_feed WHERE feed ~ '^[0-9]{4}$')"
        } else {
            "SELECT (SELECT count(*) FROM sec_nvd_cve), (SELECT count(*) FROM sec_nvd_cpe), (SELECT count(*) FROM sec_nvd_feed WHERE feed GLOB '[0-9][0-9][0-9][0-9]')"
        }).fetch_one(p).await).map_err(db)?;
        let detail = json!({ "years_loaded_now": done.len(), "deferred": deferred, "failed": failed.len(), "modified": modified,
            "cves": cves, "cpe_rows": cpe_rows, "years_loaded": years_loaded, "seconds": t0.elapsed().as_secs(),
            "years": done.into_iter().filter(|y| y["cves"].as_u64() > Some(0)).collect::<Vec<_>>() });
        if !failed.is_empty() { return Err(format!("{} feed(s) failed: {}", failed.len(), failed.join("; ")).chars().take(300).collect()); }
        Ok(Outcome { detail, cursor: None })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        vec![Job { name: crate::ops::NVD_FULL_JOB, every: Duration::from_secs(3600), run: Arc::new(move |pool, _| { let n = self.clone(); Box::pin(async move { n.sync(&pool).await }) }) }]
    }
}

async fn clear_stage(pool: &Pool) -> Result<(), String> {
    crate::on_pool!(pool, p, _ => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM nvd_stage_cpe").execute(&mut *tx).await.map_err(db)?;
        sqlx::query("DELETE FROM nvd_stage_cve").execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

/// One chunk of a feed into the staging tables, in its own short transaction.
async fn stage(pool: &Pool, cves: &[Value], cpes: &[Value]) -> Result<(), String> {
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        if !cves.is_empty() {
            sqlx::query(if pg {
                "INSERT INTO nvd_stage_cve (cve_id, cvss, severity, published, last_modified, rejected, description)
                 SELECT x.cve_id, x.cvss, x.severity, x.published, x.last_modified, x.rejected, x.description
                   FROM jsonb_to_recordset($1) AS x(cve_id text, cvss double precision, severity text, published timestamptz, last_modified timestamptz, rejected boolean, description text)
                 ON CONFLICT (cve_id) DO UPDATE SET cvss = excluded.cvss, severity = excluded.severity, published = excluded.published, last_modified = excluded.last_modified,
                   rejected = excluded.rejected, description = excluded.description"
            } else {
                "INSERT INTO nvd_stage_cve (cve_id, cvss, severity, published, last_modified, rejected, description)
                 SELECT x.value ->> 'cve_id', x.value ->> 'cvss', x.value ->> 'severity', x.value ->> 'published', x.value ->> 'last_modified', x.value ->> 'rejected', x.value ->> 'description'
                   FROM json_each($1) AS x WHERE true
                 ON CONFLICT (cve_id) DO UPDATE SET cvss = excluded.cvss, severity = excluded.severity, published = excluded.published, last_modified = excluded.last_modified,
                   rejected = excluded.rejected, description = excluded.description"
            }).bind(Value::Array(cves.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        for c in cpes.chunks(5000) {
            sqlx::query(if pg {
                "INSERT INTO nvd_stage_cpe (cve_id, cpe, part, ranges) SELECT x.cve_id, x.cpe, x.part, x.ranges FROM jsonb_to_recordset($1) AS x(cve_id text, cpe text, part text, ranges jsonb)
                 ON CONFLICT (cve_id, cpe) DO UPDATE SET ranges = excluded.ranges, part = excluded.part"
            } else {
                "INSERT INTO nvd_stage_cpe (cve_id, cpe, part, ranges) SELECT x.value ->> 'cve_id', x.value ->> 'cpe', x.value ->> 'part', x.value -> 'ranges' FROM json_each($1) AS x WHERE true
                 ON CONFLICT (cve_id, cpe) DO UPDATE SET ranges = excluded.ranges, part = excluded.part"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

/// The staged feed into the store, in one transaction, under the guards.
async fn swap(pool: &Pool, name: &str, year: Option<i32>, meta: &Meta, n: &mut Loaded) -> Result<(), String> {
    let file_at = meta.last_modified.as_deref().and_then(store::ts_text).and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok()).map(|t| store::Ts(t.with_timezone(&chrono::Utc)));
    // The year's CVEs by their id's prefix (LIKE, not a range: PostgreSQL's default collation ignores punctuation).
    let like = match year { Some(y) => format!("CVE-{y}-%"), None => String::new() };
    crate::on_pool!(pool, p, pg => {
        // It reads before it writes, so on SQLite it takes the write lock at its start (db/sqlite.rs).
        let mut tx = p.begin_with(if pg { "BEGIN" } else { "BEGIN IMMEDIATE" }).await.map_err(db)?;
        let (fresh,): (i64,) = sqlx::query_as("SELECT count(*) FROM nvd_stage_cve").fetch_one(&mut *tx).await.map_err(db)?;
        if year.is_some() {
            let (stored,): (i64,) = sqlx::query_as("SELECT count(*) FROM sec_nvd_cve WHERE cve_id LIKE $1").bind(&like).fetch_one(&mut *tx).await.map_err(db)?;
            if stored >= 100 && (fresh as f64) < stored as f64 * MIN_KEEP {
                return Err(format!("{name}: the feed has {fresh} CVEs against {stored} stored (below {}%); kept what's stored", (MIN_KEEP * 100.0) as i64));
            }
            // CVEs of this year the file no longer lists are gone from NVD, but only those no newer than the file: a CVE
            // published or changed after the file was built (applied from the modified feed) is simply not in it yet.
            if let Some(at) = file_at {
                sqlx::query("DELETE FROM sec_nvd_cpe WHERE cve_id IN (SELECT c.cve_id FROM sec_nvd_cve c WHERE c.cve_id LIKE $1
                               AND NOT EXISTS (SELECT 1 FROM nvd_stage_cve s WHERE s.cve_id = c.cve_id) AND (c.last_modified IS NULL OR c.last_modified <= $2))")
                    .bind(&like).bind(at).execute(&mut *tx).await.map_err(db)?;
                n.removed = sqlx::query("DELETE FROM sec_nvd_cve WHERE cve_id LIKE $1
                               AND NOT EXISTS (SELECT 1 FROM nvd_stage_cve s WHERE s.cve_id = sec_nvd_cve.cve_id) AND (last_modified IS NULL OR last_modified <= $2)")
                    .bind(&like).bind(at).execute(&mut *tx).await.map_err(db)?.rows_affected() as i64;
            }
        }
        // A stored copy newer than the feed's wins.
        n.kept_newer = sqlx::query("DELETE FROM nvd_stage_cve WHERE EXISTS (SELECT 1 FROM sec_nvd_cve c WHERE c.cve_id = nvd_stage_cve.cve_id AND c.last_modified > nvd_stage_cve.last_modified)")
            .execute(&mut *tx).await.map_err(db)?.rows_affected() as i64;
        sqlx::query("DELETE FROM nvd_stage_cpe WHERE NOT EXISTS (SELECT 1 FROM nvd_stage_cve s WHERE s.cve_id = nvd_stage_cpe.cve_id)").execute(&mut *tx).await.map_err(db)?;
        sqlx::query("DELETE FROM sec_nvd_cpe WHERE cve_id IN (SELECT cve_id FROM nvd_stage_cve)").execute(&mut *tx).await.map_err(db)?;
        n.applied = sqlx::query(
            "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, published, last_modified, rejected, description)
             SELECT cve_id, cvss, severity, published, last_modified, rejected, description FROM nvd_stage_cve WHERE true
             ON CONFLICT (cve_id) DO UPDATE SET cvss = excluded.cvss, severity = excluded.severity, published = excluded.published,
               last_modified = excluded.last_modified, rejected = excluded.rejected, description = excluded.description")
            .execute(&mut *tx).await.map_err(db)?.rows_affected() as i64;
        sqlx::query("INSERT INTO sec_nvd_cpe (cve_id, cpe, part, ranges) SELECT cve_id, cpe, part, ranges FROM nvd_stage_cpe WHERE true
                     ON CONFLICT (cve_id, cpe) DO UPDATE SET ranges = excluded.ranges, part = excluded.part").execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO sec_nvd_feed (feed, sha256, feed_modified, loaded_at, cves, cpe_rows) VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (feed) DO UPDATE SET sha256 = excluded.sha256, feed_modified = excluded.feed_modified, loaded_at = excluded.loaded_at,
                       cves = excluded.cves, cpe_rows = excluded.cpe_rows")
            .bind(name).bind(meta.sha256.as_deref()).bind(file_at).bind(store::now()).bind(n.cves as i64).bind(n.cpe_rows as i64).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}
