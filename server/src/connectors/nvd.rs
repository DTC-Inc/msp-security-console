//! NVD, per product (this slice): for each curated product, every CVE whose configurations name it, through the CVE
//! API 2.0 (`virtualMatchString`). After the first full read, only what changed since the last run (lastModStartDate,
//! NVD allows at most 120 days). NVD_API_KEY is optional: without it NVD allows 5 requests per 30 s, with it 50.
//! This is the console's NVD with NVD_FEEDS=curated; with full (the default), the yearly feeds replace it (nvd_feed.rs).

use super::{send_json, Backoff, Limiter};
use crate::connectors::ninja::{db, urlenc};
use crate::matching::{cvss_of, nvd_all_ranges, severity_of};
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Map, Value};
use crate::db::{self as store, Pool};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE: usize = 2000;

#[derive(Clone)]
pub struct Nvd { pub url: String, key: Option<String>, http: reqwest::Client, limiter: Limiter }

impl std::fmt::Debug for Nvd { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("Nvd").field("url", &self.url).field("key", &self.key.is_some()).finish_non_exhaustive() } }

impl Nvd {
    pub fn new(url: &str, key: Option<String>, http: reqwest::Client) -> Self {
        let limiter = if key.is_some() { Limiter::new(50, Duration::from_secs(30)) } else { Limiter::new(5, Duration::from_secs(30)) };
        Self { url: url.trim_end_matches('/').into(), key, http, limiter }
    }

    async fn page(&self, query: &str) -> Result<Value, String> {
        let url = format!("{}?{query}", self.url);
        send_json(&self.limiter, Backoff { floor: Duration::from_secs(30), tries: 4 }, || {
            let r = self.http.get(&url);
            match &self.key { Some(k) => r.header("apiKey", k), None => r }
        }).await.map_err(|e| format!("NVD: {e}"))
    }

    /// One product's CVEs (all of them, or those modified since `since`), stored with every CPE they name.
    pub async fn sync_product(&self, pool: &Pool, cpe: &str, since: Option<&str>) -> Result<usize, String> {
        let window = match since {
            Some(s) => format!("&lastModStartDate={}&lastModEndDate={}", urlenc(s), urlenc(&chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())),
            None => String::new(),
        };
        let mut start = 0usize;
        let mut n = 0usize;
        loop {
            let j = self.page(&format!("virtualMatchString={}&resultsPerPage={PAGE}&startIndex={start}{window}", urlenc(&format!("cpe:2.3:a:{cpe}")))).await?;
            let vulns = j.get("vulnerabilities").and_then(Value::as_array).cloned().unwrap_or_default();
            let mut cves = Vec::new();
            let mut cpes = Vec::new();
            for v in &vulns {
                let Some(c) = v.get("cve") else { continue };
                let Some(id) = c.get("id").and_then(Value::as_str) else { continue };
                let desc = c.get("descriptions").and_then(Value::as_array).and_then(|d| d.iter().find(|x| x.get("lang").and_then(Value::as_str) == Some("en")))
                    .and_then(|x| x.get("value")).and_then(Value::as_str).map(|s| s.chars().take(2000).collect::<String>());
                let when = |k: &str| c.get(k).and_then(Value::as_str).and_then(store::ts_text);
                cves.push(json!({ "cve_id": id, "cvss": cvss_of(c), "severity": severity_of(c), "published": when("published"),
                    "last_modified": when("lastModified"), "rejected": c.get("vulnStatus").and_then(Value::as_str) == Some("Rejected"), "description": desc }));
                for (key, ranges) in nvd_all_ranges(c) {
                    cpes.push(json!({ "cve_id": id, "cpe": key, "part": if key.starts_with("o:") { "o" } else { "a" }, "ranges": ranges }));
                }
            }
            let ids: Vec<String> = cves.iter().filter_map(|c| c["cve_id"].as_str().map(String::from)).collect();
            crate::on_pool!(pool, p, pg => {
                let mut tx = p.begin().await.map_err(db)?;
                sqlx::query(if pg {
                    "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, published, last_modified, rejected, description)
                     SELECT x.cve_id, x.cvss, x.severity, x.published, x.last_modified, x.rejected, x.description
                       FROM jsonb_to_recordset($1) AS x(cve_id text, cvss double precision, severity text, published timestamptz, last_modified timestamptz, rejected boolean, description text)
                     ON CONFLICT (cve_id) DO UPDATE SET cvss = excluded.cvss, severity = excluded.severity, published = excluded.published,
                       last_modified = excluded.last_modified, rejected = excluded.rejected, description = excluded.description"
                } else {
                    "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, published, last_modified, rejected, description)
                     SELECT x.value ->> 'cve_id', x.value ->> 'cvss', x.value ->> 'severity', x.value ->> 'published', x.value ->> 'last_modified',
                            x.value ->> 'rejected', x.value ->> 'description'
                       FROM json_each($1) AS x WHERE true
                     ON CONFLICT (cve_id) DO UPDATE SET cvss = excluded.cvss, severity = excluded.severity, published = excluded.published,
                       last_modified = excluded.last_modified, rejected = excluded.rejected, description = excluded.description"
                }).bind(Value::Array(cves.clone())).execute(&mut *tx).await.map_err(db)?;
                sqlx::query(if pg { "DELETE FROM sec_nvd_cpe WHERE cve_id = ANY($1)" } else { "DELETE FROM sec_nvd_cpe WHERE cve_id IN (SELECT value FROM json_each($1))" })
                    .bind(store::list(&ids)).execute(&mut *tx).await.map_err(db)?;
                sqlx::query(if pg {
                    "INSERT INTO sec_nvd_cpe (cve_id, cpe, part, ranges)
                     SELECT x.cve_id, x.cpe, x.part, x.ranges FROM jsonb_to_recordset($1) AS x(cve_id text, cpe text, part text, ranges jsonb)
                     ON CONFLICT (cve_id, cpe) DO UPDATE SET ranges = excluded.ranges, part = excluded.part"
                } else {
                    "INSERT INTO sec_nvd_cpe (cve_id, cpe, part, ranges)
                     SELECT x.value ->> 'cve_id', x.value ->> 'cpe', x.value ->> 'part', x.value -> 'ranges' FROM json_each($1) AS x WHERE true
                     ON CONFLICT (cve_id, cpe) DO UPDATE SET ranges = excluded.ranges, part = excluded.part"
                }).bind(Value::Array(cpes.clone())).execute(&mut *tx).await.map_err(db)?;
                tx.commit().await.map_err(db)?;
            });
            n += vulns.len();
            let total = j.get("totalResults").and_then(Value::as_u64).unwrap_or(0) as usize;
            start += vulns.len();
            if vulns.is_empty() || start >= total { break; }
        }
        Ok(n)
    }

    /// Every active product. The cursor keeps, per product, when it was last read: a product read within NVD's
    /// 120-day window is read incrementally; one never read, or read too long ago, is read whole.
    pub async fn sync(&self, pool: &Pool, cursor: Option<Value>) -> Result<Outcome, String> {
        let products: Vec<(String, String)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT product_key, cpe FROM sec_product WHERE active AND source = 'curated' ORDER BY sort_order").fetch_all(p).await).map_err(db)?;
        let mut last: Map<String, Value> = cursor.and_then(|c| c.as_object().cloned()).unwrap_or_default();
        let now = chrono::Utc::now();
        let (mut read, mut cves) = (0usize, 0usize);
        for (key, cpe) in &products {
            let since = last.get(key).and_then(Value::as_str)
                .filter(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok_and(|t| (now - t.with_timezone(&chrono::Utc)).num_days() < 115))
                .map(String::from);
            cves += self.sync_product(pool, cpe, since.as_deref()).await?;
            last.insert(key.clone(), json!(now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()));
            read += 1;
        }
        Ok(Outcome { detail: json!({ "products": read, "cves_read": cves }), cursor: Some(Value::Object(last)) })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        vec![Job { name: crate::ops::NVD_CURATED_JOB, every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, cur| { let n = self.clone(); Box::pin(async move { n.sync(&pool, cur).await }) }) }]
    }
}

