//! CISA's Known Exploited Vulnerabilities catalog, the whole of it, daily. Public; no credentials.

use super::{send_json, Backoff, Limiter};
use crate::connectors::ninja::db;
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Value};
use crate::db::Pool;
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Clone)]
pub struct Kev { pub url: String, http: reqwest::Client, limiter: Limiter }

impl Kev {
    pub fn new(url: &str, http: reqwest::Client) -> Self { Self { url: url.into(), http, limiter: Limiter::new(2, Duration::from_secs(1)) } }

    pub async fn sync(&self, pool: &Pool) -> Result<Outcome, String> {
        let j = send_json(&self.limiter, Backoff { floor: Duration::from_secs(10), tries: 3 }, || self.http.get(&self.url)).await.map_err(|e| format!("CISA KEV: {e}"))?;
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::trim).filter(|x| !x.is_empty()).map(String::from);
        // A date is kept only when it's one (YYYY-MM-DD); anything else is NULL, on either store.
        let date = |v: &Value, k: &str| s(v, k).and_then(|d| chrono::NaiveDate::parse_from_str(d.get(..10)?, "%Y-%m-%d").ok()).map(|d| d.to_string());
        let rows: Vec<Value> = j.get("vulnerabilities").and_then(Value::as_array).into_iter().flatten().filter_map(|v| {
            let id = s(v, "cveID")?.to_uppercase();
            Some(json!({ "cve_id": id, "vendor": s(v, "vendorProject"), "product": s(v, "product"), "name": s(v, "vulnerabilityName"),
                "date_added": date(v, "dateAdded"), "due_date": date(v, "dueDate"), "ransomware": s(v, "knownRansomwareCampaignUse").as_deref() == Some("Known"),
                "description": s(v, "shortDescription") }))
        }).collect();
        let (held,): (i64,) = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT count(*) FROM sec_kev").fetch_one(p).await).map_err(db)?;
        // The catalog only grows; an answer with fewer than half the rows we hold is a broken answer, not a purge.
        if rows.is_empty() || (rows.len() as i64) * 2 < held { return Err(format!("CISA KEV answered {} entries (we hold {held}); kept what we have", rows.len())); }
        crate::on_pool!(pool, p, pg => {
            let mut tx = p.begin().await.map_err(db)?;
            sqlx::query("DELETE FROM sec_kev").execute(&mut *tx).await.map_err(db)?;
            sqlx::query(if pg {
                "INSERT INTO sec_kev (cve_id, vendor, product, name, date_added, due_date, ransomware, description)
                 SELECT x.cve_id, x.vendor, x.product, x.name, x.date_added, x.due_date, x.ransomware, x.description
                   FROM jsonb_to_recordset($1) AS x(cve_id text, vendor text, product text, name text, date_added date, due_date date, ransomware boolean, description text)
                 ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO sec_kev (cve_id, vendor, product, name, date_added, due_date, ransomware, description)
                 SELECT x.value ->> 'cve_id', x.value ->> 'vendor', x.value ->> 'product', x.value ->> 'name', date(x.value ->> 'date_added'),
                        date(x.value ->> 'due_date'), x.value ->> 'ransomware', x.value ->> 'description'
                   FROM json_each($1) AS x WHERE true ON CONFLICT DO NOTHING"
            }).bind(Value::Array(rows.clone())).execute(&mut *tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
        });
        Ok(Outcome { detail: json!({ "entries": rows.len() }), cursor: None })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        vec![Job { name: "kev", every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, _| { let k = self.clone(); Box::pin(async move { k.sync(&pool).await }) }) }]
    }
}
