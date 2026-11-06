//! HaloPSA: clients, each one's NinjaOne link (`ninjarmmid`) and its websites, from the installing MSP's own Halo.
//! Read-only. Halo's limit (700 per rolling 5 minutes) is the WHOLE tenant's, shared with every other integration, so
//! this connector takes only HALO_REQUESTS_PER_5MIN of it (default 150), waits a full minute after a 429, and reads at
//! most HALO_DETAIL_BUDGET client details a run (never-read first, then the stalest). The Halo-to-NinjaOne
//! mapping follows the console's rule for every vendor's clients: Halo's own link confirms, a name only suggests.

use super::{send_json, Backoff, Limiter, Token, TokenCache};
use crate::connectors::ninja::db;
use crate::scheduler::{Job, Outcome};
use crate::website;
use serde_json::{json, Value};
use crate::db::{self as store, Pool};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The limiter for one Halo account (its address and API client) in this process, made on first use with that
/// connector's share of the budget. Every Halo built for the same account takes the same one.
pub fn shared_limiter(base: &str, client_id: &str, per_5min: usize) -> Limiter {
    static ALL: std::sync::OnceLock<std::sync::Mutex<HashMap<(String, String), Limiter>>> = std::sync::OnceLock::new();
    let mut m = ALL.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    m.entry((base.to_string(), client_id.to_string())).or_insert_with(|| Limiter::new(per_5min, Duration::from_secs(300))).clone()
}

#[derive(Clone)]
pub struct Halo {
    pub base: String, auth_url: String, client_id: String, client_secret: String, tenant: Option<String>,
    http: reqwest::Client, pub limiter: Limiter, pub backoff: Backoff, pub detail_budget: usize, token: TokenCache,
    /// How long a write (a ticket) waits for Halo's answer: 60 s; a test shortens it.
    pub write_timeout: Duration,
}

impl std::fmt::Debug for Halo { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("Halo").field("base", &self.base).finish_non_exhaustive() } }

pub struct HaloSettings { pub base: String, pub auth_url: Option<String>, pub client_id: String, pub client_secret: String, pub tenant: Option<String>, pub per_5min: usize, pub detail_budget: usize }

impl Halo {
    pub fn new(s: HaloSettings, http: reqwest::Client) -> Self {
        let base = s.base.trim_end_matches('/').to_string();
        let auth_url = s.auth_url.unwrap_or_else(|| format!("{}/auth/token", base.trim_end_matches("/api")));
        // One limiter per Halo account in this process: the clients job's reads and a ticket's write share Halo's budget.
        let limiter = shared_limiter(&base, &s.client_id, s.per_5min);
        Self { base, auth_url, client_id: s.client_id, client_secret: s.client_secret, tenant: s.tenant, http,
               limiter, backoff: Backoff { floor: Duration::from_secs(60), tries: 3 },
               detail_budget: s.detail_budget, token: Default::default(), write_timeout: Duration::from_secs(60) }
    }

    pub fn limiter_window(&self) -> Duration { self.limiter.window() }

    async fn bearer(&self, fresh: bool) -> Result<String, String> {
        let mut t = self.token.lock().await;
        if !fresh && let Some(tok) = t.as_ref() && tok.until > Instant::now() { return Ok(tok.value.clone()); }
        let mut form = vec![("grant_type", "client_credentials".to_string()), ("client_id", self.client_id.clone()), ("client_secret", self.client_secret.clone()), ("scope", "all".to_string())];
        if let Some(tn) = &self.tenant { form.push(("tenant", tn.clone())); }
        let j = send_json(&self.limiter, self.backoff, || self.http.post(&self.auth_url).header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(serde_urlencoded::to_string(&form).unwrap_or_default())).await.map_err(|e| format!("Halo sign-in: {e}"))?;
        let value = j.get("access_token").and_then(Value::as_str).ok_or("Halo sign-in: no access token")?.to_string();
        let secs = j.get("expires_in").and_then(Value::as_u64).unwrap_or(3600);
        *t = Some(Token { value: value.clone(), until: Instant::now() + Duration::from_secs(secs.saturating_sub(60)) });
        Ok(value)
    }

    pub async fn get(&self, path_and_query: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base, path_and_query);
        for fresh in [false, true] {
            let tok = self.bearer(fresh).await?;
            match send_json(&self.limiter, self.backoff, || self.http.get(&url).bearer_auth(&tok)).await {
                Err(e) if e.starts_with("HTTP 401") && !fresh => continue,
                other => return other.map_err(|e| format!("Halo: {e}")),
            }
        }
        unreachable!()
    }

    /// One POST (a write: a ticket), through the same limiter as every read. Sent once, never retried on a 429 or a
    /// 503, so a write can't land twice; a 401 re-mints the token and tries again, since Halo refused it unread. The
    /// error is the status, never Halo's text (which can echo what it was sent) or the URL.
    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base, path);
        for fresh in [false, true] {
            let tok = self.bearer(fresh).await?;
            self.limiter.acquire().await;
            // Unreachable is a connection Halo never took, so nothing was sent; a timeout or a dropped connection came
            // after the request went, so Halo may have acted on it (src/ops/tickets.rs keeps that claim as unknown).
            let r = self.http.post(&url).bearer_auth(&tok).json(body).timeout(self.write_timeout).send().await
                .map_err(|e| if e.is_timeout() { "Halo: timed out".to_string() } else if e.is_connect() { "Halo: unreachable".to_string() } else { "Halo: the connection dropped".to_string() })?;
            let st = r.status();
            if st.as_u16() == 401 && !fresh { continue; }
            if st.is_redirection() { return Err(format!("Halo: HTTP {}: the address redirected; set the final address", st.as_u16())); }
            if !st.is_success() { return Err(format!("Halo: HTTP {}{}", st.as_u16(), st.canonical_reason().map(|x| format!(" {x}")).unwrap_or_default())); }
            return r.json::<Value>().await.map_err(|_| "Halo: the answer isn't JSON".to_string());
        }
        unreachable!()
    }

    pub async fn sync_clients(&self, pool: &Pool) -> Result<Outcome, String> {
        let mut clients: Vec<(i64, String)> = Vec::new();
        for page in 1..=1000 {
            let j = self.get(&format!("/Client?pageinate=true&page_size=100&page_no={page}&includeinactive=false")).await?;
            let rows = j.get("clients").and_then(Value::as_array).cloned().unwrap_or_default();
            clients.extend(rows.iter().filter_map(|c| Some((c.get("id")?.as_i64()?, c.get("name")?.as_str()?.trim().to_string()))));
            if rows.len() < 100 { break; }
        }
        // Details: never-read first, then the stalest, within the budget.
        let stored: Vec<(i64, Option<chrono::DateTime<chrono::Utc>>)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT halo_client_id, checked_at FROM halo_client").fetch_all(p).await).map_err(db)?;
        let checked: HashMap<i64, Option<chrono::DateTime<chrono::Utc>>> = stored.into_iter().collect();
        let mut order: Vec<&(i64, String)> = clients.iter().collect();
        order.sort_by_key(|(id, _)| checked.get(id).copied().flatten().map(|t| t.timestamp()).unwrap_or(i64::MIN));
        let mut details: Vec<Value> = Vec::new();
        let mut failed = 0usize;
        for (id, _) in order.into_iter().take(self.detail_budget) {
            match self.get(&format!("/Client/{id}")).await {
                Ok(d) if d.is_object() => {
                    let link = d.get("ninjarmmid").and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).filter(|v| *v > 0);
                    let sites = website::parse(d.get("website").and_then(Value::as_str), d.get("domain").and_then(Value::as_str));
                    details.push(json!({ "id": id, "link": link, "sites": sites }));
                }
                Ok(_) => failed += 1,
                Err(e) if e.contains("HTTP 401") || e.contains("HTTP 403") => return Err(e),
                Err(_) => failed += 1,
            }
        }
        if !details.is_empty() && failed * 5 > details.len() + failed { return Err(format!("{failed} Halo client details failed; nothing written")); }
        let now = store::now();
        let named = json!(clients.iter().map(|(id, n)| json!({ "id": id, "name": n, "name_key": store::name_key(n) })).collect::<Vec<_>>());
        crate::on_pool!(pool, p, pg => {
            let mut tx = p.begin().await.map_err(db)?;
            sqlx::query(if pg {
                "INSERT INTO halo_client (halo_client_id, name, name_key, seen_at, deleted_at)
                 SELECT x.id, x.name, x.name_key, $2, NULL FROM jsonb_to_recordset($1) AS x(id bigint, name text, name_key text)
                 ON CONFLICT (halo_client_id) DO UPDATE SET name = excluded.name, name_key = excluded.name_key, seen_at = excluded.seen_at, deleted_at = NULL"
            } else {
                "INSERT INTO halo_client (halo_client_id, name, name_key, seen_at, deleted_at)
                 SELECT x.value ->> 'id', x.value ->> 'name', x.value ->> 'name_key', $2, NULL FROM json_each($1) AS x WHERE true
                 ON CONFLICT (halo_client_id) DO UPDATE SET name = excluded.name, name_key = excluded.name_key, seen_at = excluded.seen_at, deleted_at = NULL"
            }).bind(&named).bind(now).execute(&mut *tx).await.map_err(db)?;
            sqlx::query(if pg {
                "UPDATE halo_client SET ninjarmm_org_id = x.link, website_sites = x.sites, checked_at = $2
                   FROM jsonb_to_recordset($1) AS x(id bigint, link bigint, sites jsonb) WHERE halo_client.halo_client_id = x.id"
            } else {
                "UPDATE halo_client SET ninjarmm_org_id = x.value ->> 'link', website_sites = x.value -> 'sites', checked_at = $2
                   FROM json_each($1) AS x WHERE halo_client.halo_client_id = x.value ->> 'id'"
            }).bind(Value::Array(details.clone())).bind(now).execute(&mut *tx).await.map_err(db)?;
            if !clients.is_empty() {
                let ids: Vec<i64> = clients.iter().map(|c| c.0).collect();
                let (held,): (i64,) = sqlx::query_as("SELECT count(*) FROM halo_client WHERE deleted_at IS NULL").fetch_one(&mut *tx).await.map_err(db)?;
                if ids.len() as i64 * 2 >= held {
                    sqlx::query(if pg { "UPDATE halo_client SET deleted_at = $2 WHERE deleted_at IS NULL AND NOT (halo_client_id = ANY($1))" }
                                else { "UPDATE halo_client SET deleted_at = $2 WHERE deleted_at IS NULL AND halo_client_id NOT IN (SELECT value FROM json_each($1))" })
                        .bind(store::list(&ids)).bind(now).execute(&mut *tx).await.map_err(db)?;
                }
            }
            // The mapping rule: an organization that exactly one Halo client links to is confirmed; else a normalised-name match is
            // a suggestion; else nothing. Recomputed whole each run, so a link that went away doesn't linger. The same
            // SQL on both stores.
            sqlx::query("UPDATE client SET halo_client_id = NULL, halo_matched_by = NULL").execute(&mut *tx).await.map_err(db)?;
            sqlx::query("UPDATE client SET halo_client_id = l.hid, halo_matched_by = 'ninjarmm_id'
                           FROM (SELECT ninjarmm_org_id AS org, min(halo_client_id) AS hid FROM halo_client WHERE deleted_at IS NULL AND ninjarmm_org_id IS NOT NULL
                                  GROUP BY ninjarmm_org_id HAVING count(*) = 1) AS l WHERE client.org_id = l.org").execute(&mut *tx).await.map_err(db)?;
            // The names were reduced to name_key when they were stored (db::name_key), so both stores compare the same
            // text. Two Halo clients with the same key both match, as before; the lowest id wins, the same one every run.
            sqlx::query("UPDATE client SET halo_client_id = h.hid, halo_matched_by = 'name'
                           FROM (SELECT name_key, min(halo_client_id) AS hid FROM halo_client WHERE deleted_at IS NULL GROUP BY name_key) AS h
                          WHERE client.halo_client_id IS NULL AND h.name_key = client.name_key").execute(&mut *tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
        });
        Ok(Outcome { detail: json!({ "halo_clients": clients.len(), "details_read": details.len(), "details_failed": failed }), cursor: None })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        vec![Job { name: "halo_clients", every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, _| { let h = self.clone(); Box::pin(async move { h.sync_clients(&pool).await }) }) }]
    }
}
