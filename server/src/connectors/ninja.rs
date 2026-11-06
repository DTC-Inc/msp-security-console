//! NinjaOne: organizations (the console's clients), devices, and each device's installed software. The installing
//! MSP's own API client (client credentials, scope "monitoring": read-only). The devices pass also keeps each device's
//! public address (device_wan, for the exposure job), so the addresses cost no NinjaOne calls of their own. It reads
//! only what the evidence model needs.

use super::{from_epoch, send_json, Backoff, Limiter, Token, TokenCache};
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Value};
use crate::db::{self as store, Pool};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Ninja { pub base: String, client_id: String, client_secret: String, http: reqwest::Client, limiter: Limiter, token: TokenCache }

impl std::fmt::Debug for Ninja { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("Ninja").field("base", &self.base).finish_non_exhaustive() } }

const PAGE: usize = 1000;
const BACKOFF: Backoff = Backoff { floor: Duration::from_secs(5), tries: 4 };

impl Ninja {
    pub fn new(base: &str, client_id: &str, client_secret: &str, http: reqwest::Client) -> Self {
        Self { base: base.trim_end_matches('/').into(), client_id: client_id.into(), client_secret: client_secret.into(), http,
               limiter: Limiter::new(5, Duration::from_secs(1)), token: Default::default() }
    }

    async fn bearer(&self, fresh: bool) -> Result<String, String> {
        let mut t = self.token.lock().await;
        if !fresh && let Some(tok) = t.as_ref() && tok.until > Instant::now() { return Ok(tok.value.clone()); }
        let url = format!("{}/ws/oauth/token", self.base);
        let form = [("grant_type", "client_credentials"), ("client_id", self.client_id.as_str()), ("client_secret", self.client_secret.as_str()), ("scope", "monitoring")];
        let j = send_json(&self.limiter, BACKOFF, || self.http.post(&url).header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(serde_urlencoded::to_string(form).unwrap_or_default())).await.map_err(|e| format!("NinjaOne sign-in: {e}"))?;
        let value = j.get("access_token").and_then(Value::as_str).ok_or("NinjaOne sign-in: no access token")?.to_string();
        let secs = j.get("expires_in").and_then(Value::as_u64).unwrap_or(3600);
        *t = Some(Token { value: value.clone(), until: Instant::now() + Duration::from_secs(secs.saturating_sub(60)) });
        Ok(value)
    }

    /// GET a path under the API, re-minting the token once on a 401.
    pub async fn get(&self, path_and_query: &str) -> Result<Value, String> {
        let url = format!("{}{}", self.base, path_and_query);
        for fresh in [false, true] {
            let tok = self.bearer(fresh).await?;
            match send_json(&self.limiter, BACKOFF, || self.http.get(&url).bearer_auth(&tok)).await {
                Err(e) if e.starts_with("HTTP 401") && !fresh => continue,
                other => return other.map_err(|e| format!("NinjaOne: {e}")),
            }
        }
        unreachable!()
    }

    /// Every organization, device and device class; clients and devices no longer in NinjaOne are marked deleted.
    pub async fn sync_devices(&self, pool: &Pool) -> Result<Outcome, String> {
        let orgs = self.get("/v2/organizations?pageSize=10000").await?;
        let orgs: Vec<(i64, String)> = orgs.as_array().into_iter().flatten()
            .filter_map(|o| Some((o.get("id")?.as_i64()?, o.get("name")?.as_str()?.trim().to_string()))).collect();
        // Chassis per device, from the bulk query (devices-detailed carries none): laptop or desktop.
        let mut chassis = std::collections::HashMap::<i64, String>::new();
        let mut cursor: Option<String> = None;
        for _ in 0..50 {
            let q = match &cursor { Some(c) => format!("/v2/queries/computer-systems?pageSize={PAGE}&cursor={}", urlenc(c)), None => format!("/v2/queries/computer-systems?pageSize={PAGE}") };
            let j = self.get(&q).await?;
            for r in j.get("results").and_then(Value::as_array).into_iter().flatten() {
                if let (Some(id), Some(c)) = (r.get("deviceId").and_then(Value::as_i64), r.get("chassisType").and_then(Value::as_str)) { chassis.insert(id, c.to_uppercase()); }
            }
            cursor = j.pointer("/cursor/name").and_then(Value::as_str).map(String::from);
            if cursor.is_none() { break; }
        }
        let mut devices: Vec<Value> = Vec::new();
        // Each device's public address from the same pass (`publicIP`), for the exposure job: public IPv4 only.
        let mut wan: Vec<Value> = Vec::new();
        let mut after = 0i64;
        for _ in 0..1000 {
            let j = self.get(&format!("/v2/devices-detailed?pageSize={PAGE}&after={after}")).await?;
            let batch = j.as_array().cloned().unwrap_or_default();
            if batch.is_empty() { break; }
            for d in &batch {
                let Some(id) = d.get("id").and_then(Value::as_i64) else { continue };
                after = after.max(id);
                let node = d.get("nodeClass").and_then(Value::as_str).unwrap_or("").to_string();
                let os = d.pointer("/os/name").and_then(Value::as_str).unwrap_or("").to_string();
                if let Some(ip) = d.get("publicIP").and_then(Value::as_str).and_then(super::ninja_wan::public_ipv4) {
                    wan.push(json!({ "device_id": id, "org_id": d.get("organizationId").and_then(Value::as_i64).unwrap_or(0), "public_ip": ip }));
                }
                devices.push(json!({ "device_id": id, "org_id": d.get("organizationId").and_then(Value::as_i64).unwrap_or(0),
                    "name": d.get("systemName").or_else(|| d.get("displayName")).and_then(Value::as_str).unwrap_or("").trim(),
                    "device_class": device_class(&node, &os, chassis.get(&id).map(String::as_str)), "node_class": node, "os_name": os,
                    "os_build": d.pointer("/os/buildNumber").and_then(|b| b.as_str().map(String::from).or_else(|| b.as_i64().map(|n| n.to_string()))),
                    "last_contact": d.get("lastContact").and_then(from_epoch).map(store::ts) }));
            }
            if batch.len() < PAGE { break; }
        }
        let now = store::now();
        let clients = json!(orgs.iter().map(|(id, n)| json!({ "org_id": id, "name": n, "name_key": store::name_key(n) })).collect::<Vec<_>>());
        let ids: Vec<i64> = devices.iter().filter_map(|d| d["device_id"].as_i64()).collect();
        let oids: Vec<i64> = orgs.iter().map(|o| o.0).collect();
        let marked = crate::on_pool!(pool, p, pg => {
            let mut tx = p.begin().await.map_err(db)?;
            // SQLite reads the JSON with json_each ("WHERE true": its upsert after an INSERT ... SELECT needs a WHERE to
            // parse unambiguously); PostgreSQL with jsonb_to_recordset, typed.
            sqlx::query(if pg {
                "INSERT INTO client (org_id, name, name_key, seen_at, deleted_at)
                 SELECT x.org_id, x.name, x.name_key, $2, NULL FROM jsonb_to_recordset($1) AS x(org_id bigint, name text, name_key text)
                 ON CONFLICT (org_id) DO UPDATE SET name = excluded.name, name_key = excluded.name_key, seen_at = excluded.seen_at, deleted_at = NULL"
            } else {
                "INSERT INTO client (org_id, name, name_key, seen_at, deleted_at)
                 SELECT x.value ->> 'org_id', x.value ->> 'name', x.value ->> 'name_key', $2, NULL FROM json_each($1) AS x WHERE true
                 ON CONFLICT (org_id) DO UPDATE SET name = excluded.name, name_key = excluded.name_key, seen_at = excluded.seen_at, deleted_at = NULL"
            }).bind(&clients).bind(now).execute(&mut *tx).await.map_err(db)?;
            sqlx::query(if pg {
                "INSERT INTO device (device_id, org_id, name, device_class, node_class, os_name, os_build, last_contact, seen_at, deleted_at)
                 SELECT x.device_id, x.org_id, x.name, x.device_class, x.node_class, x.os_name, x.os_build, x.last_contact, $2, NULL
                   FROM jsonb_to_recordset($1) AS x(device_id bigint, org_id bigint, name text, device_class text, node_class text, os_name text, os_build text, last_contact timestamptz)
                 ON CONFLICT (device_id) DO UPDATE SET org_id = excluded.org_id, name = excluded.name, device_class = excluded.device_class,
                   node_class = excluded.node_class, os_name = excluded.os_name, os_build = excluded.os_build, last_contact = excluded.last_contact, seen_at = excluded.seen_at, deleted_at = NULL"
            } else {
                "INSERT INTO device (device_id, org_id, name, device_class, node_class, os_name, os_build, last_contact, seen_at, deleted_at)
                 SELECT x.value ->> 'device_id', x.value ->> 'org_id', x.value ->> 'name', x.value ->> 'device_class', x.value ->> 'node_class',
                        x.value ->> 'os_name', x.value ->> 'os_build', x.value ->> 'last_contact', $2, NULL
                   FROM json_each($1) AS x WHERE true
                 ON CONFLICT (device_id) DO UPDATE SET org_id = excluded.org_id, name = excluded.name, device_class = excluded.device_class,
                   node_class = excluded.node_class, os_name = excluded.os_name, os_build = excluded.os_build, last_contact = excluded.last_contact, seen_at = excluded.seen_at, deleted_at = NULL"
            }).bind(Value::Array(devices.clone())).bind(now).execute(&mut *tx).await.map_err(db)?;
            // Gone from NinjaOne: marked, not removed. Guarded: an answer with less than half of what we hold is a bad
            // answer (a permission change, an outage), not a mass deletion.
            let (held,): (i64,) = sqlx::query_as("SELECT count(*) FROM device WHERE deleted_at IS NULL").fetch_one(&mut *tx).await.map_err(db)?;
            let marked = if !devices.is_empty() && devices.len() as i64 * 2 >= held {
                sqlx::query(if pg { "UPDATE client SET deleted_at = $2 WHERE deleted_at IS NULL AND NOT (org_id = ANY($1))" }
                            else { "UPDATE client SET deleted_at = $2 WHERE deleted_at IS NULL AND org_id NOT IN (SELECT value FROM json_each($1))" })
                    .bind(store::list(&oids)).bind(now).execute(&mut *tx).await.map_err(db)?;
                sqlx::query(if pg { "UPDATE device SET deleted_at = $2 WHERE deleted_at IS NULL AND NOT (device_id = ANY($1))" }
                            else { "UPDATE device SET deleted_at = $2 WHERE deleted_at IS NULL AND device_id NOT IN (SELECT value FROM json_each($1))" })
                    .bind(store::list(&ids)).bind(now).execute(&mut *tx).await.map_err(db)?.rows_affected()
            } else { 0 };
            // The public addresses, replaced whole under the same guard: a bad answer keeps the old ones.
            if !devices.is_empty() && devices.len() as i64 * 2 >= held {
                sqlx::query("DELETE FROM device_wan").execute(&mut *tx).await.map_err(db)?;
                sqlx::query(if pg {
                    "INSERT INTO device_wan (device_id, org_id, public_ip, seen_at) SELECT x.device_id, x.org_id, x.public_ip, $2 FROM jsonb_to_recordset($1) AS x(device_id bigint, org_id bigint, public_ip text)"
                } else {
                    "INSERT INTO device_wan (device_id, org_id, public_ip, seen_at) SELECT x.value ->> 'device_id', x.value ->> 'org_id', x.value ->> 'public_ip', $2 FROM json_each($1) AS x"
                }).bind(Value::Array(wan.clone())).bind(now).execute(&mut *tx).await.map_err(db)?;
            }
            tx.commit().await.map_err(db)?;
            marked
        });
        Ok(Outcome { detail: json!({ "clients": orgs.len(), "devices": devices.len(), "marked_gone": marked, "with_public_ip": wan.len() }), cursor: None })
    }

    /// Installed software, one organization at a time (df=org=<id>), each replaced whole once it's read completely.
    /// The cursor lists the organizations done this round, so a run cut short resumes with the next one.
    pub async fn sync_software(&self, pool: &Pool, cursor: Option<Value>) -> Result<Outcome, String> {
        let orgs: Vec<(i64,)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT org_id FROM client WHERE deleted_at IS NULL ORDER BY org_id").fetch_all(p).await).map_err(db)?;
        let done: Vec<i64> = cursor.as_ref().and_then(|c| c.get("done")).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
        let mut done_now = done.clone();
        let (mut rows_total, mut orgs_read) = (0usize, 0usize);
        let started = Instant::now();
        for (org,) in orgs.iter().filter(|(o,)| !done.contains(o)) {
            if started.elapsed() > Duration::from_secs(20 * 60) { break; }   // the rest next run, from the cursor
            let mut rows: Vec<Value> = Vec::new();
            let mut cur: Option<String> = None;
            for _ in 0..500 {
                let q = match &cur { Some(c) => format!("/v2/queries/software?df=org%3D{org}&pageSize={PAGE}&cursor={}", urlenc(c)), None => format!("/v2/queries/software?df=org%3D{org}&pageSize={PAGE}") };
                let j = self.get(&q).await?;
                let res = j.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
                for x in &res {
                    let (Some(dev), Some(name)) = (x.get("deviceId").and_then(Value::as_i64), x.get("name").and_then(Value::as_str)) else { continue };
                    let clip = |v: Option<&Value>, n: usize| v.and_then(Value::as_str).unwrap_or("").trim().chars().take(n).collect::<String>();
                    rows.push(json!({ "device_id": dev, "name": name.trim().chars().take(300).collect::<String>(), "publisher": clip(x.get("publisher"), 200), "version": clip(x.get("version"), 100) }));
                }
                cur = j.pointer("/cursor/name").and_then(Value::as_str).map(String::from);
                if cur.is_none() || res.is_empty() { break; }
            }
            crate::on_pool!(pool, p, pg => {
                let mut tx = p.begin().await.map_err(db)?;
                sqlx::query("DELETE FROM software WHERE org_id = $1").bind(org).execute(&mut *tx).await.map_err(db)?;
                sqlx::query(if pg {
                    "INSERT INTO software (device_id, org_id, name, publisher, version)
                     SELECT x.device_id, $2, x.name, x.publisher, x.version FROM jsonb_to_recordset($1) AS x(device_id bigint, name text, publisher text, version text)
                     ON CONFLICT DO NOTHING"
                } else {
                    "INSERT INTO software (device_id, org_id, name, publisher, version)
                     SELECT x.value ->> 'device_id', $2, x.value ->> 'name', x.value ->> 'publisher', x.value ->> 'version' FROM json_each($1) AS x
                      WHERE true ON CONFLICT DO NOTHING"
                }).bind(Value::Array(rows.clone())).bind(org).execute(&mut *tx).await.map_err(db)?;
                sqlx::query("INSERT INTO software_sync (org_id, synced_at, rows) VALUES ($1, $2, $3) ON CONFLICT (org_id) DO UPDATE SET synced_at = excluded.synced_at, rows = excluded.rows")
                    .bind(org).bind(store::now()).bind(rows.len() as i64).execute(&mut *tx).await.map_err(db)?;
                tx.commit().await.map_err(db)?;
            });
            rows_total += rows.len(); orgs_read += 1; done_now.push(*org);
        }
        let complete = orgs.iter().all(|(o,)| done_now.contains(o));
        Ok(Outcome { detail: json!({ "clients_read": orgs_read, "rows": rows_total, "round_complete": complete }),
                     cursor: if complete { None } else { Some(json!({ "done": done_now })) } })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        let a = self.clone();
        let b = self.clone();
        vec![
            Job { name: "ninja_devices", every: Duration::from_secs(6 * 3600), run: Arc::new(move |pool, _| { let n = a.clone(); Box::pin(async move { n.sync_devices(&pool).await }) }) },
            // Software after the devices it hangs on: due a little later on a fresh install, then daily.
            Job { name: "ninja_software", every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, cur| { let n = b.clone(); Box::pin(async move { n.sync_software(&pool, cur).await }) }) },
        ]
    }
}

/// server | desktop | laptop | other. Servers by NinjaOne's node class or the OS name;
/// the rest by the chassis NinjaOne reports.
pub fn device_class(node_class: &str, os_name: &str, chassis: Option<&str>) -> &'static str {
    let nc = node_class.to_uppercase();
    if nc.contains("SERVER") || nc.contains("_VM_HOST") || nc.contains("VMM_HOST") || os_name.to_lowercase().contains("server") { return "server"; }
    match chassis { Some("LAPTOP") => "laptop", Some("DESKTOP") => "desktop", _ => "other" }
}

pub fn urlenc(s: &str) -> String { serde_urlencoded::to_string([("x", s)]).map(|q| q[2..].to_string()).unwrap_or_default() }
/// A job's database failure as its last_error: what failed, never a value (crate::db::why).
pub fn db(e: sqlx::Error) -> String { format!("database: {}", crate::db::why(&e)) }
