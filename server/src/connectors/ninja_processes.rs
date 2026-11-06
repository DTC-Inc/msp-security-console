//! Running processes from NinjaOne: the endpoint script (endpoint/process, process-inventory.ps1, schema 1)
//! publishes, per Windows device, every running binary into a hidden WYSIWYG custom field as base64(gzip(JSON)). This
//! job reads it back through the NinjaOne connector's client, in two phases, so a quiet run downloads no payloads:
//!   1. <field>CollectedAt, <field>Hash and <field>Bytes for every device: small. The hash (endpoint 1.2.1), else the
//!      bytes field's time (written in the same run as the payload), says whether the payload changed.
//!   2. <field> and <field>Bytes, `df=id in (…)`, 100 devices at a time, for the devices whose payload changed (or that
//!      have none held, or whose last read failed). Each batch is written before the next is read.
//!
//! A payload replaces a device's rows only when it was collected later than what's held; an unknown schema is refused
//! and the device keeps its rows. A device that hasn't run the script for 30 days loses its rows.
//!
//! The field's name is NINJA_PROCESS_FIELD (default processInventory, the script's own; endpoint/README.md says how to
//! create the fields). Without the script deployed, NinjaOne has no such field on any device, and the job says so and
//! does nothing else.

use super::ninja::{db, Ninja};
use crate::db::{self as store, Pool};
use crate::process::{self, Decoded, Held, Write};
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_FIELD: &str = "processInventory";
const BATCH: usize = 100;
const RETENTION_DAYS: i64 = 30;
const BUDGET: Duration = Duration::from_secs(20 * 60);

/// A NinjaOne custom field's name: a letter, then letters, digits and _ (at most 64), so the companions' names
/// (<field>Hash ...) are fields too, and nothing in it changes the query it goes into.
pub fn field_name_ok(f: &str) -> bool {
    let b = f.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_alphabetic() && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

#[derive(Clone)]
pub struct NinjaProcesses { pub ninja: Arc<Ninja>, pub field: String, pub budget: Duration }

/// One device's small fields.
struct Light { hash: Option<String>, bytes_updated: Option<String>, ran_at: Option<Value>, empty: bool }

fn field<'a>(fields: &'a [Value], name: &str) -> Option<&'a Value> { fields.iter().find(|f| f.get("name").and_then(Value::as_str) == Some(name)) }

impl NinjaProcesses {
    pub fn new(ninja: Arc<Ninja>, field: &str) -> Self { Self { ninja, field: field.into(), budget: BUDGET } }

    async fn page(&self, fields: &str, ids: Option<&[i64]>, size: usize, cursor: Option<&str>) -> Result<Value, String> {
        let mut q = format!("/v2/queries/custom-fields-detailed?fields={}&pageSize={size}", super::ninja::urlenc(fields));
        if let Some(ids) = ids { q.push_str(&format!("&df={}", super::ninja::urlenc(&format!("id in ({})", ids.iter().map(i64::to_string).collect::<Vec<_>>().join(","))))); }
        if let Some(c) = cursor { q.push_str(&format!("&cursor={}", super::ninja::urlenc(c))); }
        self.ninja.get(&q).await
    }

    pub async fn sync(&self, pool: &Pool) -> Result<Outcome, String> {
        let t0 = Instant::now();
        let f = &self.field;
        let (f_at, f_hash, f_bytes) = (format!("{f}CollectedAt"), format!("{f}Hash"), format!("{f}Bytes"));
        type HeldRow = (i64, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>, Option<String>, Option<String>, Option<chrono::DateTime<chrono::Utc>>);
        let held_rows: Vec<HeldRow> = crate::on_pool!(pool, p, _ => sqlx::query_as(
            "SELECT device_id, collected_at, bytes_updated_at, content_hash, error, last_seen_at FROM process_snapshot").fetch_all(p).await).map_err(db)?;
        let mut held: BTreeMap<i64, (Held, Option<String>)> = held_rows.into_iter().map(|(d, c, b, h, e, s)|
            (d, (Held { collected_at: c.map(store::ts), bytes_updated_at: b.map(store::ts), content_hash: h, error: e.is_some() }, s.map(store::ts)))).collect();
        // ---- Phase 1: the small fields, every device.
        let mut light: BTreeMap<i64, Light> = BTreeMap::new();
        let mut cursor: Option<String> = None;
        let light_fields = format!("{f_at},{f_hash},{f_bytes}");
        for _ in 0..1000 {
            if t0.elapsed() > self.budget { return Err("stopped at its time budget reading the small fields; nothing was replaced".into()); }
            let j = self.page(&light_fields, None, 1000, cursor.as_deref()).await?;
            let results = j.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
            for r in &results {
                let Some(id) = r.get("deviceId").and_then(Value::as_i64).filter(|d| *d > 0) else { continue };
                let fields = r.get("fields").and_then(Value::as_array).cloned().unwrap_or_default();
                let bytes = field(&fields, &f_bytes);
                light.insert(id, Light {
                    hash: process::content_hash(field(&fields, &f_hash).and_then(|x| x.get("value"))),
                    bytes_updated: bytes.and_then(|b| crate::windows::epoch(b.get("updated"))).map(|t| store::ts(rounded(t))),
                    ran_at: field(&fields, &f_at).and_then(|x| x.get("value")).cloned(),
                    empty: bytes.and_then(|b| b.get("value")).and_then(Value::as_f64) == Some(0.0),
                });
            }
            cursor = j.pointer("/cursor/name").and_then(Value::as_str).map(String::from);
            if cursor.is_none() || results.is_empty() { break; }
        }
        let mut res = json!({ "devices_seen": light.len(), "payloads_downloaded": 0, "unchanged": 0, "replaced": 0, "same": 0, "older": 0, "errors": 0, "rows_written": 0, "pruned_devices": 0 });
        let bump = |res: &mut Value, k: &str, n: u64| { res[k] = json!(res[k].as_u64().unwrap_or(0) + n); };
        if light.is_empty() {
            res["note"] = json!(format!("no device has the {f} field: deploy endpoint/process (endpoint/README.md) to collect running processes"));
        }
        // Which payloads to download: only those rewritten since the stored snapshot. The rest only record the run.
        let mut fetch = Vec::new();
        let mut seen_only: Vec<Value> = Vec::new();
        for (id, l) in &light {
            let h = held.get(id);
            if !l.empty && process::plan_fetch(h.map(|x| &x.0), l.bytes_updated.as_deref(), l.hash.as_deref()) { fetch.push(*id); continue; }
            bump(&mut res, "unchanged", 1);
            let ls = process::last_seen(l.ran_at.as_ref(), None);
            if ls.is_some() && h.is_some_and(|x| x.1 < ls) { seen_only.push(json!({ "device_id": id, "last_seen_at": ls })); }
        }
        if !seen_only.is_empty() { write_seen(pool, &seen_only).await?; }
        // ---- Phase 2: those devices' payloads, a batch at a time.
        for ids in fetch.chunks(BATCH) {
            if t0.elapsed() > self.budget { res["stopped"] = json!("at its time budget; the rest next run"); break; }
            let mut c2: Option<String> = None;
            for _ in 0..100 {
                let j = self.page(&format!("{f},{f_bytes}"), Some(ids), BATCH, c2.as_deref()).await?;
                let results = j.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
                let (mut replace, mut touch, mut errors) = (Vec::new(), Vec::new(), Vec::new());
                for r in &results {
                    let Some(id) = r.get("deviceId").and_then(Value::as_i64).filter(|d| ids.contains(d)) else { continue };   // never a device not asked for
                    let fields = r.get("fields").and_then(Value::as_array).cloned().unwrap_or_default();
                    let Some(inv) = field(&fields, f) else { continue };
                    bump(&mut res, "payloads_downloaded", 1);
                    let l = &light[&id];
                    let snap = |doc: Option<&Value>| json!({ "device_id": id, "collected_at": doc.and_then(|d| process::iso(d.get("collectedAt"))),
                        "last_seen_at": process::last_seen(l.ran_at.as_ref(), doc.and_then(|d| process::iso(d.get("collectedAt"))).as_deref()),
                        "bytes_updated_at": l.bytes_updated, "content_hash": l.hash,
                        "script_version": doc.and_then(|d| process::clean(d.get("scriptVersion"), 20)),
                        "binary_count": doc.and_then(|d| d.get("binaryCount")).and_then(Value::as_i64),
                        "trimmed": doc.is_some_and(|d| d.get("trimmed") == Some(&Value::Bool(true))) });
                    match process::decode_inventory(inv.get("value").unwrap_or(&Value::Null)) {
                        Decoded::Absent => continue,
                        Decoded::Bad(why) => { bump(&mut res, "errors", 1); let mut s = snap(None); s["error"] = json!(why); errors.push(s); }
                        Decoded::Doc(doc) => {
                            let s = snap(Some(&doc));
                            let collected = s["collected_at"].as_str().unwrap_or_default().to_string();
                            match process::decide_write(held.get(&id).and_then(|h| h.0.collected_at.as_deref()), &collected) {
                                Write::Replace => { bump(&mut res, "replaced", 1); replace.push((id, process::process_rows(id, &doc), s)); }
                                Write::Same => { bump(&mut res, "same", 1); touch.push(s); }
                                Write::Older => { bump(&mut res, "older", 1); touch.push(s); }
                            }
                        }
                    }
                }
                let written: usize = replace.iter().map(|x| x.1.len()).sum();
                put_batch(pool, &replace, &touch, &errors).await?;
                bump(&mut res, "rows_written", written as u64);
                for (id, _, s) in &replace { held.insert(*id, (Held { collected_at: s["collected_at"].as_str().map(String::from), ..Default::default() }, None)); }
                c2 = j.pointer("/cursor/name").and_then(Value::as_str).map(String::from);
                if c2.is_none() || results.is_empty() { break; }
            }
        }
        // Age is the only clear: a device absent from NinjaOne's answer is never read as "nothing running".
        let cutoff = store::Ts(store::now().0 - chrono::Duration::days(RETENTION_DAYS));
        let pruned = crate::on_pool!(pool, p, _ => {
            let mut tx = p.begin().await.map_err(db)?;
            let gone: Vec<(i64,)> = sqlx::query_as("DELETE FROM process_snapshot WHERE COALESCE(last_seen_at, collected_at, synced_at) < $1 RETURNING device_id")
                .bind(cutoff).fetch_all(&mut *tx).await.map_err(db)?;
            for (d,) in &gone { sqlx::query("DELETE FROM device_process WHERE device_id = $1").bind(d).execute(&mut *tx).await.map_err(db)?; }
            tx.commit().await.map_err(db)?;
            gone.len()
        });
        res["pruned_devices"] = json!(pruned);
        res["seconds"] = json!((t0.elapsed().as_millis() as f64) / 1000.0);
        Ok(Outcome { detail: res, cursor: None })
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        // Every 30 minutes, as the endpoint script runs; an unchanged payload isn't downloaded.
        vec![Job { name: "ninja_processes", every: Duration::from_secs(30 * 60), run: Arc::new(move |pool, _| { let n = self.clone(); Box::pin(async move { n.sync(&pool).await }) }) }]
    }
}

/// NinjaOne's "updated" times carry microseconds; the store keeps milliseconds, so compare at that.
fn rounded(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(t.timestamp_millis()).unwrap_or(t)
}

/// Liveness without touching the rows: the last run moves forward only.
async fn write_seen(pool: &Pool, seen: &[Value]) -> Result<(), String> {
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        for c in seen.chunks(2000) {
            sqlx::query(if pg {
                "UPDATE process_snapshot s SET last_seen_at = GREATEST(s.last_seen_at, x.last_seen_at)
                   FROM jsonb_to_recordset($1) AS x(device_id bigint, last_seen_at timestamptz) WHERE s.device_id = x.device_id"
            } else {
                "UPDATE process_snapshot SET last_seen_at = (SELECT x.value ->> 'last_seen_at' FROM json_each($1) AS x WHERE x.value ->> 'device_id' = process_snapshot.device_id)
                  WHERE device_id IN (SELECT x.value ->> 'device_id' FROM json_each($1) AS x)
                    AND (last_seen_at IS NULL OR last_seen_at < (SELECT x.value ->> 'last_seen_at' FROM json_each($1) AS x WHERE x.value ->> 'device_id' = process_snapshot.device_id))"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

/// One batch in one transaction: a device's rows and its snapshot change together. A failed read keeps the device's
/// rows and its collectedAt; the snapshot says why, and the next run downloads it again.
async fn put_batch(pool: &Pool, replace: &[(i64, Vec<process::Binary>, Value)], touch: &[Value], errors: &[Value]) -> Result<(), String> {
    if replace.is_empty() && touch.is_empty() && errors.is_empty() { return Ok(()); }
    let ids: Vec<i64> = replace.iter().map(|x| x.0).collect();
    let rows: Vec<Value> = replace.iter().flat_map(|x| x.1.iter().map(|b| serde_json::to_value(b).unwrap_or_default())).collect();
    let mut snaps: Vec<Value> = replace.iter().map(|x| { let mut s = x.2.clone(); s["rows"] = json!(x.1.len()); s["replace"] = json!(true); s }).collect();
    snaps.extend(touch.iter().map(|s| { let mut s = s.clone(); s["replace"] = json!(false); s }));
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        if !ids.is_empty() {
            sqlx::query(if pg { "DELETE FROM device_process WHERE device_id = ANY($1)" } else { "DELETE FROM device_process WHERE device_id IN (SELECT value FROM json_each($1))" })
                .bind(store::list(&ids)).execute(&mut *tx).await.map_err(db)?;
        }
        for c in rows.chunks(2000) {
            sqlx::query(if pg {
                "INSERT INTO device_process (device_id, key, sha256, name, paths, path_count, file_version, product, company, signer, signature_status, trust, instance_count, collected_at)
                 SELECT x.device_id, x.key, x.sha256, x.name, x.paths, x.path_count, x.file_version, x.product, x.company, x.signer, x.signature_status, x.trust, x.instance_count, x.collected_at
                   FROM jsonb_to_recordset($1) AS x(device_id bigint, key text, sha256 text, name text, paths jsonb, path_count bigint, file_version text, product text, company text,
                        signer text, signature_status text, trust text, instance_count bigint, collected_at timestamptz)
                 ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO device_process (device_id, key, sha256, name, paths, path_count, file_version, product, company, signer, signature_status, trust, instance_count, collected_at)
                 SELECT x.value ->> 'device_id', x.value ->> 'key', x.value ->> 'sha256', x.value ->> 'name', x.value -> 'paths', x.value ->> 'path_count', x.value ->> 'file_version',
                        x.value ->> 'product', x.value ->> 'company', x.value ->> 'signer', x.value ->> 'signature_status', x.value ->> 'trust', x.value ->> 'instance_count', x.value ->> 'collected_at'
                   FROM json_each($1) AS x WHERE true ON CONFLICT DO NOTHING"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        // A replaced snapshot takes the payload's header; a touched one (the same, or an older, payload) only its liveness.
        for s in &snaps {
            let at = |k: &str| s[k].as_str().and_then(|x| chrono::DateTime::parse_from_rfc3339(x).ok()).map(|t| store::Ts(t.with_timezone(&chrono::Utc)));
            sqlx::query(
                "INSERT INTO process_snapshot (device_id, collected_at, last_seen_at, bytes_updated_at, content_hash, script_version, binary_count, rows, trimmed, error, synced_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, $10)
                 ON CONFLICT (device_id) DO UPDATE SET
                   last_seen_at = CASE WHEN process_snapshot.last_seen_at IS NULL OR excluded.last_seen_at > process_snapshot.last_seen_at THEN excluded.last_seen_at ELSE process_snapshot.last_seen_at END,
                   bytes_updated_at = excluded.bytes_updated_at, content_hash = excluded.content_hash, error = NULL, synced_at = excluded.synced_at,
                   collected_at = CASE WHEN $11 THEN excluded.collected_at ELSE process_snapshot.collected_at END,
                   script_version = CASE WHEN $11 THEN excluded.script_version ELSE process_snapshot.script_version END,
                   binary_count = CASE WHEN $11 THEN excluded.binary_count ELSE process_snapshot.binary_count END,
                   rows = CASE WHEN $11 THEN excluded.rows ELSE process_snapshot.rows END,
                   trimmed = CASE WHEN $11 THEN excluded.trimmed ELSE process_snapshot.trimmed END")
                .bind(s["device_id"].as_i64()).bind(at("collected_at")).bind(at("last_seen_at")).bind(at("bytes_updated_at")).bind(s["content_hash"].as_str())
                .bind(s["script_version"].as_str()).bind(s["binary_count"].as_i64()).bind(s["rows"].as_i64().unwrap_or(0)).bind(s["trimmed"].as_bool().unwrap_or(false))
                .bind(store::now()).bind(s["replace"].as_bool().unwrap_or(false)).execute(&mut *tx).await.map_err(db)?;
        }
        for e in errors {
            let at = |k: &str| e[k].as_str().and_then(|x| chrono::DateTime::parse_from_rfc3339(x).ok()).map(|t| store::Ts(t.with_timezone(&chrono::Utc)));
            sqlx::query(
                "INSERT INTO process_snapshot (device_id, last_seen_at, bytes_updated_at, error, synced_at) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (device_id) DO UPDATE SET error = excluded.error, synced_at = excluded.synced_at, bytes_updated_at = excluded.bytes_updated_at,
                   last_seen_at = CASE WHEN process_snapshot.last_seen_at IS NULL OR excluded.last_seen_at > process_snapshot.last_seen_at THEN excluded.last_seen_at ELSE process_snapshot.last_seen_at END")
                .bind(e["device_id"].as_i64()).bind(at("last_seen_at")).bind(at("bytes_updated_at")).bind(e["error"].as_str()).bind(store::now())
                .execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}
