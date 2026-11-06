//! The `process_match` job: what's running (device_process, from ninja_processes) as products, and that as the
//! `process` evidence source, so a vulnerable binary that is RUNNING is evidence like an installed one, and an old
//! binary still running after its update was installed shows:
//!   1. sec_process_class: each distinct (product, company, file version) named as a product, with how sure
//!      (process::plan_classes): a curated rule, the inventory's automatic map, a person's decision, or a confident
//!      NVD match. Windows' own binaries are left to the `msrc` source.
//!   2. sec_map_review (kind 'process'): names NVD has products for that the match wouldn't decide. Never applied on
//!      their own; a signed-in user accepts a candidate or rejects the name (ops::processes), and the next run applies it.
//!   3. sec_evidence, source 'process': per device, product and version, with the binaries (name, path, hash).
//!
//! Then the inventory match runs, which compares every (product, version) seen installed or running with NVD.

use crate::connectors::ninja::db;
use crate::cpe_map;
use crate::db::{self as store, Pool};
use crate::process::{self, Binary, Combo, Decision};
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Every NVD application, as the automatic mapping searches them.
pub async fn nvd_index(pool: &Pool) -> Result<cpe_map::Index, String> {
    let rows: Vec<(String,)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT DISTINCT cpe FROM sec_nvd_cpe WHERE part = 'a'").fetch_all(p).await).map_err(db)?;
    Ok(cpe_map::product_index(rows.into_iter().filter_map(|(c,)| cpe_map::CpeProduct::parse(&c))))
}

/// The decisions people made, for one kind of name.
pub async fn decisions(pool: &Pool, kind: &str) -> Result<HashMap<(String, String), Decision>, String> {
    let rows: Vec<(String, String, String, Option<String>)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT name, company, status, cpe FROM sec_map_review WHERE kind = $1 AND status <> 'pending'").bind(kind).fetch_all(p).await).map_err(db)?;
    Ok(rows.into_iter().map(|(n, c, status, cpe)| ((n, c), Decision { status, cpe })).collect())
}

/// Review rows for one kind: the pending ones refreshed, the pending ones this run didn't raise cleared (the name is
/// classified now, or gone), and a decided one keeps its decision.
pub async fn put_review<'a, I>(pool: &Pool, kind: &str, rows: I) -> Result<usize, String> where I: IntoIterator<Item = (&'a str, &'a str, &'a [cpe_map::Candidate], &'a [String], i64)> {
    let rows: Vec<Value> = rows.into_iter().map(|(n, c, cands, versions, devices)| json!({ "name": n, "company": c, "candidates": cands, "versions": versions, "devices": devices })).collect();
    let now = store::now();
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query(if pg {
            "DELETE FROM sec_map_review r WHERE r.kind = $1 AND r.status = 'pending'
               AND NOT EXISTS (SELECT 1 FROM jsonb_to_recordset($2) AS x(name text, company text) WHERE x.name = r.name AND x.company = r.company)"
        } else {
            "DELETE FROM sec_map_review WHERE kind = $1 AND status = 'pending'
               AND NOT EXISTS (SELECT 1 FROM json_each($2) AS x WHERE x.value ->> 'name' = sec_map_review.name AND x.value ->> 'company' = sec_map_review.company)"
        }).bind(kind).bind(Value::Array(rows.clone())).execute(&mut *tx).await.map_err(db)?;
        for c in rows.chunks(2000) {
            sqlx::query(if pg {
                "INSERT INTO sec_map_review (kind, name, company, candidates, versions, devices, first_seen, last_seen)
                 SELECT $1, x.name, x.company, x.candidates, x.versions, x.devices, $3, $3
                   FROM jsonb_to_recordset($2) AS x(name text, company text, candidates jsonb, versions jsonb, devices bigint)
                 ON CONFLICT (kind, name, company) DO UPDATE SET candidates = excluded.candidates, versions = excluded.versions, devices = excluded.devices,
                   last_seen = excluded.last_seen WHERE sec_map_review.status = 'pending'"
            } else {
                "INSERT INTO sec_map_review (kind, name, company, candidates, versions, devices, first_seen, last_seen)
                 SELECT $1, x.value ->> 'name', x.value ->> 'company', x.value -> 'candidates', x.value -> 'versions', x.value ->> 'devices', $3, $3
                   FROM json_each($2) AS x WHERE true
                 ON CONFLICT (kind, name, company) DO UPDATE SET candidates = excluded.candidates, versions = excluded.versions, devices = excluded.devices,
                   last_seen = excluded.last_seen WHERE sec_map_review.status = 'pending'"
            }).bind(kind).bind(Value::Array(c.to_vec())).bind(now).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
    });
    Ok(rows.len())
}

/// The automatic products the mappings named, beside the curated ones, so they carry a label and their NVD name.
pub async fn put_auto_products(pool: &Pool, products: &[(String, String, String)]) -> Result<(), String> {
    if products.is_empty() { return Ok(()); }
    let rows: Vec<Value> = products.iter().map(|(k, label, cpe)| json!({ "product_key": k, "label": label, "cpe": cpe })).collect();
    crate::on_pool!(pool, p, pg => {
        for c in rows.chunks(2000) {
            sqlx::query(if pg {
                "INSERT INTO sec_product (product_key, label, cpe, match, sort_order, active, source)
                 SELECT x.product_key, x.label, x.cpe, '{}'::jsonb, 1000, TRUE, 'auto' FROM jsonb_to_recordset($1) AS x(product_key text, label text, cpe text)
                 ON CONFLICT (product_key) DO UPDATE SET active = TRUE WHERE sec_product.source = 'auto'"
            } else {
                "INSERT INTO sec_product (product_key, label, cpe, match, sort_order, active, source)
                 SELECT x.value ->> 'product_key', x.value ->> 'label', x.value ->> 'cpe', '{}', 1000, 1, 'auto' FROM json_each($1) AS x WHERE true
                 ON CONFLICT (product_key) DO UPDATE SET active = 1 WHERE sec_product.source = 'auto'"
            }).bind(Value::Array(c.to_vec())).execute(p).await.map_err(db)?;
        }
    });
    Ok(())
}

type ProcRow = (i64, String, Option<String>, String, Value, i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String, i64, Option<chrono::DateTime<chrono::Utc>>);

pub async fn run(pool: &Pool) -> Result<Outcome, String> {
    let combos: Vec<(String, Option<String>, Option<String>, i64)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT product, company, file_version, count(DISTINCT device_id) FROM device_process WHERE product IS NOT NULL GROUP BY product, company, file_version").fetch_all(p).await).map_err(db)?;
    let (held,): (i64,) = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT count(*) FROM sec_process_class").fetch_one(p).await).map_err(db)?;
    if combos.is_empty() {
        if held > 0 { return Err(format!("refused: no running products against {held} classified; nothing replaced. Check the ninja_processes job first")); }
        return Ok(Outcome { detail: json!({ "skipped": "no process inventory yet" }), cursor: None });
    }
    let combos: Vec<Combo> = combos.into_iter().map(|(product, company, v, devices)| Combo { product, company: company.unwrap_or_default(), file_version: v.unwrap_or_default(), devices }).collect();
    let rules = crate::inventory::rules(pool).await?;
    let class_rows: Vec<(String, String, String)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT name, publisher, product_key FROM sec_software_class WHERE product_key IS NOT NULL ORDER BY name, publisher, (method = 'rule') DESC").fetch_all(p).await).map_err(db)?;
    let mut class_map: HashMap<(String, String), String> = HashMap::new();
    for (n, p, k) in class_rows { class_map.entry((n, p)).or_insert(k); }
    let decided = decisions(pool, "process").await?;
    let idx = nvd_index(pool).await?;
    let plan = process::plan_classes(&combos, &rules, &class_map, &decided, &idx);
    // The rows of classified products only.
    let products: Vec<String> = plan.classes.iter().filter(|c| c.product_version.is_some()).map(|c| c.product.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    let mut bins: Vec<Binary> = Vec::new();
    for chunk in products.chunks(2000) {
        let rows: Vec<ProcRow> = crate::on_pool!(pool, p, pg => sqlx::query_as(if pg {
            "SELECT device_id, key, sha256, name, paths, path_count, file_version, product, company, signer, signature_status, trust, instance_count, collected_at
               FROM device_process WHERE product = ANY($1)"
        } else {
            "SELECT device_id, key, sha256, name, paths, path_count, file_version, product, company, signer, signature_status, trust, instance_count, collected_at
               FROM device_process WHERE product IN (SELECT value FROM json_each($1))"
        }).bind(store::list(chunk)).fetch_all(p).await).map_err(db)?;
        bins.extend(rows.into_iter().map(|(device_id, key, sha256, name, paths, path_count, file_version, product, company, signer, signature_status, _trust, instance_count, collected_at)| Binary {
            device_id, key, sha256, name, paths: serde_json::from_value(paths).unwrap_or_default(), path_count, file_version, product, company, signer, signature_status,
            trust: "valid", instance_count, collected_at: collected_at.map(store::ts) }));
    }
    let running = process::running(&bins, &plan.classes);
    let evidence: Vec<Value> = running.iter().map(|((d, k, v), b)| json!({ "device_id": d, "product_key": k, "version": v, "detail": { "binaries": b } })).collect();
    let classes: Vec<Value> = plan.classes.iter().map(|c| serde_json::to_value(c).unwrap_or_default()).collect();
    let autos: Vec<(String, String, String)> = plan.auto_products.iter().map(|(k, (label, cpe))| (k.clone(), label.clone(), cpe.clone())).collect();
    put_auto_products(pool, &autos).await?;
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM sec_process_class").execute(&mut *tx).await.map_err(db)?;
        for c in classes.chunks(2000) {
            sqlx::query(if pg {
                "INSERT INTO sec_process_class (product, company, file_version, product_key, product_version, method, confidence, devices)
                 SELECT x.product, x.company, x.file_version, x.product_key, x.product_version, x.method, x.confidence, x.devices
                   FROM jsonb_to_recordset($1) AS x(product text, company text, file_version text, product_key text, product_version text, method text, confidence double precision, devices bigint)
                 ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO sec_process_class (product, company, file_version, product_key, product_version, method, confidence, devices)
                 SELECT x.value ->> 'product', x.value ->> 'company', x.value ->> 'file_version', x.value ->> 'product_key', x.value ->> 'product_version', x.value ->> 'method',
                        x.value ->> 'confidence', x.value ->> 'devices'
                   FROM json_each($1) AS x WHERE true ON CONFLICT DO NOTHING"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        sqlx::query("DELETE FROM sec_evidence WHERE source = 'process'").execute(&mut *tx).await.map_err(db)?;
        for c in evidence.chunks(2000) {
            sqlx::query(if pg {
                "INSERT INTO sec_evidence (device_id, product_key, version, source, detail)
                 SELECT x.device_id, x.product_key, x.version, 'process', x.detail FROM jsonb_to_recordset($1) AS x(device_id bigint, product_key text, version text, detail jsonb)
                  WHERE EXISTS (SELECT 1 FROM device d WHERE d.device_id = x.device_id AND d.deleted_at IS NULL)"
            } else {
                "INSERT INTO sec_evidence (device_id, product_key, version, source, detail)
                 SELECT x.value ->> 'device_id', x.value ->> 'product_key', x.value ->> 'version', 'process', x.value -> 'detail' FROM json_each($1) AS x
                  WHERE EXISTS (SELECT 1 FROM device d WHERE d.device_id = x.value ->> 'device_id' AND d.deleted_at IS NULL)"
            }).bind(Value::Array(c.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
    });
    let review = put_review(pool, "process", plan.review.iter().map(|r| (r.name.as_str(), r.company.as_str(), r.candidates.as_slice(), r.versions.as_slice(), r.devices))).await?;
    // The CVEs of what's running: the inventory match compares every (product, version) seen with NVD.
    let matched = crate::inventory::run(pool).await?;
    let mut by_method: std::collections::BTreeMap<&str, usize> = Default::default();
    for c in &plan.classes { *by_method.entry(c.method).or_default() += 1; }
    Ok(Outcome { detail: json!({ "combos": combos.len(), "classified": plan.classes.len(), "by_method": by_method, "review": review, "windows_devices": plan.windows,
        "evidence_rows": evidence.len(), "match": matched.detail }), cursor: None })
}

pub fn jobs() -> Vec<Job> {
    vec![Job { name: "process_match", every: Duration::from_secs(30 * 60), run: Arc::new(|pool, _| Box::pin(async move { run(&pool).await })) }]
}
