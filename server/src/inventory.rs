//! The match: installed software (NinjaOne) against the product map and NVD, into the evidence model:
//!   1. each distinct installed (name, publisher, version) is classified once (sec_software_class): by a curated rule,
//!      by a person's decision, or, once NVD's data is loaded, automatically as the one NVD product whose vendor is the
//!      publisher (cpe_map). A name the mapping wouldn't decide waits in sec_map_review (kind 'software');
//!   2. every device's recognised installs become `ninja_software` evidence (sec_evidence), replaced whole;
//!   3. each (product, version) installed or running (the `process` source, process_match) is compared with NVD's
//!      affected versions for that product, and every CVE it falls in is a row of sec_pair_cve, with its score and
//!      whether CISA lists it as exploited. An automatic product's version numbered another way than NVD's ranges
//!      (cpe_map::scheme_mismatch) isn't compared.

use crate::connectors::ninja::db;
use crate::cpe_map;
use crate::db::Pool;
use crate::matching::{affects, norm_version, Compiled, Range, Rule};
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Value};
use crate::db as store;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub async fn rules(pool: &Pool) -> Result<Vec<Compiled>, String> {
    let rows: Vec<(String, Value)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT product_key, match FROM sec_product WHERE active AND source = 'curated' ORDER BY sort_order, product_key").fetch_all(p).await).map_err(db)?;
    Ok(rows.into_iter().filter_map(|(key, m)| {
        let mut r: Rule = serde_json::from_value(m).ok()?;
        r.product_key = key;
        Compiled::new(&r)
    }).collect())
}

/// (cpe, cve, ranges, cvss, published, kev) as read; (cve, ranges, cvss, published, kev) per product.
type VulnRow = (String, String, Value, Option<f64>, Option<chrono::DateTime<chrono::Utc>>, bool);
type Affected<'a> = (&'a str, Vec<Range>, Option<f64>, Option<String>, bool);

pub async fn run(pool: &Pool) -> Result<Outcome, String> {
    let (installs, running): (i64, i64) = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT (SELECT count(*) FROM software), (SELECT count(*) FROM sec_evidence WHERE source = 'process')").fetch_one(p).await).map_err(db)?;
    if installs == 0 && running == 0 { return Ok(Outcome { detail: json!({ "skipped": "no software inventory yet" }), cursor: None }); }
    let rules = rules(pool).await?;
    // Every NVD application, for the automatic mapping (empty until NVD's data is loaded), and people's decisions.
    let idx = crate::process_match::nvd_index(pool).await?;
    let decided = crate::process_match::decisions(pool, "software").await?;

    // 1. Classify each distinct entry once: the automatic mapping per (name, publisher), whatever the version.
    let distinct: Vec<(String, String, String, i64)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT name, publisher, version, count(DISTINCT device_id) FROM software GROUP BY name, publisher, version").fetch_all(p).await).map_err(db)?;
    let mut memo: HashMap<(String, String), cpe_map::Search> = HashMap::new();
    type Pending = (Vec<cpe_map::Candidate>, Vec<String>, i64);
    let mut review: std::collections::BTreeMap<(String, String), Pending> = Default::default();
    let mut autos: std::collections::BTreeMap<String, (String, String, i64)> = Default::default();
    let classes: Vec<Value> = distinct.iter().map(|(n, p, v, devices)| {
        let row = |key: Option<String>, version: Option<String>, method: Option<&str>, confidence: Option<f64>|
            json!({ "name": n, "publisher": p, "version": v, "product_key": key, "product_version": version, "method": method, "confidence": confidence });
        if let Some((key, version)) = crate::matching::classify(n, p, v, &rules) { return row(Some(key), version, Some("rule"), Some(1.0)); }
        let nk = (n.clone(), p.clone());
        let d = decided.get(&nk);
        if d.is_some_and(|d| d.status == "rejected") { return row(None, None, None, None); }
        // The version field only, never a number from the name: "Microsoft SQL Server 2014" with no version would read
        // as 2014 and match every CVE NVD pins to the product line.
        let version = norm_version(v);
        let (cpe, method, confidence) = match d.and_then(|d| d.cpe.clone()) {
            Some(cpe) => (Some(cpe), "reviewed", 1.0),
            None if !idx.is_empty() => {
                let m = memo.entry(nk.clone()).or_insert_with(|| cpe_map::cpe_candidates(n, p, &idx));
                match &m.mapping {
                    Some(x) => (Some(format!("{}:{}", x.vendor, x.product)), "auto", x.confidence),
                    None => {
                        if !m.candidates.is_empty() {
                            let r = review.entry(nk.clone()).or_insert_with(|| (m.candidates.clone(), vec![], 0));
                            if !v.is_empty() && !r.1.contains(v) { r.1.push(v.clone()); }
                            r.2 += devices;
                        }
                        (None, "", 0.0)
                    }
                }
            }
            None => (None, "", 0.0),
        };
        let Some(product) = cpe.as_deref().and_then(cpe_map::CpeProduct::parse) else { return row(None, None, None, None) };
        let key = cpe_map::auto_key(&product);
        let a = autos.entry(key.clone()).or_insert_with(|| (cpe_map::auto_label(n), product.key(), 0));
        if *devices > a.2 { a.0 = cpe_map::auto_label(n); a.2 = *devices; }
        row(Some(key), version, Some(method), Some(confidence))
    }).collect();
    let recognised = classes.iter().filter(|c| !c["product_key"].is_null()).count();
    let auto_rows: Vec<(String, String, String)> = autos.iter().map(|(k, (label, cpe, _))| (k.clone(), label.clone(), cpe.clone())).collect();
    crate::process_match::put_auto_products(pool, &auto_rows).await?;
    type ReviewRow = (String, String, Vec<cpe_map::Candidate>, Vec<String>, i64);
    let review_rows: Vec<ReviewRow> = review.into_iter().map(|((n, c), (cands, mut vs, d))| { vs.sort(); (n, c, cands, vs, d) }).collect();
    let reviewing = crate::process_match::put_review(pool, "software", review_rows.iter().map(|r| (r.0.as_str(), r.1.as_str(), r.2.as_slice(), r.3.as_slice(), r.4))).await?;

    // The rest in one transaction, so the evidence and its CVEs are replaced together. Each dialect reads the JSON it's
    // handed its own way (SQLite's json_each, PostgreSQL's jsonb_to_recordset); the rest is the same SQL.
    let done = crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM sec_software_class").execute(&mut *tx).await.map_err(db)?;
        // The classes are distinct already; a repeat (the same entry twice in one answer) is skipped, never a failure.
        for chunk in classes.chunks(5000) {
            sqlx::query(if pg {
                "INSERT INTO sec_software_class (name, publisher, version, product_key, product_version, method, confidence)
                 SELECT x.name, x.publisher, x.version, x.product_key, x.product_version, x.method, x.confidence
                   FROM jsonb_to_recordset($1) AS x(name text, publisher text, version text, product_key text, product_version text, method text, confidence double precision)
                 ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO sec_software_class (name, publisher, version, product_key, product_version, method, confidence)
                 SELECT x.value ->> 'name', x.value ->> 'publisher', x.value ->> 'version', x.value ->> 'product_key', x.value ->> 'product_version',
                        x.value ->> 'method', x.value ->> 'confidence'
                   FROM json_each($1) AS x WHERE true ON CONFLICT DO NOTHING"
            }).bind(Value::Array(chunk.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        // 2. Installed evidence, per device, product and version, for devices still in NinjaOne.
        sqlx::query("DELETE FROM sec_evidence WHERE source = 'ninja_software'").execute(&mut *tx).await.map_err(db)?;
        let ev = sqlx::query(if pg {
            "INSERT INTO sec_evidence (device_id, product_key, version, source, detail)
             SELECT s.device_id, c.product_key, COALESCE(c.product_version, ''), 'ninja_software', jsonb_build_object('names', jsonb_agg(DISTINCT s.name ORDER BY s.name))
               FROM software s JOIN sec_software_class c USING (name, publisher, version) JOIN device d ON d.device_id = s.device_id AND d.deleted_at IS NULL
              WHERE c.product_key IS NOT NULL
              GROUP BY s.device_id, c.product_key, COALESCE(c.product_version, '')"
        } else {
            "INSERT INTO sec_evidence (device_id, product_key, version, source, detail)
             SELECT device_id, product_key, pv, 'ninja_software', json_object('names', json_group_array(name))
               FROM (SELECT DISTINCT s.device_id, c.product_key, COALESCE(c.product_version, '') AS pv, s.name
                       FROM software s JOIN sec_software_class c USING (name, publisher, version) JOIN device d ON d.device_id = s.device_id AND d.deleted_at IS NULL
                      WHERE c.product_key IS NOT NULL
                      ORDER BY s.device_id, c.product_key, pv, s.name)
              GROUP BY device_id, product_key, pv"
        }).execute(&mut *tx).await.map_err(db)?.rows_affected();

        // 3. Each (product, version) installed or running against NVD's ranges for that product.
        let pairs_in: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT DISTINCT e.product_key, e.version, p.cpe FROM sec_evidence e JOIN sec_product p USING (product_key)
              WHERE e.source IN ('ninja_software', 'process') AND e.version <> ''")
            .fetch_all(&mut *tx).await.map_err(db)?;
        let cpes: Vec<String> = pairs_in.iter().map(|p| p.2.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let vulns: Vec<VulnRow> = sqlx::query_as(if pg {
            "SELECT c.cpe, c.cve_id, c.ranges, n.cvss, n.published, (k.cve_id IS NOT NULL)
               FROM sec_nvd_cpe c JOIN sec_nvd_cve n ON n.cve_id = c.cve_id AND NOT n.rejected LEFT JOIN sec_kev k ON k.cve_id = c.cve_id
              WHERE c.part = 'a' AND c.cpe = ANY($1)"
        } else {
            "SELECT c.cpe, c.cve_id, c.ranges, n.cvss, n.published, (k.cve_id IS NOT NULL)
               FROM sec_nvd_cpe c JOIN sec_nvd_cve n ON n.cve_id = c.cve_id AND NOT n.rejected LEFT JOIN sec_kev k ON k.cve_id = c.cve_id
              WHERE c.part = 'a' AND c.cpe IN (SELECT value FROM json_each($1))"
        }).bind(store::list(&cpes)).fetch_all(&mut *tx).await.map_err(db)?;
        let mut by_cpe: HashMap<&str, Vec<Affected>> = HashMap::new();
        for (cpe, cve, ranges, cvss, published, kev) in &vulns {
            let r: Vec<Range> = serde_json::from_value(ranges.clone()).unwrap_or_default();
            by_cpe.entry(cpe.as_str()).or_default().push((cve.as_str(), r, *cvss, published.map(store::ts), *kev));
        }
        // The majors each automatic product's NVD data mentions, for the scheme check.
        let majors: HashMap<&str, Vec<u64>> = by_cpe.iter().map(|(c, list)| (*c, list.iter().flat_map(|a| cpe_map::majors_of(&a.1)).collect())).collect();
        let mut pairs: Vec<Value> = Vec::new();
        let mut mismatched = 0usize;
        for (product, version, cpe) in &pairs_in {
            if product.starts_with("nvd:") && cpe_map::scheme_mismatch(version, majors.get(cpe.as_str()).map(Vec::as_slice).unwrap_or(&[])) { mismatched += 1; continue; }
            for (cve, ranges, cvss, published, kev) in by_cpe.get(cpe.as_str()).into_iter().flatten() {
                if affects(version, ranges) { pairs.push(json!({ "product_key": product, "version": version, "cve_id": cve, "cvss": cvss, "kev": kev, "published": published })); }
            }
        }
        sqlx::query("DELETE FROM sec_pair_cve").execute(&mut *tx).await.map_err(db)?;
        for chunk in pairs.chunks(5000) {
            sqlx::query(if pg {
                "INSERT INTO sec_pair_cve (product_key, version, cve_id, cvss, kev, published)
                 SELECT x.product_key, x.version, x.cve_id, x.cvss, x.kev, x.published
                   FROM jsonb_to_recordset($1) AS x(product_key text, version text, cve_id text, cvss double precision, kev boolean, published text)
                 ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO sec_pair_cve (product_key, version, cve_id, cvss, kev, published)
                 SELECT x.value ->> 'product_key', x.value ->> 'version', x.value ->> 'cve_id', x.value ->> 'cvss', x.value ->> 'kev', x.value ->> 'published'
                   FROM json_each($1) AS x WHERE true ON CONFLICT DO NOTHING"
            }).bind(Value::Array(chunk.to_vec())).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        (ev, pairs.len(), mismatched)
    });
    let (ev, pairs, mismatched) = done;
    // 4. Advisories ahead of NVD, against the same inventory (src/advisory.rs).
    let advisories = crate::advisory::apply(pool).await?;
    Ok(Outcome { detail: json!({ "distinct_installs": distinct.len(), "recognised": recognised, "automatic_products": autos.len(), "review": reviewing,
        "evidence_rows": ev, "vulnerable_pairs": pairs, "scheme_mismatches": mismatched, "advisory_rows": advisories["advisory_rows"] }), cursor: None })
}

pub fn jobs() -> Vec<Job> {
    vec![Job { name: "match", every: Duration::from_secs(30 * 60), run: Arc::new(|pool, _| Box::pin(async move { run(&pool).await })) }]
}
