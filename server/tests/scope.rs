//! A caller pinned to one client never sees another (a client portal's guarantee), held for EVERY op the contract
//! lists, on both stores. The ops are read from the contract's own schema, so an op added later is in this test the
//! moment it exists, and one this test doesn't know how to call fails it.
//!
//! The method, per op: answer it before and after a second client (Zulu) arrives with data in every source, once
//! unscoped and once pinned to the first client (Yankee). The unscoped answer must change, which proves the op reads
//! Zulu's data with these params (so dropping its client filter would show). The pinned answer must not change by a
//! byte. Every client, device, address and CVE here is made up.
mod common;
use common::*;
use msp_console::contract::{EvidenceRequest, ReadOp};
use msp_console::ops::{Scope, Store};
use serde_json::{json, Value};

both!(every_op_answers_a_pinned_caller_only_for_its_own_client);

/// Each op, with params that reach Zulu's records where it takes an id.
fn params(op: &str) -> Option<Value> {
    Some(match op {
        "cve.get" | "cve.products" | "cve.devices" => json!({ "cve_id": "CVE-2026-4242" }),
        "cve.similar" => json!({ "cve_id": "CVE-2026-4141", "limit": 5 }),
        "device.get" | "device.cves" | "device.products" | "device.software" => json!({ "device_id": 424201 }),
        "product.get" | "product.versions" | "product.devices" => json!({ "product_key": "chrome" }),
        "version.cves" => json!({ "product_key": "chrome", "version": "120.0" }),
        "client.get" => json!({ "org_id": 4242 }),
        "search" => json!({ "q": "zulu" }),
        "detection.get" => json!({ "detection_id": "zd-1" }),
        "exposure.get" => json!({ "ip": "198.51.100.77" }),
        "cves.list" | "devices.list" | "clients.list" | "clients.overview" | "products.list" | "coverage.list" | "coverage.devices"
        | "advisories.list" | "detections.list" | "blackpoint.tenants" | "darkweb.list" | "exposure.list" | "windows.devices"
        | "windows.cves" | "processes.list" | "processes.review" => json!({}),
        _ => return None,
    })
}

/// Every op name in the contract, from the schema the client's types are generated from.
fn ops() -> Vec<String> {
    let schema = serde_json::to_value(schemars::schema_for!(ReadOp)).unwrap();
    let mut out = Vec::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if let Some(Value::String(c)) = m.get("const") { out.push(c.clone()); }
                if let Some(Value::Array(e)) = m.get("enum") { out.extend(e.iter().filter_map(|x| x.as_str().map(String::from))); }
                m.values().for_each(|x| walk(x, out));
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    walk(&schema, &mut out);
    out.sort();
    out.dedup();
    out
}

async fn run(db: &msp_console::db::Pool, sql: &[&'static str]) {
    for q in sql { msp_console::on_pool!(db, p, _ => { sqlx::query(*q).execute(p).await.unwrap_or_else(|e| panic!("{q}: {e}")); }) }
}

/// Yankee Dental: one desktop with an old Chrome, its own Blackpoint tenant, a detection, a dark-web row, a public
/// address, a Windows device and a running binary. And an advisory (vendor facts, no client in it).
async fn yankee(pool: &msp_console::db::Pool) {
    run(pool, &[
        "INSERT INTO client (org_id, name, name_key) VALUES (4141, 'Yankee Dental', 'yankee dental')",
        "INSERT INTO device (device_id, org_id, name, device_class, node_class) VALUES (414101, 4141, 'YANKEE-PC', 'desktop', 'WINDOWS_WORKSTATION')",
        "INSERT INTO software (device_id, org_id, name, publisher, version) VALUES (414101, 4141, 'Google Chrome', 'Google LLC', '131.0')",
        "INSERT INTO sec_evidence (device_id, product_key, version, source) VALUES (414101, 'chrome', '131.0', 'ninja_software')",
        "INSERT INTO sec_pair_cve (product_key, version, cve_id, cvss, kev) VALUES ('chrome', '131.0', 'CVE-2026-4141', 8.8, FALSE), ('chrome', '120.0', 'CVE-2026-4242', 9.8, TRUE)",
        "INSERT INTO sec_kev (cve_id, name) VALUES ('CVE-2026-4242', 'A made-up exploited flaw')",
        "INSERT INTO sec_advisory (advisory_id, cve_id, title, product_key, match, ranges) VALUES ('EXAMPLE-ADV-1', 'CVE-2026-4343', 'A made-up widget flaw', 'widget', '{\"name_re\": \"^Widget\"}', '[]')",
        "INSERT INTO bp_tenant (tenant_id, name, name_key, org_id, mapped_by) VALUES ('yt-1', 'Yankee Tenant', 'yankee tenant', 4141, 'tech@example.com')",
        "INSERT INTO bp_detection (detection_id, tenant_id, status, risk_score, hostname, username, detection_name, synced_at) VALUES ('yd-1', 'yt-1', 'OPEN', 50, 'YANKEE-PC', 'yankee.user', 'A made-up detection', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO bp_darkweb (exposure_id, tenant_id, email, source, kind, synced_at) VALUES ('yw-1', 'yt-1', 'staff@yankee.example', 'Made-up Breach', 'email', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO device_wan (device_id, org_id, public_ip, seen_at) VALUES (414101, 4141, '203.0.113.41', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO exposure_host (ip, found, ports) VALUES ('203.0.113.41', TRUE, '[443]')",
        "INSERT INTO sec_windows_device (device_id, server, build_major, state) VALUES (414101, FALSE, 26100, 'unknown')",
        "INSERT INTO device_process (device_id, key, sha256, name, trust) VALUES (414101, 'k-y', 'yy', 'yankee-tool.exe', 'valid')",
    ]).await;
    for (id, d) in [("CVE-2026-4141", "A made-up use-after-free in Chrome's renderer lets a remote page run code."),
                    ("CVE-2026-4242", "A made-up use-after-free in Chrome's renderer lets a remote page run code through a crafted page.")] {
        nvd_cve(pool, id, Some(d), "2026-10-01T00:00:00.000Z", false).await;
    }
}

/// Zulu Clinic: the same kinds of data, every source, all of it another client's.
async fn zulu(pool: &msp_console::db::Pool) {
    run(pool, &[
        "INSERT INTO client (org_id, name, name_key) VALUES (4242, 'Zulu Clinic', 'zulu clinic')",
        "INSERT INTO device (device_id, org_id, name, device_class, node_class) VALUES (424201, 4242, 'ZULU-PC', 'desktop', 'WINDOWS_WORKSTATION')",
        "INSERT INTO software (device_id, org_id, name, publisher, version) VALUES (424201, 4242, 'Google Chrome', 'Google LLC', '120.0')",
        "INSERT INTO sec_evidence (device_id, product_key, version, source) VALUES (424201, 'chrome', '120.0', 'ninja_software'), (424201, 'chrome', '120.0', 'process')",
        "INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, detail) VALUES (424201, 'CVE-2026-4343', 'widget', '', 'advisory', '{\"advisories\": [\"EXAMPLE-ADV-1\"]}')",
        "INSERT INTO bp_tenant (tenant_id, name, name_key, org_id, mapped_by) VALUES ('zt-1', 'Zulu Tenant', 'zulu tenant', 4242, 'tech@example.com')",
        "INSERT INTO bp_tenant (tenant_id, name, name_key, suggested_org_id) VALUES ('zt-2', 'Zulu Holdings', 'zulu holdings', 4141)",
        "INSERT INTO bp_detection (detection_id, tenant_id, status, risk_score, hostname, username, detection_name, synced_at) VALUES ('zd-1', 'zt-1', 'OPEN', 90, 'ZULU-PC', 'zulu.user', 'A made-up Zulu detection', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO bp_darkweb (exposure_id, tenant_id, email, source, kind, synced_at) VALUES ('zw-1', 'zt-1', 'staff@zulu.example', 'Made-up Breach', 'email', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO device_wan (device_id, org_id, public_ip, seen_at) VALUES (424201, 4242, '198.51.100.77', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO exposure_host (ip, found, ports) VALUES ('198.51.100.77', TRUE, '[22]')",
        "INSERT INTO exposure_service (ip, port, transport, product, version, nvd_cves) VALUES ('198.51.100.77', 22, 'tcp', 'OpenSSH', '8.2p1', '[{\"cve\": \"CVE-2026-4242\"}]')",
        "INSERT INTO sec_windows_device (device_id, server, build_major, state, cve_count) VALUES (424201, FALSE, 26100, 'vulnerable', 1)",
        "INSERT INTO sec_windows_finding (device_id, cve, kb, fixed_build, title) VALUES (424201, 'CVE-2026-4444', '5900001', '10.0.26100.9711', 'A made-up Windows flaw')",
        "INSERT INTO device_process (device_id, key, sha256, name, trust) VALUES (424201, 'k-z', 'zz', 'zulu-tool.exe', 'unsigned')",
        "INSERT INTO sec_map_review (kind, name, company, devices) VALUES ('process', 'Zulu Widget', 'Zulu Tools', 1)",
    ]).await;
}

async fn ask(s: &Store, op: &str, p: &Value, scope: &Scope) -> (u16, Value) {
    let req = EvidenceRequest::parse(json!({ "op": op, "params": p }).to_string().as_bytes()).unwrap_or_else(|e| panic!("{op} {p}: {e}"));
    let (code, mut a) = s.call_scoped(&req, scope).await;
    if let Some(o) = a.as_object_mut() { o.remove("as_of"); }
    (code, a)
}

async fn every_op_answers_a_pinned_caller_only_for_its_own_client(db: TestDb) {
    let ops = ops();
    assert!(ops.len() >= 32, "the contract's ops: {ops:?}");
    let unknown: Vec<&String> = ops.iter().filter(|o| params(o).is_none()).collect();
    assert!(unknown.is_empty(), "a new op needs its params here, so its scope is checked: {unknown:?}");
    yankee(&db.pool).await;
    // Similar-CVE search on the real model, where this store has vectors: its device counts are scoped too.
    let e = embedder();
    let similar = match &e {
        Some(e) if msp_console::vectors::available(&db.pool).await.is_ok() => {
            msp_console::embed_job::EmbedJob::new(e.clone()).run(&db.pool).await.unwrap();
            Some(msp_console::embed::State::On(e.clone()))
        }
        _ => { eprintln!("no embedder or no vectors on this store: cve.similar is checked off"); None }
    };
    let s = match similar.clone() { Some(st) => Store::new(db.pool.clone()).with_similar(st), None => Store::new(db.pool.clone()) };
    let open = Scope::default();
    let pin = Scope { org_id: Some(4141), require_org: false };
    let mut before = Vec::new();
    for op in &ops {
        let p = params(op).unwrap();
        before.push((ask(&s, op, &p, &open).await, ask(&s, op, &p, &pin).await));
    }
    zulu(&db.pool).await;
    let mut checked = 0;
    for (op, (open_before, pin_before)) in ops.iter().zip(before) {
        let p = params(op).unwrap();
        let (open_after, pin_after) = (ask(&s, op, &p, &open).await, ask(&s, op, &p, &pin).await);
        if op == "cve.similar" && similar.is_none() { continue; }
        assert_ne!(open_before, open_after, "{op}: Zulu's data doesn't reach it unscoped, so this test couldn't see a leak; give it params that do");
        assert!(pin_after.0 < 500, "{op}: {pin_after:?}");
        assert_eq!(pin_before, pin_after, "{op}: a caller pinned to Yankee sees Zulu's data");
        let text = pin_after.1.to_string().to_lowercase();
        for marker in ["zulu", "424201", "198.51.100.77", "4242,", "4242}"] { assert!(!text.contains(marker), "{op}: {marker} in {text}"); }
        checked += 1;
    }
    let expected = ops.len() - usize::from(similar.is_none());
    assert_eq!(checked, expected, "every op was checked");
    // The ones a pinned caller is refused outright say so.
    for op in msp_console::ops::FLEET_OPS {
        let (code, a) = ask(&s, op.as_str(), &json!({}), &pin).await;
        assert_eq!((code, a["refused"].clone()), (403, json!(true)), "{a}");
    }
}
