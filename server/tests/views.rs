//! The whole evidence API on the console's own data, on both stores: every count the core views show equals the
//! rows of the list it opens (the counts lab, on a made-up fleet), the scope rules a portal relies on, keyset pages,
//! the advisories ahead of NVD (validated, saved once, applied at once, superseded with a reason), and the admin role
//! with Settings → Connectors. Every client, device, CVE and address here is invented.
mod common;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use common::*;
use http_body_util::BodyExt;
use msp_console::admin::{self, Admin};
use msp_console::advisory::{self, Action};
use msp_console::app::{router, AppState};
use msp_console::audit::AuditRecord;
use msp_console::contract::EvidenceRequest;
use msp_console::identity::{Identity, TrustedHeader, WithAdmins};
use msp_console::ops::{Scope, Store};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

both!(
    every_count_opens_exactly_the_rows_it_counts,
    the_answers_on_the_fleet_are_the_ones_expected,
    a_pinned_caller_never_sees_another_client,
    pages_walk_the_whole_list_and_a_bad_cursor_is_refused,
    an_advisory_is_checked_saved_once_applied_at_once_and_superseded_with_a_reason,
    search_folds_every_letter_not_only_ascii,
);

/// "ärzte" finds "ÄRZTE" and the other way round, on SQLite as on PostgreSQL.
async fn search_folds_every_letter_not_only_ascii(db: TestDb) {
    exec(&db.pool, "INSERT INTO client (org_id, name, name_key) VALUES (11, 'ÄRZTE Zentrum', 'rzte zentrum'), (12, 'Praxis Ärztehaus', 'praxis rztehaus'), (13, 'Ortho Example', 'ortho example')").await;
    exec(&db.pool, "INSERT INTO device (device_id, org_id, name, device_class) VALUES (1101, 11, 'ÉCOLE-PC', 'desktop')").await;
    let s = Store::new(db.pool.clone());
    for q in ["ärzte", "ÄRZTE", "Ärzte"] {
        let hits = call(&s, "search", json!({ "q": q })).await["data"].clone();
        let ids: Vec<i64> = hits.as_array().unwrap().iter().filter(|h| h["type"] == "client").map(|h| h["id"].as_i64().unwrap()).collect();
        assert_eq!(ids.iter().collect::<std::collections::BTreeSet<_>>(), [11, 12].iter().collect(), "{q}: {hits}");
    }
    let hits = call(&s, "search", json!({ "q": "école" })).await["data"].clone();
    assert_eq!(hits.as_array().unwrap().iter().filter(|h| h["type"] == "device").count(), 1, "{hits}");
    // And the escaping still holds: _ is a character, not a wildcard.
    assert_eq!(call(&s, "search", json!({ "q": "rzte_" })).await["data"], json!([]));
}

// ---------------------------------------------------------------- the fleet

/// Three clients: Alpha with a desktop running a KEV-listed Chrome, a server with 7-Zip and a Windows update missing,
/// and a laptop on a fixed Chrome; Beta with Chrome (also seen by Blackpoint) and a server with 7-Zip and Notepad++;
/// Gamma with nothing vulnerable. A deleted device carries a CVE that must never be counted.
async fn fleet(pool: &msp_console::db::Pool) {
    for q in [
        "INSERT INTO client (org_id, name, name_key) VALUES (7, 'Alpha Dental', 'alpha dental'), (8, 'Beta Clinic', 'beta clinic'), (9, 'Gamma Practice', 'gamma practice')",
        "INSERT INTO device (device_id, org_id, name, device_class, node_class) VALUES (701, 7, 'FRONT-1', 'desktop', 'WINDOWS_WORKSTATION'), (702, 7, 'ALPHA-DC', 'server', 'WINDOWS_SERVER'),
            (703, 7, 'LT-1', 'laptop', 'WINDOWS_WORKSTATION'), (801, 8, 'BETA-1', 'desktop', 'WINDOWS_WORKSTATION'), (802, 8, 'BETA-SRV', 'server', 'WINDOWS_SERVER'),
            (901, 9, 'GAMMA-1', 'desktop', 'WINDOWS_WORKSTATION')",
        "INSERT INTO device (device_id, org_id, name, device_class, deleted_at) VALUES (799, 7, 'GONE-1', 'desktop', '2026-10-01T00:00:00.000Z')",
        "INSERT INTO sec_evidence (device_id, product_key, version, source) VALUES (701, 'chrome', '120.0', 'ninja_software'), (701, 'chrome', '120.0', 'process'),
            (702, '7zip', '22.01', 'ninja_software'), (703, 'chrome', '131.0', 'ninja_software'), (801, 'chrome', '120.0', 'ninja_software'),
            (802, '7zip', '22.01', 'ninja_software'), (802, 'notepadpp', '8.5.7', 'ninja_software'), (901, 'chrome', '131.0', 'ninja_software'), (799, 'chrome', '120.0', 'ninja_software')",
        "INSERT INTO sec_pair_cve (product_key, version, cve_id, cvss, kev) VALUES ('chrome', '120.0', 'CVE-2026-0001', 9.8, TRUE), ('chrome', '120.0', 'CVE-2026-0002', 6.5, FALSE),
            ('7zip', '22.01', 'CVE-2026-0003', 7.8, FALSE), ('notepadpp', '8.5.7', 'CVE-2026-0004', 5.5, FALSE)",
        "INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, cvss, exploited) VALUES (702, 'CVE-2026-0005', 'msrc:windows', '', 'msrc', 8.1, TRUE),
            (801, 'CVE-2026-0001', 'bp:google:chrome', '', 'blackpoint', 9.8, FALSE)",
        "INSERT INTO sec_kev (cve_id, name) VALUES ('CVE-2026-0001', 'Made-up Chrome flaw')",
        "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, description) VALUES ('CVE-2026-0001', 9.8, 'CRITICAL', 'A made-up use-after-free.'), ('CVE-2026-0003', 7.8, 'HIGH', 'A made-up archive bug.')",
        "INSERT INTO sec_nvd_cpe (cve_id, cpe, ranges) VALUES ('CVE-2026-0001', 'google:chrome', '[]'), ('CVE-2026-0002', 'google:chrome', '[]'), ('CVE-2026-0003', '7-zip:7-zip', '[]')",
        "INSERT INTO software (device_id, org_id, name, publisher, version) VALUES (701, 7, 'Google Chrome', 'Google LLC', '120.0'), (702, 7, '7-Zip 22.01 (x64)', 'Igor Pavlov', '22.01'),
            (703, 7, 'Google Chrome', 'Google LLC', '131.0'), (801, 8, 'Google Chrome', 'Google LLC', '120.0'), (802, 8, 'Notepad++ (64-bit x64)', 'Notepad++ Team', '8.5.7'),
            (802, 8, '7-Zip 22.01 (x64)', 'Igor Pavlov', '22.01')",
    ] { msp_console::on_pool!(pool, p, _ => { sqlx::query(q).execute(p).await.unwrap(); }) }
}

async fn call(s: &Store, op: &str, params: Value) -> Value {
    let req = EvidenceRequest::parse(json!({ "op": op, "params": params }).to_string().as_bytes()).unwrap_or_else(|e| panic!("{op} {params}: {e}"));
    let (code, a) = s.call(&req).await;
    assert_eq!(code, 200, "{op} {params}: {a}");
    a
}
async fn total(s: &Store, op: &str, params: Value, key: &str) -> i64 {
    let a = call(s, op, params.clone()).await;
    a["totals"][key].as_i64().unwrap_or_else(|| panic!("{op} {params}: no totals.{key}: {a}"))
}
fn n(v: &Value) -> i64 { v.as_i64().unwrap_or_else(|| panic!("not a count: {v}")) }
/// `base` with `extra`'s keys set over it.
fn with(base: &Value, extra: Value) -> Value { let mut b = base.clone(); for (k, v) in extra.as_object().unwrap() { b[k] = v.clone(); } b }

/// The counts lab: each count beside the list it opens, with the filter it carries. `checked` proves how many ran.
async fn every_count_opens_exactly_the_rows_it_counts(db: TestDb) {
    fleet(&db.pool).await;
    let s = Store::new(db.pool.clone());
    let mut checked = 0;
    macro_rules! same { ($count:expr, $op:expr, $p:expr, $key:expr) => {{
        let (c, p) = ($count, $p);
        assert_eq!(c, total(&s, $op, p.clone(), $key).await, "{} != {} {} totals.{}", stringify!($count), $op, p, $key);
        checked += 1;
    }} }
    for src in [json!(null), json!(["ninja_software", "process"])] {
        let f = if src.is_null() { json!({}) } else { json!({ "source": src }) };
        // The Clients tab.
        let ov = call(&s, "clients.overview", f.clone()).await;
        for r in ov["data"].as_array().unwrap() {
            let o = with(&f, json!({ "org_id": r["org_id"] }));
            same!(n(&r["devices"]), "coverage.devices", o.clone(), "devices");
            same!(n(&r["vulnerable_devices"]), "devices.list", o.clone(), "devices");
            same!(n(&r["kev_devices"]), "devices.list", with(&o, json!({ "kev": true })), "devices");
            same!(n(&r["critical_devices"]), "devices.list", with(&o, json!({ "critical": true })), "devices");
            same!(n(&r["running_devices"]), "devices.list", with(&o, json!({ "running_only": true })), "devices");
            same!(n(&r["kev_servers"]), "devices.list", with(&o, json!({ "kev": true, "device_class": "server" })), "devices");
            for (k, c) in [("servers", "server"), ("desktops", "desktop"), ("laptops", "laptop")] {
                same!(n(&r[k]), "coverage.devices", with(&o, json!({ "device_class": c })), "devices");
                same!(n(&r[format!("vuln_{k}")]), "devices.list", with(&o, json!({ "device_class": c })), "devices");
            }
            if let Some(m) = r["max_cvss"].as_f64() { assert!(total(&s, "cves.list", with(&o, json!({ "cvss_min": m })), "cves").await >= 1); checked += 1; }
        }
        same!(n(&ov["totals"]["vulnerable_devices"]), "devices.list", f.clone(), "devices");
        same!(n(&ov["totals"]["kev_devices"]), "devices.list", with(&f, json!({ "kev": true })), "devices");
        same!(n(&ov["totals"]["kev_clients"]), "clients.list", with(&f, json!({ "kev": true })), "clients");
        same!(n(&ov["totals"]["devices"]), "coverage.devices", json!({}), "devices");
        for c in ov["by_class"].as_array().unwrap() {
            let cf = with(&f, json!({ "device_class": c["device_class"] }));
            same!(n(&c["devices"]), "coverage.devices", json!({ "device_class": c["device_class"] }), "devices");
            same!(n(&c["vulnerable"]), "devices.list", cf.clone(), "devices");
            same!(n(&c["kev"]), "devices.list", with(&cf, json!({ "kev": true })), "devices");
        }
        // The Software tab.
        for r in call(&s, "products.list", f.clone()).await["data"].as_array().unwrap() {
            let pf = with(&f, json!({ "product_key": r["product_key"] }));
            same!(n(&r["installed_devices"]), "devices.list", with(&pf, json!({ "has": "product" })), "devices");
            same!(n(&r["vulnerable_devices"]), "devices.list", pf.clone(), "devices");
            same!(n(&r["kev_devices"]), "devices.list", with(&pf, json!({ "kev": true })), "devices");
            same!(n(&r["critical_devices"]), "devices.list", with(&pf, json!({ "critical": true })), "devices");
            same!(n(&r["running_devices"]), "devices.list", with(&pf, json!({ "running_only": true })), "devices");
            same!(n(&r["clients"]), "clients.list", pf.clone(), "clients");
            // The product's own page.
            let pg = call(&s, "product.get", pf.clone()).await["data"].clone();
            same!(n(&pg["devices"]), "devices.list", with(&pf, json!({ "has": "product" })), "devices");
            same!(n(&pg["vulnerable_devices"]), "devices.list", pf.clone(), "devices");
            same!(n(&pg["cves"]), "cves.list", pf.clone(), "cves");
            same!(n(&pg["clients"]), "clients.list", pf.clone(), "clients");
            same!(n(&pg["versions"]), "product.versions", pf.clone(), "versions");
            same!(n(&pg["devices"]), "product.devices", pf.clone(), "devices");
            for v in call(&s, "product.versions", pf.clone()).await["data"].as_array().unwrap() {
                let vf = with(&pf, json!({ "version": if v["version"] == "" { json!("(none)") } else { v["version"].clone() } }));
                same!(n(&v["cves"]), "cves.list", vf.clone(), "cves");
                same!(n(&v["devices"]), "devices.list", with(&vf, json!({ "has": "product" })), "devices");
                same!(n(&v["running_devices"]), "devices.list", with(&vf, json!({ "has": "product", "source": ["process"] })), "devices");
            }
            for d in call(&s, "product.devices", pf.clone()).await["data"].as_array().unwrap() {
                same!(n(&d["cves"]), "cves.list", with(&pf, json!({ "device_id": d["device_id"] })), "cves");
            }
        }
        // A client's page.
        for org in [7, 8, 9] {
            let o = with(&f, json!({ "org_id": org }));
            let c = call(&s, "client.get", o.clone()).await["data"].clone();
            same!(n(&c["devices"]), "coverage.devices", json!({ "org_id": org }), "devices");
            same!(n(&c["devices_with_cves"]), "devices.list", o.clone(), "devices");
            same!(n(&c["cves"]), "cves.list", o.clone(), "cves");
            same!(n(&c["inventoried"]), "coverage.devices", json!({ "org_id": org, "has": "software" }), "devices");
            for src in msp_console::ops::SOURCES {
                let b = &c["by_source"][src];
                let so = with(&o, json!({ "source": [src] }));
                same!(n(&b["devices_with_cves"]), "devices.list", so.clone(), "devices");
                same!(n(&b["cves"]), "cves.list", so.clone(), "cves");
                same!(n(&b["kev_devices"]), "devices.list", with(&so, json!({ "kev": true })), "devices");
                same!(n(&b["devices_seen"]), "coverage.devices", json!({ "org_id": org, "source": [src], "seen": true }), "devices");
            }
            for d in c["device_rows"].as_array().unwrap() {
                let df = with(&f, json!({ "device_id": d["device_id"] }));
                same!(n(&d["cves"]), "cves.list", df.clone(), "cves");
                same!(n(&d["kev_cves"]), "cves.list", with(&df, json!({ "kev": true })), "cves");
                same!(n(&d["cves"]), "device.cves", df.clone(), "cves");
                same!(n(&d["software"]), "device.software", json!({ "device_id": d["device_id"] }), "software");
            }
            for p in c["products"].as_array().unwrap() {
                let pf = with(&o, json!({ "product_key": p["product_key"] }));
                same!(n(&p["devices"]), "devices.list", pf.clone(), "devices");
                same!(n(&p["kev_devices"]), "devices.list", with(&pf, json!({ "kev": true })), "devices");
            }
        }
        // A device's page, and its products.
        for dev in [701, 702, 703, 801, 802, 901] {
            let df = with(&f, json!({ "device_id": dev }));
            let d = call(&s, "device.get", df.clone()).await["data"].clone();
            same!(n(&d["cves"]), "cves.list", df.clone(), "cves");
            same!(n(&d["kev_cves"]), "cves.list", with(&df, json!({ "kev": true })), "cves");
            same!(n(&d["products"]), "device.products", df.clone(), "products");
            for src in msp_console::ops::SOURCES { same!(n(&d["by_source"][src]["cves"]), "cves.list", with(&df, json!({ "source": [src] })), "cves"); }
            for p in call(&s, "device.products", df.clone()).await["data"].as_array().unwrap() {
                same!(n(&p["cves"]), "cves.list", with(&df, json!({ "product_key": p["product_key"], "version": p["version"] })), "cves");
            }
        }
        // A CVE, and the CVE list's own counts.
        for r in call(&s, "cves.list", f.clone()).await["data"].as_array().unwrap() {
            let cf = with(&f, json!({ "cve_id": r["cve_id"] }));
            same!(n(&r["devices"]), "devices.list", cf.clone(), "devices");
            same!(n(&r["running_devices"]), "devices.list", with(&cf, json!({ "source": ["process"] })), "devices");
            let g = call(&s, "cve.get", cf.clone()).await["data"].clone();
            same!(n(&g["devices"]), "cve.devices", cf.clone(), "devices");
            same!(n(&g["clients"]), "clients.list", cf.clone(), "clients");
            for src in msp_console::ops::SOURCES { same!(n(&g["devices_by_source"][src]), "devices.list", with(&cf, json!({ "source": [src] })), "devices"); }
        }
    }
    // Coverage: each client's per-source counts.
    for r in call(&s, "coverage.list", json!({})).await["data"].as_array().unwrap() {
        let o = json!({ "org_id": r["org_id"] });
        same!(n(&r["devices"]), "coverage.devices", o.clone(), "devices");
        same!(n(&r["inventoried"]), "coverage.devices", with(&o, json!({ "has": "software" })), "devices");
        for src in msp_console::ops::SOURCES { same!(n(&r["by_source"][src]), "coverage.devices", with(&o, json!({ "source": [src], "seen": true })), "devices"); }
    }
    assert!(checked > 300, "the lab ran its counts: {checked}");
}

/// The numbers themselves, so the lab above isn't comparing two empty answers.
async fn the_answers_on_the_fleet_are_the_ones_expected(db: TestDb) {
    fleet(&db.pool).await;
    let s = Store::new(db.pool.clone());
    let alpha = call(&s, "clients.overview", json!({})).await["data"].as_array().unwrap().iter().find(|r| r["org_id"] == 7).unwrap().clone();
    assert_eq!((n(&alpha["devices"]), n(&alpha["vulnerable_devices"]), n(&alpha["kev_devices"]), n(&alpha["running_devices"]), n(&alpha["critical_devices"])), (3, 2, 1, 1, 1),
        "the deleted device isn't counted: {alpha}");
    // A CVE seen by two sources on one device is one CVE there (a counting rule).
    assert_eq!(total(&s, "cves.list", json!({ "device_id": 801 }), "cves").await, 2);
    let d = call(&s, "cve.devices", json!({ "cve_id": "CVE-2026-0001" })).await;
    assert_eq!(d["totals"], json!({ "devices": 2, "clients": 2 }));
    let beta = d["data"].as_array().unwrap().iter().find(|x| x["device_id"] == 801).unwrap();
    assert_eq!(beta["sources"], json!(["ninja_software", "blackpoint"]));
    assert_eq!(beta["evidence"].as_array().unwrap().len(), 2, "each piece of evidence behind it");
    // Exploited first: the Windows CVE leads Alpha's list.
    assert_eq!(call(&s, "cves.list", json!({ "org_id": 7 })).await["data"][0]["cve_id"], "CVE-2026-0005");
    // Labels: the map's, Windows for Microsoft's updates, Blackpoint's words.
    let prods = call(&s, "cve.products", json!({ "cve_id": "CVE-2026-0001" })).await;
    let labels: Vec<&str> = prods["data"].as_array().unwrap().iter().map(|x| x["label"].as_str().unwrap()).collect();
    assert_eq!(labels, ["Google Chrome", "google chrome"]);
    assert_eq!(call(&s, "device.products", json!({ "device_id": 702 })).await["data"][0]["label"], "7-Zip");
    assert_eq!(call(&s, "cve.products", json!({ "cve_id": "CVE-2026-0005" })).await["data"][0]["label"], "Windows");
    // The Software tab: installed and vulnerable, and NVD's catalogue.
    let chrome = call(&s, "products.list", json!({})).await["data"].as_array().unwrap().iter().find(|x| x["product_key"] == "chrome").unwrap().clone();
    assert_eq!((n(&chrome["installed_devices"]), n(&chrome["vulnerable_devices"]), n(&chrome["kev_devices"]), n(&chrome["known_cves"])), (4, 2, 2, 2), "{chrome}");
    let vs = call(&s, "product.versions", json!({ "product_key": "chrome" })).await;
    assert_eq!(vs["data"].as_array().unwrap().iter().map(|v| v["version"].as_str().unwrap()).collect::<Vec<_>>(), ["120.0", "131.0"]);
    // A device's software, recognised first (the match job hasn't run, so nothing is recognised yet).
    assert_eq!(total(&s, "device.software", json!({ "device_id": 802 }), "software").await, 2);
    // Coverage: Alpha's three, NinjaOne saw all three, Microsoft's updates one.
    let cov = call(&s, "coverage.list", json!({})).await["data"].as_array().unwrap().iter().find(|r| r["org_id"] == 7).unwrap().clone();
    assert_eq!((n(&cov["devices"]), n(&cov["by_source"]["ninja_software"]), n(&cov["by_source"]["msrc"]), n(&cov["inventoried"])), (3, 3, 1, 3));
    assert_eq!(total(&s, "coverage.devices", json!({ "org_id": 8, "source": ["blackpoint"], "seen": false }), "devices").await, 1, "the gap: BETA-SRV");
    // Search: devices, products, clients, within the fleet.
    let hits = call(&s, "search", json!({ "q": "beta" })).await["data"].clone();
    assert!(hits.as_array().unwrap().iter().any(|h| h["type"] == "client" && h["id"] == 8) && hits.as_array().unwrap().iter().any(|h| h["type"] == "device" && h["id"] == 801), "{hits}");
    // msa: nothing tells the console which clients are MSA, so it says so rather than answer wrongly.
    let (code, a) = s.call(&EvidenceRequest::parse(br#"{"op":"devices.list","params":{"msa":true}}"#).unwrap()).await;
    assert_eq!((code, a["error"].as_str().unwrap()), (400, msp_console::ops::NO_MSA));
    // A device that isn't there is a 404, not an empty page.
    let (code, _) = s.call(&EvidenceRequest::parse(br#"{"op":"device.get","params":{"device_id":799}}"#).unwrap()).await;
    assert_eq!(code, 404, "a deleted device is gone");
}

async fn a_pinned_caller_never_sees_another_client(db: TestDb) {
    fleet(&db.pool).await;
    let s = Store::new(db.pool.clone());
    let pin = Scope { org_id: Some(7), require_org: false };
    let ask = |op: &str, p: Value| EvidenceRequest::parse(json!({ "op": op, "params": p }).to_string().as_bytes()).unwrap();
    // Its own client, with no org named: pinned.
    let (code, a) = s.call_scoped(&ask("devices.list", json!({})), &pin).await;
    assert_eq!(code, 200);
    assert!(a["data"].as_array().unwrap().iter().all(|d| d["org_id"] == 7) && a["totals"]["devices"] == 2, "{a}");
    // Naming another client is refused, never answered for the pinned one.
    let (code, a) = s.call_scoped(&ask("cves.list", json!({ "org_id": 8 })), &pin).await;
    assert_eq!((code, a["refused"].clone()), (403, json!(true)), "{a}");
    // A device, a CVE, a product: only what's at the pinned client.
    assert_eq!(s.call_scoped(&ask("device.get", json!({ "device_id": 801 })), &pin).await.0, 404);
    let (_, a) = s.call_scoped(&ask("cve.get", json!({ "cve_id": "CVE-2026-0001" })), &pin).await;
    assert_eq!((a["data"]["devices"].clone(), a["data"]["clients"].clone()), (json!(1), json!(1)));
    let (_, a) = s.call_scoped(&ask("clients.overview", json!({})), &pin).await;
    assert_eq!(a["data"].as_array().unwrap().len(), 1);
    let (_, a) = s.call_scoped(&ask("search", json!({ "q": "beta" })), &pin).await;
    assert_eq!(a["data"], json!([]), "another client's name and devices aren't found: {a}");
    // A filter can't widen it: a device id of another client finds nothing.
    let (_, a) = s.call_scoped(&ask("cves.list", json!({ "device_id": 801 })), &pin).await;
    assert_eq!(a["totals"]["cves"], 0);
    // A caller that must name one client is refused without one.
    let need = Scope { org_id: None, require_org: true };
    assert_eq!(s.call_scoped(&ask("devices.list", json!({})), &need).await.0, 403);
    assert_eq!(s.call_scoped(&ask("devices.list", json!({ "org_id": 8 })), &need).await.0, 200);
}

async fn pages_walk_the_whole_list_and_a_bad_cursor_is_refused(db: TestDb) {
    fleet(&db.pool).await;
    let s = Store::new(db.pool.clone());
    for (op, key, id) in [("devices.list", "devices", "device_id"), ("cves.list", "cves", "cve_id"), ("clients.overview", "clients", "org_id"), ("coverage.devices", "devices", "device_id")] {
        let all = total(&s, op, json!({}), key).await;
        let (mut seen, mut cursor, mut pages) = (Vec::new(), None::<String>, 0);
        loop {
            let mut p = json!({ "limit": 1 });
            if let Some(c) = &cursor { p["cursor"] = json!(c); }
            let a = call(&s, op, p).await;
            seen.extend(a["data"].as_array().unwrap().iter().map(|x| x[id].to_string()));
            pages += 1;
            match a["next_cursor"].as_str() { Some(c) => cursor = Some(c.to_string()), None => break }
        }
        assert_eq!((seen.len() as i64, pages as i64), (all, all.max(1)), "{op}");
        assert_eq!(seen.iter().collect::<std::collections::BTreeSet<_>>().len(), seen.len(), "{op}: no row twice");
    }
    let (code, a) = s.call(&EvidenceRequest::parse(br#"{"op":"devices.list","params":{"cursor":"not-a-cursor"}}"#).unwrap()).await;
    assert_eq!((code, a["error"].as_str().unwrap()), (400, "invalid cursor"));
}

// ---------------------------------------------------------------- advisories

fn adv(extra: Value) -> Value {
    with(&json!({ "advisory_id": "EXAMPLE-2026-001", "cve_id": "cve-2026-9999", "title": "A made-up Notepad++ flaw before 8.6", "severity": "high", "cvss": 8.2,
        "product_key": "notepadpp", "product_label": "Notepad++", "match": { "name_re": "^Notepad\\+\\+" }, "ranges": [{ "si": "8.5.0", "ee": "8.6" }], "fixed_in": ["8.6"],
        "url": "https://example.com/advisory" }), extra)
}

async fn an_advisory_is_checked_saved_once_applied_at_once_and_superseded_with_a_reason(db: TestDb) {
    fleet(&db.pool).await;
    let s = Store::new(db.pool.clone());
    // Checked field by field, without echoing what was sent.
    let bad = advisory::validate(&adv(json!({ "advisory_id": "x", "cve_id": "CVE-12", "match": { "name_re": "(" }, "ranges": [{ "si": "eight" }], "url": "http://example.com", "cvss": 11 }))).unwrap_err();
    for want in ["advisory_id", "cve_id", "match.name_re", "ranges", "url", "cvss"] { assert!(bad.iter().any(|e| e.starts_with(want)), "{want}: {bad:?}"); }
    assert!(advisory::validate(&adv(json!({ "match": {} }))).unwrap_err().iter().any(|e| e.contains("at least one")));
    // Saved twice (a double click): one advisory.
    for _ in 0..2 { advisory::save(&db.pool, Action::Save, &adv(json!({})), "", "admin@example.com").await.ok().unwrap(); }
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_advisory").await, 1);
    // Applied at once: BETA-SRV has Notepad++ 8.5.7, in the range.
    let a = call(&s, "advisories.list", json!({})).await;
    assert_eq!((a["data"][0]["cve_id"].clone(), a["data"][0]["devices"].clone(), a["data"][0]["added_by"].clone()), (json!("CVE-2026-9999"), json!(1), json!("admin@example.com")));
    let g = call(&s, "cve.get", json!({ "cve_id": "CVE-2026-9999" })).await["data"].clone();
    assert_eq!((g["devices"].clone(), g["devices_by_source"]["advisory"].clone(), g["advisories"][0]["devices"].clone()), (json!(1), json!(1), json!(1)));
    assert_eq!(total(&s, "devices.list", json!({ "advisory_id": "EXAMPLE-2026-001" }), "devices").await, 1);
    assert_eq!(call(&s, "search", json!({ "q": "made-up notepad" })).await["data"][0], json!({ "type": "cve", "id": "CVE-2026-9999", "label": "named by an advisory" }));
    // A running binary's rows (the process match's, another area) are never touched by the installed apply.
    exec(&db.pool, "INSERT INTO sec_evidence_cve (device_id, cve_id, product_key, version, source, detail) VALUES (701, 'CVE-2026-9999', 'notepadpp', '8.5.7', 'advisory', '{\"via\":\"running\",\"advisories\":[{\"advisory_id\":\"EXAMPLE-2026-001\"}]}')").await;
    advisory::apply(&db.pool).await.unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_evidence_cve WHERE source = 'advisory'").await, 2);
    // A rule about running binaries only (product_re) doesn't name installed software.
    advisory::save(&db.pool, Action::Save, &adv(json!({ "advisory_id": "EXAMPLE-2026-002", "match": { "product_re": "Notepad" } })), "", "admin@example.com").await.ok().unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_evidence_cve WHERE source = 'advisory' AND device_id = 802").await, 1);
    // Superseding needs a reason; with one, its evidence goes, and the note says who and why.
    assert!(matches!(advisory::save(&db.pool, Action::Supersede, &json!({ "advisory_id": "EXAMPLE-2026-001" }), " ", "admin@example.com").await, Err(advisory::SaveError::Bad(_))));
    advisory::save(&db.pool, Action::Supersede, &json!({ "advisory_id": "EXAMPLE-2026-001" }), "NVD covers it now", "admin@example.com").await.ok().unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_evidence_cve WHERE source = 'advisory' AND device_id = 802").await, 0);
    let a = call(&s, "advisories.list", json!({ "cve_id": "CVE-2026-9999" })).await;
    let one = a["data"].as_array().unwrap().iter().find(|x| x["advisory_id"] == "EXAMPLE-2026-001").unwrap().clone();
    assert_eq!(one["status"], "superseded");
    assert!(one["notes"].as_str().unwrap().contains("superseded by admin@example.com") && one["notes"].as_str().unwrap().contains("NVD covers it now"));
    advisory::save(&db.pool, Action::Reactivate, &json!({ "advisory_id": "EXAMPLE-2026-001" }), "", "admin@example.com").await.ok().unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_evidence_cve WHERE source = 'advisory' AND device_id = 802").await, 1);
    assert!(matches!(advisory::save(&db.pool, Action::Reactivate, &json!({ "advisory_id": "NOPE-1" }), "", "a@example.com").await, Err(advisory::SaveError::NotFound)));
    // And the match job applies them too, after the inventory.
    let o = msp_console::inventory::run(&db.pool).await.unwrap();
    assert_eq!(o.detail["advisory_rows"], 1, "{:?}", o.detail);
}

// ---------------------------------------------------------------- the admin role, Settings → Connectors

const ADMIN: &str = "admin@example.com";
const TECH: &str = "tech@example.com";
const LEGACY_SECRET: &str = "legacy-plain-ninja-secret-1f2e";

struct Rig { app: axum::Router, audit: Arc<Mutex<Vec<AuditRecord>>>, saved: Arc<AtomicU32>, dir: std::path::PathBuf, _db: TestDb }
impl Drop for Rig { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.dir); } }

/// A configured console behind a trusted header (ADMIN_EMAILS: one admin), its config file holding sign-in and
/// NinjaOne, NinjaOne's secret still in plaintext (a file from before encryption); NVD_URL set by environment.
async fn rig(vendors: &str) -> Rig {
    let db = test_db().await;
    let dir = std::env::temp_dir().join(format!("msp-admin-{}", hex(6)));
    std::fs::create_dir_all(dir.join("config")).unwrap();
    let file: std::collections::BTreeMap<String, String> = [("AUTH_MODE", "proxy"), ("PROXY_KIND", "trusted_header"), ("TRUSTED_HEADER", "x-who"), ("TRUSTED_PROXY_CIDRS", "127.0.0.1/32"),
        ("ADMIN_EMAILS", ADMIN), ("DATABASE_PATH", "/tmp/never-opened.db"), ("NINJA_BASE_URL", &format!("{vendors}/ninja")), ("NINJA_CLIENT_ID", "old-id"), ("NINJA_CLIENT_SECRET", LEGACY_SECRET)]
        .into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    msp_console::setup::write_config(&dir.join("config/config.json"), &file).unwrap();
    let env: HashMap<String, String> = [("CONFIG_PATH", dir.join("config/config.json").display().to_string()), ("MASTER_KEY_PATH", dir.join("key/master.key").display().to_string()),
        ("NVD_URL", format!("{vendors}/nvd"))].into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let audit = Arc::new(Mutex::new(Vec::new()));
    let saved = Arc::new(AtomicU32::new(0));
    let id: Arc<dyn Identity> = Arc::new(WithAdmins { inner: Arc::new(TrustedHeader { header: "x-who".into(), cidrs: vec!["127.0.0.1/32".parse().unwrap()] }), emails: vec![ADMIN.into()] });
    let (a1, a2, sv) = (audit.clone(), audit.clone(), saved.clone());
    let mut admin = Admin::new(id.clone(), env, msp_console::http_client(), db.pool.clone(), Arc::new(move || { sv.fetch_add(1, Ordering::SeqCst); }));
    admin.audit = Arc::new(move |r| a1.lock().unwrap().push(r));
    let state = AppState { identity: id, store: Store::new(db.pool.clone()), audit: Arc::new(move |r| a2.lock().unwrap().push(r)) };
    let app = router(state, None).merge(admin::router(Arc::new(admin))).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
    Rig { app, audit, saved, dir, _db: db }
}
fn req(method: &str, path: &str, who: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(w) = who { b = b.header("x-who", w); }
    match body { Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(), None => b.body(Body::empty()).unwrap() }
}
async fn send(r: &Rig, rq: Request<Body>) -> (StatusCode, Value) {
    let res = r.app.clone().oneshot(rq).await.unwrap();
    let st = res.status();
    (st, serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap_or(Value::Null))
}

#[tokio::test]
async fn only_an_admin_changes_settings_and_advisories_and_everyone_can_tell_which_they_are() {
    let (vendors, _) = vendors().await;
    let r = rig(&vendors).await;
    assert_eq!(send(&r, req("GET", "/api/me", Some(ADMIN), None)).await.1["admin"], true);
    assert_eq!(send(&r, req("GET", "/api/me", Some("ADMIN@example.com"), None)).await.1["admin"], true, "addresses compare without case");
    assert_eq!(send(&r, req("GET", "/api/me", Some(TECH), None)).await.1["admin"], false);
    for (m, path, body) in [("GET", "/api/admin/connectors", None), ("POST", "/api/admin/connectors/test", Some(json!({ "section": "ninja" }))),
                            ("POST", "/api/admin/connectors/save", Some(json!({ "section": "ninja", "values": {} }))), ("POST", "/api/admin/advisories", Some(json!({ "action": "save", "advisory": adv(json!({})) })))] {
        let (st, b) = send(&r, req(m, path, Some(TECH), body.clone())).await;
        assert_eq!((st, b["error"].as_str()), (StatusCode::FORBIDDEN, Some(admin::NOT_ADMIN)), "{path}");
        assert_eq!(send(&r, req(m, path, None, body)).await.0, StatusCode::UNAUTHORIZED, "{path}");
    }
    assert_eq!(count(&r._db.pool, "SELECT count(*) FROM sec_advisory").await, 0, "nothing was saved by anyone but an admin");
    assert_eq!(r.saved.load(Ordering::SeqCst), 0);
    assert!(r.audit.lock().unwrap().iter().any(|x| x.status == 403 && x.who.as_deref() == Some(TECH) && x.op.as_deref() == Some("admin.connectors.save")), "the refusal is audited, naming who");
    // An admin's advisory: saved, applied, and audited by its ids alone.
    let (st, b) = send(&r, req("POST", "/api/admin/advisories", Some(ADMIN), Some(json!({ "action": "save", "advisory": adv(json!({})) })))).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let a = r.audit.lock().unwrap();
    let line = a.iter().find(|x| x.op.as_deref() == Some("admin.advisories.save")).unwrap();
    assert_eq!((line.who.as_deref(), line.params.clone()), (Some(ADMIN), json!({ "advisory_id": "EXAMPLE-2026-001", "cve_id": "cve-2026-9999" })));
    assert!(!serde_json::to_string(&*a).unwrap().contains("Notepad"), "no title or rule in the audit");
}

#[tokio::test]
async fn settings_shows_tests_and_saves_a_connector_without_ever_showing_a_secret() {
    let (vendors, hits) = vendors().await;
    let r = rig(&vendors).await;
    let (st, s) = send(&r, req("GET", "/api/admin/connectors", Some(ADMIN), None)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(s["sections"], json!(["ninja", "halo", "nvd", "msrc", "blackpoint", "shodan"]), "every connector the wizard registers, and not the database or sign-in: {s}");
    assert_eq!(s["keys"]["NINJA_CLIENT_SECRET"], json!({ "set": true, "env": false, "value": null, "secret": true, "section": "ninja" }));
    assert_eq!(s["keys"]["NINJA_CLIENT_ID"]["value"], "old-id");
    assert_eq!((s["keys"]["NVD_URL"]["env"].clone(), s["keys"]["NVD_URL"]["value"].clone()), (json!(true), json!(format!("{vendors}/nvd"))), "the environment's, read-only");
    assert_eq!(s["plaintext_secrets"], json!(["NINJA_CLIENT_SECRET"]));
    assert!(!s.to_string().contains(LEGACY_SECRET));
    // The live Test, with the stored secret: the stand-in refuses it (it wants its own), and says only the status.
    let (_, t) = send(&r, req("POST", "/api/admin/connectors/test", Some(ADMIN), Some(json!({ "section": "ninja", "values": { "NINJA_CLIENT_SECRET": NINJA_SECRET } })))).await;
    assert_eq!(t["ok"], true, "{t}");
    assert!(hits.lock().unwrap().get("ninja_token").copied().unwrap_or(0) >= 1, "the test really called NinjaOne");
    // A stored secret never goes to a new address the caller typed.
    let (_, t) = send(&r, req("POST", "/api/admin/connectors/test", Some(ADMIN), Some(json!({ "section": "ninja", "values": { "NINJA_BASE_URL": "http://127.0.0.1:9/elsewhere", "NINJA_CLIENT_ID": "old-id" } })))).await;
    assert_eq!(t["message"], msp_console::setup::NEW_ADDRESS_TEST);
    let (st, b) = send(&r, req("POST", "/api/admin/connectors/save", Some(ADMIN), Some(json!({ "section": "ninja", "values": { "NINJA_BASE_URL": "http://127.0.0.1:9/elsewhere", "NINJA_CLIENT_ID": "old-id" } })))).await;
    assert_eq!((st, b["error"].as_str()), (StatusCode::BAD_REQUEST, Some(msp_console::setup::NEW_ADDRESS_SAVE)));
    // A half-filled connector refuses with start-up's own words, and nothing is written.
    let before = std::fs::read_to_string(r.dir.join("config/config.json")).unwrap();
    let (st, b) = send(&r, req("POST", "/api/admin/connectors/save", Some(ADMIN), Some(json!({ "section": "halo", "values": { "HALO_BASE_URL": format!("{vendors}/halo/api") } })))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(b["error"].as_str().unwrap().contains("HaloPSA needs"), "{b}");
    assert_eq!(std::fs::read_to_string(r.dir.join("config/config.json")).unwrap(), before);
    assert_eq!(r.saved.load(Ordering::SeqCst), 0);
    // A change: the client id, the stored secret kept (not sent), and the legacy plaintext one encrypted on the way.
    let (st, b) = send(&r, req("POST", "/api/admin/connectors/save", Some(ADMIN), Some(json!({ "section": "ninja",
        "values": { "NINJA_BASE_URL": format!("{vendors}/ninja"), "NINJA_CLIENT_ID": "new-id", "HALO_CLIENT_ID": "sneaked-in" } })))).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!((b["restarting"].clone(), b["changed"].clone(), b["reencrypted"].clone()), (json!(true), json!(["NINJA_CLIENT_ID"]), json!(["NINJA_CLIENT_SECRET"])));
    assert_eq!(r.saved.load(Ordering::SeqCst), 1, "it restarts with the change");
    let file = std::fs::read_to_string(r.dir.join("config/config.json")).unwrap();
    assert!(!file.contains(LEGACY_SECRET) && file.contains("enc:v1:") && file.contains("new-id") && !file.contains("sneaked-in") && !file.contains("NVD_URL"), "{file}");
    let env: HashMap<String, String> = [("CONFIG_PATH", r.dir.join("config/config.json").display().to_string()), ("MASTER_KEY_PATH", r.dir.join("key/master.key").display().to_string())]
        .into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let msp_console::config::Startup::Configured(cfg) = msp_console::config::load(&env, &|p| std::fs::read_to_string(p)).unwrap() else { panic!("unconfigured") };
    assert_eq!((cfg.connectors.ninja.as_ref().unwrap().client_id.as_str(), cfg.connectors.ninja.as_ref().unwrap().client_secret.as_str()), ("new-id", LEGACY_SECRET));
    assert!(cfg.warnings.is_empty(), "no plaintext secret left: {:?}", cfg.warnings);
    // The same again changes nothing, and doesn't restart.
    let (_, b) = send(&r, req("POST", "/api/admin/connectors/save", Some(ADMIN), Some(json!({ "section": "ninja", "values": { "NINJA_BASE_URL": format!("{vendors}/ninja"), "NINJA_CLIENT_ID": "new-id" } })))).await;
    assert_eq!((b["restarting"].clone(), r.saved.load(Ordering::SeqCst)), (json!(false), 1));
    // Turning it off clears the section, its secret included.
    let (_, b) = send(&r, req("POST", "/api/admin/connectors/save", Some(ADMIN), Some(json!({ "section": "ninja", "off": true })))).await;
    assert_eq!(b["changed"], json!(["NINJA_BASE_URL", "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET"]));
    // The audit: who, and which settings, never a value.
    let a = r.audit.lock().unwrap();
    let saves: Vec<&AuditRecord> = a.iter().filter(|x| x.op.as_deref() == Some("admin.connectors.save.ninja") && x.status == 200).collect();
    assert_eq!(saves.len(), 3);
    assert_eq!((saves[0].who.as_deref(), saves[0].params["changed"].clone()), (Some(ADMIN), json!(["NINJA_CLIENT_ID"])));
    let all = serde_json::to_string(&*a).unwrap();
    for secret in [LEGACY_SECRET, NINJA_SECRET, "new-id", "old-id"] { assert!(!all.contains(secret), "{secret} in the audit"); }
}

#[test]
fn admins_are_chosen_by_sign_in_mode_and_a_setting_for_another_mode_refuses() {
    use msp_console::config::{load, Admins, Startup};
    let env = |kv: &[(&str, &str)]| -> HashMap<String, String> { kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() };
    let none = |_: &std::path::Path| -> std::io::Result<String> { Err(std::io::ErrorKind::NotFound.into()) };
    let proxy = [("AUTH_MODE", "proxy"), ("PROXY_KIND", "trusted_header"), ("TRUSTED_HEADER", "x-who"), ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8"), ("CONFIG_PATH", "/nonexistent/c.json")];
    let cfg = |kv: &[(&str, &str)]| match load(&env(kv), &none) { Ok(Startup::Configured(c)) => Ok(c), Ok(_) => panic!("unconfigured"), Err(e) => Err(e) };
    let mut p = proxy.to_vec(); p.push(("ADMIN_EMAILS", " A@Example.com, b@example.com ,"));
    assert_eq!(cfg(&p).unwrap().admins, Admins::Emails(vec!["a@example.com".into(), "b@example.com".into()]));
    assert_eq!(cfg(&proxy).unwrap().admins, Admins::None);
    let mut p = proxy.to_vec(); p.push(("OIDC_ADMIN_GROUP", "group-admins"));
    assert!(cfg(&p).unwrap_err().contains("ADMIN_EMAILS"));
    let oidc = [("AUTH_MODE", "oidc"), ("OIDC_ISSUER", "https://login.example.com/t/v2.0"), ("OIDC_CLIENT_ID", "c"), ("OIDC_CLIENT_SECRET", "s"), ("OIDC_ALLOWED_GROUP", "g"),
        ("SESSION_KEY", "a-session-key-of-at-least-thirty-two-chars"), ("PUBLIC_URL", "https://console.example.com"), ("CONFIG_PATH", "/nonexistent/c.json")];
    let mut o = oidc.to_vec(); o.push(("OIDC_ADMIN_GROUP", "group-admins"));
    assert_eq!(cfg(&o).unwrap().admins, Admins::Group("group-admins".into()));
    let mut o = oidc.to_vec(); o.push(("ADMIN_EMAILS", "a@example.com"));
    assert!(cfg(&o).unwrap_err().contains("OIDC_ADMIN_GROUP"));
    assert_eq!(cfg(&[("AUTH_MODE", "dev_insecure"), ("CONFIG_PATH", "/nonexistent/c.json")]).unwrap().admins, Admins::Local);
}

#[tokio::test]
async fn on_only_this_computer_the_local_user_is_the_admin() {
    let who = msp_console::identity::DevInsecure.identify(&Default::default(), "127.0.0.1".parse().unwrap()).await.unwrap();
    assert!(who.admin);
}
