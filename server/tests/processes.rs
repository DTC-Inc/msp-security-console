//! Running processes: the endpoint script's payload read back from NinjaOne, classified into products, and the
//! `process` evidence source; the review of names the mapping wouldn't decide, by a signed-in user, audited, and
//! honoured by the match. The payloads here are made up (example names, synthetic hashes). Acceptance criteria: an unknown schema is refused; an older
//! payload never replaces a newer one; a quiet run downloads no payloads; the binary's name, hash and path only.
mod common;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{Query, State};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use common::*;
use http_body_util::BodyExt;
use msp_console::connectors::ninja::Ninja;
use msp_console::connectors::ninja_processes::NinjaProcesses;
use msp_console::contract::{Decide, EvidenceRequest, ReviewDecision, ReviewKind};
use msp_console::ops::Store;
use msp_console::process::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

both!(processes_are_read_quietly_classified_and_reviewed);

fn sha(c: char) -> String { std::iter::repeat_n(c, 64).collect() }
fn bin(name: &str, product: &str, company: &str, version: &str, status: &str, c: char) -> Value {
    json!({ "key": format!("sha256:{}", sha(c)), "sha256": sha(c), "name": name, "paths": [format!("C:\\Program Files\\Example\\{name}")], "pathCount": 1,
            "fileVersion": version, "product": product, "company": company, "signer": company, "signatureStatus": status, "signatureValid": status == "Valid",
            "count": 2, "users": ["EXAMPLE\\someone"], "services": ["ExampleSvc"], "firstStart": "2026-11-01T08:00:00Z" })
}
fn doc(collected: &str, binaries: Vec<Value>) -> Value {
    json!({ "schema": 1, "scriptVersion": "1.3.3", "collectedAt": collected, "processCount": 9, "binaryCount": binaries.len(), "unsignedCount": 1, "binaries": binaries })
}
fn encode(d: &Value) -> String {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(d.to_string().as_bytes()).unwrap();
    base64::engine::general_purpose::STANDARD.encode(e.finish().unwrap())
}
/// What NinjaOne's API returns for the WYSIWYG field: { text, html }, the editor wrapping and breaking the value.
fn as_field(b64: &str) -> Value {
    let wrapped: String = b64.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");
    json!({ "text": b64, "html": format!("<p>{wrapped}</p>") })
}
fn fleet() -> Vec<Value> {
    vec![bin("chrome.exe", "Google Chrome", "Google LLC", "120.0.6099.71", "Valid", 'a'),
         bin("svchost.exe", "Microsoft® Windows® Operating System", "Microsoft Corporation", "10.0.26100.1", "Valid", 'b'),
         bin("widget.exe", "Widget", "Nobody Ltd", "2.1.0", "NotSigned", 'c'),
         json!({ "key": "name:system", "name": "System", "unhashed": true, "unhashedReason": "no-path", "count": 1 })]
}

// ---------------------------------------------------------------- the pure rules

#[test]
fn a_payload_decodes_only_whole_and_known() {
    let d = doc("2026-11-05T17:53:17Z", fleet());
    let b64 = encode(&d);
    let Decoded::Doc(ok) = decode_inventory(&as_field(&b64)) else { panic!("decodes") };
    assert_eq!(ok["binaries"].as_array().unwrap().len(), 4);
    assert!(matches!(decode_inventory(&json!({ "html": as_field(&b64)["html"] })), Decoded::Doc(_)), "html with tags and line breaks");
    assert!(matches!(decode_inventory(&json!(b64)), Decoded::Doc(_)), "a bare string");
    assert_eq!(decode_inventory(&Value::Null), Decoded::Absent);
    assert_eq!(decode_inventory(&json!({ "text": "" })), Decoded::Absent);
    let bad = |mut x: Value, k: &str, v: Value| { x[k] = v; decode_inventory(&json!(encode(&x))) };
    assert!(matches!(bad(d.clone(), "schema", json!(2)), Decoded::Bad(m) if m.contains("schema 2")), "an unknown schema is refused and says which");
    assert!(matches!(bad(d.clone(), "schema", Value::Null), Decoded::Bad(_)));
    assert!(matches!(bad(d.clone(), "binaries", Value::Null), Decoded::Bad(_)));
    assert!(matches!(bad(d.clone(), "collectedAt", json!("yesterday")), Decoded::Bad(_)));
    assert!(matches!(decode_inventory(&json!("not base64 at all!!")), Decoded::Bad(m) if m.contains("base64")));
    let plain = base64::engine::general_purpose::STANDARD.encode("plain text, not gzip");
    assert!(matches!(decode_inventory(&json!(plain)), Decoded::Bad(m) if m.contains("gzip")));
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(b"{not json").unwrap();
    assert!(matches!(decode_inventory(&json!(base64::engine::general_purpose::STANDARD.encode(e.finish().unwrap()))), Decoded::Bad(m) if m.contains("JSON")));
}

#[test]
fn trust_rows_and_what_is_kept() {
    assert_eq!((trust_of(Some("Valid"), false), trust_of(Some("NotSigned"), false), trust_of(Some("HashMismatch"), false), trust_of(Some("Unavailable"), false), trust_of(None, true)),
               ("valid", "unsigned", "invalid", "unchecked", "unhashed"));
    let mut b = fleet();
    b.push(bin("chrome.exe", "Google Chrome", "Google LLC", "120.0.6099.71", "Valid", 'a'));   // a key repeated: the first
    b.push(json!({ "key": "sha256:ABC'; drop table", "sha256": "ABC'; drop table", "name": "evil\u{0}.exe", "product": "x".repeat(5000) }));
    b.push(json!({ "key": "", "name": "nokey.exe" }));
    let rows = process_rows(701, &doc("2026-11-05T17:53:17Z", b));
    assert_eq!(rows.len(), 5, "one per key, a keyless row skipped");
    let sys = rows.iter().find(|r| r.key == "name:system").unwrap();
    assert!(sys.sha256.is_none() && sys.trust == "unhashed");
    let evil = rows.iter().find(|r| r.key.starts_with("sha256:ABC")).unwrap();
    assert!(evil.sha256.is_none() && evil.name == "evil.exe" && evil.product.as_ref().unwrap().chars().count() <= 500, "{evil:?}");
    assert!(rows.iter().all(|r| r.collected_at.as_deref() == Some("2026-11-05T17:53:17.000Z")));
    // The binary's name, hash, paths, version and signature: never the users it ran as or the services it hosts.
    let text = serde_json::to_string(&rows).unwrap();
    assert!(!text.contains("someone") && !text.contains("ExampleSvc"), "{text}");
}

#[test]
fn when_to_download_and_when_to_write() {
    let held = Held { collected_at: Some("2026-11-05T00:00:00.000Z".into()), bytes_updated_at: Some("2026-11-05T00:00:01.000Z".into()), content_hash: Some(sha('d')), error: false };
    assert!(plan_fetch(None, None, None), "nothing held: download");
    assert!(!plan_fetch(Some(&held), None, Some(&sha('d'))), "the same hash: a quiet run downloads nothing");
    assert!(plan_fetch(Some(&held), None, Some(&sha('e'))), "a new hash");
    assert!(!plan_fetch(Some(&Held { content_hash: None, ..held.clone() }), Some("2026-11-05T00:00:01.000Z"), None), "before 1.2.1: the bytes field's time");
    assert!(plan_fetch(Some(&Held { content_hash: None, ..held.clone() }), None, None), "no time from NinjaOne: never assume unchanged");
    assert!(plan_fetch(Some(&Held { error: true, ..held.clone() }), None, Some(&sha('d'))), "a failed read is read again");
    assert_eq!(decide_write(None, "2026-11-05T17:53:17.000Z"), Write::Replace);
    assert_eq!(decide_write(Some("2026-11-05T17:53:17.000Z"), "2026-11-05T17:53:17.000Z"), Write::Same);
    assert_eq!(decide_write(Some("2026-11-04T06:00:00.000Z"), "2026-11-05T17:53:17.000Z"), Write::Replace);
    assert_eq!(decide_write(Some("2026-11-06T06:00:00.000Z"), "2026-11-05T17:53:17.000Z"), Write::Older, "an older payload never replaces newer rows");
    assert_eq!(last_seen(Some(&json!({ "text": "2026-11-06T00:00:00Z" })), Some("2026-11-05T00:00:00.000Z")).as_deref(), Some("2026-11-06T00:00:00.000Z"));
    assert_eq!(last_seen(Some(&json!("2026-11-01T00:00:00Z")), Some("2026-11-05T00:00:00.000Z")).as_deref(), Some("2026-11-05T00:00:00.000Z"), "never earlier than the payload");
    assert_eq!(content_hash(Some(&json!({ "text": sha('F') }))), Some(sha('f')));
    assert!(content_hash(Some(&json!("not a hash"))).is_none());
}

#[test]
fn binaries_become_products_by_rule_by_map_by_decision_or_wait_for_review() {
    let rules: Vec<msp_console::matching::Compiled> = [("chrome", r#"{"name_re":"^Google Chrome$"}"#)].iter()
        .filter_map(|(k, m)| { let mut r: msp_console::matching::Rule = serde_json::from_str(m).unwrap(); r.product_key = k.to_string(); msp_console::matching::Compiled::new(&r) }).collect();
    let map: HashMap<(String, String), String> = [(("Deskflow".to_string(), "Deskflow Devs".to_string()), "nvd:deskflow:deskflow".to_string())].into();
    let idx = msp_console::cpe_map::product_index(["acme:widget", "other:widget", "nobody:gadget"].iter().filter_map(|c| msp_console::cpe_map::CpeProduct::parse(c)));
    let c = |p: &str, co: &str, v: &str| Combo { product: p.into(), company: co.into(), file_version: v.into(), devices: 1 };
    let combos = vec![c("Google Chrome", "Google LLC", "120.0.6099.71"), c("Deskflow", "Deskflow Devs", "1.17.0.0"), c("Microsoft® Windows® Operating System", "Microsoft Corporation", "10.0.1"),
                      c("Widget", "Nobody Ltd", "2.1.0"), c("Gadget", "Nobody Ltd", "3.0"), c("Unknown Thing", "Nobody", "1")];
    let p = plan_classes(&combos, &rules, &map, &HashMap::new(), &idx);
    let m: HashMap<&str, (&str, &str, f64)> = p.classes.iter().map(|x| (x.product.as_str(), (x.product_key.as_str(), x.method, x.confidence))).collect();
    assert_eq!(m["Google Chrome"], ("chrome", "rule", 1.0));
    assert_eq!(m["Deskflow"].1, "auto");
    assert_eq!(m["Gadget"], ("nvd:nobody:gadget", "cpe", 0.9), "one NVD product whose vendor is the company");
    assert!(!m.contains_key("Widget") && !m.contains_key("Unknown Thing") && p.windows == 1, "Windows itself is msrc's");
    assert_eq!(p.review.len(), 1, "Widget's two candidates, neither the company's, wait for a person");
    assert!(p.review[0].candidates.iter().all(|c| !c.vendor_match && c.confidence < msp_console::cpe_map::REVIEW_BELOW));
    let decided: HashMap<(String, String), Decision> = [(("Widget".to_string(), "Nobody Ltd".to_string()), Decision { status: "accepted".into(), cpe: Some("acme:widget".into()) }),
        (("Gadget".to_string(), "Nobody Ltd".to_string()), Decision { status: "rejected".into(), cpe: None })].into();
    let p = plan_classes(&combos, &rules, &map, &decided, &idx);
    let m: HashMap<&str, (&str, &str)> = p.classes.iter().map(|x| (x.product.as_str(), (x.product_key.as_str(), x.method))).collect();
    assert_eq!(m["Widget"], ("nvd:acme:widget", "reviewed"));
    assert!(!m.contains_key("Gadget") && p.review.is_empty(), "a rejected name is never matched, an accepted one isn't asked again");
}

// ---------------------------------------------------------------- end to end

type H = Arc<Mutex<Vec<(String, String)>>>;
struct Ninjas { payload: Mutex<HashMap<i64, (String, Value)>> }

/// NinjaOne's custom fields, made up: 701 runs Chrome 120 (vulnerable), Windows' own svchost, an unsigned widget, and
/// the kernel; 702 reports a payload of a schema this console doesn't read; 703 has no field.
async fn ninja(n: Arc<Ninjas>) -> (String, H) {
    let h: H = Default::default();
    let r = Router::new()
        .route("/ninja/ws/oauth/token", post(|| async { Json(json!({ "access_token": "b", "expires_in": 3600 })) }))
        .route("/ninja/v2/queries/custom-fields-detailed", get(move |State((h, n)): State<(H, Arc<Ninjas>)>, Query(q): Query<HashMap<String, String>>| async move {
            let fields = q.get("fields").cloned().unwrap_or_default();
            let df = q.get("df").cloned().unwrap_or_default();
            h.lock().unwrap().push((fields.clone(), df.clone()));
            let p = n.payload.lock().unwrap().clone();
            let results: Vec<Value> = if fields.starts_with("processInventoryCollectedAt") {
                p.iter().map(|(d, (hash, doc))| json!({ "deviceId": d, "fields": [
                    { "name": "processInventoryCollectedAt", "value": doc["collectedAt"] }, { "name": "processInventoryHash", "value": { "text": hash } },
                    { "name": "processInventoryBytes", "value": 1234, "updated": 1793037212.085108 }] })).collect()
            } else {
                p.iter().filter(|(d, _)| df.contains(&d.to_string())).map(|(d, (_, doc))| json!({ "deviceId": d, "fields": [
                    { "name": "processInventory", "value": as_field(&encode(doc)), "updated": 1793037212.0 }, { "name": "processInventoryBytes", "value": 1234 }] })).collect()
            };
            Json(json!({ "results": results, "cursor": null }))
        }))
        .with_state((h.clone(), n));
    (serve(r).await, h)
}
fn payload_reads(h: &H, device: i64) -> usize { h.lock().unwrap().iter().filter(|(f, df)| f.starts_with("processInventory,") && df.contains(&device.to_string())).count() }

async fn op(store: &Store, body: Value) -> Value {
    let (code, a) = store.call(&EvidenceRequest::parse(body.to_string().as_bytes()).unwrap()).await;
    assert_eq!(code, 200, "{a}");
    a
}

async fn processes_are_read_quietly_classified_and_reviewed(db: TestDb) {
    let n = Arc::new(Ninjas { payload: Mutex::new([(701, (sha('1'), doc("2026-11-05T17:53:17Z", fleet()))),
        (702, (sha('2'), { let mut d = doc("2026-11-05T17:53:17Z", fleet()); d["schema"] = json!(2); d }))].into()) });
    let (base, h) = ninja(n.clone()).await;
    for q in ["INSERT INTO client (org_id, name, name_key) VALUES (7, 'Alpha Dental', 'alpha dental')",
              "INSERT INTO device (device_id, org_id, name, device_class) VALUES (701, 7, 'DESIGN-1', 'desktop'), (702, 7, 'DESIGN-2', 'desktop'), (703, 7, 'DESIGN-3', 'desktop')",
              "INSERT INTO sec_nvd_cve (cve_id, cvss, severity, description) VALUES ('CVE-2026-0001', 8.8, 'HIGH', 'A made-up Chrome flaw before 121.'), ('CVE-2026-0002', 7.0, 'HIGH', 'A made-up widget flaw before 3.')",
              "INSERT INTO sec_nvd_cpe (cve_id, cpe, part, ranges) VALUES ('CVE-2026-0001', 'google:chrome', 'a', '[{\"ee\": \"121.0\"}]'), ('CVE-2026-0002', 'acme:widget', 'a', '[{\"ee\": \"3.0\"}]'),
                 ('CVE-2026-0002', 'other:widget', 'a', '[{\"ee\": \"3.0\"}]')"] {
        msp_console::on_pool!(&db.pool, p, _ => { sqlx::query(q).execute(p).await.unwrap(); })
    }
    let job = NinjaProcesses::new(Arc::new(Ninja::new(&format!("{base}/ninja"), "id", "secret", msp_console::http_client())), "processInventory");
    let o = job.sync(&db.pool).await.unwrap();
    assert_eq!((o.detail["devices_seen"].as_i64(), o.detail["payloads_downloaded"].as_i64(), o.detail["replaced"].as_i64(), o.detail["errors"].as_i64(), o.detail["rows_written"].as_i64()),
               (Some(2), Some(2), Some(1), Some(1), Some(4)), "{}", o.detail);
    assert_eq!(count(&db.pool, "SELECT count(*) FROM device_process WHERE device_id = 702").await, 0, "an unknown schema is refused");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM process_snapshot WHERE device_id = 702 AND error IS NOT NULL").await, 1, "and the snapshot says why");
    // A quiet run: 701's hash is unchanged, so its payload isn't downloaded; 702's last read failed, so it's read again.
    let o = job.sync(&db.pool).await.unwrap();
    assert_eq!((payload_reads(&h, 701), payload_reads(&h, 702), o.detail["unchanged"].as_i64()), (1, 2, Some(1)), "{}", o.detail);
    // An older payload, under a new hash: downloaded, and never replaces the newer rows.
    n.payload.lock().unwrap().insert(701, (sha('3'), doc("2026-11-01T00:00:00Z", vec![bin("old.exe", "Old", "Nobody", "1", "Valid", 'f')])));
    let o = job.sync(&db.pool).await.unwrap();
    assert_eq!((o.detail["older"].as_i64(), o.detail["replaced"].as_i64()), (Some(1), Some(0)), "{}", o.detail);
    assert_eq!(count(&db.pool, "SELECT count(*) FROM device_process WHERE device_id = 701").await, 4, "the newer rows stand");

    // The match: Chrome by rule, svchost left to msrc, the widget waiting for a person; Chrome 120 running is evidence.
    let m = msp_console::process_match::run(&db.pool).await.unwrap();
    assert_eq!((m.detail["classified"].as_i64(), m.detail["review"].as_i64(), m.detail["windows_devices"].as_i64()), (Some(1), Some(1), Some(1)), "{}", m.detail);
    let store = Store::new(db.pool.clone());
    let a = op(&store, json!({ "op": "cves.list", "params": { "org_id": 7 } })).await;
    assert_eq!(a["data"], json!([{ "cve_id": "CVE-2026-0001", "sources": ["process"], "devices": 1, "running_devices": 1, "kev": false, "exploited": false, "cvss": 8.8 }]), "{a}");
    let a = op(&store, json!({ "op": "processes.list", "params": { "org_id": 7 } })).await;
    let rows = a["data"].as_array().unwrap();
    assert_eq!(rows.iter().map(|r| r["name"].as_str().unwrap()).collect::<Vec<_>>(), ["widget.exe", "System", "chrome.exe", "svchost.exe"], "worst trust first, then those with CVEs: {a}");
    let chrome = &rows[2];
    assert_eq!((chrome["product_key"].as_str(), chrome["method"].as_str(), chrome["cve_count"].as_i64(), chrome["devices"].as_i64()), (Some("chrome"), Some("rule"), Some(1), Some(1)), "{chrome}");
    assert_eq!((a["totals"]["binaries"].as_i64(), a["totals"]["devices_reporting"].as_i64(), a["totals"]["devices_failing"].as_i64()), (Some(4), Some(1), Some(1)), "{a}");
    // The binary's CVE count opens its product version's CVEs (version.cves): the same count, with the device behind it.
    let v = op(&store, json!({ "op": "version.cves", "params": { "product_key": "chrome", "version": chrome["product_version"] } })).await;
    assert_eq!((v["totals"]["cves"].as_i64(), chrome["cve_count"].as_i64()), (Some(1), Some(1)), "the count and its rows agree: {v}");
    assert_eq!((v["data"][0]["cve_id"].clone(), v["data"][0]["devices"].clone(), v["data"][0]["running_devices"].clone(), v["data"][0]["sources"].clone()),
               (json!("CVE-2026-0001"), json!(1), json!(1), json!(["process"])), "{v}");
    assert_eq!(op(&store, json!({ "op": "version.cves", "params": { "product_key": "chrome", "version": chrome["product_version"], "kev": true } })).await["totals"]["cves"], json!(0), "kev narrows it");
    let (code, e) = store.call(&EvidenceRequest::parse(br#"{"op":"version.cves","params":{"product_key":"chrome"}}"#).unwrap()).await;
    assert_eq!((code, e["error"].as_str().map(|x| x.starts_with("version is required"))), (400, Some(true)), "{e}");
    let a = op(&store, json!({ "op": "processes.list", "params": { "q": sha('a') } })).await;
    assert_eq!(a["data"][0]["device_list"][0]["device_name"], json!("DESIGN-1"), "a hash lists the devices: {a}");
    let (code, e) = store.call(&EvidenceRequest::parse(br#"{"op":"cves.list","params":{"state":"unsigned"}}"#).unwrap()).await;
    assert_eq!((code, e["error"].as_str().map(|x| x.starts_with("state isn't a filter of cves.list"))), (400, Some(true)), "an op without states refuses one: {e}");
    let a = op(&store, json!({ "op": "processes.list", "params": { "state": "unsigned" } })).await;
    assert_eq!(a["data"].as_array().unwrap().len(), 1);
    let a = op(&store, json!({ "op": "processes.review", "params": {} })).await;
    assert_eq!((a["totals"]["pending"].as_i64(), a["data"][0]["name"].as_str(), a["data"][0]["candidates"].as_array().map(Vec::len)), (Some(1), Some("Widget"), Some(2)), "{a}");

    // A decision through the API: signed in, one of the name's own candidates, audited without the name, once.
    let audit = Arc::new(Mutex::new(Vec::new()));
    let au = audit.clone();
    let app = msp_console::app::router(msp_console::app::AppState { identity: Arc::new(msp_console::identity::TrustedHeader { header: "x-who".into(), cidrs: vec!["127.0.0.1/32".parse().unwrap()] }),
        store: store.clone(), audit: Arc::new(move |r| au.lock().unwrap().push(r)) }, None).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000))));
    let send = |body: Value, who: Option<&'static str>| { let app = app.clone(); async move {
        let mut b = Request::post("/api/review").header("content-type", "application/json");
        if let Some(w) = who { b = b.header("x-who", w); }
        let r = app.oneshot(b.body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let st = r.status();
        (st, serde_json::from_slice::<Value>(&r.into_body().collect().await.unwrap().to_bytes()).unwrap_or(Value::Null))
    } };
    let accept = json!({ "kind": "process", "name": "Widget", "company": "Nobody Ltd", "decision": "accept", "cpe": "acme:widget" });
    assert_eq!(send(accept.clone(), None).await.0, StatusCode::UNAUTHORIZED, "never without sign-in");
    assert_eq!(send(json!({ "kind": "process", "name": "Widget", "company": "Nobody Ltd", "decision": "accept", "cpe": "evil:widget" }), Some("tech@example.com")).await.0, StatusCode::BAD_REQUEST, "only its own candidates");
    let (st, a) = send(accept.clone(), Some("tech@example.com")).await;
    assert_eq!((st, a["status"].as_str(), a["unchanged"].as_bool()), (StatusCode::OK, Some("accepted"), Some(false)), "{a}");
    let (st, a) = send(accept.clone(), Some("tech@example.com")).await;
    assert_eq!((st, a["unchanged"].as_bool()), (StatusCode::OK, Some(true)), "a double click is one decision");
    let lines = audit.lock().unwrap().clone();
    let decided: Vec<_> = lines.iter().filter(|r| r.op.as_deref() == Some("review.decide")).collect();
    assert_eq!(decided.len(), 3, "every decision call is audited");
    assert!(decided.iter().all(|r| r.who.as_deref() == Some("tech@example.com") && !r.params.to_string().contains("Widget")), "who, never the name: {decided:?}");
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_map_review WHERE status = 'accepted' AND decided_by = 'tech@example.com'").await, 1);
    // The next match honours it: the widget is that NVD product now, and its version's CVE is running evidence.
    let m = msp_console::process_match::run(&db.pool).await.unwrap();
    assert_eq!(m.detail["by_method"]["reviewed"].as_i64(), Some(1), "{}", m.detail);
    let a = op(&store, json!({ "op": "cves.list", "params": { "org_id": 7, "running_only": true } })).await;
    assert_eq!(a["totals"]["cves"].as_i64(), Some(2), "{a}");
    // Rejected: never matched again; reopen puts it back in the queue.
    let r = store.decide("tech@example.com", &ReviewDecision { kind: ReviewKind::Process, name: "Widget".into(), company: "Nobody Ltd".into(), decision: Decide::Reject, cpe: None }).await;
    assert_eq!(r.0, 200);
    msp_console::process_match::run(&db.pool).await.unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_evidence WHERE source = 'process' AND product_key = 'nvd:acme:widget'").await, 0);
    store.decide("tech@example.com", &ReviewDecision { kind: ReviewKind::Process, name: "Widget".into(), company: "Nobody Ltd".into(), decision: Decide::Reopen, cpe: None }).await;
    msp_console::process_match::run(&db.pool).await.unwrap();
    assert_eq!(count(&db.pool, "SELECT count(*) FROM sec_map_review WHERE status = 'pending'").await, 1);
}

#[test]
fn a_decision_is_strict() {
    assert!(ReviewDecision::parse(br#"{"kind":"process","name":"W","decision":"accept"}"#).is_err(), "accept needs a cpe");
    assert!(ReviewDecision::parse(br#"{"kind":"process","name":"W","decision":"reject","cpe":"a:b"}"#).is_err());
    assert!(ReviewDecision::parse(br#"{"kind":"process","name":"W","decision":"reject","scope":1}"#).is_err(), "unknown keys refused");
    assert!(ReviewDecision::parse(br#"{"kind":"software","name":"W","company":"C","decision":"accept","cpe":"a:b"}"#).is_ok());
}
