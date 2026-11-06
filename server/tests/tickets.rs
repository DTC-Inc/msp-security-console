//! A Halo ticket from a finding, on both stores, against a made-up Halo (never a real one): the preview shows exactly
//! what's sent; a create without that preview's digest, or after the finding changed, sends nothing; two clicks at once
//! make one ticket; a second click links to the first; only a confirmed client gets one; every step is audited with who.
mod common;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use common::*;
use http_body_util::BodyExt;
use msp_console::app::{router_with, AppState};
use msp_console::audit::AuditRecord;
use msp_console::connectors::halo::{Halo, HaloSettings};
use msp_console::identity::TrustedHeader;
use msp_console::ops::actions::Actions;
use msp_console::ops::tickets::TicketCfg;
use msp_console::ops::Store;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

type Sent = Arc<Mutex<Vec<Value>>>;
async fn halo() -> (String, Sent) {
    let sent: Sent = Default::default();
    let r = Router::new()
        .route("/halo/auth/token", post(|| async { Json(json!({ "access_token": "halo-bearer", "expires_in": 3600 })) }))
        .route("/halo/api/Tickets", post(|State(s): State<Sent>, Json(b): Json<Value>| async move {
            // Slow enough that two clicks at once are both in flight.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let mut g = s.lock().unwrap();
            g.push(b);
            Json(json!([{ "id": 5000 + g.len() as i64 }]))
        }))
        .with_state(sent.clone());
    (serve(r).await, sent)
}

async fn seed(pool: &msp_console::db::Pool) {
    for q in [
        "INSERT INTO client (org_id, name, name_key, halo_client_id, halo_matched_by) VALUES (1, 'Alpha Dental', 'alpha dental', 10, 'ninjarmm_id')",
        "INSERT INTO client (org_id, name, name_key, halo_client_id, halo_matched_by) VALUES (2, 'Beta Ortho', 'beta ortho', 20, 'name')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (101, 1, 'FRONTDESK-1', 'desktop')",
        "INSERT INTO device (device_id, org_id, name, device_class) VALUES (201, 2, 'BETA-DC', 'server')",
        "INSERT INTO bp_tenant (tenant_id, name, name_key, org_id, mapped_by) VALUES ('t-a', 'Alpha', 'alpha', 1, 'tech@example.com')",
        "INSERT INTO bp_tenant (tenant_id, name, name_key) VALUES ('t-x', 'Unknown', 'unknown')",
        "INSERT INTO bp_asset (asset_id, tenant_id, hostname, device_id, synced_at) VALUES ('as-1', 't-a', 'FRONTDESK-1', 101, '2026-11-01T00:00:00.000Z')",
        "INSERT INTO bp_detection (detection_id, tenant_id, status, risk_score, alert_count, hostname, username, detection_name, synced_at)
           VALUES ('g-1', 't-a', 'OPEN', 92, 3, 'FRONTDESK-1', 'frontdesk', 'Suspicious <script> PowerShell', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO bp_detection (detection_id, tenant_id, status, risk_score, synced_at) VALUES ('g-9', 't-x', 'OPEN', 50, '2026-11-01T00:00:00.000Z')",
        "INSERT INTO device_wan (device_id, org_id, public_ip, seen_at) VALUES (101, 1, '203.0.113.10', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO device_wan (device_id, org_id, public_ip, seen_at) VALUES (201, 2, '203.0.113.20', '2026-11-01T00:00:00.000Z')",
        "INSERT INTO exposure_host (ip, found, ports) VALUES ('203.0.113.10', true, '[3389]')",
        "INSERT INTO exposure_service (ip, port, transport, product) VALUES ('203.0.113.10', 3389, 'tcp', 'RDP')",
    ] { exec(pool, q).await; }
}

struct Rig { app: Router, audit: Arc<Mutex<Vec<AuditRecord>>> }
fn rig(pool: msp_console::db::Pool, base: &str) -> Rig {
    let audit = Arc::new(Mutex::new(Vec::new()));
    let a = audit.clone();
    let state = AppState { identity: Arc::new(TrustedHeader { header: "x-who".into(), cidrs: vec!["127.0.0.1/32".parse().unwrap()] }), store: Store::new(pool),
                           audit: Arc::new(move |r| a.lock().unwrap().push(r)) };
    let h = Halo::new(HaloSettings { base: format!("{base}/halo/api"), auth_url: None, client_id: "tickets-test".into(), client_secret: "halo-secret-tickets".into(), tenant: None, per_5min: 150, detail_budget: 10 },
                      msp_console::http_client());
    let acts = Arc::new(Actions { halo: Some(h), tickets: Some(TicketCfg { type_id: 31, status_id: 1, priority_id: 3 }), blackpoint: true, shodan: true, admins: vec![], everyone_admin: false });
    Rig { app: router_with(state, None, msp_console::ops::actions::routes(acts)).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000)))), audit }
}
async fn call(r: &Rig, path: &str, body: Value) -> (StatusCode, Value) { call_as(r, path, body, "tech@example.com").await }
async fn call_as(r: &Rig, path: &str, body: Value, who: &str) -> (StatusCode, Value) {
    let req = Request::post(path).header("content-type", "application/json").header("x-who", who).body(Body::from(body.to_string())).unwrap();
    let res = r.app.clone().oneshot(req).await.unwrap();
    let st = res.status();
    (st, serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap_or(Value::Null))
}

async fn a_ticket_from_a_finding(db: TestDb) {
    seed(&db.pool).await;
    let (base, sent) = halo().await;
    let r = rig(db.pool.clone(), &base);

    // The preview: exactly what goes to Halo, with Halo's settings, nothing sent yet.
    let (st, p) = call(&r, "/api/tickets/preview", json!({ "finding": "detection:g-1" })).await;
    assert_eq!(st, StatusCode::OK, "{p}");
    let payload = p["payload"].clone();
    assert_eq!((payload["client_id"].clone(), payload["tickettype_id"].clone(), payload["status_id"].clone(), payload["priority_id"].clone()), (json!(10), json!(31), json!(1), json!(3)));
    assert_eq!(payload["summary"], json!("Security alert: Suspicious <script> PowerShell on FRONTDESK-1"));
    let html = payload["details_html"].as_str().unwrap();
    assert!(html.contains("Suspicious &lt;script&gt; PowerShell") && !html.contains("<script>"), "the details are escaped: {html}");
    assert!(html.contains("Client: Alpha Dental") && html.contains("by tech@example.com"), "{html}");
    assert_eq!(sent.lock().unwrap().len(), 0);

    // Without the preview's digest, or with another, nothing is sent.
    let (st, _) = call(&r, "/api/tickets", json!({ "finding": "detection:g-1" })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, a) = call(&r, "/api/tickets", json!({ "finding": "detection:g-1", "digest": "0".repeat(64) })).await;
    assert_eq!((st, a["error"].as_str().unwrap().starts_with("the finding changed")), (StatusCode::CONFLICT, true));
    assert_eq!(sent.lock().unwrap().len(), 0);

    // Two clicks at once: one ticket, and both answers name it.
    let body = json!({ "finding": "detection:g-1", "digest": p["digest"] });
    let ((s1, a1), (s2, a2)) = tokio::join!(call(&r, "/api/tickets", body.clone()), call(&r, "/api/tickets", body.clone()));
    let made: Vec<(StatusCode, Value)> = vec![(s1, a1), (s2, a2)];
    assert!(made.iter().any(|(s, a)| *s == StatusCode::OK && a["created"] == json!(true) && a["halo_ticket_id"] == json!(5001)), "{made:?}");
    assert!(made.iter().all(|(s, a)| *s == StatusCode::OK || (*s == StatusCode::CONFLICT && a["error"].as_str().unwrap().contains("being raised"))), "{made:?}");
    assert_eq!(sent.lock().unwrap().len(), 1, "one ticket");
    assert_eq!(sent.lock().unwrap()[0], json!([payload]), "what was sent is what was shown");
    // A click later: the same ticket, nothing sent; the preview and the finding say so too.
    let (st, a) = call(&r, "/api/tickets", body).await;
    assert_eq!((st, a["created"].clone(), a["halo_ticket_id"].clone()), (StatusCode::OK, json!(false), json!(5001)));
    let (_, p2) = call(&r, "/api/tickets/preview", json!({ "finding": "detection:g-1" })).await;
    assert_eq!(p2, json!({ "existing": { "state": "created", "halo_ticket_id": 5001 } }));
    assert_eq!(sent.lock().unwrap().len(), 1);
    let store = Store::new(db.pool.clone());
    let (_, d) = store.call(&msp_console::contract::EvidenceRequest::parse(br#"{"op":"detection.get","params":{"detection_id":"g-1"}}"#).unwrap()).await;
    assert_eq!(d["data"]["halo_ticket_id"], json!(5001));

    // An exposed address: its own ticket.
    let (_, p) = call(&r, "/api/tickets/preview", json!({ "finding": "exposure:203.0.113.10" })).await;
    assert!(p["payload"]["details_html"].as_str().unwrap().contains("3389/tcp (Remote Desktop (RDP))"), "{p}");
    let (st, a) = call(&r, "/api/tickets", json!({ "finding": "exposure:203.0.113.10", "digest": p["digest"] })).await;
    assert_eq!((st, a["halo_ticket_id"].clone()), (StatusCode::OK, json!(5002)));

    // Only a confirmed client: a tenant no one confirmed, and a Halo client matched by name alone.
    let (st, a) = call(&r, "/api/tickets/preview", json!({ "finding": "detection:g-9" })).await;
    assert_eq!(st, StatusCode::CONFLICT, "{a}");
    let (st, a) = call(&r, "/api/tickets/preview", json!({ "finding": "exposure:203.0.113.20" })).await;
    assert_eq!((st, a["error"].as_str().unwrap().contains("has no confirmed Halo client")), (StatusCode::CONFLICT, true), "{a}");
    let (st, _) = call(&r, "/api/tickets/preview", json!({ "finding": "something:else" })).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(sent.lock().unwrap().len(), 2);

    // Every step audited, naming who; never a value from the finding.
    let audit = r.audit.lock().unwrap().clone();
    assert!(audit.iter().all(|x| x.who.as_deref() == Some("tech@example.com")));
    let creates: Vec<(u16, Value)> = audit.iter().filter(|x| x.op.as_deref() == Some("ticket.create")).map(|x| (x.status, x.params.clone())).collect();
    assert_eq!(creates.iter().filter(|c| c.0 == 200 && c.1["created"] == json!(true)).count(), 2, "{creates:?}");
    let text = serde_json::to_string(&audit).unwrap();
    for s in ["203.0.113", "FRONTDESK", "PowerShell", "frontdesk"] { assert!(!text.contains(s), "{s} in the audit: {text}"); }
}
both!(a_ticket_from_a_finding, a_lost_answer_keeps_the_claim_and_a_refusal_gives_it_back);

/// Halo makes the detection's ticket and then never answers (the console's wait runs out), and refuses the exposed
/// address's outright. The first may exist, so its claim stays `unknown`, a retry is refused naming the title to search
/// Halo for, and only an admin, once Halo has been checked, releases it; the second certainly doesn't exist, so its
/// claim is given back and a retry may send again.
async fn a_lost_answer_keeps_the_claim_and_a_refusal_gives_it_back(db: TestDb) {
    seed(&db.pool).await;
    let sent: Sent = Default::default();
    let mock = Router::new()
        .route("/halo/auth/token", post(|| async { Json(json!({ "access_token": "halo-bearer", "expires_in": 3600 })) }))
        .route("/halo/api/Tickets", post(|State(s): State<Sent>, Json(b): Json<Value>| async move {
            let exposure = b.to_string().contains("203.0.113.10");
            s.lock().unwrap().push(b);
            if exposure { return (axum::http::StatusCode::BAD_REQUEST, Json(json!({ "error": "refused" }))); }
            // The ticket is made; the answer never comes in time.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            (axum::http::StatusCode::OK, Json(json!([{ "id": 7001 }])))
        }))
        .with_state(sent.clone());
    let base = serve(mock).await;
    let audit = Arc::new(Mutex::new(Vec::new()));
    let au = audit.clone();
    let proxy = Arc::new(TrustedHeader { header: "x-who".into(), cidrs: vec!["127.0.0.1/32".parse().unwrap()] });
    let identity = Arc::new(msp_console::identity::WithAdmins { inner: proxy, emails: vec!["admin@example.com".into()] });
    let state = AppState { identity, store: Store::new(db.pool.clone()), audit: Arc::new(move |r| au.lock().unwrap().push(r)) };
    let mut h = Halo::new(HaloSettings { base: format!("{base}/halo/api"), auth_url: None, client_id: "tickets-lost".into(), client_secret: "halo-secret-lost".into(), tenant: None, per_5min: 150, detail_budget: 10 },
                          msp_console::http_client());
    h.write_timeout = std::time::Duration::from_millis(500);
    let acts = Arc::new(Actions { halo: Some(h), tickets: Some(TicketCfg { type_id: 31, status_id: 1, priority_id: 3 }), blackpoint: true, shodan: true, admins: vec![], everyone_admin: false });
    let r = Rig { app: router_with(state, None, msp_console::ops::actions::routes(acts)).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5000)))), audit };
    let state_of = |f: &'static str| { let pool = db.pool.clone(); async move {
        msp_console::on_pool!(&pool, p, _ => sqlx::query_scalar::<_, String>("SELECT state FROM finding_ticket WHERE finding_key = $1").bind(f).fetch_optional(p).await.unwrap()) } };

    // The lost answer: refused as "may exist", the claim kept as unknown.
    let (_, p) = call(&r, "/api/tickets/preview", json!({ "finding": "detection:g-1" })).await;
    let body = json!({ "finding": "detection:g-1", "digest": p["digest"] });
    let (st, a) = call(&r, "/api/tickets", body.clone()).await;
    assert_eq!((st, a["unknown"].clone()), (StatusCode::BAD_GATEWAY, json!(true)), "{a}");
    let says = "A ticket may already exist in Halo. Search Halo for 'Security alert: Suspicious <script> PowerShell on FRONTDESK-1' before an admin releases this.";
    assert_eq!((a["error"].as_str(), a.get("halo_search")), (Some(format!("Halo: timed out. {says}").as_str()), None), "{a}");
    assert_eq!(state_of("detection:g-1").await.as_deref(), Some("unknown"));
    // A retry sends nothing and names the title to search Halo for; the preview says the same.
    let (st, a) = call(&r, "/api/tickets", body.clone()).await;
    assert_eq!((st, a["unknown"].clone(), a["error"].as_str()), (StatusCode::CONFLICT, json!(true), Some(says)), "{a}");
    let (_, p) = call(&r, "/api/tickets/preview", json!({ "finding": "detection:g-1" })).await;
    assert_eq!((p["existing"]["state"].clone(), p["existing"]["message"].as_str()), (json!("unknown"), Some(says)), "{p}");
    assert_eq!(sent.lock().unwrap().len(), 1, "one request to Halo, never a second");
    // The release: not for someone who isn't an admin, and nothing to release on a finding with no unknown claim.
    let (st, _) = call_as(&r, "/api/tickets/release", json!({ "finding": "detection:g-1" }), "tech@example.com").await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(state_of("detection:g-1").await.as_deref(), Some("unknown"), "still held");
    let (st, _) = call_as(&r, "/api/tickets/release", json!({ "finding": "exposure:203.0.113.10" }), "admin@example.com").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // An admin, having checked Halo: the claim goes, and the finding can be raised again.
    let (st, a) = call_as(&r, "/api/tickets/release", json!({ "finding": "detection:g-1" }), "admin@example.com").await;
    assert_eq!((st, a["released"].clone()), (StatusCode::OK, json!(true)), "{a}");
    assert_eq!(state_of("detection:g-1").await, None);
    let (st, p) = call(&r, "/api/tickets/preview", json!({ "finding": "detection:g-1" })).await;
    assert_eq!((st, p.get("existing").is_none(), p["digest"].is_string()), (StatusCode::OK, true, true), "raisable again: {p}");
    let (st, _) = call(&r, "/api/tickets", body).await;
    assert_eq!((st, sent.lock().unwrap().len()), (StatusCode::BAD_GATEWAY, 2), "sent again after the release (and lost again, so held again)");
    assert_eq!(state_of("detection:g-1").await.as_deref(), Some("unknown"));

    // A refusal: no ticket, the claim given back, and a retry sends again.
    let (_, p) = call(&r, "/api/tickets/preview", json!({ "finding": "exposure:203.0.113.10" })).await;
    let body = json!({ "finding": "exposure:203.0.113.10", "digest": p["digest"] });
    let (st, a) = call(&r, "/api/tickets", body.clone()).await;
    assert_eq!((st, a["error"].as_str()), (StatusCode::BAD_GATEWAY, Some("Halo: HTTP 400 Bad Request: no ticket was made")), "{a}");
    assert_eq!(state_of("exposure:203.0.113.10").await, None);
    call(&r, "/api/tickets", body).await;
    assert_eq!(sent.lock().unwrap().len(), 4, "the refused one was tried again");
    let a = r.audit.lock().unwrap();
    assert!(a.iter().any(|x| x.op.as_deref() == Some("ticket.create") && x.params["unknown"] == json!(true)), "the unknown is in the audit line");
    let releases: Vec<(Option<&str>, u16, Value)> = a.iter().filter(|x| x.op.as_deref() == Some("ticket.release")).map(|x| (x.who.as_deref(), x.status, x.params.clone())).collect();
    assert_eq!(releases, vec![(Some("tech@example.com"), 403, json!({ "kind": "detection" })), (Some("admin@example.com"), 404, json!({ "kind": "exposure" })),
                              (Some("admin@example.com"), 200, json!({ "kind": "detection", "released": true }))], "who, and never the finding's value");
    assert!(a.iter().filter(|x| x.op.as_deref() == Some("ticket.release")).all(|x| !x.at.is_empty()), "and when");
}
