//! The console's writes for Blackpoint, exposure and tickets: JSON calls behind sign-in, beside the evidence API's
//! reads. Each one is a signed-in person's own act, named in its audit line (who, the call, the ids, never a value),
//! and the web app asks them to confirm it first. Each refuses anything but a JSON body, so another site's form can't
//! send one.
//!
//! | Call | Who | What |
//! |---|---|---|
//! | `GET /api/features` | anyone signed in | which of these are on, whether you may set scan policies, and Halo's ticket address |
//! | `POST /api/blackpoint/tenant` `{tenant_id, action, org_id?}` | anyone signed in | confirm which client a Blackpoint tenant is (`confirm`), say it's no client (`not_client`), or undo either (`clear`) |
//! | `POST /api/exposure/edge` `{ip, edge, note?}` | anyone signed in | mark an address as an edge entry point (meant to face the internet), or unmark it |
//! | `POST /api/exposure/scan-policy` `{org_id, frequency_days}` | a console admin, or one of SCAN_POLICY_ADMINS | turn a client's on-demand scans on (every N days) or off (0) |
//! | `POST /api/tickets/preview` `{finding}` | anyone signed in | the Halo ticket exactly as it would be sent, and its digest, or the ticket already raised |
//! | `POST /api/tickets/release` `{finding}` | an admin | after checking Halo has no ticket for a finding left unknown: release its claim |
//! | `POST /api/tickets` `{finding, digest}` | anyone signed in | raise it, once per finding; an answer lost after sending keeps the claim `unknown`, never a second ticket |

use crate::app::AppState;
use crate::audit::{now, AuditRecord};
use crate::connectors::halo::Halo;
use crate::identity::Who;
use crate::ops::tickets::{self, TicketCfg};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

/// What the writes need beyond the store: Halo for tickets, and who's an admin.
pub struct Actions {
    pub halo: Option<Halo>,
    pub tickets: Option<TicketCfg>,
    pub blackpoint: bool,
    pub shodan: bool,
    /// Who else may set scan policies (SCAN_POLICY_ADMINS, lowercased), beside the console's admins.
    pub admins: Vec<String>,
    /// No sign-in (only this computer): the one person there is the admin.
    pub everyone_admin: bool,
}

impl Actions {
    /// May set scan policies: the console's admins (OIDC_ADMIN_GROUP or ADMIN_EMAILS, the same role Settings needs),
    /// and anyone SCAN_POLICY_ADMINS adds for scans alone.
    pub fn admin(&self, who: &Who) -> bool { self.everyone_admin || who.admin || self.admins.iter().any(|a| a.eq_ignore_ascii_case(who.email.trim())) }
    /// Halo's own ticket page, for a link: its address without /api.
    pub fn ticket_url(&self) -> Option<String> { self.halo.as_ref().map(|h| format!("{}/tickets?id=", h.base.trim_end_matches("/api"))) }
    /// May release a ticket claim left unknown: the console's admins (the same role Settings needs).
    pub fn console_admin(&self, who: &Who) -> bool { self.everyone_admin || who.admin }
}

pub fn routes(a: Arc<Actions>) -> Router<AppState> {
    Router::new()
        .route("/api/features", get(features))
        .route("/api/blackpoint/tenant", post(tenant))
        .route("/api/exposure/edge", post(edge))
        .route("/api/exposure/scan-policy", post(scan_policy))
        .route("/api/tickets/preview", post(preview))
        .route("/api/tickets", post(create))
        .route("/api/tickets/release", post(release))
        .layer(Extension(a))
}

fn answer(code: u16, v: Value) -> Response { (StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), Json(v)).into_response() }

fn audit(s: &AppState, who: &Who, op: &str, params: Value, status: u16, t0: Instant) {
    (s.audit)(AuditRecord { at: now(), who: Some(who.email.clone()), op: Some(op.into()), params, rows: None, status, ms: t0.elapsed().as_millis() });
}

/// The body as a JSON object; anything else is refused (another site's form can't send JSON without asking first).
fn body(headers: &HeaderMap, b: &Bytes) -> Result<Value, (u16, &'static str)> {
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.trim_start().to_ascii_lowercase().starts_with("application/json") { return Err((415, "send JSON")); }
    serde_json::from_slice::<Value>(b).ok().filter(Value::is_object).ok_or((400, "the body isn't a JSON object"))
}

const DB: &str = "the console's database didn't answer";

async fn features(Extension(who): Extension<Who>, Extension(a): Extension<Arc<Actions>>) -> Json<Value> {
    Json(json!({ "blackpoint": a.blackpoint, "shodan": a.shodan, "tickets": a.tickets.is_some() && a.halo.is_some(), "halo_ticket_url": a.ticket_url(), "scan_admin": a.shodan && a.admin(&who), "ticket_admin": a.console_admin(&who) }))
}

async fn tenant(State(s): State<AppState>, Extension(who): Extension<Who>, headers: HeaderMap, b: Bytes) -> Response {
    let t0 = Instant::now();
    let (code, v, params) = tenant_inner(&s, &who, &headers, &b).await;
    audit(&s, &who, "blackpoint.tenant", params, code, t0);
    answer(code, v)
}
async fn tenant_inner(s: &AppState, who: &Who, headers: &HeaderMap, b: &Bytes) -> (u16, Value, Value) {
    let j = match body(headers, b) { Ok(j) => j, Err((c, w)) => return (c, json!({ "error": w }), json!({})) };
    let tid = j.get("tenant_id").and_then(Value::as_str).unwrap_or("").to_string();
    let action = j.get("action").and_then(Value::as_str).unwrap_or("").to_string();
    let org = j.get("org_id").and_then(Value::as_i64);
    let params = json!({ "tenant_id": tid, "action": action, "org_id": org });
    if tid.is_empty() || tid.len() > 100 { return (400, json!({ "error": "tenant_id is required" }), params); }
    let pool = &s.store.pool;
    let known: Option<(String,)> = match crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT tenant_id FROM bp_tenant WHERE tenant_id = $1 AND deleted_at IS NULL").bind(&tid).fetch_optional(p).await) {
        Ok(k) => k, Err(_) => return (503, json!({ "error": DB }), params) };
    if known.is_none() { return (404, json!({ "error": "that Blackpoint tenant isn't in the console" }), params); }
    let by = who.email.as_str();
    let r = match action.as_str() {
        "confirm" => {
            let Some(org) = org else { return (400, json!({ "error": "confirm needs org_id, the client it is" }), params) };
            let c: Option<(i64,)> = match crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT org_id FROM client WHERE org_id = $1 AND deleted_at IS NULL").bind(org).fetch_optional(p).await) {
                Ok(c) => c, Err(_) => return (503, json!({ "error": DB }), params) };
            if c.is_none() { return (404, json!({ "error": "that client isn't in the console" }), params); }
            crate::on_pool!(pool, p, _ => sqlx::query("UPDATE bp_tenant SET org_id = $2, not_client = false, mapped_by = $3, mapped_at = $4, suggested_org_id = NULL, suggested_by = NULL WHERE tenant_id = $1")
                .bind(&tid).bind(org).bind(by).bind(crate::db::now()).execute(p).await.map(|_| ()))
        }
        "not_client" => crate::on_pool!(pool, p, _ => sqlx::query("UPDATE bp_tenant SET org_id = NULL, not_client = true, mapped_by = $2, mapped_at = $3, suggested_org_id = NULL, suggested_by = NULL WHERE tenant_id = $1")
            .bind(&tid).bind(by).bind(crate::db::now()).execute(p).await.map(|_| ())),
        "clear" => crate::on_pool!(pool, p, _ => sqlx::query("UPDATE bp_tenant SET org_id = NULL, not_client = false, mapped_by = NULL, mapped_at = NULL WHERE tenant_id = $1")
            .bind(&tid).execute(p).await.map(|_| ())),
        _ => return (400, json!({ "error": "action must be confirm, not_client or clear" }), params),
    };
    if r.is_err() { return (503, json!({ "error": DB }), params); }
    // At once, not at the next sweep: the tenant's assets move with it, its evidence too, and a cleared one gets its
    // suggestion back.
    let redo = async {
        crate::connectors::blackpoint::suggest(pool).await?;
        let m = crate::connectors::blackpoint::rematch(pool).await?;
        let e = crate::connectors::blackpoint::build_evidence(pool).await?;
        Ok::<_, String>((m, e))
    }.await;
    match redo {
        Ok((m, e)) => (200, json!({ "ok": true, "assets_matched": m, "evidence": e }), params),
        Err(_) => (503, json!({ "error": "the mapping is saved, but tying its assets to devices didn't finish; the next Blackpoint sweep does it" }), params),
    }
}

async fn edge(State(s): State<AppState>, Extension(who): Extension<Who>, headers: HeaderMap, b: Bytes) -> Response {
    let t0 = Instant::now();
    let (code, v, params) = edge_inner(&s, &who, &headers, &b).await;
    audit(&s, &who, "exposure.edge", params, code, t0);
    answer(code, v)
}
async fn edge_inner(s: &AppState, who: &Who, headers: &HeaderMap, b: &Bytes) -> (u16, Value, Value) {
    let j = match body(headers, b) { Ok(j) => j, Err((c, w)) => return (c, json!({ "error": w }), json!({})) };
    let on = j.get("edge").and_then(Value::as_bool);
    let params = json!({ "edge": on });
    let Some(ip) = j.get("ip").and_then(Value::as_str).and_then(|i| i.parse::<std::net::Ipv4Addr>().ok()).map(|i| i.to_string()) else { return (400, json!({ "error": "ip must be an IPv4 address" }), params) };
    let Some(on) = on else { return (400, json!({ "error": "edge must be true or false" }), params) };
    let note: Option<String> = j.get("note").and_then(Value::as_str).map(|n| n.trim().chars().take(300).collect::<String>()).filter(|n| !n.is_empty());
    let pool = &s.store.pool;
    let known: Result<Option<(i64,)>, _> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT CAST(1 AS BIGINT) FROM device_wan WHERE public_ip = $1 UNION SELECT CAST(1 AS BIGINT) FROM exposure_site WHERE ip = $1 AND classification = 'dedicated' LIMIT 1").bind(&ip).fetch_optional(p).await);
    match known { Err(_) => return (503, json!({ "error": DB }), params), Ok(None) => return (404, json!({ "error": "that isn't a current client internet address" }), params), Ok(Some(_)) => {} }
    let r = crate::on_pool!(pool, p, _ => sqlx::query("INSERT INTO exposure_mark (ip, edge, note, marked_by, marked_at) VALUES ($1, $2, $3, $4, $5)
                                                        ON CONFLICT (ip) DO UPDATE SET edge = excluded.edge, note = COALESCE(excluded.note, exposure_mark.note), marked_by = excluded.marked_by, marked_at = excluded.marked_at")
        .bind(&ip).bind(on).bind(note).bind(&who.email).bind(crate::db::now()).execute(p).await.map(|_| ()));
    if r.is_err() { return (503, json!({ "error": DB }), params); }
    (200, json!({ "ok": true, "ip": ip, "edge": on, "marked_by": who.email }), params)
}

async fn scan_policy(State(s): State<AppState>, Extension(who): Extension<Who>, Extension(a): Extension<Arc<Actions>>, headers: HeaderMap, b: Bytes) -> Response {
    let t0 = Instant::now();
    let (code, v, params) = policy_inner(&s, &who, &a, &headers, &b).await;
    audit(&s, &who, "exposure.scan_policy", params, code, t0);
    answer(code, v)
}
async fn policy_inner(s: &AppState, who: &Who, a: &Actions, headers: &HeaderMap, b: &Bytes) -> (u16, Value, Value) {
    let j = match body(headers, b) { Ok(j) => j, Err((c, w)) => return (c, json!({ "error": w }), json!({})) };
    let org = j.get("org_id").and_then(Value::as_i64);
    let days = j.get("frequency_days").and_then(Value::as_i64);
    let params = json!({ "org_id": org, "frequency_days": days });
    if !a.shodan { return (409, json!({ "error": "Shodan isn't connected, so there's nothing to scan with" }), params); }
    if !a.admin(who) { return (403, json!({ "error": "Only an admin can change scan policies: ask one, or add your sign-in to SCAN_POLICY_ADMINS" }), params); }
    let (Some(org), Some(days)) = (org, days) else { return (400, json!({ "error": "org_id and frequency_days are required" }), params) };
    if !(0..=365).contains(&days) { return (400, json!({ "error": "frequency_days must be 0 (off) to 365" }), params); }
    let pool = &s.store.pool;
    let c: Result<Option<(i64,)>, _> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT org_id FROM client WHERE org_id = $1 AND deleted_at IS NULL").bind(org).fetch_optional(p).await);
    match c { Err(_) => return (503, json!({ "error": DB }), params), Ok(None) => return (404, json!({ "error": "that client isn't in the console" }), params), Ok(Some(_)) => {} }
    let r = if days == 0 {
        crate::on_pool!(pool, p, _ => sqlx::query("DELETE FROM scan_policy WHERE org_id = $1").bind(org).execute(p).await.map(|_| ()))
    } else {
        crate::on_pool!(pool, p, _ => sqlx::query("INSERT INTO scan_policy (org_id, frequency_days, set_by, set_at) VALUES ($1, $2, $3, $4)
                                                    ON CONFLICT (org_id) DO UPDATE SET frequency_days = excluded.frequency_days, set_by = excluded.set_by, set_at = excluded.set_at")
            .bind(org).bind(days).bind(&who.email).bind(crate::db::now()).execute(p).await.map(|_| ()))
    };
    if r.is_err() { return (503, json!({ "error": DB }), params); }
    (200, json!({ "ok": true, "org_id": org, "frequency_days": days, "set_by": who.email }), params)
}

fn finding_of(j: &Value) -> Result<String, (u16, Value)> {
    let f = j.get("finding").and_then(Value::as_str).unwrap_or("").to_string();
    tickets::parse_finding(&f).map(|_| f).map_err(|(c, w)| (c, json!({ "error": w })))
}
fn kind_of(f: &str) -> &str { f.split(':').next().unwrap_or("") }

async fn preview(State(s): State<AppState>, Extension(who): Extension<Who>, Extension(a): Extension<Arc<Actions>>, headers: HeaderMap, b: Bytes) -> Response {
    let t0 = Instant::now();
    let (code, v, params) = preview_inner(&s, &who, &a, &headers, &b).await;
    audit(&s, &who, "ticket.preview", params, code, t0);
    answer(code, v)
}
async fn preview_inner(s: &AppState, who: &Who, a: &Actions, headers: &HeaderMap, b: &Bytes) -> (u16, Value, Value) {
    let j = match body(headers, b) { Ok(j) => j, Err((c, w)) => return (c, json!({ "error": w }), json!({})) };
    let f = match finding_of(&j) { Ok(f) => f, Err((c, v)) => return (c, v, json!({})) };
    let params = json!({ "kind": kind_of(&f) });
    let Some(cfg) = a.tickets.filter(|_| a.halo.is_some()) else { return (409, json!({ "error": "Halo tickets aren't set up: choose Halo's ticket type, status and priority in setup (HALO_TICKET_TYPE_ID, HALO_TICKET_STATUS_ID, HALO_TICKET_PRIORITY_ID)" }), params) };
    match tickets::existing(&s.store.pool, &f).await {
        Err((c, w)) => return (c, json!({ "error": w }), params),
        Ok(Some((state, id))) => {
            let mut e = json!({ "state": state, "halo_ticket_id": id });
            if state == "unknown" {
                let title = tickets::title_of(&s.store.pool, &cfg, &f, &who.email).await;
                e["message"] = json!(tickets::may_exist(&title)); e["title"] = json!(title);
            }
            return (200, json!({ "existing": e }), params);
        }
        Ok(None) => {}
    }
    match tickets::build(&s.store.pool, &cfg, &f, &who.email).await {
        Ok(t) => (200, json!({ "finding": t.finding, "client": t.client, "halo_client_id": t.halo_client_id, "payload": t.payload, "digest": t.digest }), params),
        Err((c, w)) => (c, json!({ "error": w }), params),
    }
}

async fn create(State(s): State<AppState>, Extension(who): Extension<Who>, Extension(a): Extension<Arc<Actions>>, headers: HeaderMap, b: Bytes) -> Response {
    let t0 = Instant::now();
    let (code, v, params) = create_inner(&s, &who, &a, &headers, &b).await;
    audit(&s, &who, "ticket.create", params, code, t0);
    answer(code, v)
}
async fn create_inner(s: &AppState, who: &Who, a: &Actions, headers: &HeaderMap, b: &Bytes) -> (u16, Value, Value) {
    let j = match body(headers, b) { Ok(j) => j, Err((c, w)) => return (c, json!({ "error": w }), json!({})) };
    let f = match finding_of(&j) { Ok(f) => f, Err((c, v)) => return (c, v, json!({})) };
    let mut params = json!({ "kind": kind_of(&f) });
    let (Some(cfg), Some(halo)) = (a.tickets, a.halo.as_ref()) else { return (409, json!({ "error": "Halo tickets aren't set up" }), params) };
    let Some(digest) = j.get("digest").and_then(Value::as_str) else { return (400, json!({ "error": "digest is required: preview the ticket first, and send the digest it gave" }), params) };
    match tickets::create(&s.store.pool, halo, &cfg, &f, digest, &who.email).await {
        Ok((id, made)) => { params["halo_ticket_id"] = json!(id); params["created"] = json!(made); (200, json!({ "ok": true, "halo_ticket_id": id, "created": made }), params) }
        Err((c, w)) if w.contains(tickets::MAY_EXIST) => {
            params["unknown"] = json!(true);
            (c, json!({ "error": w, "unknown": true }), params)
        }
        Err((c, w)) => (c, json!({ "error": w }), params),
    }
}

async fn release(State(s): State<AppState>, Extension(who): Extension<Who>, Extension(a): Extension<Arc<Actions>>, headers: HeaderMap, b: Bytes) -> Response {
    let t0 = Instant::now();
    let (code, v, params) = release_inner(&s, &who, &a, &headers, &b).await;
    audit(&s, &who, "ticket.release", params, code, t0);
    answer(code, v)
}
/// An admin's word that Halo has no ticket for a finding whose claim was left unknown: the claim goes, and the finding
/// can be raised again. Audited with who and when (the audit line's own), and the finding's kind, never its value.
async fn release_inner(s: &AppState, who: &Who, a: &Actions, headers: &HeaderMap, b: &Bytes) -> (u16, Value, Value) {
    let j = match body(headers, b) { Ok(j) => j, Err((c, w)) => return (c, json!({ "error": w }), json!({})) };
    let f = match finding_of(&j) { Ok(f) => f, Err((c, v)) => return (c, v, json!({})) };
    let mut params = json!({ "kind": kind_of(&f) });
    if !a.console_admin(who) { return (403, json!({ "error": "Only an admin can release a ticket claim, once Halo has been checked." }), params); }
    match tickets::release(&s.store.pool, &f).await {
        Ok(true) => { params["released"] = json!(true); (200, json!({ "ok": true, "released": true }), params) }
        Ok(false) => (404, json!({ "error": "this finding has no ticket claim waiting to be checked" }), params),
        Err((c, w)) => (c, json!({ "error": w }), params),
    }
}
