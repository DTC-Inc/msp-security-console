//! The server's routes: health, the API behind sign-in (every /api call, failing closed), the contract checked first,
//! answered from the console's own store, the jobs' status, an audit line per request, and the web app's files.

use crate::audit::{audit_params, now, AuditRecord, AuditSink};
use crate::contract::EvidenceRequest;
use crate::ops::Store;
use crate::identity::{Identity, Who};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Extension, Json, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(Clone)]
pub struct AppState { pub identity: Arc<dyn Identity>, pub store: Store, pub audit: AuditSink }

pub const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub fn security_headers(r: Router) -> Router {
    r.layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP)))
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
        .layer(SetResponseHeaderLayer::overriding(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
}

pub fn router(state: AppState, static_dir: Option<PathBuf>) -> Router { router_with(state, static_dir, Router::new()) }

/// The router with more /api calls behind the same sign-in (the Blackpoint, exposure and ticket writes: ops::actions).
pub fn router_with(state: AppState, static_dir: Option<PathBuf>, extra: Router<AppState>) -> Router {
    let api = Router::new()
        .route("/api/me", get(me))
        .route("/api/evidence", post(evidence))
        .route("/api/status", get(status))
        .route("/api/review", post(review))
        // Any other /api path is a JSON 404, still behind sign-in, never the web app's index.html.
        .route("/api", any(no_such_call))
        .route("/api/{*rest}", any(no_such_call))
        .merge(extra)
        .layer(middleware::from_fn_with_state(state.clone(), sign_in))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state.clone());
    // Ready means the database answers: a replica that lost it takes no traffic.
    let pool = state.store.pool.clone();
    let ready = get(move || { let pool = pool.clone(); async move {
        if crate::db::ping(&pool).await { (StatusCode::OK, "ok") } else { (StatusCode::SERVICE_UNAVAILABLE, "the database doesn't answer") }
    } });
    let mut r = Router::new().route("/healthz", get(|| async { "ok" })).route("/readyz", ready).merge(api);
    if let Some(dir) = static_dir {
        // The exported web app; any other path is the app's own (it keeps its view in the URL hash).
        let index = dir.join("index.html");
        r = r.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)));
    }
    security_headers(r)
}

async fn sign_in(State(s): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    let t0 = Instant::now();
    match s.identity.identify(req.headers(), peer.ip()).await {
        Ok(who) => { req.extensions_mut().insert(who); next.run(req).await }
        Err(_) => {
            (s.audit)(AuditRecord { at: now(), who: None, op: None, params: json!({}), rows: None, status: 401, ms: t0.elapsed().as_millis() });
            // When the console signs people in itself (oidc), say where; the app sends the browser there.
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": "sign in first", "login": s.identity.login_url() }))).into_response()
        }
    }
}

async fn no_such_call() -> Response { (StatusCode::NOT_FOUND, Json(json!({ "error": "there's no such API call" }))).into_response() }

/// Who is signed in, and where to sign out when the console signed them in itself (oidc).
async fn me(State(s): State<AppState>, Extension(who): Extension<Who>) -> Json<serde_json::Value> {
    Json(json!({ "email": who.email, "admin": who.admin, "logout": s.identity.login_url().map(|_| "/auth/logout") }))
}

async fn evidence(State(s): State<AppState>, Extension(who): Extension<Who>, body: Bytes) -> Response {
    let t0 = Instant::now();
    let req = match EvidenceRequest::parse(&body) {
        Ok(r) => r,
        Err(why) => {
            (s.audit)(AuditRecord { at: now(), who: Some(who.email), op: None, params: json!({}), rows: None, status: 400, ms: t0.elapsed().as_millis() });
            return (StatusCode::BAD_REQUEST, Json(json!({ "v": 1, "error": why }))).into_response();
        }
    };
    let (code, ans) = s.store.call(&req).await;
    let failed = code != 200;
    let rows = ans.get("data").map(|d| d.as_array().map(Vec::len).unwrap_or(usize::from(!d.is_null())));
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (s.audit)(AuditRecord { at: now(), who: Some(who.email), op: Some(req.op.as_str().into()), params: audit_params(&req.params), rows: if failed { None } else { rows }, status: status.as_u16(), ms: t0.elapsed().as_millis() });
    (status, Json(ans)).into_response()
}

/// The jobs behind the data: when each last succeeded, its last error (a status, never a secret), when it runs next;
/// the store: which kind, whether it can hold vectors, and whose the backups are; and the embedder: on (its model,
/// its threads) or off and why. The embed job's own counts (embedded, remaining) are its detail in `jobs`.
async fn status(State(s): State<AppState>) -> Response {
    match crate::scheduler::status(&s.store.pool).await {
        Ok(jobs) => Json(json!({ "jobs": jobs, "store": crate::db::describe(&s.store.pool).await, "embedder": s.store.similar.describe() })).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "the console's database didn't answer" }))).into_response(),
    }
}

/// A signed-in user's decision on a name the automatic mapping wouldn't decide (ops::processes). Audited with who
/// decided, the kind and the decision; never the name.
async fn review(State(s): State<AppState>, Extension(who): Extension<Who>, body: Bytes) -> Response {
    let t0 = Instant::now();
    let (code, ans, params) = match crate::contract::ReviewDecision::parse(&body) {
        Err(why) => (400, json!({ "error": why }), json!({})),
        Ok(d) => {
            let (code, ans) = s.store.decide(&who.email, &d).await;
            let params = json!({ "kind": d.kind.as_str(), "decision": d.decision, "unchanged": ans.get("unchanged") });
            (code, ans, params)
        }
    };
    (s.audit)(AuditRecord { at: now(), who: Some(who.email), op: Some("review.decide".into()), params, rows: None, status: code, ms: t0.elapsed().as_millis() });
    (StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), Json(ans)).into_response()
}
