//! Who is signed in (design rev 3.1, "Identity"): one trait, failing closed, with an implementation per AUTH_MODE.

use crate::config::AuthConfig;
use axum::http::HeaderMap;
use ipnet::IpNet;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Who is signed in, and whether they're an admin: chosen by sign-in mode (OIDC_ADMIN_GROUP in the token for oidc,
/// ADMIN_EMAILS behind a proxy, and the local user on "only this computer"). Everyone signed in reads everything;
/// only an admin changes settings or advisories.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Who { pub email: String, pub admin: bool }

#[derive(Debug, Clone, PartialEq)]
pub struct Refusal(pub String);

pub type IdFuture<'a> = Pin<Box<dyn Future<Output = Result<Who, Refusal>> + Send + 'a>>;

pub trait Identity: Send + Sync {
    fn identify<'a>(&'a self, headers: &'a HeaderMap, peer: IpAddr) -> IdFuture<'a>;
    fn mode(&self) -> &'static str;
    /// Where a browser goes to sign in, when the console does the signing in itself (oidc); a proxy mode has none.
    fn login_url(&self) -> Option<&'static str> { None }
}

/// The configured sign-in, and the routes it adds (oidc's /auth/*).
pub fn from_config(cfg: &crate::config::Config, http: reqwest::Client) -> (Arc<dyn Identity>, Option<axum::Router>) {
    match cfg.auth.clone() {
        AuthConfig::CloudflareAccess { team_domain, aud, certs_url } => (with_admins(Arc::new(CloudflareAccess::new(&team_domain, &aud, &certs_url, http)), &cfg.admins), None),
        AuthConfig::TrustedHeader { header, cidrs } => (with_admins(Arc::new(TrustedHeader { header, cidrs }), &cfg.admins), None),
        AuthConfig::Oidc { issuer, client_id, client_secret, allowed_group, session_key } => {
            let public_url = cfg.public_url.clone().unwrap_or_default();
            let group = match &cfg.admins { crate::config::Admins::Group(g) => Some(g.clone()), _ => None };
            let o = Arc::new(crate::oidc::Oidc::new(crate::oidc::OidcSettings { issuer, client_id, client_secret, allowed_group, session_key, public_url }, http).with_admin_group(group));
            (o.clone(), Some(crate::oidc::routes(o)))
        }
        AuthConfig::DevInsecure => (Arc::new(DevInsecure), None),
    }
}

/// A proxy's sign-in, with ADMIN_EMAILS made admins (case-insensitively). Any other admin setting leaves it as it is.
fn with_admins(inner: Arc<dyn Identity>, admins: &crate::config::Admins) -> Arc<dyn Identity> {
    match admins { crate::config::Admins::Emails(e) => Arc::new(WithAdmins { inner, emails: e.clone() }), _ => inner }
}

/// A sign-in whose admins are a list of addresses (ADMIN_EMAILS), for the proxy modes, whose identities carry no groups.
pub struct WithAdmins { pub inner: Arc<dyn Identity>, pub emails: Vec<String> }

impl Identity for WithAdmins {
    fn mode(&self) -> &'static str { self.inner.mode() }
    fn login_url(&self) -> Option<&'static str> { self.inner.login_url() }
    fn identify<'a>(&'a self, headers: &'a HeaderMap, peer: IpAddr) -> IdFuture<'a> {
        Box::pin(async move {
            let mut who = self.inner.identify(headers, peer).await?;
            who.admin = who.admin || self.emails.iter().any(|e| e.eq_ignore_ascii_case(who.email.trim()));
            Ok(who)
        })
    }
}

/// Cloudflare Access: RS256 against the team's keys (fetched from its certs endpoint, cached, refetched on an unknown
/// key id at most once a minute), the application's audience tag, the team as issuer, the expiry.
pub struct CloudflareAccess { issuer: String, aud: String, certs_url: String, http: reqwest::Client, keys: RwLock<(HashMap<String, DecodingKey>, Option<Instant>)> }

#[derive(Deserialize)]
struct AccessClaims { email: Option<String>, common_name: Option<String> }

impl CloudflareAccess {
    pub fn new(team_domain: &str, aud: &str, certs_url: &str, http: reqwest::Client) -> Self {
        Self { issuer: format!("https://{team_domain}"), aud: aud.into(), certs_url: certs_url.into(), http, keys: RwLock::new((HashMap::new(), None)) }
    }
    async fn key(&self, kid: &str) -> Option<DecodingKey> {
        if let Some(k) = self.keys.read().await.0.get(kid) { return Some(k.clone()); }
        let mut w = self.keys.write().await;
        if let Some(k) = w.0.get(kid) { return Some(k.clone()); }
        if w.1.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) { return None; }   // an unknown kid can't make us fetch on every request
        w.1 = Some(Instant::now());
        let set: JwkSet = self.http.get(&self.certs_url).timeout(Duration::from_secs(10)).send().await.ok()?.error_for_status().ok()?.json().await.ok()?;
        w.0 = set.keys.iter().filter_map(|j| Some((j.common.key_id.clone()?, DecodingKey::from_jwk(j).ok()?))).collect();
        w.0.get(kid).cloned()
    }
}

impl Identity for CloudflareAccess {
    fn mode(&self) -> &'static str { "proxy/cloudflare_access" }
    fn identify<'a>(&'a self, headers: &'a HeaderMap, _peer: IpAddr) -> IdFuture<'a> {
        Box::pin(async move {
            let token = headers.get("cf-access-jwt-assertion").and_then(|v| v.to_str().ok()).filter(|s| !s.is_empty()).ok_or(Refusal("no Access token".into()))?;
            let header = decode_header(token).map_err(|_| Refusal("Access token unreadable".into()))?;
            if header.alg != Algorithm::RS256 { return Err(Refusal("Access token not RS256".into())); }
            let kid = header.kid.ok_or(Refusal("Access token names no key".into()))?;
            let key = self.key(&kid).await.ok_or(Refusal("Access token signed by a key the team doesn't publish".into()))?;
            let mut v = Validation::new(Algorithm::RS256);
            v.set_audience(&[&self.aud]);
            v.set_issuer(&[&self.issuer]);
            v.set_required_spec_claims(&["exp", "iss", "aud"]);
            let data = decode::<AccessClaims>(token, &key, &v).map_err(|e| Refusal(format!("Access token refused: {:?}", e.kind())))?;
            match (data.claims.email, data.claims.common_name) {
                (Some(e), _) if !e.is_empty() => Ok(Who { email: e, admin: false }),
                (_, Some(cn)) if !cn.is_empty() => Ok(Who { email: format!("service:{cn}"), admin: false }),
                _ => Err(Refusal("Access token names no one".into())),
            }
        })
    }
}

/// A reverse proxy that authenticates and passes the user in a header. Believed only from TRUSTED_PROXY_CIDRS: anyone
/// who reaches the pod another way could name any user, which is why the addresses are required and the
/// NetworkPolicy should admit only the proxy.
pub struct TrustedHeader { pub header: String, pub cidrs: Vec<IpNet> }

impl Identity for TrustedHeader {
    fn mode(&self) -> &'static str { "proxy/trusted_header" }
    fn identify<'a>(&'a self, headers: &'a HeaderMap, peer: IpAddr) -> IdFuture<'a> {
        Box::pin(async move {
            if !self.cidrs.iter().any(|c| c.contains(&peer)) { return Err(Refusal("not from the trusted proxy".into())); }
            let who = headers.get(self.header.as_str()).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty() && s.len() <= 320)
                .ok_or(Refusal("the trusted proxy named no one".into()))?;
            Ok(Who { email: who.to_string(), admin: false })
        })
    }
}

pub struct DevInsecure;
impl Identity for DevInsecure {
    fn mode(&self) -> &'static str { "dev_insecure" }
    fn identify<'a>(&'a self, _h: &'a HeaderMap, _p: IpAddr) -> IdFuture<'a> { Box::pin(async { Ok(Who { email: "local-dev (no sign-in)".into(), admin: true }) }) }
}
