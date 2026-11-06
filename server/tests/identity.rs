//! Sign-in, each AUTH_MODE, failing closed. Cloudflare Access is checked against a real key pair served from a local
//! certs endpoint; the trusted header against the peer's address.
mod common;
use axum::http::{HeaderMap, HeaderValue};
use common::*;
use msp_console::identity::{CloudflareAccess, Identity, TrustedHeader};
use serde_json::json;
use std::net::IpAddr;

fn h(name: &'static str, v: &str) -> HeaderMap { let mut m = HeaderMap::new(); m.insert(name, HeaderValue::from_str(v).unwrap()); m }
const LOCAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

#[tokio::test]
async fn access_accepts_a_valid_token_and_names_the_person() {
    let (url, _) = certs().await;
    let id = CloudflareAccess::new(TEAM, AUD, &url, msp_console::http_client());
    let who = id.identify(&h("cf-access-jwt-assertion", &sign(claims(json!({})), &keys().a_pem, "kid-a")), LOCAL).await.unwrap();
    assert_eq!(who.email, "tech@example.com");
    let svc = id.identify(&h("cf-access-jwt-assertion", &sign(claims(json!({ "email": null, "common_name": "svc.abc" })), &keys().a_pem, "kid-a")), LOCAL).await.unwrap();
    assert_eq!(svc.email, "service:svc.abc");
}

#[tokio::test]
async fn access_refuses_everything_else() {
    let (url, _) = certs().await;
    let id = CloudflareAccess::new(TEAM, AUD, &url, msp_console::http_client());
    let bad = [
        ("no token", HeaderMap::new()),
        ("junk", h("cf-access-jwt-assertion", "not-a-jwt")),
        ("another audience", h("cf-access-jwt-assertion", &sign(claims(json!({ "aud": "other" })), &keys().a_pem, "kid-a"))),
        ("another team", h("cf-access-jwt-assertion", &sign(claims(json!({ "iss": "https://evil.cloudflareaccess.com" })), &keys().a_pem, "kid-a"))),
        ("expired", h("cf-access-jwt-assertion", &sign(claims(json!({ "exp": now() - 600 })), &keys().a_pem, "kid-a"))),
        ("no expiry", h("cf-access-jwt-assertion", &sign(claims(json!({ "exp": null })), &keys().a_pem, "kid-a"))),
        ("a stranger's key under the team's kid", h("cf-access-jwt-assertion", &sign(claims(json!({})), &keys().b_pem, "kid-a"))),
        ("a key the team doesn't publish", h("cf-access-jwt-assertion", &sign(claims(json!({})), &keys().b_pem, "kid-b"))),
        ("names no one", h("cf-access-jwt-assertion", &sign(claims(json!({ "email": null })), &keys().a_pem, "kid-a"))),
        ("a token in the wrong header", h("authorization", &format!("Bearer {}", sign(claims(json!({})), &keys().a_pem, "kid-a")))),
    ];
    for (what, headers) in bad { assert!(id.identify(&headers, LOCAL).await.is_err(), "accepted: {what}"); }
    let hs = jsonwebtoken::encode(&jsonwebtoken::Header { kid: Some("kid-a".into()), ..jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256) },
        &claims(json!({})), &jsonwebtoken::EncodingKey::from_secret(b"secret-secret-secret-secret-1234")).unwrap();
    assert!(id.identify(&h("cf-access-jwt-assertion", &hs), LOCAL).await.is_err(), "accepted HS256");
}

#[tokio::test]
async fn an_unknown_key_id_cannot_make_the_server_fetch_on_every_request() {
    let (url, n) = certs().await;
    let id = CloudflareAccess::new(TEAM, AUD, &url, msp_console::http_client());
    for _ in 0..5 { let _ = id.identify(&h("cf-access-jwt-assertion", &sign(claims(json!({})), &keys().b_pem, "kid-zzz")), LOCAL).await; }
    assert_eq!(*n.lock().unwrap(), 1, "the certs were fetched more than once a minute");
    assert!(id.identify(&h("cf-access-jwt-assertion", &sign(claims(json!({})), &keys().a_pem, "kid-a")), LOCAL).await.is_ok(), "the team's own key, cached from that one fetch");
}

#[tokio::test]
async fn the_trusted_header_is_believed_only_from_the_proxy() {
    let id = TrustedHeader { header: "x-forwarded-email".into(), cidrs: vec!["10.0.5.0/24".parse().unwrap()] };
    let proxy: IpAddr = "10.0.5.7".parse().unwrap();
    let other: IpAddr = "10.0.6.7".parse().unwrap();
    assert_eq!(id.identify(&h("x-forwarded-email", "tech@example.com"), proxy).await.unwrap().email, "tech@example.com");
    assert!(id.identify(&h("x-forwarded-email", "ceo@example.com"), other).await.is_err(), "believed a header from outside the proxy's range");
    assert!(id.identify(&HeaderMap::new(), proxy).await.is_err(), "no header from the proxy is no one");
    assert!(id.identify(&h("x-forwarded-email", "  "), proxy).await.is_err());
}
