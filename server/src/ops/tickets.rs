//! A Halo ticket from a finding: a Blackpoint detection (`detection:<id>`) or an
//! exposed address (`exposure:<ip>`). The rules:
//! - **What's sent is what was shown.** The preview builds the ticket and a digest of it; the create builds it again
//!   and sends it only when the digest is the one the person confirmed, so a finding that changed in between is
//!   refused and shown again.
//! - **One ticket per finding.** The finding's row is claimed (`pending`) before Halo is called, so a second click,
//!   or a second person, gets the first ticket's link (or "being raised"), never another ticket. A call Halo refused
//!   (an HTTP 4xx), or one that never reached it, gives the claim back. A call whose answer was lost after it was sent
//!   (a timeout, a dropped connection, a 5xx, or a success without the ticket's id) may have made the ticket, so the
//!   claim stays, as `unknown`, and every later click is refused, naming the ticket's title to search Halo for. Once
//!   someone has looked and Halo has no such ticket, an admin releases the claim (`release`), audited, and the finding
//!   can be raised again: never a second ticket in a client's Halo without someone checking first.
//! - **Only a confirmed client.** The ticket goes to the client's Halo client only when Halo's own link to it is
//!   confirmed (its NinjaOne link), and a detection only when its tenant is confirmed. A name match is never enough.
//! - **Halo's settings decide its type, status and priority** (HALO_TICKET_TYPE_ID, HALO_TICKET_STATUS_ID,
//!   HALO_TICKET_PRIORITY_ID), picked from Halo's own lists in the setup wizard. There are no defaults.
//! - Halo's write goes through the same limiter as its reads (connectors::halo::shared_limiter).

use crate::connectors::halo::Halo;
use crate::connectors::ninja::db;
use crate::db::{self as store, Pool};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TicketCfg { pub type_id: i64, pub status_id: i64, pub priority_id: i64 }

pub const KEYS: [&str; 3] = ["HALO_TICKET_TYPE_ID", "HALO_TICKET_STATUS_ID", "HALO_TICKET_PRIORITY_ID"];

/// Tickets are on when all three are set (and Halo is), off when none are, and a refusal otherwise.
pub fn settings(get: &dyn Fn(&str) -> Option<String>, halo_on: bool) -> Result<Option<TicketCfg>, String> {
    let v: Vec<Option<String>> = KEYS.iter().map(|k| get(k)).collect();
    if v.iter().all(Option::is_none) { return Ok(None); }
    if v.iter().any(Option::is_none) { return Err("Halo tickets need HALO_TICKET_TYPE_ID, HALO_TICKET_STATUS_ID and HALO_TICKET_PRIORITY_ID together".into()); }
    if !halo_on { return Err("HALO_TICKET_TYPE_ID and the other ticket settings need HaloPSA's connector (HALO_BASE_URL, HALO_CLIENT_ID, HALO_CLIENT_SECRET)".into()); }
    let n = |i: usize| v[i].as_deref().and_then(|s| s.trim().parse::<i64>().ok()).filter(|n| *n > 0).ok_or(format!("{} must be Halo's id for it, a number above zero", KEYS[i]));
    Ok(Some(TicketCfg { type_id: n(0)?, status_id: n(1)?, priority_id: n(2)? }))
}

/// A refusal: the HTTP status to answer and a plain sentence.
pub type Refusal = (u16, String);
fn bad(s: &str) -> Refusal { (400, s.into()) }

fn esc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;") }
fn or_dash(v: &Value) -> String { match v { Value::Null => "—".into(), Value::String(s) => esc(s), x => esc(&x.to_string()) } }

/// The finding's key, checked: `detection:<id>` or `exposure:<IPv4>`.
pub fn parse_finding(f: &str) -> Result<(&'static str, String), Refusal> {
    match f.split_once(':') {
        Some(("detection", id)) if !id.is_empty() && id.len() <= 100 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') => Ok(("detection", id.to_string())),
        Some(("exposure", ip)) if ip.parse::<std::net::Ipv4Addr>().is_ok() => Ok(("exposure", ip.to_string())),
        _ => Err(bad("finding must be detection:<id> or exposure:<IPv4 address>")),
    }
}

/// What a ticket for this finding would be: the payload exactly as it would go to Halo, who it's for, and its digest.
#[derive(Debug, Clone)]
pub struct Built { pub finding: String, pub org_id: i64, pub client: String, pub halo_client_id: i64, pub payload: Value, pub digest: String }

pub fn digest(payload: &Value) -> String { Sha256::digest(serde_json::to_vec(payload).unwrap_or_default()).iter().map(|b| format!("{b:02x}")).collect() }

/// The client's Halo client, when Halo's link to it is confirmed.
async fn halo_client(pool: &Pool, org: i64) -> Result<(String, i64), Refusal> {
    let r: Option<(String, Option<i64>, Option<String>)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT name, halo_client_id, halo_matched_by FROM client WHERE org_id = $1 AND deleted_at IS NULL")
        .bind(org).fetch_optional(p).await).map_err(|_| (503, "the console's database didn't answer".to_string()))?;
    match r {
        None => Err(bad("that client isn't in the console")),
        Some((name, Some(h), Some(by))) if by == "ninjarmm_id" => Ok((name, h)),
        Some((name, _, _)) => Err((409, format!("{name} has no confirmed Halo client: link it to its NinjaOne organization in Halo, then try again"))),
    }
}

pub async fn build(pool: &Pool, cfg: &TicketCfg, finding: &str, who: &str) -> Result<Built, Refusal> {
    let (kind, id) = parse_finding(finding)?;
    let st = crate::ops::Store::new(pool.clone());
    let p = match kind {
        "detection" => crate::contract::Params { detection_id: Some(id.clone()), ..Default::default() },
        _ => crate::contract::Params { ip: Some(id.clone()), ..Default::default() },
    };
    let ans = match kind { "detection" => crate::ops::blackpoint::detection_get(&st, &p).await, _ => crate::ops::exposure::get(&st, &p).await }
        .map_err(|_| (503, "the console's database didn't answer".to_string()))?;
    let f = ans.get("data").cloned().filter(|d| !d.is_null()).ok_or((404, format!("that {kind} isn't in the console")))?;
    let (title, lines, org) = if kind == "detection" {
        let org = f["org_id"].as_i64().ok_or((409, "this detection's Blackpoint tenant isn't a confirmed client: confirm which client it is first".to_string()))?;
        let what = f["detection_name"].as_str().or(f["rule_name"].as_str()).map(String::from)
            .unwrap_or_else(|| { let t: Vec<&str> = f["alert_types"].as_array().into_iter().flatten().filter_map(Value::as_str).collect(); if t.is_empty() { "Blackpoint detection".into() } else { t.join(", ") } });
        let on = f["device_name"].as_str().or(f["hostname"].as_str()).unwrap_or("a device");
        (format!("Security alert: {what} on {on}"), vec![
            "<p><b>Security alert for triage.</b></p>".to_string(),
            format!("<p>Device: {}<br>User: {}<br>When: {}</p>", esc(on), or_dash(&f["username"]), or_dash(&f["created"])),
            format!("<p>Source: Blackpoint CompassOne. Detection: {}. Types: {}. Risk score: {}. Alerts in group: {}.</p>", esc(&what),
                    esc(&f["alert_types"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")), or_dash(&f["risk_score"]), or_dash(&f["alert_count"])),
        ], org)
    } else {
        let orgs: Vec<i64> = f["org_ids"].as_array().into_iter().flatten().filter_map(Value::as_i64).collect();
        let &[org] = &orgs[..] else { return Err((409, "this address is shared by more than one client (or by none): raise its ticket in Halo yourself".into())) };
        let sev = f["severity"].as_str().unwrap_or("unrated");
        let ports: Vec<String> = f["services"].as_array().into_iter().flatten().map(|s| format!("{}/{}{}", s["port"], s["transport"].as_str().unwrap_or(""),
            s["rule"]["label"].as_str().map(|l| format!(" ({l})")).unwrap_or_default())).collect();
        let kev: Vec<String> = f["cves"].as_array().into_iter().flatten().filter(|c| c["kev"].is_object()).filter_map(|c| c["cve_id"].as_str().map(String::from)).collect();
        let top: Vec<String> = f["cves"].as_array().into_iter().flatten().take(10)
            .map(|c| format!("{} (CVSS {})", c["cve_id"].as_str().unwrap_or(""), c["cvss"].as_f64().map(|x| x.to_string()).unwrap_or_else(|| "unscored".into()))).collect();
        (format!("Internet exposure: {id} ({sev})"), vec![
            "<p><b>Internet exposure for triage.</b></p>".to_string(),
            format!("<p>Address: {}{}</p>", esc(&id), if f["website"] == json!(true) { format!(" (the server behind {})", esc(&f["sites"].as_array().into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))) } else { String::new() }),
            format!("<p>Open services, as Shodan's internet scan saw them: {}.</p>", if ports.is_empty() { "none".into() } else { esc(&ports.join(", ")) }),
            format!("<p>In CISA's known-exploited list: {}.<br>CVEs, worst first: {}.</p>", if kev.is_empty() { "none".into() } else { esc(&kev.join(", ")) }, if top.is_empty() { "none known".into() } else { esc(&top.join(", ")) }),
        ], org)
    };
    let (client, halo_client_id) = halo_client(pool, org).await?;
    let mut details = lines;
    details.insert(1, format!("<p>Client: {}</p>", esc(&client)));
    details.push(format!("<p>Raised from the MSP Security Console by {}. Finding: {}.</p>", esc(who), esc(finding)));
    let payload = json!({ "summary": title.chars().take(250).collect::<String>(), "details_html": details.join("\n"), "client_id": halo_client_id,
                          "tickettype_id": cfg.type_id, "status_id": cfg.status_id, "priority_id": cfg.priority_id });
    Ok(Built { finding: finding.to_string(), org_id: org, client, halo_client_id, digest: digest(&payload), payload })
}

/// The ticket already raised for this finding: Some((state, Halo's id)).
pub async fn existing(pool: &Pool, finding: &str) -> Result<Option<(String, Option<i64>)>, Refusal> {
    crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT state, halo_ticket_id FROM finding_ticket WHERE finding_key = $1").bind(finding).fetch_optional(p).await)
        .map_err(|_| (503, "the console's database didn't answer".to_string()))
}

/// The start of the refusal for a finding whose ticket may exist: its answer was lost after the request reached Halo.
pub const MAY_EXIST: &str = "A ticket may already exist in Halo.";
/// The whole refusal, naming the title to search Halo for.
pub fn may_exist(title: &str) -> String { format!("{MAY_EXIST} Search Halo for '{title}' before an admin releases this.") }

/// The title a finding's ticket has (or would have): what to search Halo for. The finding's own key if it can't be built.
pub async fn title_of(pool: &Pool, cfg: &TicketCfg, finding: &str, who: &str) -> String {
    build(pool, cfg, finding, who).await.ok().and_then(|b| b.payload["summary"].as_str().map(String::from)).unwrap_or_else(|| finding.to_string())
}

/// Give back a claim left `unknown`, once someone has checked Halo has no ticket for it: Ok(true) when one was
/// released, Ok(false) when the finding has no unknown claim (made, being made, or none).
pub async fn release(pool: &Pool, finding: &str) -> Result<bool, Refusal> {
    crate::on_pool!(pool, p, _ => sqlx::query("DELETE FROM finding_ticket WHERE finding_key = $1 AND state = 'unknown'").bind(finding).execute(p).await.map(|r| r.rows_affected() > 0))
        .map_err(|e| (503, db(e)))
}

/// Whether a failed send is known not to have made a ticket: Halo refused it (a 4xx, its sign-in included), or the
/// connection never reached Halo. Anything else (a timeout, a dropped connection, a 5xx) may have made one.
fn not_made(e: &str) -> bool { e.starts_with("Halo: HTTP 4") || e == "Halo: unreachable" || e.starts_with("Halo sign-in:") }

/// Raise it: Ok((Halo's ticket id, whether it was made now)).
pub async fn create(pool: &Pool, halo: &Halo, cfg: &TicketCfg, finding: &str, confirmed: &str, who: &str) -> Result<(i64, bool), Refusal> {
    if let Some((state, id)) = existing(pool, finding).await? {
        return match (state.as_str(), id) {
            ("created", Some(id)) => Ok((id, false)),
            ("unknown", _) => Err((409, may_exist(&title_of(pool, cfg, finding, who).await))),
            _ => Err((409, "a ticket for this finding is being raised now; reload in a moment".into())),
        };
    }
    let b = build(pool, cfg, finding, who).await?;
    if b.digest != confirmed { return Err((409, "the finding changed since you looked: review the ticket again before sending it".into())); }
    // The claim: one row per finding, so only one of two clicks gets past here.
    let claimed = crate::on_pool!(pool, p, _ => sqlx::query("INSERT INTO finding_ticket (finding_key, state, halo_client_id, org_id, created_by, created_at) VALUES ($1, 'pending', $2, $3, $4, $5)
                                                             ON CONFLICT (finding_key) DO NOTHING")
        .bind(finding).bind(b.halo_client_id).bind(b.org_id).bind(who).bind(store::now()).execute(p).await.map(|r| r.rows_affected()))
        .map_err(|e| (503, db(e)))?;
    if claimed == 0 { return Box::pin(create(pool, halo, cfg, finding, confirmed, who)).await; }
    let made = halo.post("/Tickets", &json!([b.payload])).await;
    let id = made.as_ref().ok().and_then(|j| j.get(0).unwrap_or(j).get("id").and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))));
    match (made, id) {
        (Ok(_), Some(id)) => {
            crate::on_pool!(pool, p, _ => sqlx::query("UPDATE finding_ticket SET state = 'created', halo_ticket_id = $2 WHERE finding_key = $1").bind(finding).bind(id).execute(p).await.map(|_| ()))
                .map_err(|e| (503, db(e)))?;
            Ok((id, true))
        }
        (Err(e), _) if not_made(&e) => {
            let _ = crate::on_pool!(pool, p, _ => sqlx::query("DELETE FROM finding_ticket WHERE finding_key = $1 AND state = 'pending'").bind(finding).execute(p).await.map(|_| ()));
            Err((502, format!("{e}: no ticket was made")))
        }
        (r, _) => {
            // The request went and its answer didn't come back whole: keep the claim, so no click makes a second one.
            let _ = crate::on_pool!(pool, p, _ => sqlx::query("UPDATE finding_ticket SET state = 'unknown' WHERE finding_key = $1 AND state = 'pending'").bind(finding).execute(p).await.map(|_| ()));
            let why = match r { Err(e) => e, Ok(_) => "Halo answered without the new ticket's id".into() };
            Err((502, format!("{why}. {}", may_exist(b.payload["summary"].as_str().unwrap_or(finding)))))
        }
    }
}
