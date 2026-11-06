//! Internet exposure's ops: each public address clients' servers and desktops egress from, and each website's
//! dedicated server, with what Shodan saw open on it, each port rated by its rule, and every CVE that touches it
//! (Shodan's lead, and the console's own NVD match for the version it saw) checked against KEV. Read-only; edge marks
//! and scan policies change through src/ops/actions.rs. The model: the CVEs decide an
//! address's rating, an open port's rule is only its floor, and an edge entry point counts in no total.

use super::blackpoint::job_ok;
use super::{page_by, Failure, Store};
use crate::connectors::shodan::port_rule;
use crate::contract::Params;
use crate::db::Pool;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

type When = Option<chrono::DateTime<chrono::Utc>>;

fn rank(s: &str) -> u8 { match s { "critical" => 5, "high" => 4, "medium" | "unscored" => 3, "low" | "info" | "other" => 1, _ => 0 } }

#[derive(Default)]
struct Addr { orgs: BTreeSet<i64>, clients: BTreeSet<String>, servers: i64, desktops: i64, website: bool, sites: BTreeSet<String>, devices: Vec<Value> }

/// Every address with all it carries; `org` narrows to one client's, `ip` to one address.
async fn addresses(pool: &Pool, org: Option<i64>, ip: Option<&str>) -> Result<Vec<Value>, Failure> {
    type Wan = (String, i64, String, String, i64, Option<String>);
    type Site = (String, Option<i64>, Option<String>, String);
    type Host = (String, bool, When, When, Value, Value, Value, Value, Option<String>, Option<String>, Option<String>, When, When);
    type Svc = (String, i64, String, Option<String>, Option<String>, Value, Option<String>, When, Option<String>, Option<String>, Value);
    let (wan, sites, hosts, svcs): (Vec<Wan>, Vec<Site>, Vec<Host>, Vec<Svc>) = crate::on_pool!(pool, p, _ => (
        sqlx::query_as("SELECT w.public_ip, d.org_id, d.name, d.device_class, d.device_id, c.name FROM device_wan w JOIN device d ON d.device_id = w.device_id AND d.deleted_at IS NULL
                         AND d.device_class IN ('server', 'desktop') LEFT JOIN client c ON c.org_id = d.org_id ORDER BY w.public_ip, d.name").fetch_all(p).await.map_err(|_| Failure::Db)?,
        sqlx::query_as("SELECT s.ip, s.org_id, c.name, s.hostname FROM exposure_site s LEFT JOIN client c ON c.org_id = s.org_id WHERE s.classification = 'dedicated' AND s.ip <> ''")
            .fetch_all(p).await.map_err(|_| Failure::Db)?,
        sqlx::query_as("SELECT ip, found, looked_up_at, provider_updated_at, ports, hostnames, tags, vulns, net_org, isp, error, last_scan_requested_at, last_scan_completed_at FROM exposure_host")
            .fetch_all(p).await.map_err(|_| Failure::Db)?,
        sqlx::query_as("SELECT ip, port, transport, product, version, vulns, title, seen_at, nvd_cpe, nvd_version, nvd_cves FROM exposure_service ORDER BY ip, port, transport")
            .fetch_all(p).await.map_err(|_| Failure::Db)?));
    type Mark = (String, bool, Option<String>, String, When);
    type Rest = (Vec<Mark>, Vec<(i64, i64, String, When)>, Vec<(Value, String)>, Vec<(String, Option<i64>)>);
    let (marks, policies, pending, tickets): Rest = crate::on_pool!(pool, p, _ => (
        sqlx::query_as("SELECT ip, edge, note, marked_by, marked_at FROM exposure_mark").fetch_all(p).await.map_err(|_| Failure::Db)?,
        sqlx::query_as("SELECT org_id, frequency_days, set_by, set_at FROM scan_policy").fetch_all(p).await.map_err(|_| Failure::Db)?,
        sqlx::query_as("SELECT ips, status FROM scan_request WHERE status NOT IN ('DONE', 'failed')").fetch_all(p).await.map_err(|_| Failure::Db)?,
        sqlx::query_as("SELECT finding_key, halo_ticket_id FROM finding_ticket WHERE state = 'created' AND finding_key LIKE 'exposure:%'").fetch_all(p).await.map_err(|_| Failure::Db)?));
    let mut by: BTreeMap<String, Addr> = BTreeMap::new();
    for (a, o, dname, class, did, cname) in wan {
        let x = by.entry(a).or_default();
        x.orgs.insert(o); if let Some(c) = cname { x.clients.insert(c); }
        if class == "server" { x.servers += 1; } else { x.desktops += 1; }
        x.devices.push(json!({ "device_id": did, "name": dname, "device_class": class, "org_id": o }));
    }
    for (a, o, cname, host) in sites {
        let wan_addr = by.get(&a).is_some_and(|x| !x.devices.is_empty());
        let x = by.entry(a).or_default();
        if !wan_addr { x.website = true; }
        if let Some(o) = o { x.orgs.insert(o); }
        if let Some(c) = cname { x.clients.insert(c); }
        x.sites.insert(host);
    }
    by.retain(|a, x| org.is_none_or(|o| x.orgs.contains(&o)) && ip.is_none_or(|i| i == a));
    let host_of: HashMap<&str, &Host> = hosts.iter().map(|h| (h.0.as_str(), h)).collect();
    let mut svc_of: HashMap<&str, Vec<&Svc>> = HashMap::new();
    for s in &svcs { svc_of.entry(s.0.as_str()).or_default().push(s); }
    // Every CVE that touches each address, and where it came from.
    let ids_of = |v: &Value| v.as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect::<Vec<_>>();
    let mut all: BTreeSet<String> = BTreeSet::new();
    for a in by.keys() {
        if let Some(h) = host_of.get(a.as_str()) { all.extend(ids_of(&h.7)); }
        for s in svc_of.get(a.as_str()).into_iter().flatten() { all.extend(ids_of(&s.5)); all.extend(s.10.as_array().into_iter().flatten().filter_map(|c| c.get("cve").and_then(Value::as_str)).map(String::from)); }
    }
    let ids: Vec<String> = all.into_iter().collect();
    type Nvd = (String, Option<f64>, Option<String>, Option<String>, When);
    type Facts = (Vec<Nvd>, Vec<(String, Option<String>, bool)>);
    let (nvd, kev): Facts = crate::on_pool!(pool, p, pg => (
        sqlx::query_as(if pg { "SELECT cve_id, cvss, severity, description, published FROM sec_nvd_cve WHERE cve_id = ANY($1)" }
                       else { "SELECT cve_id, cvss, severity, description, published FROM sec_nvd_cve WHERE cve_id IN (SELECT value FROM json_each($1))" })
            .bind(crate::db::list(&ids)).fetch_all(p).await.map_err(|_| Failure::Db)?,
        sqlx::query_as(if pg { "SELECT cve_id, name, ransomware FROM sec_kev WHERE cve_id = ANY($1)" } else { "SELECT cve_id, name, ransomware FROM sec_kev WHERE cve_id IN (SELECT value FROM json_each($1))" })
            .bind(crate::db::list(&ids)).fetch_all(p).await.map_err(|_| Failure::Db)?));
    let nvd: HashMap<&str, &Nvd> = nvd.iter().map(|n| (n.0.as_str(), n)).collect();
    let kev: HashMap<&str, (Option<String>, bool)> = kev.iter().map(|k| (k.0.as_str(), (k.1.clone(), k.2))).collect();
    let mark: HashMap<&str, &Mark> = marks.iter().map(|m| (m.0.as_str(), m)).collect();
    let policy: HashMap<i64, (i64, String, When)> = policies.into_iter().map(|(o, d, b, t)| (o, (d, b, t))).collect();
    let ticket: HashMap<String, Option<i64>> = tickets.into_iter().map(|(k, t)| (k.trim_start_matches("exposure:").to_string(), t)).collect();
    let mut out = Vec::new();
    for (a, x) in by {
        let h = host_of.get(a.as_str());
        // (sources, ports, the version NVD matched)
        // Each CVE: its sources, the ports it's on, and the version NVD matched.
        type Hit<'a> = (BTreeSet<&'a str>, BTreeSet<String>, Option<String>);
        let mut hits: BTreeMap<String, Hit> = BTreeMap::new();
        if let Some(h) = h { for id in ids_of(&h.7) { hits.entry(id).or_default().0.insert("shodan"); } }
        let mut services = Vec::new();
        for s in svc_of.get(a.as_str()).into_iter().flatten() {
            let port = format!("{}/{}", s.1, s.2);
            for id in ids_of(&s.5) { let e = hits.entry(id).or_default(); e.0.insert("shodan"); e.1.insert(port.clone()); }
            for c in s.10.as_array().into_iter().flatten().filter_map(|c| c.get("cve").and_then(Value::as_str)) {
                let e = hits.entry(c.to_string()).or_default(); e.0.insert("nvd"); e.1.insert(port.clone()); e.2 = s.9.clone();
            }
            let rule = port_rule(s.1, &s.2);
            services.push(json!({ "port": s.1, "transport": s.2, "product": s.3, "version": s.4, "title": s.6, "seen_at": s.7, "nvd_cpe": s.8, "nvd_version": s.9,
                "rule": rule.map(|r| json!({ "label": r.0, "severity": r.1, "why": r.2 })) }));
        }
        let mut cves: Vec<Value> = hits.into_iter().map(|(id, (src, ports, ver))| {
            let n = nvd.get(id.as_str());
            let k = kev.get(id.as_str());
            json!({ "cve_id": id, "cvss": n.and_then(|n| n.1), "severity": n.and_then(|n| n.2.clone()), "description": n.and_then(|n| n.3.as_ref()).map(|d| d.chars().take(260).collect::<String>()),
                    "published": n.and_then(|n| n.4), "kev": k.map(|k| json!({ "name": k.0, "ransomware": k.1 })), "sources": src, "ports": ports, "nvd_version": ver })
        }).collect();
        cves.sort_by(|a, b| b["kev"].is_object().cmp(&a["kev"].is_object()).then(b["cvss"].as_f64().unwrap_or(-1.0).partial_cmp(&a["cvss"].as_f64().unwrap_or(-1.0)).unwrap_or(std::cmp::Ordering::Equal))
            .then(a["cve_id"].as_str().cmp(&b["cve_id"].as_str())));
        let (kev_n, cve_n) = (cves.iter().filter(|c| c["kev"].is_object()).count(), cves.len());
        let scored: Vec<f64> = cves.iter().filter_map(|c| c["cvss"].as_f64()).collect();
        let max = scored.iter().cloned().fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
        let unscored = cves.len() - scored.len();
        let cve_sev = if kev_n > 0 { Some("critical") } else { match max { Some(m) if m >= 9.0 => Some("critical"), Some(m) if m >= 7.0 => Some("high"), Some(m) if m >= 4.0 => Some("medium"), Some(_) => Some("low"), None if unscored > 0 => Some("unscored"), None => None } };
        let rule_sev: Option<&'static str> = services.iter().filter_map(|s| s["rule"]["severity"].as_str()).max_by_key(|s| rank(s))
            .and_then(|s| ["critical", "high", "medium", "low", "info"].into_iter().find(|x| *x == s));
        let severity = match (cve_sev, rule_sev) {
            (Some(c), Some(r)) => if rank(c) >= rank(r) { Some(c) } else { Some(r) },
            (Some(c), None) => Some(c),
            (None, Some(r)) => Some(r),
            (None, None) => if services.is_empty() { None } else { Some("other") },
        };
        for s in &mut services {
            let port = format!("{}/{}", s["port"], s["transport"].as_str().unwrap_or(""));
            let mine: Vec<&Value> = cves.iter().filter(|c| c["ports"].as_array().is_some_and(|p| p.contains(&json!(port)))).collect();
            s["cve_count"] = json!(mine.len()); s["kev_count"] = json!(mine.iter().filter(|c| c["kev"].is_object()).count());
        }
        let m = mark.get(a.as_str());
        let scan = if x.website { Value::Null } else {
            let days = x.orgs.iter().filter_map(|o| policy.get(o).map(|p| p.0)).filter(|d| *d > 0).min();
            json!({ "days": days, "requested_at": h.and_then(|h| h.11), "completed_at": h.and_then(|h| h.12),
                    "pending": pending.iter().find(|(ips, _)| ips.as_array().is_some_and(|l| l.contains(&json!(a)))).map(|p| p.1.clone()) })
        };
        out.push(json!({ "ip": a, "org_ids": x.orgs, "clients": x.clients, "servers": x.servers, "desktops": x.desktops, "website": x.website, "sites": x.sites,
            "devices": x.devices, "found": h.map(|h| h.1), "looked_up_at": h.and_then(|h| h.2), "provider_updated_at": h.and_then(|h| h.3),
            "ports": h.map(|h| h.4.clone()).unwrap_or(json!([])), "hostnames": h.map(|h| h.5.clone()).unwrap_or(json!([])), "tags": h.map(|h| h.6.clone()).unwrap_or(json!([])),
            "net_org": h.and_then(|h| h.8.clone()), "isp": h.and_then(|h| h.9.clone()), "error": h.and_then(|h| h.10.clone()),
            "services": services, "cves": cves, "cve_count": cve_n, "kev_count": kev_n, "max_cvss": max, "unscored": unscored,
            "severity": severity, "rule_severity": rule_sev,
            "edge": m.is_some_and(|m| m.1), "edge_note": m.and_then(|m| m.2.clone()), "edge_by": m.map(|m| m.3.clone()), "edge_at": m.and_then(|m| m.4),
            "scan": scan, "policies": x.orgs.iter().filter_map(|o| policy.get(o).map(|p| json!({ "org_id": o, "frequency_days": p.0, "set_by": p.1, "set_at": p.2 }))).collect::<Vec<_>>(),
            "finding": format!("exposure:{a}"), "halo_ticket_id": ticket.get(&a).copied().flatten() }));
        let last = out.last_mut().expect("just pushed");
        last["risky_ports"] = json!(last["services"].as_array().into_iter().flatten().filter(|s| s["rule"]["severity"].as_str().is_some_and(|v| rank(v) >= 4)).count());
    }
    Ok(out)
}

/// The public addresses one CVE touches (Shodan's lead or the console's NVD match for a version Shodan saw), for
/// `cve.get`'s `internet_facing`: worst first is KEV-free here (one CVE), so edge entry points last, then by address.
/// `org` narrows to one client's. Each row says where the CVE came from and on which ports, and opens `/exposure/<ip>`.
pub(crate) async fn facing(pool: &Pool, org: Option<i64>, cve: &str) -> Result<Vec<Value>, Failure> {
    let mut out: Vec<Value> = addresses(pool, org, None).await?.into_iter().filter_map(|a| {
        let hit = a["cves"].as_array()?.iter().find(|c| c["cve_id"].as_str() == Some(cve))?.clone();
        let clients: Vec<String> = a["clients"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
        Some(json!({ "ip": a["ip"], "org_ids": a["org_ids"], "client_name": if clients.is_empty() { Value::Null } else { json!(clients.join(", ")) },
            "website": a["website"], "sites": a["sites"], "edge": a["edge"], "sources": hit["sources"], "ports": hit["ports"], "severity": a["severity"] }))
    }).collect();
    out.sort_by(|a, b| (a["edge"] == json!(true)).cmp(&(b["edge"] == json!(true))).then(a["ip"].as_str().cmp(&b["ip"].as_str())));
    Ok(out)
}

/// Every address (one client's, with org_id), worst first: KEV, the highest score, the most CVEs, the rating, the
/// risky ports. Edge entry points are left out unless include_edge, and never counted in a total.
pub async fn list(s: &Store, p: &Params) -> Result<Value, Failure> {
    let all = addresses(&s.pool, p.org_id.map(|x| x as i64), None).await?;
    let counted: Vec<&Value> = all.iter().filter(|r| r["edge"] != json!(true)).collect();
    let orgs = |f: &dyn Fn(&Value) -> bool| counted.iter().filter(|r| f(r)).flat_map(|r| r["org_ids"].as_array().cloned().unwrap_or_default()).filter_map(|v| v.as_i64()).collect::<BTreeSet<_>>().len();
    let totals = json!({
        "addresses": counted.len(), "edge": all.len() - counted.len(),
        "looked_up": counted.iter().filter(|r| !r["looked_up_at"].is_null()).count(),
        "kev": counted.iter().filter(|r| r["kev_count"].as_u64().unwrap_or(0) > 0).count(),
        "critical": counted.iter().filter(|r| r["severity"] == "critical").count(),
        "high": counted.iter().filter(|r| r["severity"] == "high").count(),
        "with_cves": counted.iter().filter(|r| r["cve_count"].as_u64().unwrap_or(0) > 0).count(),
        "websites": counted.iter().filter(|r| r["website"] == json!(true)).count(),
        "clients_kev": orgs(&|r| r["kev_count"].as_u64().unwrap_or(0) > 0),
        "clients_critical": orgs(&|r| r["severity"] == "critical"),
    });
    let rows: Vec<Value> = all.into_iter().filter(|r| p.include_edge.unwrap_or(false) || r["edge"] != json!(true)).map(|mut r| {
        // The list carries the counts; the address's own page carries the services and CVEs behind them.
        let kev: Vec<Value> = r["cves"].as_array().into_iter().flatten().filter(|c| c["kev"].is_object()).map(|c| c["cve_id"].clone()).collect();
        r["kev_cves"] = json!(kev);
        r["open_ports"] = json!(r["services"].as_array().into_iter().flatten().map(|s| json!({ "port": s["port"], "transport": s["transport"], "severity": s["rule"]["severity"] })).collect::<Vec<_>>());
        if let Some(o) = r.as_object_mut() { o.remove("cves"); o.remove("services"); o.remove("devices"); }
        r
    }).collect();
    let key = |x: &Value| vec![json!(-(x["kev_count"].as_i64().unwrap_or(0))), json!(-(x["max_cvss"].as_f64().unwrap_or(-1.0))), json!(-(x["cve_count"].as_i64().unwrap_or(0))),
                                json!(-i64::from(rank(x["severity"].as_str().unwrap_or("")))), json!(-(x["risky_ports"].as_i64().unwrap_or(0))), x["ip"].clone()];
    let (data, next) = page_by(rows, key, p.cursor.as_deref(), p.limit.map(|l| l as usize).unwrap_or(200)).map_err(Failure::Bad)?;
    Ok(json!({ "data": data, "next_cursor": next, "totals": totals, "as_of": job_ok(&s.pool, &["shodan_exposure", "shodan_scans", "ninja_devices"]).await }))
}

/// One address: its services, each rated, its CVEs with NVD's score and KEV's word, the devices behind it, its sites,
/// its edge mark, its clients' scan policies, and its ticket.
pub async fn get(s: &Store, p: &Params) -> Result<Value, Failure> {
    let ip = p.ip.clone().ok_or_else(|| Failure::Bad("ip is required".into()))?;
    let one = addresses(&s.pool, p.org_id.map(|x| x as i64), Some(&ip)).await?.into_iter().next();
    Ok(json!({ "data": one, "next_cursor": null, "as_of": job_ok(&s.pool, &["shodan_exposure", "shodan_scans"]).await }))
}
