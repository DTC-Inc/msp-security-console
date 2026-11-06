//! Shodan: what its own internet scan has seen open on each client's public addresses and on the servers its
//! websites live on, and, only where a scan policy asks for it, an on-demand scan.
//!
//! - **Passive first:** a lookup (`/shodan/host/{ip}`) reads what Shodan already scanned on its own schedule; nothing is
//!   sent to the client's network. An on-demand scan (`/shodan/scan`, one credit per address) is asked for only for a
//!   client whose scan policy an admin turned on, never for a website's address, and never beyond
//!   SHODAN_SCAN_CREDITS_PER_MONTH (or what Shodan says is left).
//! - **The addresses:** each server's and desktop's public IPv4 from NinjaOne (`device_wan`; laptops left out), and the
//!   addresses each client's websites resolve to (Halo's websites, for clients whose Halo link is confirmed). A site
//!   address is read as the client's own WAN, a shared host or CDN (nothing about it is attributed to the client), a
//!   dedicated server (looked up like a WAN address), or unknown.
//! - **The key** rides in the query string (Shodan's only scheme), so no request URL is ever logged, stored or put in
//!   an error: a failure is its status and Shodan's own short reason. Shodan allows about one request a second.
//! - **Services** are matched against the console's own NVD data by the CPE Shodan saw, with the same ranges as
//!   installed software. Shodan's own CVE list for a banner is a lead, not proof; the console marks which are in KEV.

use super::Limiter;
use crate::connectors::ninja::{db, urlenc};
use crate::db::{self as store, Pool};
use crate::matching::{affects, norm_version, Range};
use crate::scheduler::{Job, Outcome};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DEFAULT_URL: &str = "https://api.shodan.io";
/// A month's on-demand scan credits, unless SHODAN_SCAN_CREDITS_PER_MONTH says otherwise. 0 asks for none.
pub const DEFAULT_SCAN_CREDITS: usize = 100;
/// The most addresses one run asks Shodan to scan.
pub const MAX_SCAN_PER_RUN: usize = 200;
const RESOLVE_BATCH: usize = 50;
/// An address serving more than this many other domains is a shared host.
const SHARED_APEXES: usize = 10;

#[derive(Clone)]
pub struct ShodanCfg { pub base: String, pub key: String, pub scan_credits: usize, pub admins: Vec<String> }
impl std::fmt::Debug for ShodanCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("ShodanCfg").field("base", &self.base).field("scan_credits", &self.scan_credits).finish_non_exhaustive() }
}

/// Shodan's settings: on with SHODAN_API_KEY (SHODAN_URL is Shodan's own unless set). Beside the console's admins,
/// SCAN_POLICY_ADMINS (a comma-separated list of sign-in emails) may change scan policies; a setting without Shodan is
/// refused.
pub fn settings(get: &dyn Fn(&str) -> Option<String>, key: Option<String>, url: &dyn Fn(&str, String) -> Result<String, String>) -> Result<Option<ShodanCfg>, String> {
    let admins: Vec<String> = get("SCAN_POLICY_ADMINS").map(|s| s.split(',').map(|x| x.trim().to_lowercase()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    let Some(key) = key else {
        for k in ["SHODAN_URL", "SHODAN_SCAN_CREDITS_PER_MONTH", "SCAN_POLICY_ADMINS"] {
            if get(k).is_some() { return Err(format!("{k} is set without SHODAN_API_KEY (or _FILE): set the key, or leave Shodan's settings out")); }
        }
        return Ok(None);
    };
    let scan_credits = match get("SHODAN_SCAN_CREDITS_PER_MONTH") {
        None => DEFAULT_SCAN_CREDITS,
        Some(v) => v.parse::<usize>().ok().filter(|n| *n <= 100_000).ok_or("SHODAN_SCAN_CREDITS_PER_MONTH must be a number from 0 to 100000")?,
    };
    Ok(Some(ShodanCfg { base: url("SHODAN_URL", get("SHODAN_URL").unwrap_or_else(|| DEFAULT_URL.into()))?, key, scan_credits, admins }))
}

/// What an open port means: a floor for an address's rating when no CVE says worse.
pub const PORT_RULES: &[(u16, &str, &str, &str, &str)] = &[
    (3389, "tcp", "Remote Desktop (RDP)", "critical", "Remote Desktop open to the internet is the most common ransomware entry point; put it behind a VPN or gateway."),
    (445, "tcp", "Windows file sharing (SMB)", "critical", "SMB should never face the internet."),
    (139, "tcp", "NetBIOS session (SMB)", "critical", "Legacy Windows file sharing open to the internet."),
    (23, "tcp", "Telnet", "critical", "Unencrypted remote login; credentials cross the internet in clear text."),
    (5900, "tcp", "VNC remote control", "critical", "Remote control open to the internet, often weakly authenticated."),
    (1433, "tcp", "Microsoft SQL Server", "critical", "A database open to the internet."),
    (3306, "tcp", "MySQL / MariaDB", "critical", "A database open to the internet."),
    (5432, "tcp", "PostgreSQL", "critical", "A database open to the internet."),
    (27017, "tcp", "MongoDB", "critical", "A database open to the internet; frequently unauthenticated."),
    (6379, "tcp", "Redis", "critical", "Usually unauthenticated; a known remote-code path."),
    (9200, "tcp", "Elasticsearch", "critical", "Often unauthenticated; data exposure."),
    (5985, "tcp", "WinRM (HTTP)", "high", "Windows remote management open to the internet."),
    (5986, "tcp", "WinRM (HTTPS)", "high", "Windows remote management open to the internet."),
    (161, "udp", "SNMP", "high", "Device management; default communities leak configuration."),
    (21, "tcp", "FTP", "high", "Unencrypted file transfer; credentials in clear text."),
    (1723, "tcp", "PPTP VPN", "high", "Obsolete, broken VPN protocol."),
    (22, "tcp", "SSH", "medium", "Fine when key-only and patched; otherwise a brute-force target. Confirm it's intended."),
    (8080, "tcp", "Web admin / alternate HTTP", "medium", "Often a device or application admin page. Confirm it's intended."),
    (8443, "tcp", "Web admin (HTTPS alt)", "medium", "Often a firewall, controller or application admin page. Confirm it's intended."),
    (10443, "tcp", "Firewall / VPN web portal", "medium", "Usually an SSL-VPN or firewall admin page; these are heavily targeted, so keep it patched."),
    (4443, "tcp", "Firewall / VPN web portal", "medium", "Usually an SSL-VPN or firewall admin page; these are heavily targeted, so keep it patched."),
    (500, "udp", "IPsec VPN (IKE)", "info", "Expected on a site with a VPN."),
    (443, "tcp", "HTTPS", "info", "Expected for a published service or VPN portal; check what answers."),
    (80, "tcp", "HTTP", "info", "Plain web; check what answers and whether it redirects to HTTPS."),
];
pub fn port_rule(port: i64, transport: &str) -> Option<(&'static str, &'static str, &'static str)> {
    PORT_RULES.iter().find(|r| i64::from(r.0) == port && r.1 == transport).map(|r| (r.2, r.3, r.4))
}

/// CDNs and shared hosts, by Shodan's org or ISP (a substring) or ASN (exact). A site on one of these shares its
/// address with many others, so what Shodan finds there is the host's, not the client's.
pub const HOSTING_RULES: &[(&str, &str, &str)] = &[
    ("org", "cloudflare", "Cloudflare"), ("asn", "AS13335", "Cloudflare"), ("org", "cloudfront", "Amazon CloudFront"), ("isp", "cloudfront", "Amazon CloudFront"),
    ("org", "fastly", "Fastly"), ("asn", "AS54113", "Fastly"), ("org", "akamai", "Akamai"), ("asn", "AS20940", "Akamai"), ("asn", "AS16625", "Akamai"),
    ("org", "squarespace", "Squarespace"), ("asn", "AS53831", "Squarespace"), ("org", "wix.com", "Wix"), ("asn", "AS58182", "Wix"),
    ("org", "godaddy", "GoDaddy"), ("asn", "AS26496", "GoDaddy"), ("asn", "AS398101", "GoDaddy"), ("org", "google", "Google"), ("asn", "AS15169", "Google"),
    ("org", "shopify", "Shopify"), ("asn", "AS62679", "Shopify"), ("org", "wp engine", "WP Engine"), ("org", "wpengine", "WP Engine"),
    ("org", "automattic", "WordPress.com"), ("asn", "AS2635", "WordPress.com"), ("org", "weebly", "Weebly"), ("org", "webflow", "Webflow"),
    ("org", "hubspot", "HubSpot"), ("org", "netlify", "Netlify"), ("org", "vercel", "Vercel"), ("org", "github", "GitHub Pages"),
    ("org", "newfold", "Newfold (Bluehost, HostGator)"), ("org", "unified layer", "Newfold (Bluehost, HostGator)"), ("org", "siteground", "SiteGround"),
    ("org", "dreamhost", "DreamHost"), ("org", "inmotion", "InMotion Hosting"), ("org", "hostinger", "Hostinger"), ("org", "namecheap", "Namecheap"),
    ("org", "ionos", "IONOS"), ("org", "imperva", "Imperva"), ("org", "sucuri", "Sucuri"), ("org", "azure front door", "Azure Front Door"),
];

#[derive(Clone)]
pub struct Shodan { pub base: String, key: String, http: reqwest::Client, limiter: Limiter, pub scan_credits: usize, pub budget: Duration, calls: Arc<std::sync::atomic::AtomicU64> }
impl std::fmt::Debug for Shodan { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("Shodan").field("base", &self.base).finish_non_exhaustive() } }

/// A failed call: its status (when there was one) and a short reason; never the URL, which holds the key.
#[derive(Debug, Clone, PartialEq)]
pub struct Fail { pub status: Option<u16>, pub why: String }
impl Fail { fn refused(&self) -> bool { matches!(self.status, Some(401 | 403)) } }
impl std::fmt::Display for Fail { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "Shodan: {}", self.why) } }

impl Shodan {
    pub fn new(c: &ShodanCfg, http: reqwest::Client) -> Self {
        Self { base: c.base.trim_end_matches('/').into(), key: c.key.clone(), http, limiter: Limiter::new(1, Duration::from_millis(1100)), scan_credits: c.scan_credits,
               budget: Duration::from_secs(25 * 60), calls: Default::default() }
    }
    pub fn calls(&self) -> u64 { self.calls.load(std::sync::atomic::Ordering::Relaxed) }

    /// One call. 404 is None (Shodan has nothing on it), a real answer.
    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<Option<Value>, Fail> {
        for attempt in 0..3u32 {
            self.limiter.acquire().await;
            self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let r = rb.try_clone().expect("a plain request").timeout(Duration::from_secs(60)).send().await
                .map_err(|e| Fail { status: None, why: if e.is_timeout() { "timed out".into() } else { "unreachable".into() } })?;
            let st = r.status().as_u16();
            if st == 404 { return Ok(None); }
            if st == 429 && attempt < 2 { tokio::time::sleep(Duration::from_secs(5 << attempt)).await; continue; }
            if (300..400).contains(&st) { return Err(Fail { status: Some(st), why: format!("HTTP {st}: the address redirected; set the final address") }); }
            if !(200..300).contains(&st) {
                // Shodan says why in {"error"}; its own text, cut short, never holds the key.
                let why = r.json::<Value>().await.ok().and_then(|j| j.get("error").and_then(Value::as_str).map(|s| s.chars().take(120).collect::<String>()));
                return Err(Fail { status: Some(st), why: match why { Some(w) => format!("HTTP {st}: {w}"), None => format!("HTTP {st}") } });
            }
            return r.json::<Value>().await.map(Some).map_err(|_| Fail { status: Some(st), why: "the answer isn't JSON".into() });
        }
        Err(Fail { status: Some(429), why: "HTTP 429: still rate-limited after retrying".into() })
    }
    fn url(&self, path: &str, query: &str) -> String { format!("{}{path}?{}{}key={}", self.base, query, if query.is_empty() { "" } else { "&" }, urlenc(&self.key)) }
    async fn get(&self, path: &str, query: &str) -> Result<Option<Value>, Fail> { self.send(self.http.get(self.url(path, query))).await }

    /// The plan and the credits left (`/api-info`): a read, never a scan.
    pub async fn api_info(&self) -> Result<Value, Fail> { self.get("/api-info", "").await?.ok_or(Fail { status: Some(404), why: "HTTP 404".into() }) }
    pub async fn host(&self, ip: &str) -> Result<Option<Value>, Fail> { self.get(&format!("/shodan/host/{}", urlenc(ip)), "").await }
    pub async fn resolve(&self, hostnames: &[String]) -> Result<HashMap<String, Option<String>>, Fail> {
        let j = self.get("/dns/resolve", &format!("hostnames={}", urlenc(&hostnames.join(",")))).await?.unwrap_or(Value::Null);
        Ok(hostnames.iter().map(|h| (h.clone(), j.get(h).and_then(Value::as_str).and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()).map(|i| i.to_string()))).collect())
    }
    async fn scan(&self, ips: &[String]) -> Result<Value, Fail> {
        let body = serde_urlencoded::to_string([("ips", ips.join(","))]).unwrap_or_default();
        self.send(self.http.post(self.url("/shodan/scan", "")).header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(body)).await?
            .ok_or(Fail { status: Some(404), why: "HTTP 404".into() })
    }
    async fn scan_status(&self, id: &str) -> Result<Option<Value>, Fail> { self.get(&format!("/shodan/scan/{}", urlenc(id)), "").await }

    /// The daily pass: finished scans, every WAN address, the websites, the scans that are due, the prune, and the
    /// services against NVD.
    pub async fn sync(&self, pool: &Pool) -> Result<Outcome, String> {
        let started = Instant::now();
        let info = self.api_info().await.map_err(|e| e.to_string())?;
        let scans = self.check_scans(pool).await?;
        let wan = wan_addresses(pool).await?;
        let ips: Vec<String> = wan.keys().cloned().collect();
        let order = by_staleness(pool, &ips).await?;
        let mut look = Lookups::default();
        for ip in &order {
            if started.elapsed() > self.budget { look.deferred += 1; continue; }
            if let Err(e) = self.look_up(pool, ip, &mut look).await && e.refused() { return Err(format!("{e}; stopped")); }
        }
        let sites = if started.elapsed() < self.budget { self.websites(pool, &wan, started).await? } else { json!({ "deferred": true }) };
        let requested = self.request_scans(pool, &wan, &info).await?;
        let removed = prune(pool).await?;
        let services = match_services(pool).await?;
        if look.failed > 0 && look.failed * 2 > order.len() { return Err(format!("{} of {} lookups failed", look.failed, order.len())); }
        Ok(Outcome { detail: json!({ "addresses": order.len(), "found": look.found, "none": look.none, "failed": look.failed, "deferred": look.deferred,
            "sites": sites, "scans_checked": scans, "scan_requested": requested["ips"], "scan_credits_left": requested["credits_left"].as_i64().or_else(|| info.get("scan_credits").and_then(Value::as_i64)),
            "query_credits_left": info.get("query_credits").and_then(Value::as_i64), "removed": removed, "services": services, "api_calls": self.calls() }), cursor: None })
    }

    /// Hourly: check the scans asked for, and look up the addresses a finished one has fresh data for.
    pub async fn sync_scans(&self, pool: &Pool) -> Result<Outcome, String> {
        let checked = self.check_scans(pool).await?;
        let fresh: Vec<(String,)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
            "SELECT ip FROM exposure_host WHERE last_scan_completed_at IS NOT NULL AND (looked_up_at IS NULL OR looked_up_at < last_scan_completed_at) ORDER BY last_scan_completed_at")
            .fetch_all(p).await).map_err(db)?;
        let mut look = Lookups::default();
        for (ip,) in &fresh { if let Err(e) = self.look_up(pool, ip, &mut look).await && e.refused() { return Err(format!("{e}; stopped")); } }
        if !fresh.is_empty() { match_services(pool).await?; }
        Ok(Outcome { detail: json!({ "scans_checked": checked, "looked_up": fresh.len(), "found": look.found, "failed": look.failed }), cursor: None })
    }

    async fn look_up(&self, pool: &Pool, ip: &str, look: &mut Lookups) -> Result<(), Fail> {
        match self.host(ip).await {
            Ok(Some(j)) => { look.found += 1; store_host(pool, ip, &j).await.map_err(|e| Fail { status: None, why: e })?; Ok(()) }
            Ok(None) => { look.none += 1; store_none(pool, ip).await.map_err(|e| Fail { status: None, why: e })?; Ok(()) }
            Err(e) => {
                look.failed += 1;
                let why = e.why.clone();
                let _ = crate::on_pool!(pool, p, _ => sqlx::query("UPDATE exposure_host SET error = $2 WHERE ip = $1").bind(ip).bind(&why).execute(p).await.map(|_| ()));
                Err(e)
            }
        }
    }

    async fn check_scans(&self, pool: &Pool) -> Result<usize, String> {
        let pending: Vec<(i64, String, Value)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
            "SELECT request_id, scan_id, ips FROM scan_request WHERE scan_id IS NOT NULL AND status NOT IN ('DONE', 'failed') ORDER BY requested_at").fetch_all(p).await).map_err(db)?;
        for (rid, sid, ips) in &pending {
            let now = store::now();
            match self.scan_status(sid).await {
                Ok(j) => {
                    let st = j.as_ref().and_then(|j| j.get("status")).and_then(Value::as_str).unwrap_or("unknown").chars().take(40).collect::<String>();
                    let done = st == "DONE";
                    let ips: Vec<String> = ips.as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
                    crate::on_pool!(pool, p, pg => {
                        sqlx::query("UPDATE scan_request SET status = $2, checked_at = $3, completed_at = CASE WHEN $4 THEN $3 ELSE completed_at END WHERE request_id = $1")
                            .bind(rid).bind(&st).bind(now).bind(done).execute(p).await.map_err(db)?;
                        if done {
                            sqlx::query(if pg { "UPDATE exposure_host SET last_scan_completed_at = $2 WHERE ip = ANY($1)" } else { "UPDATE exposure_host SET last_scan_completed_at = $2 WHERE ip IN (SELECT value FROM json_each($1))" })
                                .bind(store::list(&ips)).bind(now).execute(p).await.map_err(db)?;
                        }
                    });
                }
                Err(e) => { let why = e.why; crate::on_pool!(pool, p, _ => sqlx::query("UPDATE scan_request SET checked_at = $2, error = $3 WHERE request_id = $1").bind(rid).bind(now).bind(why).execute(p).await.map(|_| ()).map_err(db))?; }
            }
        }
        Ok(pending.len())
    }

    /// Client websites: each hostname and its apex resolved (free), each address classified, and a dedicated one
    /// looked up like a WAN address. Never scanned.
    async fn websites(&self, pool: &Pool, wan: &BTreeMap<String, BTreeSet<i64>>, started: Instant) -> Result<Value, String> {
        let raw: Vec<(i64, i64, Option<Value>)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
            "SELECT h.halo_client_id, c.org_id, h.website_sites FROM halo_client h JOIN client c ON c.halo_client_id = h.halo_client_id
              WHERE h.deleted_at IS NULL AND c.deleted_at IS NULL AND c.halo_matched_by = 'ninjarmm_id'").fetch_all(p).await).map_err(db)?;
        // (halo client, hostname) -> (org, apex)
        let mut wants: BTreeMap<(i64, String), (i64, String)> = BTreeMap::new();
        let mut apexes: HashMap<i64, HashSet<String>> = HashMap::new();
        for (h, org, s) in &raw {
            for w in s.as_ref().and_then(Value::as_array).into_iter().flatten() {
                let (Some(host), Some(apex)) = (w.get("hostname").and_then(Value::as_str), w.get("apex").and_then(Value::as_str)) else { continue };
                wants.insert((*h, host.to_string()), (*org, apex.to_string()));
                if apex != host { wants.insert((*h, apex.to_string()), (*org, apex.to_string())); }
                apexes.entry(*h).or_default().insert(apex.to_string());
            }
        }
        let hostnames: Vec<String> = wants.keys().map(|k| k.1.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        let mut ip_of: HashMap<String, Option<String>> = HashMap::new();
        let mut errors = 0usize;
        for chunk in hostnames.chunks(RESOLVE_BATCH) {
            if started.elapsed() > self.budget { break; }
            match self.resolve(chunk).await { Ok(m) => ip_of.extend(m), Err(e) => { errors += 1; if e.refused() { break; } } }
        }
        let mut owners: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();   // ip -> (halo client, org)
        for ((h, host), (org, _)) in &wants { if let Some(Some(ip)) = ip_of.get(host) { let o = owners.entry(ip.clone()).or_default(); if !o.contains(&(*h, *org)) { o.push((*h, *org)); } } }
        let mut class: HashMap<(String, i64), (String, Option<String>, String)> = HashMap::new();
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for (ip, who) in &owners {
            let is_wan = |org: &i64| wan.get(ip).is_some_and(|orgs| orgs.contains(org));
            if who.iter().all(|(_, org)| is_wan(org)) {
                for (h, _) in who { class.insert((ip.clone(), *h), ("client".into(), None, "the client's own WAN address".into())); }
                continue;
            }
            if started.elapsed() > self.budget { continue; }
            let host = match self.host(ip).await { Ok(h) => h, Err(e) => { errors += 1; if e.refused() { break; } continue; } };
            for (h, org) in who {
                let c = classify_site(ip, host.as_ref(), is_wan(org), apexes.get(h).cloned().unwrap_or_default());
                class.insert((ip.clone(), *h), c);
            }
            if let Some(j) = &host && who.iter().all(|(h, _)| class.get(&(ip.clone(), *h)).is_some_and(|c| c.0 == "dedicated")) { store_host(pool, ip, j).await?; }
        }
        let mut rows: Vec<Value> = Vec::new();
        for ((h, host), (org, apex)) in &wants {
            let Some(ip) = ip_of.get(host) else { continue };   // not resolved this run: keep yesterday's rows
            let (cls, provider, reason) = match ip {
                None => ("unresolved".to_string(), None, "the name doesn't resolve".to_string()),
                Some(ip) => match class.get(&(ip.clone(), *h)) { Some(c) => c.clone(), None => continue },
            };
            *counts.entry(match cls.as_str() { "client" => "client", "shared" => "shared", "dedicated" => "dedicated", "unknown" => "unknown", _ => "unresolved" }).or_default() += 1;
            rows.push(json!({ "halo_client_id": h, "org_id": org, "hostname": host, "apex": apex, "ip": ip.clone().unwrap_or_default(), "classification": cls, "provider": provider, "reason": reason }));
        }
        let keep: Vec<String> = wants.keys().map(|(h, n)| format!("{h}|{n}")).collect();
        let pairs: Vec<Value> = rows.iter().map(|r| json!({ "h": r["halo_client_id"], "n": r["hostname"] })).collect();
        let now = store::now();
        crate::on_pool!(pool, p, pg => {
            let mut tx = p.begin().await.map_err(db)?;
            sqlx::query(if pg { "DELETE FROM exposure_site s USING jsonb_to_recordset($1) AS x(h bigint, n text) WHERE s.halo_client_id = x.h AND s.hostname = x.n" }
                        else { "DELETE FROM exposure_site WHERE EXISTS (SELECT 1 FROM json_each($1) AS x WHERE exposure_site.halo_client_id = x.value ->> 'h' AND exposure_site.hostname = x.value ->> 'n')" })
                .bind(Value::Array(pairs)).execute(&mut *tx).await.map_err(db)?;
            sqlx::query(if pg {
                "INSERT INTO exposure_site (halo_client_id, org_id, hostname, apex, ip, classification, provider, reason, looked_up_at)
                 SELECT x.halo_client_id, x.org_id, x.hostname, x.apex, x.ip, x.classification, x.provider, x.reason, $2
                   FROM jsonb_to_recordset($1) AS x(halo_client_id bigint, org_id bigint, hostname text, apex text, ip text, classification text, provider text, reason text)
                 ON CONFLICT DO NOTHING"
            } else {
                "INSERT INTO exposure_site (halo_client_id, org_id, hostname, apex, ip, classification, provider, reason, looked_up_at)
                 SELECT x.value ->> 'halo_client_id', x.value ->> 'org_id', x.value ->> 'hostname', x.value ->> 'apex', x.value ->> 'ip', x.value ->> 'classification',
                        x.value ->> 'provider', x.value ->> 'reason', $2 FROM json_each($1) AS x WHERE true
                 ON CONFLICT DO NOTHING"
            }).bind(Value::Array(rows.clone())).bind(now).execute(&mut *tx).await.map_err(db)?;
            // Guarded: no sites at all this run (Halo's job broken) must not wipe the table.
            if !wants.is_empty() {
                sqlx::query(if pg { "DELETE FROM exposure_site WHERE NOT ((halo_client_id::text || '|' || hostname) = ANY($1))" }
                            else { "DELETE FROM exposure_site WHERE (halo_client_id || '|' || hostname) NOT IN (SELECT value FROM json_each($1))" })
                    .bind(store::list(&keep)).execute(&mut *tx).await.map_err(db)?;
            }
            tx.commit().await.map_err(db)?;
        });
        Ok(json!({ "hostnames": hostnames.len(), "addresses": owners.len(), "by_class": counts, "errors": errors }))
    }

    /// On-demand scans for the WAN addresses of clients whose policy is on and due, within the month's credits.
    async fn request_scans(&self, pool: &Pool, wan: &BTreeMap<String, BTreeSet<i64>>, info: &Value) -> Result<Value, String> {
        let policies: Vec<(i64, i64)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT org_id, frequency_days FROM scan_policy WHERE frequency_days > 0").fetch_all(p).await).map_err(db)?;
        if policies.is_empty() || self.scan_credits == 0 { return Ok(json!({ "ips": 0, "credits_left": null, "why": if policies.is_empty() { "no client's scan policy is on" } else { "SHODAN_SCAN_CREDITS_PER_MONTH is 0" } })); }
        let days: HashMap<i64, i64> = policies.into_iter().collect();
        let month_start = chrono::Utc::now().format("%Y-%m-01T00:00:00.000Z").to_string();
        let since = store::Ts(chrono::DateTime::parse_from_rfc3339(&month_start).map(|t| t.with_timezone(&chrono::Utc)).unwrap_or_else(|_| chrono::Utc::now()));
        type H = (String, bool, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>);
        let (spent, hosts): (Vec<(Value,)>, Vec<H>) = crate::on_pool!(pool, p, _ => (
            sqlx::query_as("SELECT ips FROM scan_request WHERE requested_at >= $1").bind(since).fetch_all(p).await.map_err(db)?,
            sqlx::query_as("SELECT ip, found, provider_updated_at, last_scan_requested_at FROM exposure_host").fetch_all(p).await.map_err(db)?));
        let used: usize = spent.iter().map(|(ips,)| ips.as_array().map_or(0, Vec::len)).sum();
        let shodan_left = info.get("scan_credits").and_then(Value::as_i64).map(|n| n.max(0) as usize).unwrap_or(usize::MAX);
        let left = self.scan_credits.saturating_sub(used).min(shodan_left).min(MAX_SCAN_PER_RUN);
        let known: HashMap<&str, &H> = hosts.iter().map(|h| (h.0.as_str(), h)).collect();
        let now = chrono::Utc::now();
        let due: Vec<String> = wan.iter().filter_map(|(ip, orgs)| {
            // The narrowest is the client's own; an address several clients share takes the most frequent.
            let d = orgs.iter().filter_map(|o| days.get(o)).min()?;
            let h = known.get(ip.as_str());
            scan_due(h.map(|h| h.1).unwrap_or(false), h.and_then(|h| h.2), h.and_then(|h| h.3), *d, now).then(|| ip.clone())
        }).collect();
        if due.is_empty() || left == 0 { return Ok(json!({ "ips": 0, "due": due.len(), "credits_used_this_month": used, "credits_left": null })); }
        let batch: Vec<String> = due.iter().take(left).cloned().collect();
        let r = self.scan(&batch).await.map_err(|e| e.to_string())?;
        let credits_left = r.get("credits_left").and_then(Value::as_i64);
        let ts = store::now();
        crate::on_pool!(pool, p, pg => {
            let mut tx = p.begin().await.map_err(db)?;
            sqlx::query("INSERT INTO scan_request (scan_id, ips, status, credits_left, requested_at) VALUES ($1, $2, 'SUBMITTING', $3, $4)")
                .bind(r.get("id").and_then(Value::as_str)).bind(json!(batch)).bind(credits_left).bind(ts).execute(&mut *tx).await.map_err(db)?;
            sqlx::query(if pg {
                "INSERT INTO exposure_host (ip, last_scan_requested_at) SELECT x, $2 FROM unnest($1::text[]) AS x ON CONFLICT (ip) DO UPDATE SET last_scan_requested_at = excluded.last_scan_requested_at"
            } else {
                "INSERT INTO exposure_host (ip, last_scan_requested_at) SELECT value, $2 FROM json_each($1) WHERE true ON CONFLICT (ip) DO UPDATE SET last_scan_requested_at = excluded.last_scan_requested_at"
            }).bind(store::list(&batch)).bind(ts).execute(&mut *tx).await.map_err(db)?;
            tx.commit().await.map_err(db)?;
        });
        println!("{}", json!({ "msg": "shodan scan requested", "addresses": batch.len(), "due": due.len(), "credits_left": credits_left }));
        Ok(json!({ "ips": batch.len(), "due": due.len(), "credits_used_this_month": used + batch.len(), "credits_left": credits_left }))
    }

    pub fn jobs(self: Arc<Self>) -> Vec<Job> {
        let (a, b) = (self.clone(), self.clone());
        vec![
            Job { name: "shodan_exposure", every: Duration::from_secs(24 * 3600), run: Arc::new(move |pool, _| { let s = a.clone(); Box::pin(async move { s.sync(&pool).await }) }) },
            Job { name: "shodan_scans", every: Duration::from_secs(3600), run: Arc::new(move |pool, _| { let s = b.clone(); Box::pin(async move { s.sync_scans(&pool).await }) }) },
        ]
    }
}

#[derive(Default)]
struct Lookups { found: usize, none: usize, failed: usize, deferred: usize }

/// Is a scan due? Never inside the frequency since the last request; an address Shodan has nothing on is then due,
/// and one it knows is due when its data is older than the frequency.
pub fn scan_due(found: bool, updated: Option<chrono::DateTime<chrono::Utc>>, last_req: Option<chrono::DateTime<chrono::Utc>>, days: i64, now: chrono::DateTime<chrono::Utc>) -> bool {
    if days <= 0 { return false; }
    let span = chrono::Duration::days(days);
    if last_req.is_some_and(|t| now - t < span) { return false; }
    if !found { return true; }
    updated.is_none_or(|u| now - u >= span)
}

/// How a website's address reads for one client: its own WAN, a shared host, a dedicated server, or unknown.
pub fn classify_site(ip: &str, host: Option<&Value>, client_wan: bool, client_apexes: HashSet<String>) -> (String, Option<String>, String) {
    let _ = ip;
    if client_wan { return ("client".into(), None, "the client's own WAN address".into()); }
    let Some(h) = host else { return ("unknown".into(), None, "Shodan has no data on this address".into()) };
    let field = |k: &str| h.get(k).map(|v| v.as_str().map(String::from).unwrap_or_else(|| v.to_string())).unwrap_or_default();
    for (f, pat, provider) in HOSTING_RULES {
        let v = field(f);
        let hit = if *f == "asn" { v.eq_ignore_ascii_case(pat) } else { v.to_lowercase().contains(pat) };
        if hit { return ("shared".into(), Some((*provider).into()), format!("{provider} ({f} {v})")); }
    }
    let others: HashSet<String> = h.get("hostnames").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str)
        .map(crate::website::apex_of).filter(|a| !a.is_empty() && !client_apexes.contains(a)).collect();
    if others.len() > SHARED_APEXES {
        let provider = h.get("org").or_else(|| h.get("isp")).and_then(Value::as_str).map(String::from);
        return ("shared".into(), provider, format!("serves {} other domains", others.len()));
    }
    ("dedicated".into(), None, "not a known shared host, and no other domains seen on it".into())
}

fn cve_list(v: Option<&Value>) -> Vec<String> {
    let ids: Vec<String> = match v { Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(), Some(Value::Object(o)) => o.keys().cloned().collect(), _ => vec![] };
    let mut out: Vec<String> = ids.into_iter().map(|s| s.to_uppercase()).filter(|s| crate::contract::Params { cve_id: Some(s.clone()), ..Default::default() }.validate().is_ok()).collect();
    out.sort(); out.dedup(); out
}
fn strs(v: Option<&Value>, n: usize, len: usize) -> Vec<String> { v.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(|s| s.chars().take(len).collect()).take(n).collect() }

/// One Shodan host document as a host row and its services (the newest banner per port).
pub fn parse_host(j: &Value) -> (Value, Vec<Value>) {
    let mut services: BTreeMap<(i64, String), Value> = BTreeMap::new();
    for s in j.get("data").and_then(Value::as_array).into_iter().flatten() {
        let Some(port) = s.get("port").and_then(Value::as_i64).filter(|p| (1..=65535).contains(p)) else { continue };
        let transport = if s.get("transport").and_then(Value::as_str) == Some("udp") { "udp" } else { "tcp" };
        let cpes = strs(s.get("cpe23").or_else(|| s.get("cpe")), 20, 200);
        let row = json!({ "port": port, "transport": transport, "product": s.get("product").and_then(Value::as_str).map(|x| x.chars().take(200).collect::<String>()),
            "version": s.get("version").and_then(Value::as_str).map(|x| x.chars().take(100).collect::<String>()), "cpes": cpes, "vulns": cve_list(s.get("vulns")),
            "title": s.pointer("/http/title").and_then(Value::as_str).map(|x| x.chars().take(200).collect::<String>()),
            "seen_at": s.get("timestamp").and_then(Value::as_str).and_then(|t| store::ts_text(t).or_else(|| store::ts_text(&format!("{t}Z")))) });
        let key = (port, transport.to_string());
        let newer = services.get(&key).is_none_or(|p| row["seen_at"].as_str().unwrap_or("") > p["seen_at"].as_str().unwrap_or(""));
        if newer { services.insert(key, row); }
    }
    let mut ports: BTreeSet<i64> = j.get("ports").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_i64).filter(|p| (1..=65535).contains(p)).collect();
    ports.extend(services.keys().map(|k| k.0));
    let mut vulns: BTreeSet<String> = cve_list(j.get("vulns")).into_iter().collect();
    for s in services.values() { for v in s["vulns"].as_array().into_iter().flatten() { if let Some(v) = v.as_str() { vulns.insert(v.into()); } } }
    let host = json!({ "ports": ports, "hostnames": strs(j.get("hostnames"), 50, 255), "tags": strs(j.get("tags"), 50, 60), "vulns": vulns,
        "net_org": j.get("org").and_then(Value::as_str).map(|x| x.chars().take(200).collect::<String>()), "isp": j.get("isp").and_then(Value::as_str).map(|x| x.chars().take(200).collect::<String>()),
        "provider_updated_at": j.get("last_update").and_then(Value::as_str).and_then(|t| store::ts_text(t).or_else(|| store::ts_text(&format!("{t}Z")))) });
    (host, services.into_values().collect())
}

async fn store_host(pool: &Pool, ip: &str, j: &Value) -> Result<(), String> {
    let (h, services) = parse_host(j);
    let now = store::now();
    let updated = h["provider_updated_at"].as_str().and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok()).map(|t| store::Ts(t.with_timezone(&chrono::Utc)));
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM exposure_service WHERE ip = $1").bind(ip).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(if pg {
            "INSERT INTO exposure_service (ip, port, transport, product, version, cpes, vulns, title, seen_at)
             SELECT $2, x.port, x.transport, x.product, x.version, x.cpes, x.vulns, x.title, x.seen_at
               FROM jsonb_to_recordset($1) AS x(port bigint, transport text, product text, version text, cpes jsonb, vulns jsonb, title text, seen_at timestamptz)"
        } else {
            "INSERT INTO exposure_service (ip, port, transport, product, version, cpes, vulns, title, seen_at)
             SELECT $2, x.value ->> 'port', x.value ->> 'transport', x.value ->> 'product', x.value ->> 'version', x.value -> 'cpes', x.value -> 'vulns', x.value ->> 'title', x.value ->> 'seen_at'
               FROM json_each($1) AS x"
        }).bind(Value::Array(services)).bind(ip).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO exposure_host (ip, found, looked_up_at, provider_updated_at, ports, hostnames, tags, vulns, net_org, isp, error)
                     VALUES ($1, true, $2, $3, $4, $5, $6, $7, $8, $9, NULL)
                     ON CONFLICT (ip) DO UPDATE SET found = true, looked_up_at = excluded.looked_up_at, provider_updated_at = excluded.provider_updated_at, ports = excluded.ports,
                       hostnames = excluded.hostnames, tags = excluded.tags, vulns = excluded.vulns, net_org = excluded.net_org, isp = excluded.isp, error = NULL")
            .bind(ip).bind(now).bind(updated).bind(&h["ports"]).bind(&h["hostnames"]).bind(&h["tags"]).bind(&h["vulns"]).bind(h["net_org"].as_str()).bind(h["isp"].as_str())
            .execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

async fn store_none(pool: &Pool, ip: &str) -> Result<(), String> {
    let now = store::now();
    crate::on_pool!(pool, p, _ => {
        let mut tx = p.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM exposure_service WHERE ip = $1").bind(ip).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO exposure_host (ip, found, looked_up_at) VALUES ($1, false, $2)
                     ON CONFLICT (ip) DO UPDATE SET found = false, looked_up_at = excluded.looked_up_at, provider_updated_at = NULL, ports = '[]', hostnames = '[]', tags = '[]',
                       vulns = '[]', net_org = NULL, isp = NULL, error = NULL")
            .bind(ip).bind(now).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
    });
    Ok(())
}

/// Each WAN address, with the clients that egress from it: servers and desktops only.
pub async fn wan_addresses(pool: &Pool) -> Result<BTreeMap<String, BTreeSet<i64>>, String> {
    let rows: Vec<(String, i64)> = crate::on_pool!(pool, p, _ => sqlx::query_as(
        "SELECT w.public_ip, d.org_id FROM device_wan w JOIN device d ON d.device_id = w.device_id AND d.deleted_at IS NULL AND d.device_class IN ('server', 'desktop')")
        .fetch_all(p).await).map_err(db)?;
    let mut m: BTreeMap<String, BTreeSet<i64>> = BTreeMap::new();
    for (ip, org) in rows { m.entry(ip).or_default().insert(org); }
    Ok(m)
}

/// Least recently looked up first (never first of all), so a run cut short carries on where it stopped.
async fn by_staleness(pool: &Pool, ips: &[String]) -> Result<Vec<String>, String> {
    let seen: Vec<(String, Option<chrono::DateTime<chrono::Utc>>)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT ip, looked_up_at FROM exposure_host").fetch_all(p).await).map_err(db)?;
    let at: HashMap<String, Option<chrono::DateTime<chrono::Utc>>> = seen.into_iter().collect();
    let mut v: Vec<String> = ips.to_vec();
    v.sort_by_key(|ip| (at.get(ip).copied().flatten(), ip.clone()));
    Ok(v)
}

/// Addresses no client egresses from any more, and that no website's dedicated server is, drop off.
async fn prune(pool: &Pool) -> Result<u64, String> {
    crate::on_pool!(pool, p, _ => {
        let mut tx = p.begin().await.map_err(db)?;
        let (wan,): (i64,) = sqlx::query_as("SELECT count(*) FROM device_wan").fetch_one(&mut *tx).await.map_err(db)?;
        // Guarded: an empty WAN list (NinjaOne's job broken) must not wipe what we know.
        let n = if wan == 0 { 0 } else {
            sqlx::query("DELETE FROM exposure_host WHERE NOT EXISTS (SELECT 1 FROM device_wan w WHERE w.public_ip = exposure_host.ip)
                           AND NOT EXISTS (SELECT 1 FROM exposure_site s WHERE s.ip = exposure_host.ip AND s.classification = 'dedicated')").execute(&mut *tx).await.map_err(db)?.rows_affected()
        };
        sqlx::query("DELETE FROM exposure_service WHERE NOT EXISTS (SELECT 1 FROM exposure_host h WHERE h.ip = exposure_service.ip)").execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(n)
    })
}

/// What NVD calls a service: the first application or OS CPE Shodan saw, as "vendor:product" or "o:vendor:product",
/// and the version (the CPE's own, else the banner's).
pub fn service_cpe(cpes: &[String], version: Option<&str>) -> Option<(String, String)> {
    for c in cpes {
        let parts: Vec<String> = if let Some(r) = c.strip_prefix("cpe:2.3:") { crate::matching::split_cpe(r) } else if let Some(r) = c.strip_prefix("cpe:/") { r.split(':').map(String::from).collect() } else { continue };
        if parts.len() < 3 || (parts[0] != "a" && parts[0] != "o") || parts[1].is_empty() || parts[2].is_empty() { continue; }
        let ver = parts.get(3).filter(|v| !v.is_empty() && *v != "*" && *v != "-").map(String::as_str).or(version);
        let Some(v) = ver.and_then(norm_version) else { continue };
        let key = if parts[0] == "a" { format!("{}:{}", parts[1], parts[2]) } else { format!("o:{}:{}", parts[1], parts[2]) };
        return Some((key, v));
    }
    None
}

/// Every stored service against the console's NVD data: the CVEs whose ranges hold its version, KEV ones and the
/// highest scores first, kept on the service row.
pub async fn match_services(pool: &Pool) -> Result<Value, String> {
    let svcs: Vec<(String, i64, String, Value, Option<String>)> = crate::on_pool!(pool, p, _ => sqlx::query_as("SELECT ip, port, transport, cpes, version FROM exposure_service").fetch_all(p).await).map_err(db)?;
    let keyed: Vec<Option<(String, String)>> = svcs.iter().map(|s| {
        let cpes: Vec<String> = s.3.as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
        service_cpe(&cpes, s.4.as_deref())
    }).collect();
    let cpes: Vec<String> = keyed.iter().flatten().map(|k| k.0.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    type V = (String, String, Value, Option<f64>, bool);
    let vulns: Vec<V> = crate::on_pool!(pool, p, pg => sqlx::query_as(if pg {
        "SELECT c.cpe, c.cve_id, c.ranges, n.cvss, k.cve_id IS NOT NULL FROM sec_nvd_cpe c JOIN sec_nvd_cve n ON n.cve_id = c.cve_id AND NOT n.rejected LEFT JOIN sec_kev k ON k.cve_id = c.cve_id WHERE c.cpe = ANY($1)"
    } else {
        "SELECT c.cpe, c.cve_id, c.ranges, n.cvss, k.cve_id IS NOT NULL FROM sec_nvd_cpe c JOIN sec_nvd_cve n ON n.cve_id = c.cve_id AND NOT n.rejected LEFT JOIN sec_kev k ON k.cve_id = c.cve_id WHERE c.cpe IN (SELECT value FROM json_each($1))"
    }).bind(store::list(&cpes)).fetch_all(p).await).map_err(db)?;
    type Affected<'a> = (&'a str, Vec<Range>, Option<f64>, bool);
    let mut by_cpe: HashMap<&str, Vec<Affected>> = HashMap::new();
    for (cpe, cve, ranges, cvss, kev) in &vulns { by_cpe.entry(cpe.as_str()).or_default().push((cve.as_str(), serde_json::from_value(ranges.clone()).unwrap_or_default(), *cvss, *kev)); }
    let mut updates: Vec<Value> = Vec::new();
    let (mut matched, mut vulnerable) = (0usize, 0usize);
    for (s, k) in svcs.iter().zip(&keyed) {
        let (cpe, version, hits) = match k {
            Some((cpe, v)) => {
                matched += 1;
                let mut hits: Vec<(&str, Option<f64>, bool)> = by_cpe.get(cpe.as_str()).into_iter().flatten().filter(|x| affects(v, &x.1)).map(|x| (x.0, x.2, x.3)).collect();
                hits.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)).then(a.0.cmp(b.0)));
                if !hits.is_empty() { vulnerable += 1; }
                (Some(cpe.clone()), Some(v.clone()), hits.into_iter().take(50).map(|h| json!({ "cve": h.0, "cvss": h.1, "kev": h.2 })).collect::<Vec<_>>())
            }
            None => (None, None, vec![]),
        };
        updates.push(json!({ "ip": s.0, "port": s.1, "transport": s.2, "nvd_cpe": cpe, "nvd_version": version, "nvd_cves": hits }));
    }
    crate::on_pool!(pool, p, pg => {
        sqlx::query(if pg {
            "UPDATE exposure_service s SET nvd_cpe = x.nvd_cpe, nvd_version = x.nvd_version, nvd_cves = x.nvd_cves
               FROM jsonb_to_recordset($1) AS x(ip text, port bigint, transport text, nvd_cpe text, nvd_version text, nvd_cves jsonb)
              WHERE s.ip = x.ip AND s.port = x.port AND s.transport = x.transport"
        } else {
            "UPDATE exposure_service SET nvd_cpe = x.value ->> 'nvd_cpe', nvd_version = x.value ->> 'nvd_version', nvd_cves = x.value -> 'nvd_cves'
               FROM json_each($1) AS x WHERE exposure_service.ip = x.value ->> 'ip' AND exposure_service.port = x.value ->> 'port' AND exposure_service.transport = x.value ->> 'transport'"
        }).bind(Value::Array(updates)).execute(p).await.map_err(db)?;
    });
    Ok(json!({ "services": svcs.len(), "identified": matched, "vulnerable": vulnerable }))
}
