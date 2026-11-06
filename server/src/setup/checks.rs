//! Each section's live Test: read-only, one or two calls, a status and a short reason when it fails. Never a body, a
//! full URL or a secret in the answer: a vendor's own error text can echo what it was sent, so only its HTTP status
//! and that status's standard reason come back.

use reqwest::{RequestBuilder, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct Answer { pub ok: bool, pub message: String, pub status: Option<u16>, pub detail: Option<Value> }

impl Answer {
    pub fn pass(message: &str, status: Option<u16>, detail: Option<Value>) -> Self { Self { ok: true, message: message.into(), status, detail } }
    pub fn fail(message: &str, status: Option<u16>) -> Self { Self { ok: false, message: message.into(), status, detail: None } }
}

pub fn vendor(section: &str) -> &'static str {
    match section { "ninja" => "NinjaOne", "halo" => "HaloPSA", "nvd" => "NVD", "msrc" => "Microsoft's update service", "blackpoint" => "Blackpoint", "shodan" => "Shodan", "auth" => "The sign-in provider", _ => "The database" }
}

/// The settings a test runs with (crate::setup::Setup::effective), and the NAME_FILE rule for secrets.
struct Values<'a> { m: &'a HashMap<String, String>, production: bool, kubernetes: bool }

impl Values<'_> {
    fn get(&self, k: &str) -> Option<String> { self.m.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) }
    fn secret(&self, k: &str) -> Result<Option<String>, Answer> {
        match self.get(&format!("{k}_FILE")) {
            Some(f) => std::fs::read_to_string(&f).map(|s| Some(s.trim().to_string()).filter(|s| !s.is_empty()))
                .map_err(|_| Answer::fail(&format!("{k}_FILE ({f}) can't be read."), None)),
            None => Ok(self.get(k)),
        }
    }
    /// https, or plain http outside production (a local stand-in), as start-up allows.
    fn url(&self, k: &str, v: String) -> Result<String, Answer> {
        if v.starts_with("https://") || (!self.production && v.starts_with("http://")) { Ok(v.trim_end_matches('/').to_string()) }
        else { Err(Answer::fail(&format!("{k} must be an https URL."), None)) }
    }
}

pub const NO_SIGN_IN: &str = "No sign-in: anyone who can reach this port is signed in. Use it only on this computer, with the port bound to 127.0.0.1.";

pub async fn run(section: &str, m: &HashMap<String, String>, http: &reqwest::Client, production: bool, kubernetes: bool, timeout: Duration) -> Answer {
    let v = Values { m, production, kubernetes };
    let c = Call { http, timeout };
    let r = match section {
        "database" => Ok(database(&v, timeout).await),
        "auth" => auth(&v, &c).await,
        "ninja" => ninja(&v, &c).await,
        "halo" => halo(&v, &c).await,
        "nvd" => nvd(&v, &c).await,
        "msrc" => msrc(&v, &c).await,
        "blackpoint" => blackpoint(&v, &c).await,
        "shodan" => shodan(&v, &c).await,
        _ => Ok(Answer::fail("There's no such section.", None)),
    };
    r.unwrap_or_else(|a| a)
}

struct Call<'a> { http: &'a reqwest::Client, timeout: Duration }

enum Fail { Status(u16), Redirect(u16), Timeout, Unreachable, NotJson }

impl Call<'_> {
    async fn json(&self, rb: RequestBuilder) -> Result<(u16, Value), Fail> {
        let r = rb.timeout(self.timeout).send().await.map_err(|e| if e.is_timeout() { Fail::Timeout } else { Fail::Unreachable })?;
        let st = r.status();
        if st.is_redirection() { return Err(Fail::Redirect(st.as_u16())); }
        if !st.is_success() { return Err(Fail::Status(st.as_u16())); }
        r.json::<Value>().await.map(|j| (st.as_u16(), j)).map_err(|_| Fail::NotJson)
    }
}

fn http_reason(code: u16) -> String {
    match StatusCode::from_u16(code).ok().and_then(|s| s.canonical_reason()) { Some(r) => format!("HTTP {code} {r}"), None => format!("HTTP {code}") }
}

/// A failed call as a plain sentence: who, doing what, and the status.
fn failed(who: &str, doing: &str, f: Fail, timeout: Duration) -> Answer {
    match f {
        Fail::Status(code) => Answer::fail(&format!("{who} refused {doing} ({}).", http_reason(code)), Some(code)),
        Fail::Redirect(code) => Answer::fail(&format!("{who}: the address redirected ({}); enter the final address.", http_reason(code)), Some(code)),
        Fail::Timeout => Answer::fail(&format!("{who} didn't answer within {} seconds.", timeout.as_secs().max(1)), None),
        Fail::Unreachable => Answer::fail(&format!("{who} can't be reached at that address: check it, and that the console can reach it."), None),
        Fail::NotJson => Answer::fail(&format!("{who} answered, but not with JSON: check the address."), None),
    }
}

fn need(v: &Values, keys: &[&str], what: &str) -> Result<Vec<String>, Answer> {
    keys.iter().map(|k| v.get(k)).collect::<Option<Vec<_>>>().ok_or_else(|| Answer::fail(&format!("{what} needs {}.", list(keys)), None))
}
fn list(keys: &[&str]) -> String {
    match keys { [] => String::new(), [a] => a.to_string(), [rest @ .., last] => format!("{} and {last}", rest.join(", ")) }
}

// The database: PostgreSQL when the settings name one (DATABASE_URL, or its _FILE), else the SQLite file at
// DATABASE_PATH. Setup hands over only the chosen store's settings (Setup::store_keys).
async fn database(v: &Values<'_>, timeout: Duration) -> Answer {
    if v.get("DATABASE_URL").is_some() || v.get("DATABASE_URL_FILE").is_some() {
        if v.get("DATABASE_PATH").is_some() { return Answer::fail("Choose one store: DATABASE_URL for PostgreSQL, or DATABASE_PATH for a SQLite file, not both.", None); }
        let url = match v.secret("DATABASE_URL") { Ok(Some(u)) => u, Ok(None) => return Answer::fail("PostgreSQL needs DATABASE_URL.", None), Err(a) => return a };
        return match crate::db::PgConfig::new(&url, v.production) {
            Ok(c) => postgres_at(&c, timeout).await,
            Err(e) => Answer::fail(&format!("{e}."), None),
        };
    }
    database_at(&PathBuf::from(v.get("DATABASE_PATH").unwrap_or_else(|| crate::db::DEFAULT_PATH.into())))
}

/// The database answers, the user can create tables where the migrations will (a table made in a transaction and
/// rolled back), and whether pgvector is there. Nothing is migrated or kept, and the answer never carries the URL, its
/// host or its user: only what failed.
pub async fn postgres_at(c: &crate::db::PgConfig, timeout: Duration) -> Answer {
    let p = match crate::db::postgres::probe(c, timeout).await {
        Ok(p) => p,
        Err(why) => return Answer::fail(&format!("The database can't be reached: {why}."), None),
    };
    if let Err(why) = p.can_create { return Answer::fail(&format!("The database answers, but {why}."), None); }
    let vectors = match p.pgvector {
        "installed" => "pgvector is installed, so similar-CVE search will be on.",
        "available" => "pgvector is on the server but not enabled: the console tries CREATE EXTENSION vector when it starts, which needs a role allowed to; without it, similar-CVE search is off.",
        _ => "pgvector isn't on this server, so similar-CVE search will be off; everything else works.",
    };
    let tls = c.tls_note().map(|n| format!(" {n}.")).unwrap_or_default();
    Answer::pass(&format!("The database answers, and the console can make its tables there. {vectors}{tls}"), None, Some(json!({ "pgvector": p.pgvector, "sslmode": c.sslmode() })))
}

/// The file can be created and written: its directory exists and takes a new file, and the file, if there, opens for
/// writing. Nothing is migrated and no database is made.
pub fn database_at(path: &Path) -> Answer {
    let s = path.to_string_lossy();
    if s == ":memory:" || s.starts_with("file:") { return Answer::fail("DATABASE_PATH must be a file's path: the store has to outlive the process.", None); }
    let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) else { return Answer::fail("DATABASE_PATH must be an absolute file path.", None) };
    if !dir.is_dir() { return Answer::fail(&format!("The directory {} doesn't exist: mount the console's volume there.", dir.display()), None); }
    if path.is_dir() { return Answer::fail(&format!("{} is a directory, not a file.", path.display()), None); }
    let probe = dir.join(format!(".msp-console-probe-{}", crate::seal::random(6).iter().map(|b| format!("{b:02x}")).collect::<String>()));
    let wrote = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe).and_then(|mut f| { use std::io::Write; f.write_all(b"probe") });
    let _ = std::fs::remove_file(&probe);
    if wrote.is_err() { return Answer::fail(&format!("The console can't write in {}: mount a writable volume there.", dir.display()), None); }
    if path.exists() && std::fs::OpenOptions::new().read(true).write(true).open(path).is_err() {
        return Answer::fail(&format!("{} exists, and the console can't open it for writing.", path.display()), None);
    }
    Answer::pass("The database file can be created and written.", None, None)
}

async fn auth(v: &Values<'_>, c: &Call<'_>) -> Result<Answer, Answer> {
    match (v.get("AUTH_MODE").as_deref(), v.get("PROXY_KIND").as_deref()) {
        (Some("proxy"), Some("cloudflare_access")) => {
            let team = need(v, &["ACCESS_TEAM_DOMAIN"], "Cloudflare Access")?.remove(0);
            if team.is_empty() || !team.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.') {
                return Ok(Answer::fail("ACCESS_TEAM_DOMAIN must be a host name, like yourteam.cloudflareaccess.com.", None));
            }
            let certs = v.get("ACCESS_CERTS_URL").unwrap_or_else(|| format!("https://{team}/cdn-cgi/access/certs"));
            let (st, j) = c.json(c.http.get(&certs)).await.map_err(|f| failed("Cloudflare Access", "to publish the team's keys", f, c.timeout))?;
            let n = j.get("keys").and_then(Value::as_array).map_or(0, Vec::len);
            if n == 0 { return Ok(Answer::fail("Cloudflare Access answered, but published no signing keys for that team: check the team domain.", Some(st))); }
            Ok(Answer::pass(&format!("Cloudflare Access publishes {n} signing key{} for that team.", if n == 1 { "" } else { "s" }), Some(st), None))
        }
        (Some("proxy"), Some("trusted_header")) => {
            // Start-up's own rules on just these settings: no network call.
            let mut file = serde_json::Map::new();
            for k in ["AUTH_MODE", "PROXY_KIND", "TRUSTED_HEADER", "TRUSTED_PROXY_CIDRS"] { if let Some(x) = v.get(k) { file.insert(k.into(), json!(x)); } }
            let env: HashMap<String, String> = [("CONFIG_PATH".to_string(), "/setup-test.json".to_string())].into();
            let text = Value::Object(file).to_string();
            match crate::config::load(&env, &|_| Ok(text.clone())) {
                Ok(crate::config::Startup::Configured(cfg)) => match cfg.auth {
                    crate::config::AuthConfig::TrustedHeader { cidrs, .. } => Ok(Answer::pass(&format!("The header is believed from {} proxy address range{} only.", cidrs.len(), if cidrs.len() == 1 { "" } else { "s" }), None, None)),
                    _ => Ok(Answer::fail("That isn't a trusted-header configuration.", None)),
                },
                Ok(_) => Ok(Answer::fail("Nothing was filled in.", None)),
                Err(e) => Ok(Answer::fail(&format!("{e}."), None)),
            }
        }
        (Some("proxy"), _) => Ok(Answer::fail("PROXY_KIND must be cloudflare_access or trusted_header.", None)),
        // Only this computer: start-up refuses it in production and in Kubernetes, and so does its test.
        (Some("dev_insecure"), _) if v.production => Ok(Answer::fail("No sign-in isn't allowed in production (MSP_ENV=production): choose how people sign in.", None)),
        (Some("dev_insecure"), _) if v.kubernetes => Ok(Answer::fail("No sign-in isn't allowed on Kubernetes: choose how people sign in.", None)),
        (Some("dev_insecure"), _) => Ok(Answer::pass(NO_SIGN_IN, None, None)),
        (Some("oidc"), _) => {
            let issuer = v.url("OIDC_ISSUER", need(v, &["OIDC_ISSUER"], "OIDC")?.remove(0))?;
            let (st, j) = c.json(c.http.get(format!("{issuer}/.well-known/openid-configuration"))).await.map_err(|f| failed("The provider", "its discovery document", f, c.timeout))?;
            let says = j.get("issuer").and_then(Value::as_str).unwrap_or("").trim_end_matches('/');
            if says != issuer { return Ok(Answer::fail("The provider's discovery document names a different issuer: check OIDC_ISSUER (for Entra, the tenant's v2.0 issuer).", Some(st))); }
            Ok(Answer::pass("The provider's discovery document answers for this issuer.", Some(st), None))
        }
        _ => Ok(Answer::fail("Choose how people sign in: AUTH_MODE proxy (with PROXY_KIND) or oidc.", None)),
    }
}

/// A client-credentials token: the bearer, or the failure as an answer.
async fn token(c: &Call<'_>, who: &str, url: &str, form: &[(&str, String)]) -> Result<String, Answer> {
    let body = serde_urlencoded::to_string(form).unwrap_or_default();
    let (st, j) = c.json(c.http.post(url).header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(body)).await
        .map_err(|f| failed(who, "the client id and secret", f, c.timeout))?;
    j.get("access_token").and_then(Value::as_str).map(String::from).ok_or_else(|| Answer::fail(&format!("{who}'s sign-in answered without a token."), Some(st)))
}

fn secret_needed(v: &Values, k: &str, what: &str, also: &[&str]) -> Result<String, Answer> {
    v.secret(k)?.ok_or_else(|| { let mut all = also.to_vec(); all.push(k); Answer::fail(&format!("{what} needs {}.", list(&all)), None) })
}

async fn ninja(v: &Values<'_>, c: &Call<'_>) -> Result<Answer, Answer> {
    let keys = ["NINJA_BASE_URL", "NINJA_CLIENT_ID"];
    let got = need(v, &keys, "NinjaOne").map_err(|_| Answer::fail("NinjaOne needs NINJA_BASE_URL, NINJA_CLIENT_ID and NINJA_CLIENT_SECRET.", None))?;
    let secret = secret_needed(v, "NINJA_CLIENT_SECRET", "NinjaOne", &keys)?;
    let base = v.url("NINJA_BASE_URL", got[0].clone())?;
    let form = [("grant_type", "client_credentials".to_string()), ("client_id", got[1].clone()), ("client_secret", secret), ("scope", "monitoring".to_string())];
    let bearer = token(c, "NinjaOne", &format!("{base}/ws/oauth/token"), &form).await?;
    let (st, j) = c.json(c.http.get(format!("{base}/v2/organizations?pageSize=1")).bearer_auth(&bearer)).await
        .map_err(|f| failed("NinjaOne", "to list organizations (the API client needs the monitoring scope)", f, c.timeout))?;
    if !j.is_array() { return Ok(Answer::fail("NinjaOne answered, but not with a list of organizations: check NINJA_BASE_URL.", Some(st))); }
    // Running processes: whether any device reports the endpoint script's field (one page of its small companion).
    let field = v.get("NINJA_PROCESS_FIELD").unwrap_or_else(|| crate::connectors::ninja_processes::DEFAULT_FIELD.into());
    if field == "off" { return Ok(Answer::pass("NinjaOne signed in and lists organizations. Running processes are off.", Some(st), Some(json!({ "organizations_visible": true, "processes": "off" })))); }
    if !crate::connectors::ninja_processes::field_name_ok(&field) { return Ok(Answer::fail("NINJA_PROCESS_FIELD must be a NinjaOne custom field's name (letters, digits and _), or off.", None)); }
    let fields = crate::connectors::ninja::urlenc(&format!("{field}CollectedAt"));
    let reporting = match c.json(c.http.get(format!("{base}/v2/queries/custom-fields-detailed?fields={fields}&pageSize=1000")).bearer_auth(&bearer)).await {
        Ok((_, j)) => j.get("results").and_then(Value::as_array).map(|r| r.len()),
        Err(_) => None,
    };
    let (msg, n) = match reporting {
        Some(0) => (format!("NinjaOne signed in and lists organizations. No device reports {field} yet: deploy the endpoint script (endpoint/README.md) to collect running processes."), json!(0)),
        Some(n) => (format!("NinjaOne signed in and lists organizations. {n}{} device{} report{} running processes in {field}.", if n >= 1000 { " or more" } else { "" }, if n == 1 { "" } else { "s" }, if n == 1 { "s" } else { "" }), json!(n)),
        None => ("NinjaOne signed in and lists organizations. Its custom fields couldn't be read, so running processes can't be checked here.".to_string(), Value::Null),
    };
    Ok(Answer::pass(&msg, Some(st), Some(json!({ "organizations_visible": true, "devices_reporting_processes": n }))))
}

async fn halo(v: &Values<'_>, c: &Call<'_>) -> Result<Answer, Answer> {
    let keys = ["HALO_BASE_URL", "HALO_CLIENT_ID"];
    let got = need(v, &keys, "HaloPSA").map_err(|_| Answer::fail("HaloPSA needs HALO_BASE_URL, HALO_CLIENT_ID and HALO_CLIENT_SECRET.", None))?;
    let secret = secret_needed(v, "HALO_CLIENT_SECRET", "HaloPSA", &keys)?;
    let base = v.url("HALO_BASE_URL", got[0].clone())?;
    // The connector's own rule (connectors::halo): HALO_AUTH_URL, or the base without /api, then /auth/token.
    let auth = match v.get("HALO_AUTH_URL") { Some(u) => v.url("HALO_AUTH_URL", u)?, None => format!("{}/auth/token", base.trim_end_matches("/api")) };
    let mut form = vec![("grant_type", "client_credentials".to_string()), ("client_id", got[1].clone()), ("client_secret", secret), ("scope", "all".to_string())];
    if let Some(t) = v.get("HALO_TENANT") { form.push(("tenant", t)); }
    let bearer = token(c, "HaloPSA", &auth, &form).await?;
    let (st, j) = c.json(c.http.get(format!("{base}/Client?count=1&pageinate=true&page_size=1&page_no=1")).bearer_auth(&bearer)).await
        .map_err(|f| failed("HaloPSA", "to list clients (the API application needs read access to clients)", f, c.timeout))?;
    let Some(n) = j.get("record_count").and_then(Value::as_u64) else {
        return Ok(Answer::fail("HaloPSA answered, but not with its client list: check HALO_BASE_URL (it ends in /api).", Some(st)));
    };
    // Halo's own ticket types, statuses and priorities, so the wizard offers them to pick from for tickets raised from
    // findings. A list Halo won't give is left out (the API application may not read it); the test still passes.
    let mut detail = json!({ "clients": n });
    for (key, path, id_field) in [("ticket_types", "TicketType", "id"), ("statuses", "Status", "id"), ("priorities", "Priority", "priorityid")] {
        if let Ok((_, l)) = c.json(c.http.get(format!("{base}/{path}")).bearer_auth(&bearer)).await {
            let items: Vec<Value> = l.as_array().into_iter().flatten().filter(|x| x.get("ishidden").and_then(Value::as_bool) != Some(true))
                .filter_map(|x| Some(json!({ "id": x.get(id_field).and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))?, "name": x.get("name").and_then(Value::as_str)?.chars().take(100).collect::<String>() })))
                .take(500).collect();
            if !items.is_empty() { detail[key] = json!(items); }
        }
    }
    Ok(Answer::pass(&format!("HaloPSA signed in and lists {n} client{}.", if n == 1 { "" } else { "s" }), Some(st), Some(detail)))
}

async fn nvd(v: &Values<'_>, c: &Call<'_>) -> Result<Answer, Answer> {
    let url = v.url("NVD_URL", v.get("NVD_URL").unwrap_or_else(|| crate::connectors::nvd::DEFAULT_URL.into()))?;
    let key = v.secret("NVD_API_KEY")?;
    let mut rb = c.http.get(format!("{url}?resultsPerPage=1"));
    if let Some(k) = &key { rb = rb.header("apiKey", k); }
    let (st, j) = match c.json(rb).await {
        Ok(x) => x,
        Err(Fail::Status(code @ (403 | 404))) if key.is_some() => return Ok(Answer::fail(&format!("NVD refused that API key ({}).", http_reason(code)), Some(code))),
        Err(f) => return Ok(failed("NVD", "the request", f, c.timeout)),
    };
    let Some(total) = j.get("totalResults").and_then(Value::as_u64) else { return Ok(Answer::fail("NVD answered, but not as the CVE API does: check NVD_URL.", Some(st))) };
    let keyed = key.is_some();
    let how = if keyed { "with your API key (50 requests per 30 seconds)" } else { "without a key (5 requests per 30 seconds; a free key allows 50)" };
    // The whole dataset: NVD's feed host, one small .meta (no key; the feeds are public).
    let mode = v.get("NVD_FEEDS").unwrap_or_else(|| "full".into());
    if !matches!(mode.as_str(), "full" | "curated" | "on" | "off") { return Ok(Answer::fail("NVD_FEEDS must be full or curated.", None)); }
    if matches!(mode.as_str(), "curated" | "off") {
        return Ok(Answer::pass(&format!("NVD answered {how}: {total} CVEs. The console reads only the curated products."), Some(st), Some(json!({ "total_cves": total, "keyed": keyed, "feeds": "curated" }))));
    }
    let feeds = v.url("NVD_FEED_URL", v.get("NVD_FEED_URL").unwrap_or_else(|| crate::connectors::nvd_feed::DEFAULT_URL.into()))?;
    let meta = match c.http.get(format!("{feeds}/nvdcve-2.0-modified.meta")).timeout(c.timeout).send().await {
        Ok(r) if r.status().is_success() => r.text().await.ok().map(|t| crate::connectors::nvd_feed::parse_meta(&t)),
        Ok(r) => return Ok(Answer::fail(&format!("NVD's API answered, but its feeds refused ({}).", http_reason(r.status().as_u16())), Some(r.status().as_u16()))),
        Err(_) => return Ok(Answer::fail("NVD's API answered, but its feeds couldn't be reached: the console needs nvd.nist.gov too, or set NVD_FEEDS=curated.", None)),
    };
    if !meta.as_ref().is_some_and(|m| m.sha256.is_some()) { return Ok(Answer::fail("NVD's feeds answered, but not with a feed's .meta: check NVD_FEED_URL.", None)); }
    Ok(Answer::pass(&format!("NVD answered {how}: {total} CVEs. Its feeds answer too: the console loads all of NVD."), Some(st), Some(json!({ "total_cves": total, "keyed": keyed, "feeds": "full" }))))
}

/// Microsoft's update service: its index of monthly documents, public and read-only. Off is a pass that says so.
async fn msrc(v: &Values<'_>, c: &Call<'_>) -> Result<Answer, Answer> {
    match v.get("MSRC").as_deref() {
        None | Some("on") => {}
        Some("off") => return Ok(Answer::pass("Microsoft's updates are off: Windows itself is left out.", None, Some(json!({ "msrc": "off" })))),
        Some(_) => return Ok(Answer::fail("MSRC must be on or off.", None)),
    }
    let url = v.url("MSRC_URL", v.get("MSRC_URL").unwrap_or_else(|| crate::connectors::msrc::DEFAULT_URL.into()))?;
    let (st, j) = c.json(c.http.get(format!("{url}/updates")).header(reqwest::header::ACCEPT, "application/json")).await
        .map_err(|f| failed("Microsoft's update service", "to list its monthly updates", f, c.timeout))?;
    let Some(n) = j.get("value").and_then(Value::as_array).map(Vec::len) else { return Ok(Answer::fail("Microsoft's update service answered, but not with its index: check MSRC_URL.", Some(st))) };
    Ok(Answer::pass(&format!("Microsoft's update service lists {n} monthly updates."), Some(st), Some(json!({ "months": n }))))
}

async fn blackpoint(v: &Values<'_>, c: &Call<'_>) -> Result<Answer, Answer> {
    let base = v.url("BLACKPOINT_BASE_URL", v.get("BLACKPOINT_BASE_URL").ok_or_else(|| Answer::fail("Blackpoint needs BLACKPOINT_BASE_URL and BLACKPOINT_API_TOKEN.", None))?)?;
    let token = secret_needed(v, "BLACKPOINT_API_TOKEN", "Blackpoint", &["BLACKPOINT_BASE_URL"])?;
    let (st, j) = c.json(c.http.get(format!("{base}/v1/tenants?pageSize=1&page=1")).bearer_auth(token)).await
        .map_err(|f| failed("Blackpoint", "the API token", f, c.timeout))?;
    let Some(n) = j.pointer("/meta/totalItems").and_then(Value::as_u64) else {
        return Ok(Answer::fail("Blackpoint answered, but not with its tenant list: check BLACKPOINT_BASE_URL.", Some(st)));
    };
    Ok(Answer::pass(&format!("Blackpoint accepted the token and lists {n} tenant{}.", if n == 1 { "" } else { "s" }), Some(st), Some(json!({ "tenants": n }))))
}

/// Shodan's account information (`/api-info`): the plan and the credits left. A read that spends nothing.
async fn shodan(v: &Values<'_>, c: &Call<'_>) -> Result<Answer, Answer> {
    let base = v.url("SHODAN_URL", v.get("SHODAN_URL").unwrap_or_else(|| crate::connectors::shodan::DEFAULT_URL.into()))?;
    let key = secret_needed(v, "SHODAN_API_KEY", "Shodan", &[])?;
    if let Some(n) = v.get("SHODAN_SCAN_CREDITS_PER_MONTH") && n.parse::<usize>().ok().filter(|n| *n <= 100_000).is_none() {
        return Ok(Answer::fail("SHODAN_SCAN_CREDITS_PER_MONTH must be a number from 0 to 100000.", None));
    }
    // The key rides in the query string (Shodan's only scheme), so nothing from this request is ever repeated back.
    let (st, j) = c.json(c.http.get(format!("{base}/api-info?key={}", crate::connectors::ninja::urlenc(&key)))).await
        .map_err(|f| failed("Shodan", "the API key", f, c.timeout))?;
    let (Some(scan), Some(query)) = (j.get("scan_credits").and_then(Value::as_i64), j.get("query_credits").and_then(Value::as_i64)) else {
        return Ok(Answer::fail("Shodan answered, but not with its account information: check SHODAN_URL.", Some(st)));
    };
    let plan = j.get("plan").and_then(Value::as_str).map(|p| p.chars().take(40).collect::<String>());
    Ok(Answer::pass(&format!("Shodan accepted the key: {scan} scan credits and {query} query credits left this month."), Some(st),
        Some(json!({ "plan": plan, "scan_credits": scan, "query_credits": query }))))
}
