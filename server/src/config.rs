//! Configuration (design rev 3.1, "Configuration"): every setting is an environment variable, and the same names can
//! live in a JSON file at CONFIG_PATH on a mounted volume. The environment always wins. With neither, the server is
//! unconfigured and serves only the first-run setup; with something but not enough, it refuses to start (fail closed).
//! Every secret can come from NAME or NAME_FILE (a mounted Secret), the file winning. The store is a SQLite file
//! at DATABASE_PATH, which needs no secret, or the PostgreSQL database DATABASE_URL names, a secret as a whole
//! since it carries the password. Secrets in the file are encrypted at rest under the master key (crate::secrets) and
//! decrypted here; one that won't decrypt refuses to start, naming the setting.

use crate::connectors::halo::HaloSettings;
use crate::db::{DbConfig, PgConfig, SqliteConfig};
use crate::secrets;
use ipnet::IpNet;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/var/lib/msp-console/config.json";

/// The settings the setup screen and the file carry, by their environment names.
pub const KEYS: &[&str] = &[
    "DATABASE_PATH", "BACKUP_KEEP", "DATABASE_URL", "DATABASE_URL_FILE",
    "AUTH_MODE", "PROXY_KIND", "ACCESS_TEAM_DOMAIN", "ACCESS_AUD", "ACCESS_CERTS_URL",
    "TRUSTED_HEADER", "TRUSTED_PROXY_CIDRS", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET_FILE", "OIDC_ALLOWED_GROUP",
    "SESSION_KEY", "SESSION_KEY_FILE", "PUBLIC_URL",
    // Who is an admin, by sign-in mode: a group or role in the OIDC token, or a list of addresses behind a proxy.
    "OIDC_ADMIN_GROUP", "ADMIN_EMAILS",
    // The connectors: the installing MSP's own vendors. Each is off until its settings are all there.
    "NINJA_BASE_URL", "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET", "NINJA_CLIENT_SECRET_FILE",
    "HALO_BASE_URL", "HALO_AUTH_URL", "HALO_TENANT", "HALO_CLIENT_ID", "HALO_CLIENT_SECRET", "HALO_CLIENT_SECRET_FILE", "HALO_REQUESTS_PER_5MIN", "HALO_DETAIL_BUDGET",
    "NVD_API_KEY", "NVD_API_KEY_FILE", "NVD_URL", "KEV_URL", "SCHEDULER",
    // Blackpoint, Shodan, and Halo tickets: each off until its settings are there.
    "BLACKPOINT_BASE_URL", "BLACKPOINT_API_TOKEN", "BLACKPOINT_API_TOKEN_FILE",
    "SHODAN_API_KEY", "SHODAN_API_KEY_FILE", "SHODAN_URL", "SHODAN_SCAN_CREDITS_PER_MONTH", "SCAN_POLICY_ADMINS",
    "HALO_TICKET_TYPE_ID", "HALO_TICKET_STATUS_ID", "HALO_TICKET_PRIORITY_ID",
    // Windows itself (MSRC, public), the running-processes field in NinjaOne, and the full NVD feeds.
    "MSRC", "MSRC_URL", "NINJA_PROCESS_FIELD", "NVD_FEEDS", "NVD_FEED_URL",
    // The embedder (src/embed.rs): on by default, from the model baked into the image.
    "EMBEDDER", "MODEL_DIR", "EMBED_THREADS",
];

/// Settings no longer read. Set, they'd be ignored, and someone would think they applied: it refuses instead.
/// DATABASE_SSLMODE was the first PostgreSQL store's TLS switch; TLS is now the URL's own sslmode.
const RETIRED: &[&str] = &["DATABASE_SSLMODE"];

/// The connectors the settings turn on. NVD and CISA KEV are public and always on; the vendors need their settings.
#[derive(Clone)]
pub struct Connectors {
    pub ninja: Option<NinjaCfg>,
    pub halo: Option<HaloCfg>,
    pub nvd_url: String,
    pub nvd_key: Option<String>,
    pub kev_url: String,
    /// Microsoft's security updates (MSRC's CVRF API): public, on unless MSRC=off.
    pub msrc_url: Option<String>,
    /// NVD's yearly and modified JSON feeds, the whole dataset: NVD_FEEDS=full (the default). curated reads NVD per
    /// curated product through its API instead (nvd_products).
    pub nvd_feed_url: Option<String>,
    /// The NinjaOne custom field the endpoint script (endpoint/process) writes the process inventory to, and the base
    /// of its companions' names (<field>CollectedAt, <field>Hash, <field>Bytes). None when NinjaOne is off, or
    /// NINJA_PROCESS_FIELD=off.
    pub ninja_process_field: Option<String>,
}
// By hand: the NVD key is a secret, so its Debug form says only whether there is one.
impl std::fmt::Debug for Connectors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connectors").field("ninja", &self.ninja).field("halo", &self.halo).field("nvd_url", &self.nvd_url)
            .field("nvd_key", &self.nvd_key.is_some()).field("kev_url", &self.kev_url)
            .field("msrc_url", &self.msrc_url).field("nvd_feed_url", &self.nvd_feed_url).field("ninja_process_field", &self.ninja_process_field).finish()
    }
}
#[derive(Clone)]
pub struct NinjaCfg { pub base: String, pub client_id: String, pub client_secret: String }
impl std::fmt::Debug for NinjaCfg { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("NinjaCfg").field("base", &self.base).finish_non_exhaustive() } }
#[derive(Clone)]
pub struct HaloCfg { pub base: String, pub auth_url: Option<String>, pub tenant: Option<String>, pub client_id: String, pub client_secret: String, pub per_5min: usize, pub detail_budget: usize }
impl std::fmt::Debug for HaloCfg { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("HaloCfg").field("base", &self.base).finish_non_exhaustive() } }
impl HaloCfg {
    pub fn settings(&self) -> HaloSettings {
        HaloSettings { base: self.base.clone(), auth_url: self.auth_url.clone(), client_id: self.client_id.clone(), client_secret: self.client_secret.clone(),
                       tenant: self.tenant.clone(), per_5min: self.per_5min, detail_budget: self.detail_budget }
    }
}

#[derive(Clone, PartialEq)]
pub enum AuthConfig {
    /// Cloudflare Access in front; the server verifies its JWT. certs_url is the team's unless overridden (tests).
    CloudflareAccess { team_domain: String, aud: String, certs_url: String },
    /// A reverse proxy that authenticates and names the user in a header, believed only from these addresses.
    TrustedHeader { header: String, cidrs: Vec<IpNet> },
    /// The console's own OIDC sign-in (Entra in any tenant): code flow with PKCE, an encrypted session cookie.
    Oidc { issuer: String, client_id: String, client_secret: String, allowed_group: String, session_key: String },
    /// No sign-in at all: a laptop's compose run against made-up data. Refused in Kubernetes and in production.
    DevInsecure,
}
// By hand: OIDC's client secret and session key are secrets, so the Debug form (what a panic or a log line would
// show) says only that they're there.
impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthConfig::CloudflareAccess { team_domain, aud, certs_url } => f.debug_struct("CloudflareAccess").field("team_domain", team_domain).field("aud", aud).field("certs_url", certs_url).finish(),
            AuthConfig::TrustedHeader { header, cidrs } => f.debug_struct("TrustedHeader").field("header", header).field("cidrs", cidrs).finish(),
            AuthConfig::Oidc { issuer, client_id, allowed_group, .. } => f.debug_struct("Oidc").field("issuer", issuer).field("client_id", client_id)
                .field("allowed_group", allowed_group).field("client_secret", &"[redacted]").field("session_key", &"[redacted]").finish(),
            AuthConfig::DevInsecure => f.write_str("DevInsecure"),
        }
    }
}

/// Who may change settings and advisories, by sign-in mode: OIDC_ADMIN_GROUP's members (oidc), the addresses in
/// ADMIN_EMAILS (behind a proxy), or the local user (only this computer). None: no one, until one is set.
#[derive(Debug, Clone, PartialEq)]
pub enum Admins { Group(String), Emails(Vec<String>), Local, None }

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub static_dir: Option<PathBuf>,
    pub db: DbConfig,
    pub connectors: Connectors,
    /// Off (SCHEDULER=off) to serve what's stored without collecting more (a test, or a copy opened to look at).
    pub scheduler: bool,
    /// The embedder behind similar-CVE search: EMBEDDER (on or off), MODEL_DIR, EMBED_THREADS.
    pub embedder: crate::embed::EmbedConfig,
    pub auth: AuthConfig,
    /// Blackpoint, Shodan, and raising Halo tickets from findings: each None when off.
    pub blackpoint: Option<crate::connectors::blackpoint::BlackpointCfg>,
    pub shodan: Option<crate::connectors::shodan::ShodanCfg>,
    pub tickets: Option<crate::ops::tickets::TicketCfg>,
    pub public_url: Option<String>,
    pub admins: Admins,
    /// Said once at start-up: a secret stored unencrypted in the file. Names, never values.
    pub warnings: Vec<String>,
}

// Built once at start-up and matched straight away: the size difference between the variants costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Startup { Configured(Config), Unconfigured { config_path: PathBuf, port: u16 } }

/// What the config file holds, its secrets decrypted (crate::secrets): only the known settings, and a warning per
/// secret still stored in plaintext. Absent is empty. A value that can't be decrypted refuses, naming the setting.
pub struct FileSettings { pub path: PathBuf, pub values: HashMap<String, String>, pub warnings: Vec<String> }

pub fn config_path(env: &HashMap<String, String>) -> PathBuf {
    PathBuf::from(env.get("CONFIG_PATH").cloned().unwrap_or_else(|| DEFAULT_CONFIG_PATH.into()))
}

pub fn read_file(env: &HashMap<String, String>, read: &dyn Fn(&Path) -> std::io::Result<String>) -> Result<FileSettings, String> {
    let path = config_path(env);
    let mut values = HashMap::new();
    let mut warnings = Vec::new();
    let text = match read(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileSettings { path, values, warnings }),
        Err(_) => return Err(format!("the config file {} can't be read", path.display())),
    };
    let v: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&text).map_err(|_| format!("the config file {} isn't a JSON object", path.display()))?;
    if let Some(k) = v.keys().find(|k| RETIRED.contains(&k.as_str())) { return Err(retired(k)); }
    // The master key is looked for only when something is encrypted: a file without secrets needs none.
    let mut key: Option<secrets::ConfigKey> = None;
    let mut names: Vec<&String> = v.keys().collect();
    names.sort();
    for k in names {
        let Some(s) = v[k].as_str() else { continue };
        if !KEYS.contains(&k.as_str()) || s.trim().is_empty() { continue; }
        let plain = if secrets::is_encrypted(s) {
            if key.is_none() {
                key = Some(secrets::find(env, read)?.ok_or_else(|| format!(
                    "{k} in the config file is encrypted, and there's no master key: set CONSOLE_MASTER_KEY or CONSOLE_MASTER_KEY_FILE, or mount the key's volume at {} (MASTER_KEY_PATH)",
                    secrets::key_path(env).display()))?);
            }
            key.as_ref().expect("found above").decrypt(k, s)?
        } else {
            if secrets::is_secret(k) { warnings.push(format!("{k} is stored in the config file unencrypted: set it by environment instead, or save it through setup again to encrypt it")); }
            s.to_string()
        };
        values.insert(k.clone(), plain);
    }
    Ok(FileSettings { path, values, warnings })
}

/// The settings in effect: the file's (decrypted), overlaid by the environment's.
pub struct Merged { pub values: HashMap<String, String>, pub from_file: bool, pub path: PathBuf, pub warnings: Vec<String> }

pub fn merged(env: &HashMap<String, String>, read: &dyn Fn(&Path) -> std::io::Result<String>) -> Result<Merged, String> {
    let f = read_file(env, read)?;
    let mut m = f.values;
    let from_file = !m.is_empty();
    if let Some(k) = RETIRED.iter().find(|k| env.get(**k).is_some_and(|v| !v.trim().is_empty())) { return Err(retired(k)); }
    // Which store is one choice, and the environment's wins over the file's: a URL by environment sets the file's
    // SQLite settings aside, and a path by environment the file's URL. Both from the same place is still a refusal.
    let by_env = |ks: &[&str]| ks.iter().any(|k| env.get(*k).is_some_and(|v| !v.trim().is_empty()));
    if by_env(&["DATABASE_URL", "DATABASE_URL_FILE"]) { m.remove("DATABASE_PATH"); m.remove("BACKUP_KEEP"); }
    if by_env(&["DATABASE_PATH"]) { m.remove("DATABASE_URL"); m.remove("DATABASE_URL_FILE"); }
    for k in KEYS { if let Some(v) = env.get(*k) && !v.trim().is_empty() { m.insert(k.to_string(), v.clone()); } }
    Ok(Merged { values: m, from_file, path: f.path, warnings: f.warnings })
}

fn retired(k: &str) -> String { format!("{k} is no longer read: say how to reach PostgreSQL in DATABASE_URL itself, with sslmode=verify-full (or verify-ca and sslrootcert) for TLS") }

/// The settings that say how people sign in. Any one of them in the environment means the operator is configuring by
/// environment, so a gap refuses to start rather than opening the guided setup.
const SIGN_IN_KEYS: &[&str] = &["AUTH_MODE", "PROXY_KIND", "ACCESS_TEAM_DOMAIN", "ACCESS_AUD", "ACCESS_CERTS_URL", "TRUSTED_HEADER",
    "TRUSTED_PROXY_CIDRS", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET_FILE", "OIDC_ALLOWED_GROUP",
    "SESSION_KEY", "SESSION_KEY_FILE"];

pub fn load(env: &HashMap<String, String>, read: &dyn Fn(&Path) -> std::io::Result<String>) -> Result<Startup, String> {
    let port: u16 = env.get("PORT").map(|p| p.parse().map_err(|_| "PORT must be a port number".to_string())).transpose()?.unwrap_or(8080);
    let Merged { values: m, from_file, path, mut warnings } = merged(env, read)?;
    // Unconfigured: nothing saved yet and no sign-in setting at all in the environment. Settings the environment does give
    // (a connector, the database path) then show in the guided setup as set by environment, rather than refusing to
    // start. Once any sign-in setting is given, or the file exists, anything missing is a refusal (fail closed).
    if !from_file && !SIGN_IN_KEYS.iter().any(|k| m.contains_key(*k)) { return Ok(Startup::Unconfigured { config_path: path, port }); }
    let get = |k: &str| m.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let need = |k: &str| get(k).ok_or_else(|| format!("{k} is required"));
    let production = env.get("MSP_ENV").map(String::as_str) == Some("production");
    // A secret: NAME_FILE (a mounted Secret) or NAME. The error names the setting, never its value.
    let secret = |k: &str| -> Result<Option<String>, String> {
        match get(&format!("{k}_FILE")) {
            Some(f) => read(Path::new(&f)).map(|s| Some(s.trim().to_string()).filter(|s| !s.is_empty())).map_err(|_| format!("{k}_FILE ({f}) can't be read")),
            None => Ok(get(k)),
        }
    };
    let url = |k: &str, v: String| -> Result<String, String> {
        if v.starts_with("https://") || (!production && v.starts_with("http://")) { Ok(v.trim_end_matches('/').to_string()) }
        else { Err(format!("{k} must be an https URL")) }
    };

    // A connector is on when all its settings are there, off when none are, and a refusal when only some are.
    let ninja = match (get("NINJA_BASE_URL"), get("NINJA_CLIENT_ID"), secret("NINJA_CLIENT_SECRET")?) {
        (Some(b), Some(i), Some(s)) => Some(NinjaCfg { base: url("NINJA_BASE_URL", b)?, client_id: i, client_secret: s }),
        (None, None, None) => None,
        _ => return Err("NinjaOne needs NINJA_BASE_URL, NINJA_CLIENT_ID and NINJA_CLIENT_SECRET (or _FILE) together".into()),
    };
    let num = |k: &str, d: usize, max: usize| -> Result<usize, String> {
        match get(k) { None => Ok(d), Some(v) => v.parse::<usize>().ok().filter(|n| (1..=max).contains(n)).ok_or(format!("{k} must be a number from 1 to {max}")) }
    };
    // The store: PostgreSQL when DATABASE_URL (or its _FILE) is set, else the SQLite file at DATABASE_PATH. Both at
    // once is a refusal: one of them would be ignored.
    let db = match (secret("DATABASE_URL")?, get("DATABASE_PATH")) {
        (Some(_), Some(_)) => return Err("DATABASE_URL and DATABASE_PATH are both set: set DATABASE_URL for a PostgreSQL database, or DATABASE_PATH for a SQLite file on the console's volume, not both".into()),
        (Some(url), None) => {
            if get("BACKUP_KEEP").is_some() {
                warnings.push("BACKUP_KEEP is ignored with PostgreSQL: the console's daily copy is SQLite's; back the database up with pg_dump or your provider's snapshots".into());
            }
            // The URL is the one source: libpq's variables in this environment are refused (db::postgres::LIBPQ_ENV).
            let pg = PgConfig::new_in(&url, production, &|k| env.get(k).cloned())?;
            if let Some(note) = pg.tls_note() { warnings.push(format!("DATABASE_URL: {note}")); }
            DbConfig::Postgres(pg)
        }
        (None, path) => DbConfig::Sqlite(SqliteConfig {
            path: match path {
                None => PathBuf::from(crate::db::DEFAULT_PATH),
                Some(p) if p == ":memory:" || p.starts_with("file:") => return Err("DATABASE_PATH must be a file's path: the store has to outlive the process".into()),
                Some(p) => PathBuf::from(p),
            },
            backup_keep: num("BACKUP_KEEP", 7, 365)?,
        }),
    };
    let halo = match (get("HALO_BASE_URL"), get("HALO_CLIENT_ID"), secret("HALO_CLIENT_SECRET")?) {
        (Some(b), Some(i), Some(s)) => Some(HaloCfg { base: url("HALO_BASE_URL", b)?, auth_url: get("HALO_AUTH_URL").map(|u| url("HALO_AUTH_URL", u)).transpose()?, tenant: get("HALO_TENANT"),
            client_id: i, client_secret: s, per_5min: num("HALO_REQUESTS_PER_5MIN", 150, 600)?, detail_budget: num("HALO_DETAIL_BUDGET", 150, 5000)? }),
        (None, None, None) => None,
        _ => return Err("HaloPSA needs HALO_BASE_URL, HALO_CLIENT_ID and HALO_CLIENT_SECRET (or _FILE) together".into()),
    };
    let mut connectors = Connectors {
        ninja, halo,
        nvd_url: url("NVD_URL", get("NVD_URL").unwrap_or_else(|| crate::connectors::nvd::DEFAULT_URL.into()))?,
        nvd_key: secret("NVD_API_KEY")?,
        kev_url: url("KEV_URL", get("KEV_URL").unwrap_or_else(|| crate::connectors::kev::DEFAULT_URL.into()))?,
        msrc_url: match get("MSRC").as_deref() {
            None | Some("on") => Some(url("MSRC_URL", get("MSRC_URL").unwrap_or_else(|| crate::connectors::msrc::DEFAULT_URL.into()))?),
            Some("off") => None,
            Some(o) => return Err(format!("MSRC must be on or off, not {o}")),
        },
        nvd_feed_url: match get("NVD_FEEDS").as_deref() {
            None | Some("full") | Some("on") => Some(url("NVD_FEED_URL", get("NVD_FEED_URL").unwrap_or_else(|| crate::connectors::nvd_feed::DEFAULT_URL.into()))?),
            Some("curated") | Some("off") => None,
            Some(o) => return Err(format!("NVD_FEEDS must be full or curated, not {o}")),
        },
        ninja_process_field: None,
    };
    connectors.ninja_process_field = match (connectors.ninja.is_some(), get("NINJA_PROCESS_FIELD")) {
        (_, Some(f)) if f == "off" => None,
        (true, None) => Some(crate::connectors::ninja_processes::DEFAULT_FIELD.into()),
        (true, Some(f)) if crate::connectors::ninja_processes::field_name_ok(&f) => Some(f),
        (true, Some(_)) => return Err("NINJA_PROCESS_FIELD must be a NinjaOne custom field's name (letters, digits and _), or off".into()),
        (false, _) => None,
    };
    let blackpoint = crate::connectors::blackpoint::settings(&get, secret("BLACKPOINT_API_TOKEN")?, &url)?;
    let shodan = crate::connectors::shodan::settings(&get, secret("SHODAN_API_KEY")?, &url)?;
    let tickets = crate::ops::tickets::settings(&get, connectors.halo.is_some())?;
    let scheduler = match get("SCHEDULER").as_deref() { None | Some("on") => true, Some("off") => false, Some(o) => return Err(format!("SCHEDULER must be on or off, not {o}")) };
    let embedder = crate::embed::EmbedConfig {
        on: match get("EMBEDDER").as_deref() { None | Some("on") => true, Some("off") => false, Some(o) => return Err(format!("EMBEDDER must be on or off, not {o}")) },
        model_dir: get("MODEL_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(crate::embed::DEFAULT_DIR)),
        threads: num("EMBED_THREADS", 2, crate::embed::MAX_THREADS)?,
    };

    let auth = match need("AUTH_MODE")?.as_str() {
        "proxy" => match need("PROXY_KIND")?.as_str() {
            "cloudflare_access" => {
                let team_domain = need("ACCESS_TEAM_DOMAIN")?;
                let certs_url = get("ACCESS_CERTS_URL").unwrap_or_else(|| format!("https://{team_domain}/cdn-cgi/access/certs"));
                AuthConfig::CloudflareAccess { aud: need("ACCESS_AUD")?, team_domain, certs_url }
            }
            "trusted_header" => {
                let raw = need("TRUSTED_PROXY_CIDRS").map_err(|_| "TRUSTED_PROXY_CIDRS is required for trusted_header: the proxy's addresses, and only them".to_string())?;
                let cidrs = raw.split(',').map(str::trim).filter(|s| !s.is_empty())
                    .map(|c| c.parse::<IpNet>().map_err(|_| format!("TRUSTED_PROXY_CIDRS: {c} isn't a CIDR")))
                    .collect::<Result<Vec<_>, _>>()?;
                if cidrs.is_empty() { return Err("TRUSTED_PROXY_CIDRS names no address".into()); }
                if cidrs.iter().any(|c| c.prefix_len() == 0) { return Err("TRUSTED_PROXY_CIDRS may not be the whole internet".into()); }
                AuthConfig::TrustedHeader { header: need("TRUSTED_HEADER")?.to_ascii_lowercase(), cidrs }
            }
            other => return Err(format!("PROXY_KIND must be cloudflare_access or trusted_header, not {other}")),
        },
        "oidc" => {
            let session_key = secret("SESSION_KEY")?.ok_or("SESSION_KEY (or SESSION_KEY_FILE) is required")?;
            if session_key.len() < 32 { return Err("SESSION_KEY must be at least 32 characters".into()); }
            let issuer = need("OIDC_ISSUER")?;
            if !issuer.starts_with("https://") { return Err("OIDC_ISSUER must be https".into()); }
            // The sign-in comes back to PUBLIC_URL/auth/callback, and its cookies are Secure: https only.
            if !get("PUBLIC_URL").is_some_and(|u| u.starts_with("https://")) { return Err("PUBLIC_URL is required for oidc, as https://<this console's host>".into()); }
            let client_secret = secret("OIDC_CLIENT_SECRET")?.ok_or("OIDC_CLIENT_SECRET (or OIDC_CLIENT_SECRET_FILE) is required")?;
            AuthConfig::Oidc { issuer, client_id: need("OIDC_CLIENT_ID")?, client_secret, allowed_group: need("OIDC_ALLOWED_GROUP")?, session_key }
        }
        "dev_insecure" => {
            if env.contains_key("KUBERNETES_SERVICE_HOST") { return Err("AUTH_MODE=dev_insecure refuses to run in Kubernetes".into()); }
            if production { return Err("AUTH_MODE=dev_insecure refuses to run in production".into()); }
            AuthConfig::DevInsecure
        }
        other => return Err(format!("AUTH_MODE must be proxy or oidc, not {other}")),
    };
    // Admins, by sign-in mode. A setting for another mode refuses, so no one thinks it applies.
    let admins = match (&auth, get("OIDC_ADMIN_GROUP"), get("ADMIN_EMAILS")) {
        (AuthConfig::Oidc { .. }, _, Some(_)) => return Err("ADMIN_EMAILS is for sign-in behind a proxy: with oidc, admins are the members of OIDC_ADMIN_GROUP".into()),
        (AuthConfig::Oidc { .. }, Some(g), None) => Admins::Group(g),
        (AuthConfig::CloudflareAccess { .. } | AuthConfig::TrustedHeader { .. }, Some(_), _) => return Err("OIDC_ADMIN_GROUP is for the console's own sign-in (oidc): behind a proxy, admins are ADMIN_EMAILS".into()),
        (AuthConfig::CloudflareAccess { .. } | AuthConfig::TrustedHeader { .. }, None, Some(list)) => {
            let emails: Vec<String> = list.split(',').map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty()).collect();
            if emails.is_empty() || emails.iter().any(|e| e.len() > 320 || e.chars().any(char::is_whitespace)) { return Err("ADMIN_EMAILS must be addresses, comma-separated".into()); }
            Admins::Emails(emails)
        }
        (AuthConfig::DevInsecure, g, e) => {
            if g.is_some() || e.is_some() { warnings.push("OIDC_ADMIN_GROUP and ADMIN_EMAILS are ignored with no sign-in: the local user is the admin".into()); }
            Admins::Local
        }
        // No admins is allowed (everyone reads; nothing changes): main.rs says so at start.
        _ => Admins::None,
    };
    Ok(Startup::Configured(Config {
        port, static_dir: env.get("STATIC_DIR").filter(|s| !s.is_empty()).map(PathBuf::from), db, connectors, scheduler, embedder, auth, blackpoint, shodan, tickets, public_url: get("PUBLIC_URL"), admins, warnings,
    }))
}

pub fn from_process() -> Result<Startup, String> {
    let env: HashMap<String, String> = std::env::vars().collect();
    load(&env, &|p| std::fs::read_to_string(p))
}
