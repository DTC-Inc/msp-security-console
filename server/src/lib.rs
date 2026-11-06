//! MSP Security Console, the server: its own store, connectors, scheduler and sign-in, and the evidence API (docs/design.md).
pub mod admin;
pub mod advisory;
pub mod app;
pub mod audit;
pub mod backup;
pub mod config;
pub mod connectors;
pub mod contract;
pub mod cpe_map;
pub mod db;
pub mod embed;
pub mod embed_job;
pub mod identity;
pub mod inventory;
pub mod matching;
pub mod oidc;
pub mod ops;
pub mod process;
pub mod process_match;
pub mod scheduler;
pub mod seal;
pub mod secrets;
pub mod setup;
pub mod vectors;
pub mod website;
pub mod windows;

/// One HTTP client for the vendors and the identity providers: rustls on ring, the platform's roots. It never follows
/// a redirect: a 307 or 308 would resend a token form or an API key to whatever host it names. A 3xx is a failure.
pub fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder().user_agent("msp-security-console").redirect(reqwest::redirect::Policy::none()).build().expect("an HTTP client")
}

/// Every job the settings turn on: the connectors', the match, and the daily backup of a SQLite store.
pub fn jobs(c: &config::Connectors, store: &db::DbConfig, http: reqwest::Client) -> Vec<scheduler::Job> {
    use std::sync::Arc;
    let mut jobs = Vec::new();
    if let Some(n) = &c.ninja {
        let ninja = Arc::new(connectors::ninja::Ninja::new(&n.base, &n.client_id, &n.client_secret, http.clone()));
        jobs.extend(ninja.clone().jobs());
        // Windows' patch level needs Microsoft's data to mean anything; running processes need the endpoint script's field.
        if c.msrc_url.is_some() { jobs.extend(Arc::new(connectors::ninja_os::NinjaOs::new(ninja.clone())).jobs()); }
        if let Some(f) = &c.ninja_process_field { jobs.extend(Arc::new(connectors::ninja_processes::NinjaProcesses::new(ninja.clone(), f)).jobs()); }
    }
    if let Some(h) = &c.halo { jobs.extend(Arc::new(connectors::halo::Halo::new(h.settings(), http.clone())).jobs()); }
    jobs.extend(Arc::new(connectors::kev::Kev::new(&c.kev_url, http.clone())).jobs());
    if let Some(u) = &c.msrc_url { jobs.extend(Arc::new(connectors::msrc::Msrc::new(u, http.clone())).jobs()); }
    // The full NVD feeds, or (NVD_FEEDS=off) NVD's API per curated product.
    match &c.nvd_feed_url {
        Some(u) => jobs.extend(Arc::new(connectors::nvd_feed::NvdFeed::new(u, http.clone())).jobs()),
        None => jobs.extend(Arc::new(connectors::nvd::Nvd::new(&c.nvd_url, c.nvd_key.clone(), http.clone())).jobs()),
    }
    jobs.extend(inventory::jobs());
    jobs.extend(connectors::blackpoint::retention_jobs());
    if c.ninja.is_some() && c.ninja_process_field.is_some() { jobs.extend(process_match::jobs()); }
    if let Some(s) = store.sqlite() { jobs.extend(Arc::new(backup::Backup::new(s)).jobs()); }
    jobs
}

/// The jobs Blackpoint and Shodan add, when their settings are there. (NinjaOne's public addresses come from
/// the ninja_devices pass.)
pub fn exposure_jobs(cfg: &config::Config, http: reqwest::Client) -> Vec<scheduler::Job> {
    use std::sync::Arc;
    let mut jobs = Vec::new();
    if let Some(b) = &cfg.blackpoint { jobs.extend(Arc::new(connectors::blackpoint::Blackpoint::new(b, http.clone())).jobs()); }
    if let Some(s) = &cfg.shodan { jobs.extend(Arc::new(connectors::shodan::Shodan::new(s, http.clone())).jobs()); }
    jobs
}

/// What the Blackpoint, exposure and ticket writes need (src/ops/actions.rs).
pub fn actions(cfg: &config::Config, http: reqwest::Client) -> ops::actions::Actions {
    ops::actions::Actions {
        halo: cfg.connectors.halo.as_ref().map(|h| connectors::halo::Halo::new(h.settings(), http)),
        tickets: cfg.tickets, blackpoint: cfg.blackpoint.is_some(), shodan: cfg.shodan.is_some(),
        admins: cfg.shodan.as_ref().map(|s| s.admins.clone()).unwrap_or_default(),
        everyone_admin: matches!(cfg.auth, config::AuthConfig::DevInsecure),
    }
}

/// Whether this process runs in a container (Docker's or Podman's marker file).
pub fn in_container(exists: &dyn Fn(&str) -> bool) -> bool { exists("/.dockerenv") || exists("/run/.containerenv") }

pub const IN_CONTAINER_WARNING: &str = "AUTH_MODE=dev_insecure in a container: listening on every address so the container's port mapping reaches it. Anyone who can reach that port is signed in: publish it on 127.0.0.1 only (compose.yaml does)";

/// Where to listen. Everywhere, except with no sign-in (dev_insecure) outside a container: there, only this computer.
/// In a container, 127.0.0.1 would be the container's own loopback and nothing could reach it, so it stays on every
/// address, with a warning: the port mapping is what keeps it to one computer.
pub fn listen_on(dev_insecure: bool, in_container: bool) -> (std::net::IpAddr, Option<&'static str>) {
    use std::net::{IpAddr, Ipv4Addr};
    match (dev_insecure, in_container) {
        (true, false) => (IpAddr::V4(Ipv4Addr::LOCALHOST), None),
        (true, true) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(IN_CONTAINER_WARNING)),
        _ => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), None),
    }
}
