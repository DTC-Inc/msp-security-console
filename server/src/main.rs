//! The process: configuration (failing closed), then either the first-run setup or the console.
use msp_console::{admin, app, audit, config, db, embed, embed_job, http_client, identity, in_container, jobs, listen_on, ops::Store, scheduler::Scheduler, setup};
use std::net::SocketAddr;
use std::sync::Arc;

fn log(v: serde_json::Value) { println!("{v}"); }

#[tokio::main]
async fn main() {
    let env: std::collections::HashMap<String, String> = std::env::vars().collect();
    let startup = match config::load(&env, &|p| std::fs::read_to_string(p)) {
        Ok(s) => s,
        Err(e) => { log(serde_json::json!({ "msg": "msp-security-console refuses to start", "why": e })); std::process::exit(2); }
    };
    let http = http_client();
    let (router, port, dev_insecure) = match startup {
        config::Startup::Unconfigured { config_path, port } => {
            let s = Arc::new(setup::Setup::new(env, http, Arc::new(|| {
                tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_millis(800)).await; std::process::exit(0); });
            })));
            // The token is printed once, here, and never again.
            log(serde_json::json!({ "msg": "unconfigured: open /setup and enter this one-time token, or configure by environment", "setup_token": s.token, "config_path": config_path }));
            (setup::router(s), port, false)
        }
        config::Startup::Configured(cfg) => {
            for w in &cfg.warnings { log(serde_json::json!({ "msg": "warning", "why": w })); }
            // Its own database first: migrated, or the console doesn't start.
            let pool = match db::connect(&cfg.db).await {
                Ok(p) => p,
                Err(e) => { log(serde_json::json!({ "msg": "msp-security-console refuses to start", "why": e })); std::process::exit(2); }
            };
            // What the store can do, said once: on PostgreSQL without pgvector, similar-CVE search is off, and backups
            // are the operator's.
            let store = db::describe(&pool).await;
            if store["vectors"]["on"] == serde_json::json!(false) { log(serde_json::json!({ "msg": "warning", "why": store["vectors"]["why"] })); }
            // The embedder: on, or off with a reason (EMBEDDER=off, a store without vectors, a model that won't load).
            // Off never stops the console; it's said here and on /api/status.
            let similar = embed::start(&cfg.embedder, &pool).await;
            match &similar {
                embed::State::On(e) => log(serde_json::json!({ "msg": "embedder loaded", "model": embed::MODEL_KEY, "threads": e.threads })),
                // A store without vectors was said just above, in the same words.
                embed::State::Off(why) if cfg.embedder.on && store["vectors"]["on"] != serde_json::json!(false) => log(serde_json::json!({ "msg": "warning", "why": why })),
                embed::State::Off(_) => {}
            }
            let (id, auth_routes) = identity::from_config(&cfg, http.clone());
            if matches!(cfg.auth, config::AuthConfig::TrustedHeader { .. }) {
                log(serde_json::json!({ "msg": "trusted_header: identities are believed from TRUSTED_PROXY_CIDRS only; make sure nothing else can reach this port" }));
            }
            let mut job_list = jobs(&cfg.connectors, &cfg.db, http.clone());
            job_list.extend(msp_console::exposure_jobs(&cfg, http.clone()));
            if let embed::State::On(e) = &similar { job_list.extend(embed_job::EmbedJob::new(e.clone()).jobs()); }
            let dev = matches!(cfg.auth, config::AuthConfig::DevInsecure);
            let (addr, warning) = listen_on(dev, in_container(&|p| std::path::Path::new(p).exists()));
            if let Some(w) = warning { log(serde_json::json!({ "msg": "warning", "why": w })); }
            log(serde_json::json!({ "msg": "msp-security-console listening", "address": addr, "port": cfg.port, "auth": id.mode(), "web": cfg.static_dir.is_some(), "store": store, "embedder": similar.describe(),
                "connectors": { "ninjaone": cfg.connectors.ninja.is_some(), "halopsa": cfg.connectors.halo.is_some(), "nvd_key": cfg.connectors.nvd_key.is_some(),
                    "blackpoint": cfg.blackpoint.is_some(), "shodan": cfg.shodan.is_some(), "halo_tickets": cfg.tickets.is_some() },
                "jobs": if cfg.scheduler { job_list.iter().map(|j| j.name).collect::<Vec<_>>() } else { vec![] } }));
            if cfg.scheduler { tokio::spawn(Scheduler::new(pool.clone(), job_list).run_forever()); }
            if cfg.admins == config::Admins::None {
                log(serde_json::json!({ "msg": "warning", "why": "no admins: set OIDC_ADMIN_GROUP (oidc) or ADMIN_EMAILS (behind a proxy) for someone to change the connectors and advisories" }));
            }
            // Settings → Connectors and the advisories, admins only. A saved change restarts the console with it, as setup does.
            let admin = admin::Admin::new(id.clone(), env.clone(), http.clone(), pool.clone(), Arc::new(|| {
                tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_millis(800)).await; std::process::exit(0); });
            }));
            let state = app::AppState { identity: id, store: Store { pool, similar, nvd_job: Store::nvd_job_for(cfg.connectors.nvd_feed_url.is_some()) }, audit: audit::stdout_sink() };
            let actions = msp_console::ops::actions::routes(Arc::new(msp_console::actions(&cfg, http.clone())));
            let r = app::router_with(state, cfg.static_dir.clone(), actions).merge(admin::router(Arc::new(admin)));
            (match auth_routes { Some(a) => r.merge(a), None => r }, cfg.port, dev)
        }
    };
    let (addr, _) = listen_on(dev_insecure, in_container(&|p| std::path::Path::new(p).exists()));
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(addr, port)).await.expect("the port");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown())
        .await.expect("the server");
}

/// Ctrl-C, or SIGTERM (what Kubernetes and compose send to stop a container).
async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    { let _ = tokio::signal::ctrl_c().await; }
}

