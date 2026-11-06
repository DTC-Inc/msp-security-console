//! No secret in any output: the real binary, run as an operator would. Unconfigured, it prints the token; the wizard's
//! API unlocks, tests every section against stand-in vendors (right and wrong secrets), and saves; the process exits;
//! it starts again configured, its secrets decrypted; then once more with the wrong master key, and refuses. Every
//! line it wrote to stdout and stderr, every answer it gave, and the config file are searched for every secret used,
//! the master key included. The run proves it happened by counting what it expects to find. A PostgreSQL URL's password
//! is one of them: always in a Test that can't connect, and, with TEST_DATABASE_URL, as the store the run saves and
//! restarts on (a role and database of its own, with a long made-up password).
mod common;
use common::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const OIDC_SECRET: &str = "oidc-secret-a71c9e02";
const SESSION_KEY: &str = "session-key-5f0b3d8e-of-at-least-thirty-two";
const WRONG_NINJA: &str = "wrong-ninja-secret-0c4f";
const WRONG_NVD: &str = "wrong-nvd-key-93b1";
const WRONG_MASTER: &str = "the-wrong-master-key-8d2a6c4e0f1b3d5a";
const DB_PASSWORD: &str = "db-password-in-the-logs-test-6a1f3e";
const WRONG_BLACKPOINT: &str = "wrong-blackpoint-token-77d1";
const WRONG_SHODAN: &str = "wrong-shodan-key-1f9c";

struct Run { child: Child, out: Arc<Mutex<String>> }

fn start(env: &[(&str, String)], out: Arc<Mutex<String>>) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_msp-console"));
    cmd.env_clear().stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env { cmd.env(k, v); }
    let mut child = cmd.spawn().expect("the server starts");
    for pipe in [Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>, Box::new(child.stderr.take().unwrap())] {
        let o = out.clone();
        std::thread::spawn(move || { for line in BufReader::new(pipe).lines().map_while(Result::ok) { let mut g = o.lock().unwrap(); g.push_str(&line); g.push('\n'); } });
    }
    Run { child, out }
}

async fn wait_for(out: &Arc<Mutex<String>>, needle: &str) -> String {
    let t0 = Instant::now();
    loop {
        if let Some(l) = out.lock().unwrap().lines().find(|l| l.contains(needle)) { return l.to_string(); }
        assert!(t0.elapsed() < Duration::from_secs(30), "no {needle:?} in: {}", out.lock().unwrap());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn wait_exit(c: &mut Child, secs: u64) -> std::process::ExitStatus {
    let t0 = Instant::now();
    loop {
        if let Some(s) = c.try_wait().unwrap() { return s; }
        if t0.elapsed() > Duration::from_secs(secs) { let _ = c.kill(); panic!("the server didn't exit"); }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn free_port() -> u16 { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() }

#[tokio::test]
async fn no_secret_reaches_the_logs_the_answers_or_the_file_in_the_clear() {
    let (v, hits_) = vendors().await;
    // With a PostgreSQL server to hand, the run's store is a database there; without, the SQLite file.
    let pg = pg_role_db(true).await;
    let dir = temp_dir("setup-logs");
    for d in ["config", "data", "web"] { std::fs::create_dir_all(dir.join(d)).unwrap(); }
    std::fs::write(dir.join("web/index.html"), "<!doctype html><title>wizard</title>").unwrap();
    let p = |x: &str| dir.join(x).to_str().unwrap().to_string();
    let port = free_port();
    let base_env = vec![("PORT", port.to_string()), ("CONFIG_PATH", p("config/config.json")), ("MASTER_KEY_PATH", p("key/master.key")),
                        ("STATIC_DIR", p("web")), ("MSP_ENV", "development".to_string())];
    let out = Arc::new(Mutex::new(String::new()));
    let http = msp_console::http_client();
    let url = |path: &str| format!("http://127.0.0.1:{port}{path}");
    let mut answers = String::new();

    // 1. Unconfigured: the token is in the log, once.
    let mut run = start(&base_env, out.clone());
    let line = wait_for(&run.out, "setup_token").await;
    let token = serde_json::from_str::<Value>(&line).unwrap()["setup_token"].as_str().unwrap().to_string();
    // The token is printed a moment before the port is bound: wait for the port, rather than race it.
    let t0 = Instant::now();
    let r = loop {
        match http.post(url("/api/setup/unlock")).json(&json!({ "token": token })).send().await {
            Ok(r) => break r,
            Err(e) if e.is_connect() && t0.elapsed() < Duration::from_secs(10) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => panic!("the setup API never answered: {e}"),
        }
    };
    assert_eq!(r.status(), 204);
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let call = |path: &'static str, body: Value| { let (h, c, u) = (http.clone(), cookie.clone(), url(path)); async move {
        let r = h.post(u).header("cookie", c).json(&body).send().await.unwrap();
        let st = r.status().as_u16();
        (st, r.text().await.unwrap())
    } };
    let ninja = json!({ "NINJA_BASE_URL": format!("{v}/ninja"), "NINJA_CLIENT_ID": "client-1", "NINJA_CLIENT_SECRET": NINJA_SECRET });
    let halo = json!({ "HALO_BASE_URL": format!("{v}/halo/api"), "HALO_CLIENT_ID": "client-2", "HALO_CLIENT_SECRET": HALO_SECRET, "HALO_TENANT": HALO_TENANT });
    let nvd = json!({ "NVD_URL": format!("{v}/nvd"), "NVD_API_KEY": NVD_KEY });
    let blackpoint = json!({ "BLACKPOINT_BASE_URL": format!("{v}/blackpoint"), "BLACKPOINT_API_TOKEN": BLACKPOINT_TOKEN });
    let shodan = json!({ "SHODAN_URL": format!("{v}/shodan"), "SHODAN_API_KEY": SHODAN_KEY });
    let mut wrong_bp = blackpoint.clone(); wrong_bp["BLACKPOINT_API_TOKEN"] = json!(WRONG_BLACKPOINT);
    let mut wrong_shodan = shodan.clone(); wrong_shodan["SHODAN_API_KEY"] = json!(WRONG_SHODAN);
    let oidc = json!({ "AUTH_MODE": "oidc", "OIDC_ISSUER": format!("{v}/idp/v2.0"), "OIDC_CLIENT_SECRET": OIDC_SECRET, "SESSION_KEY": SESSION_KEY });
    let mut wrong_ninja = ninja.clone(); wrong_ninja["NINJA_CLIENT_SECRET"] = json!(WRONG_NINJA);
    let mut wrong_nvd = nvd.clone(); wrong_nvd["NVD_API_KEY"] = json!(WRONG_NVD);
    let mut oks = 0;
    // The store the run saves: a PostgreSQL URL (a secret) or the SQLite file.
    let store = match &pg { Some(d) => json!({ "DATABASE_URL": d.url }), None => json!({ "DATABASE_PATH": p("data/console.db") }) };
    let unreachable = json!({ "DATABASE_URL": format!("postgres://console:{DB_PASSWORD}@127.0.0.1:1/console") });
    for (section, values, ok) in [("ninja", ninja.clone(), true), ("ninja", wrong_ninja, false), ("halo", halo.clone(), true), ("nvd", nvd.clone(), true),
                                  ("nvd", wrong_nvd, false), ("auth", oidc, true), ("database", store.clone(), true), ("database", unreachable, false),
                                  ("blackpoint", blackpoint.clone(), true), ("blackpoint", wrong_bp, false), ("shodan", shodan.clone(), true), ("shodan", wrong_shodan, false)] {
        let (st, body) = call("/api/setup/test", json!({ "section": section, "values": values })).await;
        assert_eq!(st, 200, "{section}: {body}");
        let j: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(j["ok"], json!(ok), "{section}: {body}");
        oks += usize::from(ok);
        answers.push_str(&body);
    }
    assert_eq!(oks, 7);
    let state = http.get(url("/api/setup/state")).header("cookie", &cookie).send().await.unwrap().text().await.unwrap();
    answers.push_str(&state);
    let mut values = json!({ "AUTH_MODE": "proxy", "PROXY_KIND": "trusted_header", "TRUSTED_HEADER": "X-Forwarded-Email",
        "TRUSTED_PROXY_CIDRS": "127.0.0.1/32", "OIDC_CLIENT_SECRET": OIDC_SECRET, "SESSION_KEY": SESSION_KEY });
    // Halo's ticket settings, as the wizard picks them from Halo's lists.
    for (k, x) in [("HALO_TICKET_TYPE_ID", "31"), ("HALO_TICKET_STATUS_ID", "1"), ("HALO_TICKET_PRIORITY_ID", "3")] { values[k] = json!(x); }
    for part in [&store, &ninja, &halo, &nvd, &blackpoint, &shodan] { for (k, x) in part.as_object().unwrap() { values[k] = x.clone(); } }
    let (st, body) = call("/api/setup/save", json!({ "values": values })).await;
    assert_eq!(st, 200, "{body}");
    answers.push_str(&body);
    assert!(wait_exit(&mut run.child, 10).success(), "it exits so its supervisor restarts it configured");
    let master = std::fs::read_to_string(dir.join("key/master.key")).unwrap().trim().to_string();
    let file = std::fs::read_to_string(dir.join("config/config.json")).unwrap();
    let encrypted = if pg.is_some() { 6 } else { 5 };
    assert_eq!(file.matches("enc:v1:").count(), encrypted, "the five connector secrets and a database URL, encrypted (sign-in's OIDC ones were for a mode not chosen): {file}");

    // 2. Configured: the secrets decrypt, and it serves.
    let mut env2 = base_env.clone();
    env2.push(("SCHEDULER", "off".into()));
    let mut run2 = start(&env2, out.clone());
    wait_for(&run2.out, "msp-security-console listening").await;
    let ready = http.get(url("/readyz")).send().await.unwrap().status();
    assert_eq!(ready, 200);
    let status = http.get(url("/api/status")).header("x-forwarded-email", "tech@example.com").send().await.unwrap().text().await.unwrap();
    assert!(status.contains("jobs"), "{status}");
    answers.push_str(&status);
    let listening = wait_for(&run2.out, "msp-security-console listening").await;
    let l: Value = serde_json::from_str(&listening).unwrap();
    assert_eq!(l["connectors"], json!({ "ninjaone": true, "halopsa": true, "nvd_key": true, "blackpoint": true, "shodan": true, "halo_tickets": true }), "every connector on, from the decrypted file");
    assert_eq!(l["store"]["kind"], json!(if pg.is_some() { "postgresql" } else { "sqlite" }), "on the store it saved: {l}");
    assert!(status.contains(if pg.is_some() { "postgresql" } else { "sqlite" }), "{status}");
    let _ = run2.child.kill();
    let _ = run2.child.wait();

    // 3. The wrong master key: it refuses, naming a setting.
    let mut env3 = env2.clone();
    env3.push(("CONSOLE_MASTER_KEY", WRONG_MASTER.into()));
    let mut run3 = start(&env3, out.clone());
    let code = wait_exit(&mut run3.child, 10).code();
    assert_eq!(code, Some(2));
    let refusal = wait_for(&run3.out, "refuses to start").await;
    // It names the first encrypted setting it meets, in name order: Blackpoint's token, before the database URL.
    assert!(refusal.contains("BLACKPOINT_API_TOKEN") && refusal.contains("can't be decrypted"), "{refusal}");

    // Everything it said, and everything it answered, holds no secret. And it said what it should have.
    let all = format!("{}\n{answers}", out.lock().unwrap());
    let audit_lines = all.lines().filter(|l| l.contains("\"audit\":\"msp-console\"") && l.contains("\"who\":\"setup\"")).count();
    assert_eq!(audit_lines, 1 + 12 + 1 + 1, "unlock, twelve tests, state, save: {all}");
    assert!(all.contains("generated the master key") && all.contains("settings saved"), "{all}");
    assert!(hits(&hits_, "ninja_token") >= 2 && hits(&hits_, "halo_clients") >= 1 && hits(&hits_, "nvd") >= 2 && hits(&hits_, "discovery") >= 1);
    assert!(hits(&hits_, "blackpoint_tenants") >= 2 && hits(&hits_, "shodan_info") >= 2 && hits(&hits_, "halo_lists") >= 3, "Blackpoint, Shodan and Halo's lists were asked");
    assert!(answers.contains("Security Alert") && answers.contains("95 scan credits"), "the Halo lists and Shodan's credits came back: {answers}");
    let mut secrets = vec![NINJA_SECRET, HALO_SECRET, NVD_KEY, OIDC_SECRET, SESSION_KEY, WRONG_NINJA, WRONG_NVD, WRONG_MASTER, DB_PASSWORD, master.as_str(),
                       BLACKPOINT_TOKEN, SHODAN_KEY, WRONG_BLACKPOINT, WRONG_SHODAN];
    if let Some(d) = &pg { secrets.push(d.password.as_str()); }
    for s in &secrets { assert!(s.len() >= 16, "{s} is long enough to find"); }
    // The token is printed once, by design: its one line is the exception.
    let token_lines = all.lines().filter(|l| l.contains(&token)).collect::<Vec<_>>();
    assert_eq!(token_lines.len(), 1, "the token, once: {token_lines:?}");
    for s in &secrets {
        let found: Vec<&str> = all.lines().filter(|l| l.contains(s)).collect();
        assert!(found.is_empty(), "{s} appeared in: {found:?}");
        assert!(!file.contains(s), "{s} in the config file");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
