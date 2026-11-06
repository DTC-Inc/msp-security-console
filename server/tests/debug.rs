//! No secret in a Debug form (what a panic, an error or a log line shows): every configuration type that holds one,
//! formatted with {:?} and {:#?}, names its fields and never its secrets.
use msp_console::config::{load, AuthConfig, Startup};
use msp_console::oidc::OidcSettings;
use std::collections::HashMap;

const SECRETS: &[&str] = &["oidc-client-secret-for-debug", "session-key-for-debug-at-least-32-chars", "ninja-secret-for-debug", "halo-secret-for-debug",
                           "nvd-key-for-debug", "a-master-key-for-debug-tests-only-0123456789", "database-password-for-debug", "db.debug.example.com"];

fn clean(what: &str, s: &str) -> usize {
    for x in SECRETS { assert!(!s.contains(x), "{what}: {x} in {s}"); }
    s.len()
}

#[test]
fn no_configuration_type_shows_a_secret_in_its_debug_form() {
    let env: HashMap<String, String> = [("AUTH_MODE", "oidc"), ("OIDC_ISSUER", "https://login.example.com/t/v2.0"), ("OIDC_CLIENT_ID", "client-1"),
        ("OIDC_CLIENT_SECRET", SECRETS[0]), ("OIDC_ALLOWED_GROUP", "group-1"), ("SESSION_KEY", SECRETS[1]), ("PUBLIC_URL", "https://console.example.com"),
        ("NINJA_BASE_URL", "https://ninja.example.com"), ("NINJA_CLIENT_ID", "n"), ("NINJA_CLIENT_SECRET", SECRETS[2]),
        ("HALO_BASE_URL", "https://psa.example.com/api"), ("HALO_CLIENT_ID", "h"), ("HALO_CLIENT_SECRET", SECRETS[3]), ("NVD_API_KEY", SECRETS[4]),
        ("DATABASE_URL", "postgres://console:database-password-for-debug@db.debug.example.com/console?sslmode=require"),
        ("CONFIG_PATH", "/nonexistent/config.json")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let st = load(&env, &|_| Err(std::io::ErrorKind::NotFound.into())).unwrap();
    let Startup::Configured(cfg) = &st else { panic!("unconfigured") };
    assert!(matches!(&cfg.auth, AuthConfig::Oidc { client_secret, .. } if client_secret == SECRETS[0]), "the secrets are really in there");
    let oidc = OidcSettings { issuer: "https://login.example.com/t/v2.0".into(), client_id: "client-1".into(), client_secret: SECRETS[0].into(),
        allowed_group: "group-1".into(), session_key: SECRETS[1].into(), public_url: "https://console.example.com".into() };
    let key = msp_console::secrets::find(&[("CONSOLE_MASTER_KEY".to_string(), SECRETS[5].to_string())].into(), &|_| Err(std::io::ErrorKind::NotFound.into())).unwrap().unwrap();
    let ninja = cfg.connectors.ninja.clone().unwrap();
    let forms: Vec<(&str, String)> = vec![
        ("Startup", format!("{st:?}")), ("Startup pretty", format!("{st:#?}")), ("Config", format!("{cfg:?}")), ("AuthConfig", format!("{:?}", cfg.auth)),
        ("Connectors", format!("{:?}", cfg.connectors)), ("NinjaCfg", format!("{ninja:?}")), ("HaloCfg", format!("{:?}", cfg.connectors.halo)),
        ("OidcSettings", format!("{oidc:?}")), ("OidcSettings pretty", format!("{oidc:#?}")), ("ConfigKey", format!("{key:?}")),
        ("Ninja", format!("{:?}", msp_console::connectors::ninja::Ninja::new("https://ninja.example.com", "n", SECRETS[2], msp_console::http_client()))),
        ("Halo", format!("{:?}", msp_console::connectors::halo::Halo::new(cfg.connectors.halo.as_ref().unwrap().settings(), msp_console::http_client()))),
        ("Nvd", format!("{:?}", msp_console::connectors::nvd::Nvd::new("https://nvd.example.com", Some(SECRETS[4].into()), msp_console::http_client()))),
        ("DbConfig", format!("{:?}", cfg.db)), ("DbConfig pretty", format!("{:#?}", cfg.db)),
    ];
    for (what, s) in &forms { assert!(clean(what, s) > 10, "{what} formatted to nothing: {s}"); }
    // And they still say what they are.
    assert!(forms[3].1.contains("issuer") && forms[3].1.contains("client_secret") && forms[3].1.contains("[redacted]"), "{}", forms[3].1);
    assert!(forms[13].1.contains("PgConfig") && forms[13].1.contains("[redacted]") && forms[13].1.contains("require"), "{}", forms[13].1);
    assert_eq!(forms.len(), 15);
}
