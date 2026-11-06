//! The config file's secrets at rest: encrypted under the master key, each bound to its setting; decrypted at start-up;
//! a wrong or missing key refuses to start, naming the setting and never the value; plaintext from before still loads,
//! with a warning.
use msp_console::config::{load, AuthConfig, Startup};
use msp_console::secrets::{self, KeySource};
use std::collections::HashMap;
use std::path::Path;

const KEY_A: &str = "a-master-key-for-tests-only-0123456789abcdef";
const KEY_B: &str = "another-master-key-for-tests-0123456789abcdef";
const OIDC_SECRET: &str = "oidc-client-secret-9e1f4b";
const SESSION: &str = "a-session-key-of-at-least-thirty-two-characters";

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> { pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
fn key(k: &str) -> secrets::ConfigKey { secrets::find(&env(&[("CONSOLE_MASTER_KEY", k)]), &|_| Err(std::io::ErrorKind::NotFound.into())).unwrap().unwrap() }
fn only(path: &'static str, text: String) -> impl Fn(&Path) -> std::io::Result<String> {
    move |p: &Path| if p == Path::new(path) { Ok(text.clone()) } else { Err(std::io::ErrorKind::NotFound.into()) }
}
const CFG: &str = "/var/lib/msp-console/config.json";

fn oidc_file(secret: &str, session: &str) -> String {
    serde_json::json!({ "AUTH_MODE": "oidc", "OIDC_ISSUER": "https://login.example.com/t/v2.0", "OIDC_CLIENT_ID": "client-1", "OIDC_ALLOWED_GROUP": "group-1",
        "PUBLIC_URL": "https://console.example.com", "OIDC_CLIENT_SECRET": secret, "SESSION_KEY": session }).to_string()
}

#[test]
fn which_settings_are_secrets() {
    for k in ["OIDC_CLIENT_SECRET", "NINJA_CLIENT_SECRET", "HALO_CLIENT_SECRET", "SESSION_KEY", "NVD_API_KEY", "DATABASE_URL"] { assert!(secrets::is_secret(k), "{k}"); }
    for k in ["NINJA_CLIENT_SECRET_FILE", "NINJA_CLIENT_ID", "NVD_URL", "PUBLIC_URL", "SESSION_KEY_FILE", "DATABASE_URL_FILE", "DATABASE_PATH"] { assert!(!secrets::is_secret(k), "{k}"); }
}

#[test]
fn a_value_round_trips_and_is_bound_to_its_setting() {
    let k = key(KEY_A);
    let enc = k.encrypt("OIDC_CLIENT_SECRET", OIDC_SECRET);
    assert!(enc.starts_with("enc:v1:") && !enc.contains(OIDC_SECRET), "{enc}");
    assert_ne!(enc, k.encrypt("OIDC_CLIENT_SECRET", OIDC_SECRET), "a fresh nonce each time");
    assert_eq!(k.decrypt("OIDC_CLIENT_SECRET", &enc).unwrap(), OIDC_SECRET);
    // Moved to another setting, under another key, or damaged: refused, naming the setting and not the value.
    for (name, under, value) in [("SESSION_KEY", key(KEY_A), enc.clone()), ("OIDC_CLIENT_SECRET", key(KEY_B), enc.clone()),
                                 ("OIDC_CLIENT_SECRET", key(KEY_A), format!("{}{}", &enc[..enc.len() - 1], if enc.ends_with('A') { 'B' } else { 'A' }))] {
        let e = under.decrypt(name, &value).unwrap_err();
        assert!(e.contains(name) && !e.contains(OIDC_SECRET) && !e.contains(&value), "{e}");
    }
}

#[test]
fn the_master_key_is_32_bytes_or_more_raw_or_base64() {
    assert_eq!(secrets::parse_key("K", &"x".repeat(32)).unwrap().len(), 32);
    assert_eq!(secrets::parse_key("K", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap(), (0u8..32).collect::<Vec<_>>(), "base64 decodes");
    let e = secrets::parse_key("CONSOLE_MASTER_KEY", "too-short").unwrap_err();
    assert!(e.contains("CONSOLE_MASTER_KEY") && e.contains("32") && !e.contains("too-short"), "{e}");
    // The file wins over the variable, as for every other secret; a file that's missing is named.
    let read = |p: &Path| if p == Path::new("/run/key") { Ok(format!("{KEY_B}\n")) } else { Err(std::io::ErrorKind::NotFound.into()) };
    let k = secrets::find(&env(&[("CONSOLE_MASTER_KEY", KEY_A), ("CONSOLE_MASTER_KEY_FILE", "/run/key")]), &read).unwrap().unwrap();
    assert_eq!(k.source, KeySource::EnvFile("/run/key".into()));
    assert!(key(KEY_B).decrypt("X", &k.encrypt("X", "v")).is_ok(), "the file's key, not the variable's");
    assert!(secrets::find(&env(&[("CONSOLE_MASTER_KEY_FILE", "/nope")]), &read).unwrap_err().contains("CONSOLE_MASTER_KEY_FILE"));
    assert!(secrets::find(&env(&[]), &read).unwrap().is_none(), "none set, and no generated key: none");
}

#[test]
fn a_generated_key_is_0600_and_never_replaced() {
    let dir = std::env::temp_dir().join(format!("msp-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("sub").join("master.key");
    let k = secrets::generate(&path).unwrap();
    assert_eq!(k.source, KeySource::Generated(path.clone()));
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600); }
    let enc = k.encrypt("SESSION_KEY", SESSION);
    let found = secrets::find(&env(&[("MASTER_KEY_PATH", path.to_str().unwrap())]), &|p| std::fs::read_to_string(p)).unwrap().unwrap();
    assert_eq!(found.decrypt("SESSION_KEY", &enc).unwrap(), SESSION, "found again at MASTER_KEY_PATH");
    let before = std::fs::read(&path).unwrap();
    assert!(secrets::generate(&path).unwrap_err().contains("already exists"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn start_up_decrypts_the_files_secrets() {
    let k = key(KEY_A);
    let file = oidc_file(&k.encrypt("OIDC_CLIENT_SECRET", OIDC_SECRET), &k.encrypt("SESSION_KEY", SESSION));
    let Startup::Configured(c) = load(&env(&[("CONSOLE_MASTER_KEY", KEY_A)]), &only(CFG, file)).unwrap() else { panic!("unconfigured") };
    assert!(matches!(c.auth, AuthConfig::Oidc { ref client_secret, ref session_key, .. } if client_secret == OIDC_SECRET && session_key == SESSION));
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
}

#[test]
fn the_wrong_key_or_none_refuses_to_start_naming_the_setting() {
    let k = key(KEY_A);
    let enc_secret = k.encrypt("OIDC_CLIENT_SECRET", OIDC_SECRET);
    let file = oidc_file(&enc_secret, SESSION);
    let e = load(&env(&[("CONSOLE_MASTER_KEY", KEY_B)]), &only(CFG, file.clone())).unwrap_err();
    assert!(e.contains("OIDC_CLIENT_SECRET") && e.contains("can't be decrypted"), "{e}");
    assert!(!e.contains(OIDC_SECRET) && !e.contains(&enc_secret) && !e.contains(KEY_B) && !e.contains(KEY_A), "{e}");
    let e = load(&env(&[]), &only(CFG, file)).unwrap_err();
    assert!(e.contains("OIDC_CLIENT_SECRET") && e.contains("no master key") && e.contains("CONSOLE_MASTER_KEY"), "{e}");
}

#[test]
fn a_plaintext_secret_from_before_still_loads_with_a_warning() {
    let Startup::Configured(c) = load(&env(&[]), &only(CFG, oidc_file(OIDC_SECRET, SESSION))).unwrap() else { panic!("unconfigured") };
    assert!(matches!(c.auth, AuthConfig::Oidc { ref client_secret, .. } if client_secret == OIDC_SECRET), "no master key needed for plaintext");
    assert_eq!(c.warnings.len(), 2, "{:?}", c.warnings);
    assert!(c.warnings.iter().any(|w| w.contains("OIDC_CLIENT_SECRET")) && c.warnings.iter().any(|w| w.contains("SESSION_KEY")));
    for w in &c.warnings { assert!(!w.contains(OIDC_SECRET) && !w.contains(SESSION), "{w}"); }
}
