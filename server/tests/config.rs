//! Configuration: the environment, a file on a volume, the environment winning; unconfigured means setup; anything
//! short of a complete configuration refuses to start.
use msp_console::config::{load, AuthConfig, Startup};
use msp_console::db::DbConfig;
use std::collections::HashMap;
use std::path::Path;

fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> { pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
const CF: &[(&str, &str)] = &[("AUTH_MODE", "proxy"),
  ("PROXY_KIND", "cloudflare_access"), ("ACCESS_TEAM_DOMAIN", "example.cloudflareaccess.com"), ("ACCESS_AUD", "aud")];
fn files(file: Option<&'static str>) -> impl Fn(&Path) -> std::io::Result<String> {
    move |p: &Path| match p.to_str().unwrap() {
        "/var/lib/msp-console/config.json" => file.map(String::from).ok_or_else(|| std::io::ErrorKind::NotFound.into()),
        _ => Err(std::io::ErrorKind::NotFound.into()),
    }
}
fn cfg(s: Startup) -> msp_console::config::Config { match s { Startup::Configured(c) => c, _ => panic!("unconfigured") } }

#[test]
fn cloudflare_access_from_the_environment() {
    let c = cfg(load(&env(CF), &files(None)).unwrap());
    let db = c.db.sqlite().expect("SQLite, by default");
    assert_eq!((db.path.to_str().unwrap(), db.backup_keep), ("/data/console.db", 7), "the store's defaults: no database setting needed");
    assert_eq!(c.auth, AuthConfig::CloudflareAccess { team_domain: "example.cloudflareaccess.com".into(), aud: "aud".into(), certs_url: "https://example.cloudflareaccess.com/cdn-cgi/access/certs".into() });
}

#[test]
fn nothing_set_is_unconfigured_and_serves_setup() {
    assert!(matches!(load(&env(&[("PORT", "8080")]), &files(None)).unwrap(), Startup::Unconfigured { .. }));
}

#[test]
fn environment_without_a_sign_in_opens_setup_with_those_settings_locked() {
    // A connector or the database path from the environment, but no sign-in chosen and nothing saved: the guided setup
    // is served, and shows those settings as set by environment.
    let partial = env(&[("NINJA_BASE_URL", "https://ninja.example.com"), ("NINJA_CLIENT_ID", "id"), ("NINJA_CLIENT_SECRET", "s"), ("DATABASE_PATH", "/data/x.db")]);
    assert!(matches!(load(&partial, &files(None)).unwrap(), Startup::Unconfigured { .. }));
    // Once the environment chooses a sign-in, anything missing refuses to start (fail closed), as before.
    let half = env(&[("AUTH_MODE", "oidc")]);
    assert!(load(&half, &files(None)).is_err(), "a half-chosen sign-in must refuse, not open setup");
    // And a saved file with a gap refuses too: setup is for a console that has never been configured.
    assert!(load(&env(&[]), &files(Some(r#"{"DATABASE_PATH":"/data/x.db"}"#))).is_err());
}

#[test]
fn the_file_configures_it_and_the_environment_wins() {
    let file = r#"{"DATABASE_PATH":"/file/console.db","AUTH_MODE":"proxy","PROXY_KIND":"cloudflare_access","ACCESS_TEAM_DOMAIN":"file.cloudflareaccess.com","ACCESS_AUD":"file-aud","SETUP_TOKEN":"ignored"}"#;
    let c = cfg(load(&env(&[]), &files(Some(file))).unwrap());
    assert_eq!(c.db.sqlite().unwrap().path.to_str(), Some("/file/console.db"));
    let c = cfg(load(&env(&[("ACCESS_AUD", "env-aud"), ("DATABASE_PATH", "/env/console.db")]), &files(Some(file))).unwrap());
    assert!(matches!(c.auth, AuthConfig::CloudflareAccess { ref aud, ref team_domain, .. } if aud == "env-aud" && team_domain == "file.cloudflareaccess.com"));
    assert_eq!(c.db.sqlite().unwrap().path.to_str(), Some("/env/console.db"));
}

#[test]
fn half_a_configuration_refuses_to_start() {
    for (drop, why) in [("ACCESS_AUD", "ACCESS_AUD"), ("AUTH_MODE", "AUTH_MODE"), ("PROXY_KIND", "PROXY_KIND")] {
        let e = env(&CF.iter().filter(|(k, _)| *k != drop).cloned().collect::<Vec<_>>());
        let err = load(&e, &files(None)).unwrap_err();
        assert!(err.contains(why), "{drop}: {err}");
    }
    let e = load(&env(&[("NVD_API_KEY_FILE", "/nope"), ("AUTH_MODE", "dev_insecure")]), &files(None)).unwrap_err();
    assert!(e.contains("NVD_API_KEY_FILE") && e.contains("can't be read"), "{e}");
    assert!(load(&env(&[("AUTH_MODE", "magic")]), &files(None)).is_err());
    assert!(load(&env(&[("PORT", "8080"), ("AUTH_MODE", "proxy")]), &files(Some("not json"))).unwrap_err().contains("JSON"));
}

#[test]
fn trusted_header_needs_the_proxy_addresses_and_never_the_whole_internet() {
    let base = [("AUTH_MODE", "proxy"), ("PROXY_KIND", "trusted_header"), ("TRUSTED_HEADER", "X-Forwarded-Email")];
    assert!(load(&env(&base), &files(None)).unwrap_err().contains("TRUSTED_PROXY_CIDRS"));
    let mut e = env(&base);
    e.insert("TRUSTED_PROXY_CIDRS".into(), "0.0.0.0/0".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("whole internet"));
    e.insert("TRUSTED_PROXY_CIDRS".into(), "10.0.5.0/24, 10.0.9.4/32".into());
    assert!(matches!(cfg(load(&e, &files(None)).unwrap()).auth, AuthConfig::TrustedHeader { ref header, ref cidrs } if header == "x-forwarded-email" && cidrs.len() == 2));
    e.insert("TRUSTED_PROXY_CIDRS".into(), "ten.zero".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("isn't a CIDR"));
}

#[test]
fn oidc_needs_its_settings_and_a_real_session_key() {
    let base = [("AUTH_MODE", "oidc"), ("OIDC_ISSUER", "https://login.microsoftonline.com/t/v2.0"),
        ("OIDC_CLIENT_ID", "c"), ("OIDC_CLIENT_SECRET", "s"), ("OIDC_ALLOWED_GROUP", "g"), ("PUBLIC_URL", "https://security.example.com")];
    assert!(load(&env(&base), &files(None)).unwrap_err().contains("SESSION_KEY"));
    let mut e = env(&base);
    e.insert("SESSION_KEY".into(), "short".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("32"));
    e.insert("SESSION_KEY".into(), "x".repeat(40));
    assert!(matches!(cfg(load(&e, &files(None)).unwrap()).auth, AuthConfig::Oidc { .. }));
    e.insert("PUBLIC_URL".into(), "http://security.example.com".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("PUBLIC_URL"));
    e.insert("PUBLIC_URL".into(), "https://security.example.com".into());
    e.insert("OIDC_ISSUER".into(), "http://insecure".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("https"));
}

#[test]
fn dev_insecure_only_off_cluster_and_outside_production() {
    let base = [("AUTH_MODE", "dev_insecure")];
    assert_eq!(cfg(load(&env(&base), &files(None)).unwrap()).auth, AuthConfig::DevInsecure);
    let mut e = env(&base);
    e.insert("KUBERNETES_SERVICE_HOST".into(), "10.0.0.1".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("Kubernetes"));
    let mut e = env(&base);
    e.insert("MSP_ENV".into(), "production".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("production"));
}

const DEV: &[(&str, &str)] = &[("AUTH_MODE", "dev_insecure")];

#[test]
fn every_secret_can_come_from_a_file_and_the_file_wins() {
    let read = |p: &Path| match p.to_str().unwrap() {
        "/run/ninja" => Ok("ninja-secret-from-file".to_string()), "/run/halo" => Ok("halo-secret-from-file".into()),
        "/run/nvd" => Ok("nvd-key-from-file".into()), _ => Err(std::io::ErrorKind::NotFound.into()) };
    let c = cfg(load(&env(&[("AUTH_MODE", "dev_insecure"),
        ("NINJA_BASE_URL", "https://app.ninjarmm.com"), ("NINJA_CLIENT_ID", "id"), ("NINJA_CLIENT_SECRET_FILE", "/run/ninja"),
        ("HALO_BASE_URL", "https://psa.example.com/api"), ("HALO_CLIENT_ID", "hid"), ("HALO_CLIENT_SECRET_FILE", "/run/halo"), ("NVD_API_KEY_FILE", "/run/nvd")]), &read).unwrap());
    assert_eq!(c.connectors.ninja.as_ref().unwrap().client_secret, "ninja-secret-from-file");
    assert_eq!(c.connectors.halo.as_ref().unwrap().client_secret, "halo-secret-from-file");
    assert_eq!(c.connectors.nvd_key.as_deref(), Some("nvd-key-from-file"));
    // No secret in the config's debug form (what a panic or a log line would show).
    let dbg = format!("{c:?}");
    for s in ["ninja-secret", "halo-secret", "nvd-key"] { assert!(!dbg.contains(s), "{s} in {dbg}"); }
}

#[test]
fn a_connector_is_on_whole_off_whole_or_a_refusal() {
    let c = cfg(load(&env(DEV), &files(None)).unwrap());
    assert!(c.connectors.ninja.is_none() && c.connectors.halo.is_none(), "no vendor settings: those connectors are off");
    assert!(c.connectors.kev_url.starts_with("https://www.cisa.gov/") && c.connectors.nvd_url.starts_with("https://services.nvd.nist.gov/"), "the public feeds are on");
    let mut e = env(DEV); e.insert("NINJA_CLIENT_ID".into(), "id".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("NINJA_BASE_URL"));
    let mut e = env(DEV); for (k, v) in [("HALO_BASE_URL", "https://psa.example.com/api"), ("HALO_CLIENT_ID", "id"), ("HALO_CLIENT_SECRET", "s")] { e.insert(k.into(), v.into()); }
    let h = cfg(load(&e, &files(None)).unwrap()).connectors.halo.unwrap();
    assert_eq!((h.per_5min, h.detail_budget), (150, 150), "Halo takes 150 of the tenant's 700 per 5 minutes by default");
    e.insert("HALO_REQUESTS_PER_5MIN".into(), "900".into());
    assert!(load(&e, &files(None)).unwrap_err().contains("HALO_REQUESTS_PER_5MIN"));
}

#[test]
fn the_store_is_a_file_on_the_volume_and_keeps_a_weeks_backups() {
    let c = cfg(load(&env(DEV), &files(None)).unwrap());
    let db = c.db.sqlite().unwrap();
    assert_eq!((db.path.to_str().unwrap(), db.backup_dir().to_str().unwrap(), db.backup_keep), ("/data/console.db", "/data/backup", 7));
    let mut e = env(DEV);
    for (k, v) in [("DATABASE_PATH", "/srv/console/store.db"), ("BACKUP_KEEP", "30")] { e.insert(k.into(), v.into()); }
    let c = cfg(load(&e, &files(None)).unwrap());
    let db = c.db.sqlite().unwrap();
    assert_eq!((db.path.to_str().unwrap(), db.backup_dir().to_str().unwrap(), db.backup_keep), ("/srv/console/store.db", "/srv/console/backup", 30));
    for bad in ["0", "366", "a week"] { e.insert("BACKUP_KEEP".into(), bad.into()); assert!(load(&e, &files(None)).unwrap_err().contains("BACKUP_KEEP"), "{bad}"); }
    // A store that dies with the process isn't one.
    for p in [":memory:", "file::memory:?cache=shared"] {
        let e = env(&[("AUTH_MODE", "dev_insecure"), ("DATABASE_PATH", p)]);
        assert!(load(&e, &files(None)).unwrap_err().contains("must be a file's path"), "{p}");
    }
}

// A made-up database password, long enough to find anywhere it shouldn't be.
const PG_PASSWORD: &str = "pg-password-for-config-tests-71c2";
fn pg_url(query: &str) -> String { format!("postgres://console:{PG_PASSWORD}@db.example.com:5432/console{query}") }
fn refusal(pairs: &[(&str, &str)]) -> String {
    let mut e = env(DEV);
    for (k, v) in pairs { e.insert(k.to_string(), v.to_string()); }
    let why = load(&e, &files(None)).unwrap_err();
    assert!(!why.contains(PG_PASSWORD) && !why.contains("db.example.com") && !why.contains("console:"), "the refusal shows the URL: {why}");
    why
}

#[test]
fn database_url_picks_postgresql_and_is_never_shown() {
    let url = pg_url("?sslmode=verify-full");
    let mut e = env(DEV);
    e.insert("DATABASE_URL".into(), url.clone());
    let c = cfg(load(&e, &files(None)).unwrap());
    let DbConfig::Postgres(pg) = &c.db else { panic!("{:?}", c.db) };
    assert_eq!(pg.sslmode(), "verify-full");
    assert_eq!(c.db.kind(), msp_console::db::Kind::Postgresql);
    for s in [format!("{c:?}"), format!("{c:#?}"), format!("{pg:?}")] { assert!(!s.contains(PG_PASSWORD) && !s.contains("db.example.com") && s.contains("[redacted]"), "{s}"); }
    // From a mounted Secret, as DATABASE_URL_FILE, too.
    let mut e = env(DEV);
    e.insert("DATABASE_URL_FILE".into(), "/run/secrets/database-url".into());
    let read = move |p: &Path| if p == Path::new("/run/secrets/database-url") { Ok(format!("{url}\n")) } else { Err(std::io::ErrorKind::NotFound.into()) };
    assert!(matches!(cfg(load(&e, &read).unwrap()).db, DbConfig::Postgres(_)));
    // postgresql:// is the same thing.
    let c = cfg(load(&env(&[("AUTH_MODE", "dev_insecure"), ("DATABASE_URL", "postgresql://u:p@localhost/db")]), &files(None)).unwrap());
    assert_eq!(c.db.kind(), msp_console::db::Kind::Postgresql);
}

#[test]
fn both_stores_at_once_or_a_url_that_isnt_postgresql_refuses_to_start() {
    let both = refusal(&[("DATABASE_URL", &pg_url("")), ("DATABASE_PATH", "/data/console.db")]);
    assert!(both.contains("DATABASE_URL and DATABASE_PATH are both set") && both.contains("not both"), "{both}");
    let e = refusal(&[("DATABASE_URL", "sqlite:///data/console.db")]);
    assert!(e.contains("must be a postgres:// URL") && e.contains("DATABASE_PATH"), "{e}");
    let e = refusal(&[("DATABASE_URL", &pg_url("?sslmode=sometimes"))]);
    assert!(e.contains("DATABASE_URL isn't a PostgreSQL URL"), "{e}");
    // The first PostgreSQL store's TLS switch is refused rather than ignored: TLS is the URL's sslmode now.
    let e = refusal(&[("DATABASE_SSLMODE", "require")]);
    assert!(e.contains("DATABASE_SSLMODE is no longer read") && e.contains("sslmode=verify-full"), "{e}");
    let file = r#"{"DATABASE_SSLMODE":"disable","AUTH_MODE":"dev_insecure"}"#;
    assert!(load(&env(&[]), &files(Some(file))).unwrap_err().contains("no longer read"));
}

#[test]
fn the_environment_chooses_the_store_over_the_file() {
    // The wizard saved the SQLite file; the operator later points the environment at PostgreSQL: PostgreSQL, not a
    // refusal. And the other way round.
    let file = r#"{"DATABASE_PATH":"/data/console.db","BACKUP_KEEP":"7","AUTH_MODE":"dev_insecure"}"#;
    let c = cfg(load(&env(&[("DATABASE_URL", &pg_url(""))]), &files(Some(file))).unwrap());
    assert!(matches!(c.db, DbConfig::Postgres(_)) && !c.warnings.iter().any(|w| w.contains("BACKUP_KEEP")), "the file's SQLite settings set aside, not warned about: {:?} {:?}", c.db, c.warnings);
    let file = serde_json::json!({ "DATABASE_URL": pg_url(""), "AUTH_MODE": "dev_insecure" }).to_string();
    let read = move |p: &Path| if p == Path::new("/var/lib/msp-console/config.json") { Ok(file.clone()) } else { Err(std::io::ErrorKind::NotFound.into()) };
    let c = cfg(load(&env(&[("DATABASE_PATH", "/srv/console.db")]), &read).unwrap());
    assert_eq!(c.db.sqlite().unwrap().path.to_str(), Some("/srv/console.db"));
    // Both in the file is a refusal, as both in the environment is.
    let both = serde_json::json!({ "DATABASE_URL": pg_url(""), "DATABASE_PATH": "/data/console.db", "AUTH_MODE": "dev_insecure" }).to_string();
    let read = move |p: &Path| if p == Path::new("/var/lib/msp-console/config.json") { Ok(both.clone()) } else { Err(std::io::ErrorKind::NotFound.into()) };
    assert!(load(&env(&[]), &read).unwrap_err().contains("both set"));
}

#[test]
fn production_wants_tls_to_the_database() {
    let prod = |query: &str| {
        let mut e = env(&[("MSP_ENV", "production"), ("AUTH_MODE", "proxy"), ("PROXY_KIND", "cloudflare_access"), ("ACCESS_TEAM_DOMAIN", "t.cloudflareaccess.com"), ("ACCESS_AUD", "a")]);
        e.insert("DATABASE_URL".into(), pg_url(query));
        load(&e, &files(None))
    };
    // Production checks the certificate: verify-full, or verify-ca with its CA named. Everything else is refused,
    // require included (it encrypts but takes any certificate), saying what to set.
    for (weak, has) in [("?sslmode=disable", "sslmode=disable"), ("?sslmode=allow", "sslmode=allow"), ("?sslmode=prefer", "sslmode=prefer"),
                        ("?sslmode=require", "accepts any certificate"), ("?sslmode=verify-ca", "verify-ca without sslrootcert")] {
        let e = prod(weak).unwrap_err();
        assert!(e.contains("must check the database's certificate in production") && e.contains("set sslmode=verify-full") && e.contains(has) && !e.contains(PG_PASSWORD), "{weak}: {e}");
    }
    for strong in ["?sslmode=verify-full", "?sslmode=verify-full&sslrootcert=/etc/ssl/db-ca.pem", "?sslmode=verify-ca&sslrootcert=/etc/ssl/db-ca.pem"] {
        let c = cfg(prod(strong).unwrap());
        assert!(c.warnings.is_empty(), "{strong}: {:?}", c.warnings);
    }
    // Outside production every mode loads; anything short of a checked certificate is said at start.
    for (mode, says) in [("disable", Some("TLS isn't required")), ("prefer", Some("TLS isn't required")), ("require", Some("TLS without certificate check")),
                         ("verify-ca", None), ("verify-full", None)] {
        let mut e = env(DEV);
        e.insert("DATABASE_URL".into(), pg_url(&format!("?sslmode={mode}")));
        let c = cfg(load(&e, &files(None)).unwrap());
        match says {
            Some(s) => assert!(c.warnings.iter().any(|w| w.starts_with("DATABASE_URL: ") && w.contains(s) && !w.contains(PG_PASSWORD)), "{mode}: {:?}", c.warnings),
            None => assert!(c.warnings.is_empty(), "{mode}: {:?}", c.warnings),
        }
    }
}

#[test]
fn the_url_is_the_one_source_libpqs_variables_are_refused() {
    // sqlx fills what a URL leaves out from libpq's variables; set, they'd quietly change where or how it connects.
    for k in msp_console::db::postgres::LIBPQ_ENV {
        let e = refusal(&[("DATABASE_URL", &pg_url("?sslmode=verify-full")), (k, "verify-full")]);
        assert!(e.starts_with(&format!("{k} is set in the console's environment")) && e.contains("DATABASE_URL alone") && e.contains(&format!("unset {k}")), "{k}: {e}");
    }
    // Production wants sslmode in the URL itself; PGSSLMODE doesn't stand in for it (and is refused on its own account).
    let prod = |extra: &[(&str, &str)], url: String| {
        let mut e = env(&[("MSP_ENV", "production"), ("AUTH_MODE", "proxy"), ("PROXY_KIND", "cloudflare_access"), ("ACCESS_TEAM_DOMAIN", "t.cloudflareaccess.com"), ("ACCESS_AUD", "a")]);
        e.insert("DATABASE_URL".into(), url);
        for (k, v) in extra { e.insert(k.to_string(), v.to_string()); }
        load(&e, &files(None)).unwrap_err()
    };
    let e = prod(&[], pg_url(""));
    assert!(e.contains("sets no sslmode") && e.contains("set sslmode=verify-full") && !e.contains(PG_PASSWORD), "{e}");
    let e = prod(&[("PGSSLMODE", "verify-full")], pg_url(""));
    assert!(e.starts_with("PGSSLMODE is set"), "{e}");
    // sqlx's own spelling counts as the URL saying it.
    let mut e = env(&[("MSP_ENV", "production"), ("AUTH_MODE", "dev_insecure")]);
    e.insert("DATABASE_URL".into(), pg_url("?ssl-mode=verify-full"));
    assert!(load(&e, &files(None)).unwrap_err().contains("dev_insecure"), "the URL passed; the refusal is sign-in's");
}

#[test]
fn backup_keep_with_postgresql_is_said_to_be_ignored() {
    let mut e = env(DEV);
    e.insert("DATABASE_URL".into(), pg_url(""));
    e.insert("BACKUP_KEEP".into(), "7".into());
    let c = cfg(load(&e, &files(None)).unwrap());
    assert!(c.warnings.iter().any(|w| w.contains("BACKUP_KEEP is ignored with PostgreSQL") && w.contains("pg_dump")), "{:?}", c.warnings);
}

#[test]
fn a_saved_database_url_is_a_secret_like_any_other() {
    // In the file unencrypted (from before setup encrypted it): it loads, with a warning naming the setting.
    let file = serde_json::json!({ "AUTH_MODE": "dev_insecure", "DATABASE_URL": pg_url("") }).to_string();
    let read = move |p: &Path| if p == Path::new("/var/lib/msp-console/config.json") { Ok(file.clone()) } else { Err(std::io::ErrorKind::NotFound.into()) };
    let c = cfg(load(&env(&[]), &read).unwrap());
    assert!(matches!(c.db, DbConfig::Postgres(_)));
    assert!(c.warnings.iter().any(|w| w.starts_with("DATABASE_URL is stored in the config file unencrypted") && !w.contains(PG_PASSWORD)), "{:?}", c.warnings);
}

#[test]
fn production_refuses_plain_http_to_a_vendor() {
    let mut e = env(&[("AUTH_MODE", "proxy"), ("PROXY_KIND", "cloudflare_access"), ("ACCESS_TEAM_DOMAIN", "t.cloudflareaccess.com"), ("ACCESS_AUD", "a"),
        ("MSP_ENV", "production"), ("NINJA_BASE_URL", "http://app.ninjarmm.com"), ("NINJA_CLIENT_ID", "id"), ("NINJA_CLIENT_SECRET", "s")]);
    assert!(load(&e, &files(None)).unwrap_err().contains("NINJA_BASE_URL must be an https URL"));
    e.insert("NINJA_BASE_URL".into(), "https://app.ninjarmm.com/".into());
    assert_eq!(cfg(load(&e, &files(None)).unwrap()).connectors.ninja.unwrap().base, "https://app.ninjarmm.com");
}

/// The image's own environment must leave it unconfigured, or a fresh compose install never gets the setup wizard (an
/// ENV line once set DATABASE_PATH, which counts as configuration, and a fresh container refused to start).
#[test]
fn the_images_environment_alone_is_unconfigured() {
    let dockerfile = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../Dockerfile")).unwrap();
    let line = dockerfile.lines().rfind(|l| l.starts_with("ENV ") && l.contains("STATIC_DIR=")).expect("the runtime stage's ENV line");
    let image: HashMap<String, String> = line[4..].split_whitespace().filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    assert!(image.contains_key("MSP_ENV") && image.contains_key("CONFIG_PATH"), "{image:?}");
    assert!(matches!(load(&image, &files(None)).unwrap(), Startup::Unconfigured { .. }), "the image's ENV configures it: {image:?}");
}

#[test]
fn the_embedder_is_on_by_default_from_the_images_model_and_off_by_setting() {
    let c = cfg(load(&env(CF), &files(None)).unwrap());
    assert_eq!(c.embedder, msp_console::embed::EmbedConfig { on: true, model_dir: "/models/bge-small-en-v1.5-int8".into(), threads: 2 });
    let mut e = env(CF);
    e.extend(env(&[("EMBEDDER", "off"), ("MODEL_DIR", "/elsewhere/model"), ("EMBED_THREADS", "4")]));
    assert_eq!(cfg(load(&e, &files(None)).unwrap()).embedder, msp_console::embed::EmbedConfig { on: false, model_dir: "/elsewhere/model".into(), threads: 4 });
    // Anything else is a refusal that names the setting, never a guess.
    for (k, v, why) in [("EMBEDDER", "maybe", "EMBEDDER must be on or off"), ("EMBED_THREADS", "0", "EMBED_THREADS must be a number from 1 to 64"), ("EMBED_THREADS", "65", "1 to 64")] {
        let mut e = env(CF);
        e.insert(k.into(), v.into());
        let err = load(&e, &files(None)).unwrap_err();
        assert!(err.contains(why), "{k}={v}: {err}");
    }
}
