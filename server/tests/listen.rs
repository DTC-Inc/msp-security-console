//! "Only this computer" (AUTH_MODE=dev_insecure) listens on 127.0.0.1 outside a container; in one it listens on every
//! address, so the port mapping reaches it, and says so. Every other mode listens on every address.
mod common;
use msp_console::{in_container, listen_on, IN_CONTAINER_WARNING};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Stdio};

#[test]
fn where_each_mode_listens() {
    assert_eq!(listen_on(true, false), (IpAddr::V4(Ipv4Addr::LOCALHOST), None));
    assert_eq!(listen_on(true, true), (IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(IN_CONTAINER_WARNING)));
    assert!(IN_CONTAINER_WARNING.contains("127.0.0.1"));
    for c in [false, true] { assert_eq!(listen_on(false, c), (IpAddr::V4(Ipv4Addr::UNSPECIFIED), None)); }
    assert!(in_container(&|p| p == "/.dockerenv") && in_container(&|p| p == "/run/.containerenv") && !in_container(&|_| false));
}

/// The real binary, here (not in a container): it says it listens on 127.0.0.1, and answers there.
#[test]
fn dev_insecure_binds_loopback_outside_a_container() {
    if in_container(&|p| std::path::Path::new(p).exists()) { panic!("this test expects to run outside a container"); }
    let dir = common::temp_dir("listen");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_msp-console")).env_clear()
        .envs([("PORT", port.to_string()), ("AUTH_MODE", "dev_insecure".into()), ("MSP_ENV", "development".into()), ("SCHEDULER", "off".into()),
               ("DATABASE_PATH", dir.join("console.db").to_str().unwrap().into()), ("CONFIG_PATH", dir.join("none.json").to_str().unwrap().into())])
        .stdout(Stdio::piped()).spawn().unwrap();
    let line = BufReader::new(child.stdout.take().unwrap()).lines().map_while(Result::ok).find(|l| l.contains("listening")).expect("a listening line");
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!((v["address"].as_str(), v["auth"].as_str()), (Some("127.0.0.1"), Some("dev_insecure")), "{line}");
    let mut ok = false;
    for _ in 0..50 { if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() { ok = true; break; } std::thread::sleep(std::time::Duration::from_millis(50)); }
    let _ = child.kill();
    let _ = child.wait();
    assert!(ok, "it answers on 127.0.0.1");
}
