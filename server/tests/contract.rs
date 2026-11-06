//! Contract v1 at the door: what parses, what doesn't, and that the schema the client's types come from names every op.
use msp_console::contract::{EvidenceRequest, ReadOp};

#[test]
fn reads_parse_and_anything_else_is_refused_without_echoing_it() {
    let ok = EvidenceRequest::parse(br#"{"op":"devices.list","params":{"org_id":7,"kev":true,"source":["ninja_software","process"],"device_class":"server","role":"server","version":"(none)","has":"product","limit":500}}"#).unwrap();
    assert_eq!(ok.op, ReadOp::DevicesList);
    assert_eq!(EvidenceRequest::parse(br#"{"op":"search"}"#).unwrap().params, Default::default());
    for (b, why) in [(&br#"{"op":"cves.list","params":{"scope":{"org_id":1}}}"#[..], "a key the contract doesn't name"), (br#"{"op":"cves.delete"}"#, "doesn't list"),
        (br#"{"op":"cves.list","params":{"limit":0}}"#, "limit"), (br#"{"op":"cves.list","params":{"cvss_min":11}}"#, "cvss_min"), (br#"{"op":"cves.list","params":{"org_id":0}}"#, "above zero"),
        (br#"{"op":"cve.get","params":{"cve_id":"CVE-2026-1"}}"#, "CVE id"), (br#"{"op":"cves.list","params":{"source":[]}}"#, "source")] {
        let e = EvidenceRequest::parse(b).unwrap_err();
        assert!(e.contains(why), "{}: {e}", String::from_utf8_lossy(b));
    }
    assert!(!EvidenceRequest::parse(br#"{"op":"cves.list","params":{"q":1234567}}"#).unwrap_err().contains("1234567"), "the error echoed the value");
}

#[test]
fn the_schema_names_every_op_and_refuses_unknown_keys() {
    let s = serde_json::to_string(&schemars::schema_for!(EvidenceRequest)).unwrap();
    for op in ["cves.list", "devices.list", "clients.list", "cve.get", "cve.products", "cve.devices", "cve.similar", "device.get", "device.cves", "device.products", "product.get", "product.versions", "product.devices", "client.get", "search"] {
        assert!(s.contains(&format!("\"{op}\"")), "{op}");
    }
    assert!(s.contains("\"additionalProperties\":false"));
}

#[test]
fn the_audit_time_is_rfc3339_utc() {
    use msp_console::audit::rfc3339;
    use std::time::Duration;
    assert_eq!(rfc3339(Duration::from_millis(0)), "1970-01-01T00:00:00.000Z");
    assert_eq!(rfc3339(Duration::from_millis(1_793_059_322_957)), "2026-10-27T00:02:02.957Z");
    assert_eq!(rfc3339(Duration::from_secs(951_782_400)), "2000-02-29T00:00:00.000Z");
}
