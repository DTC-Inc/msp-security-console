//! Which of NinjaOne's `publicIP` values is an internet address the exposure job can look up. The devices job
//! (connectors::ninja, ninja_devices) reads them in its own devices-detailed pass and keeps them in device_wan, so the
//! addresses cost no NinjaOne calls of their own.

/// A public IPv4 address, or None: private, carrier-grade NAT, loopback, link-local, multicast and malformed values
/// aren't an address anyone can look up.
pub fn public_ipv4(v: &str) -> Option<String> {
    let ip: std::net::Ipv4Addr = v.trim().parse().ok()?;
    let [a, b, ..] = ip.octets();
    if a == 0 || a == 10 || a == 127 || a >= 224 { return None; }
    if (a == 169 && b == 254) || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 100 && (64..=127).contains(&b)) { return None; }
    Some(ip.to_string())
}
