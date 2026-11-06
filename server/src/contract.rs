//! Contract v1: the evidence API's read operations and their parameters, the list ops every count opens included.
//! The one source of truth: the JSON Schema
//! (`contract-schema`) and the client's TypeScript types (packages/contract) are generated from these types.
//! Strict: a key the contract doesn't name (a "scope", say) is refused, not passed on.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ReadOp {
    #[serde(rename = "cves.list")] CvesList,
    #[serde(rename = "devices.list")] DevicesList,
    #[serde(rename = "clients.list")] ClientsList,
    #[serde(rename = "cve.get")] CveGet,
    #[serde(rename = "cve.products")] CveProducts,
    #[serde(rename = "cve.devices")] CveDevices,
    // The CVEs whose NVD descriptions are nearest in meaning to this one's (the console's own embedder). Params: `cve_id`, and `org_id` and `limit` (at most 50) like the other CVE ops. A plain
    // comment, not a doc comment: schemars would turn a documented variant into a oneOf, and the enum is a list.
    #[serde(rename = "cve.similar")] CveSimilar,
    #[serde(rename = "device.get")] DeviceGet,
    #[serde(rename = "device.cves")] DeviceCves,
    #[serde(rename = "device.products")] DeviceProducts,
    #[serde(rename = "product.get")] ProductGet,
    #[serde(rename = "product.versions")] ProductVersions,
    #[serde(rename = "product.devices")] ProductDevices,
    #[serde(rename = "client.get")] ClientGet,
    #[serde(rename = "search")] Search,
    // The core views' own ops (M2): the Clients tab's counts, the Software tab's products, which source saw which device,
    // one device's installed software, and the advisories entered ahead of NVD. Plain comments, as above.
    #[serde(rename = "clients.overview")] ClientsOverview,
    #[serde(rename = "products.list")] ProductsList,
    #[serde(rename = "coverage.list")] CoverageList,
    #[serde(rename = "coverage.devices")] CoverageDevices,
    #[serde(rename = "device.software")] DeviceSoftware,
    #[serde(rename = "advisories.list")] AdvisoriesList,
    // Blackpoint and internet exposure (src/ops/blackpoint.rs, src/ops/exposure.rs).
    #[serde(rename = "detections.list")] DetectionsList,
    #[serde(rename = "detection.get")] DetectionGet,
    #[serde(rename = "blackpoint.tenants")] BlackpointTenants,
    #[serde(rename = "darkweb.list")] DarkwebList,
    #[serde(rename = "exposure.list")] ExposureList,
    #[serde(rename = "exposure.get")] ExposureGet,
    // Windows itself (the msrc source): devices with their patch state, and the open Windows CVEs with the update
    // (KB) that fixes each. Params: org_id, device_id, device_class, cve_id, state (vulnerable | patched | unknown | untracked),
    // and for windows.cves cve_id and kev; keyset pages.
    #[serde(rename = "windows.devices")] WindowsDevices,
    #[serde(rename = "windows.cves")] WindowsCves,
    // Running processes (the process source): binaries, one row each, with what product and version they are and
    // that version's CVEs. Params: q (a SHA-256, or text), org_id, device_id, product_key, state (a trust class); and
    // the names the automatic mapping wouldn't decide, for a person to (state: pending | accepted | rejected).
    #[serde(rename = "processes.list")] ProcessesList,
    #[serde(rename = "processes.review")] ProcessesReview,
    // One product version's CVEs, as NVD's ranges put them, whatever device runs it: what a binary's CVE count opens.
    // Params: product_key and version (both required; "(none)" is the empty version), kev, critical, cvss_min, org_id.
    #[serde(rename = "version.cves")] VersionCves,
}

impl ReadOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReadOp::CvesList => "cves.list", ReadOp::DevicesList => "devices.list", ReadOp::ClientsList => "clients.list",
            ReadOp::CveGet => "cve.get", ReadOp::CveProducts => "cve.products", ReadOp::CveDevices => "cve.devices", ReadOp::CveSimilar => "cve.similar",
            ReadOp::DeviceGet => "device.get", ReadOp::DeviceCves => "device.cves", ReadOp::DeviceProducts => "device.products",
            ReadOp::ProductGet => "product.get", ReadOp::ProductVersions => "product.versions", ReadOp::ProductDevices => "product.devices",
            ReadOp::ClientGet => "client.get", ReadOp::Search => "search",
            ReadOp::ClientsOverview => "clients.overview", ReadOp::ProductsList => "products.list", ReadOp::CoverageList => "coverage.list", ReadOp::CoverageDevices => "coverage.devices",
            ReadOp::DeviceSoftware => "device.software", ReadOp::AdvisoriesList => "advisories.list",
            ReadOp::DetectionsList => "detections.list", ReadOp::DetectionGet => "detection.get", ReadOp::BlackpointTenants => "blackpoint.tenants",
            ReadOp::DarkwebList => "darkweb.list", ReadOp::ExposureList => "exposure.list", ReadOp::ExposureGet => "exposure.get",
            ReadOp::WindowsDevices => "windows.devices", ReadOp::WindowsCves => "windows.cves", ReadOp::ProcessesList => "processes.list", ReadOp::ProcessesReview => "processes.review",
            ReadOp::VersionCves => "version.cves",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Source { NinjaSoftware, Process, Msrc, Blackpoint, Advisory }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass { Server, Desktop, Laptop, Other }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Has { Product, Software }

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    #[serde(skip_serializing_if = "Option::is_none")] pub org_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")] pub device_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")] pub cve_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub product_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub advisory_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub source: Option<Vec<Source>>,
    #[serde(skip_serializing_if = "Option::is_none")] pub device_class: Option<DeviceClass>,
    #[serde(skip_serializing_if = "Option::is_none")] pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub msa: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] pub kev: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] pub critical: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] pub running_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] pub cvss_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")] pub has: Option<Has>,
    #[serde(skip_serializing_if = "Option::is_none")] pub seen: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] pub q: Option<String>,
    /// A state to filter by, and it means something different per op; every other op refuses it.
    /// `windows.devices`: a patch state (vulnerable | unknown | untracked | patched).
    /// `processes.list`: a binary's trust (invalid | unsigned | unchecked | unhashed | valid).
    /// `processes.review`: a review's status (pending | accepted | rejected).
    #[serde(skip_serializing_if = "Option::is_none")] pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub limit: Option<u32>,
    // Blackpoint and exposure: a tenant, a detection, an address; closed detections too; edge entry points too.
    #[serde(skip_serializing_if = "Option::is_none")] pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub detection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub include_closed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")] pub include_edge: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequest {
    pub op: ReadOp,
    #[serde(default)]
    pub params: Params,
}

fn is_cve_id(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 13 && s[..4].eq_ignore_ascii_case("CVE-") && b[4..8].iter().all(u8::is_ascii_digit) && b[8] == b'-' && b[9..].iter().all(u8::is_ascii_digit)
}

impl Params {
    /// What serde's types can't say: ranges, lengths, the CVE id's shape, ids above zero.
    pub fn validate(&self) -> Result<(), String> {
        let len = |name: &str, v: &Option<String>, min: usize, max: usize| match v {
            Some(s) if s.chars().count() < min || s.chars().count() > max => Err(format!("{name} must be {min} to {max} characters")),
            _ => Ok(()),
        };
        if self.org_id == Some(0) { return Err("org_id must be above zero".into()); }
        if self.device_id == Some(0) { return Err("device_id must be above zero".into()); }
        if let Some(c) = &self.cve_id && !is_cve_id(c) { return Err("cve_id must be a CVE id".into()); }
        len("product_key", &self.product_key, 1, 200)?;
        len("version", &self.version, 0, 100)?;
        len("advisory_id", &self.advisory_id, 1, 200)?;
        len("role", &self.role, 1, 40)?;
        len("q", &self.q, 0, 200)?;
        if let Some(st) = &self.state && (st.is_empty() || st.len() > 20 || !st.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')) {
            return Err("state must be one of the op's states".into());
        }
        len("cursor", &self.cursor, 1, 2000)?;
        len("tenant_id", &self.tenant_id, 1, 100)?;
        len("detection_id", &self.detection_id, 1, 100)?;
        if let Some(ip) = &self.ip && ip.parse::<std::net::Ipv4Addr>().is_err() { return Err("ip must be an IPv4 address".into()); }
        if let Some(s) = &self.source && (s.is_empty() || s.len() > 5) { return Err("source must name 1 to 5 sources".into()); }
        if let Some(c) = self.cvss_min && !(0.0..=10.0).contains(&c) { return Err("cvss_min must be 0 to 10".into()); }
        if let Some(l) = self.limit && !(1..=500).contains(&l) { return Err("limit must be 1 to 500".into()); }
        Ok(())
    }
}

impl EvidenceRequest {
    /// Parse and check a request body. The error says what was wrong, never echoing the value.
    pub fn parse(body: &[u8]) -> Result<Self, String> {
        let req: EvidenceRequest = serde_json::from_slice(body).map_err(|e| {
            let m = e.to_string();
            if m.contains("unknown field") { "a key the contract doesn't name".to_string() }
            else if m.contains("unknown variant") { "an operation or value the contract doesn't list".to_string() }
            else { "not a contract v1 read".to_string() }
        })?;
        req.params.validate()?;
        Ok(req)
    }
}

/// A person's decision on a name the automatic mapping wouldn't decide (`POST /api/review`): accept one of its
/// candidates as the NVD product it is, reject the name (never matched), or reopen it. Strict like the reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewDecision {
    pub kind: ReviewKind,
    pub name: String,
    #[serde(default)]
    pub company: String,
    pub decision: Decide,
    /// The accepted candidate, as vendor:product; only with accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind { Process, Software }
impl ReviewKind { pub fn as_str(&self) -> &'static str { match self { ReviewKind::Process => "process", ReviewKind::Software => "software" } } }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Decide { Accept, Reject, Reopen }

impl ReviewDecision {
    pub fn parse(body: &[u8]) -> Result<Self, String> {
        let d: ReviewDecision = serde_json::from_slice(body).map_err(|_| "not a review decision: kind, name, company, decision (accept, reject or reopen) and, to accept, cpe".to_string())?;
        if d.name.trim().is_empty() || d.name.chars().count() > 500 || d.company.chars().count() > 500 { return Err("name must be 1 to 500 characters, company at most 500".into()); }
        match (d.decision, &d.cpe) {
            (Decide::Accept, None) => Err("accept needs the candidate's cpe".into()),
            (Decide::Accept, Some(c)) if c.chars().count() > 400 || !c.contains(':') => Err("cpe must be one of the name's candidates, as vendor:product".into()),
            (Decide::Reject | Decide::Reopen, Some(_)) => Err("only accept takes a cpe".into()),
            _ => Ok(d),
        }
    }
}
