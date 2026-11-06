//! One audit line per API request (design rev 3, "Data handling"): who, the op, the ids and flags it asked with, how
//! many rows came back, the status and the time. Never a name: a free-text query is recorded by its length only, and
//! nothing from the answer but its row count. Lines go to stdout, which the cluster keeps.

use crate::contract::Params;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuditRecord { pub at: String, pub who: Option<String>, pub op: Option<String>, pub params: Value, pub rows: Option<usize>, pub status: u16, pub ms: u128 }

pub type AuditSink = Arc<dyn Fn(AuditRecord) + Send + Sync>;

pub fn stdout_sink() -> AuditSink {
    Arc::new(|r: AuditRecord| { if let Ok(mut v) = serde_json::to_value(&r) { v["audit"] = json!("msp-console"); println!("{v}"); } })
}

pub fn audit_params(p: &Params) -> Value {
    let full = serde_json::to_value(p).unwrap_or(json!({}));
    let mut out = Map::new();
    if let Some(obj) = full.as_object() {
        for (k, v) in obj {
            match k.as_str() {
                "q" => { out.insert("q".into(), json!(format!("[{} chars]", v.as_str().map(|s| s.chars().count()).unwrap_or(0)))); }
                "cursor" => { out.insert("cursor".into(), json!(true)); }
                _ => { out.insert(k.clone(), v.clone()); }   // ids, keys and flags: no names among them
            }
        }
    }
    Value::Object(out)
}

/// The time as RFC 3339 in UTC (what log tools read), without a date library.
pub fn now() -> String { rfc3339(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default()) }

pub fn rfc3339(d: std::time::Duration) -> String {
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, d.subsec_millis())
}
