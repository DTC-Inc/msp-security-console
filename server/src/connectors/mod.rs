//! The connectors ("The connector shape"): one module per vendor, each with its config from the settings, a
//! client with that vendor's auth, a rate limiter, and its jobs. Shared here: the limiter and the one way every
//! connector calls a vendor (Retry-After honoured, a status and a short reason on failure, never a URL or a body).

pub mod blackpoint;
pub mod halo;
pub mod kev;
pub mod msrc;
pub mod ninja;
pub mod ninja_os;
pub mod ninja_processes;
pub mod ninja_wan;
pub mod nvd;
pub mod nvd_feed;
pub mod shodan;

use reqwest::{RequestBuilder, StatusCode};
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// At most `max` calls in any `window`, shared by every caller in this process. Halo's is the tight one: its 700 per
/// rolling 5 minutes is the whole tenant's, so the console takes only HALO_REQUESTS_PER_5MIN of it.
#[derive(Clone)]
pub struct Limiter { max: usize, window: Duration, sent: Arc<Mutex<VecDeque<Instant>>> }

impl Limiter {
    pub fn new(max: usize, window: Duration) -> Self { Self { max: max.max(1), window, sent: Arc::new(Mutex::new(VecDeque::new())) } }
    pub fn window(&self) -> Duration { self.window }
    /// Wait until one more call fits in the window, then count it.
    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut q = self.sent.lock().await;
                let now = Instant::now();
                while q.front().is_some_and(|t| now.duration_since(*t) >= self.window) { q.pop_front(); }
                if q.len() < self.max { q.push_back(now); return; }
                self.window - now.duration_since(*q.front().unwrap())
            };
            tokio::time::sleep(wait + Duration::from_millis(5)).await;
        }
    }
}

/// How a connector waits after a 429 or 503 without a Retry-After (Halo's window is minutes, so its floor is a minute).
#[derive(Clone, Copy)]
pub struct Backoff { pub floor: Duration, pub tries: u32 }

/// Send through the limiter, retrying 429 and 503 (Retry-After honoured, never below the floor). The error is the
/// status and the vendor's own short reason when it gives one: never the URL, which can carry a key.
pub async fn send_json(limiter: &Limiter, backoff: Backoff, make: impl Fn() -> RequestBuilder) -> Result<Value, String> {
    for attempt in 0..=backoff.tries {
        limiter.acquire().await;
        let r = make().timeout(Duration::from_secs(60)).send().await.map_err(|e| if e.is_timeout() { "timed out".to_string() } else { "unreachable".to_string() })?;
        let st = r.status();
        if (st == StatusCode::TOO_MANY_REQUESTS || st == StatusCode::SERVICE_UNAVAILABLE) && attempt < backoff.tries {
            let ra = r.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|s| s.parse::<u64>().ok()).map(Duration::from_secs);
            tokio::time::sleep(ra.unwrap_or(backoff.floor).max(backoff.floor)).await;
            continue;
        }
        if st == StatusCode::NOT_FOUND { return Ok(Value::Null); }
        if st.is_redirection() { return Err(format!("HTTP {}: the address redirected; set the final address", st.as_u16())); }
        if !st.is_success() {
            let why = r.json::<Value>().await.ok().and_then(|j| ["error", "message", "error_description"].iter().find_map(|k| j.get(*k).and_then(Value::as_str).map(|s| s.chars().take(120).collect::<String>())));
            return Err(match why { Some(w) => format!("HTTP {}: {w}", st.as_u16()), None => format!("HTTP {}", st.as_u16()) });
        }
        return r.json::<Value>().await.map_err(|_| "the answer isn't JSON".to_string());
    }
    Err("still rate-limited after retrying".into())
}

/// A client-credentials bearer, minted on demand and re-minted a minute before it expires (or after a 401).
pub struct Token { pub value: String, pub until: Instant }
pub type TokenCache = Arc<Mutex<Option<Token>>>;

/// RFC 3339 for an epoch-seconds value (NinjaOne's timestamps are seconds, sometimes fractional).
pub fn from_epoch(v: &Value) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = v.as_f64()?;
    chrono::DateTime::from_timestamp(s.trunc() as i64, ((s.fract()) * 1e9) as u32)
}
