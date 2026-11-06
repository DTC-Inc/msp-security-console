//! Authenticated encryption, in one place: XChaCha20-Poly1305 under a key derived with HKDF-SHA256, a random 24-byte
//! nonce per value, and associated data that binds each value to what it's for. Two uses: short-lived sealed cookies
//! (the OIDC sign-in and session, the setup unlock), whose purpose and expiry are inside, and the secrets in the config
//! file (crate::secrets), each bound to its setting's name.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NONCE: usize = 24;
const TAG: usize = 16;

/// A cipher keyed by HKDF-SHA256 over `ikm`, with this salt and info.
#[derive(Clone)]
pub struct Cipher { cipher: XChaCha20Poly1305 }

impl Cipher {
    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Self {
        let hk = hkdf::Hkdf::<Sha256>::new(salt, ikm);
        let mut key = [0u8; 32];
        hk.expand(info, &mut key).expect("32 bytes from HKDF");
        Self { cipher: XChaCha20Poly1305::new(&key.into()) }
    }

    /// base64url(nonce || ciphertext), bound to `aad`.
    pub fn seal(&self, aad: &[u8], plain: &[u8]) -> String {
        let nonce_bytes = random(NONCE);
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("24 bytes");
        let ct = self.cipher.encrypt(&nonce, Payload { msg: plain, aad }).expect("encryption");
        B64.encode([nonce_bytes, ct].concat())
    }

    /// The plaintext, if `v` was sealed by this key with this `aad` and hasn't been altered.
    pub fn open(&self, aad: &[u8], v: &str) -> Option<Vec<u8>> {
        let raw = B64.decode(v.trim()).ok()?;
        if raw.len() < NONCE + TAG { return None; }
        let nonce = XNonce::try_from(&raw[..NONCE]).ok()?;
        self.cipher.decrypt(&nonce, Payload { msg: &raw[NONCE..], aad }).ok()
    }
}

impl std::fmt::Debug for Cipher { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Cipher(..)") } }

#[derive(Serialize, Deserialize)]
struct Sealed<T> { k: String, exp: u64, d: T }

/// Sealed values with a purpose and an expiry inside: a value sealed for one purpose ("login", "session", "setup")
/// can't be replayed as another, and it stops opening when it expires.
#[derive(Clone, Debug)]
pub struct Sealer(Cipher);

impl Sealer {
    pub fn new(salt: &[u8], secret: &[u8]) -> Self { Self(Cipher::derive(Some(salt), secret, b"xchacha20poly1305")) }

    /// A key that lives only as long as the process (the setup unlock: a restart signs everyone out of setup).
    pub fn ephemeral(salt: &[u8]) -> Self { Self::new(salt, &random(32)) }

    pub fn seal<T: Serialize>(&self, kind: &str, d: T, ttl: Duration) -> String {
        let plain = serde_json::to_vec(&Sealed { k: kind.into(), exp: now() + ttl.as_secs(), d }).expect("json");
        self.0.seal(kind.as_bytes(), &plain)
    }

    pub fn open<T: DeserializeOwned>(&self, kind: &str, v: &str) -> Option<T> {
        let plain = self.0.open(kind.as_bytes(), v)?;
        let s: Sealed<T> = serde_json::from_slice(&plain).ok()?;
        (s.k == kind && s.exp > now()).then_some(s.d)
    }
}

pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
pub fn random(n: usize) -> Vec<u8> { let mut b = vec![0u8; n]; getrandom::fill(&mut b).expect("the OS's random source"); b }
