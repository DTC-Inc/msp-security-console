//! The secrets in the config file, encrypted at rest (docs/design.md, "Configuration"). Each is stored as
//! `enc:v1:<base64url(nonce24 || ciphertext)>`: XChaCha20-Poly1305 under a key from HKDF-SHA256 over the master key
//! (info "msp-console config v1"), with the setting's name as associated data, so a value can't be moved to another
//! setting. The master key is CONSOLE_MASTER_KEY_FILE or CONSOLE_MASTER_KEY (32 or more bytes, raw or base64), or the
//! file at MASTER_KEY_PATH that the first save generates. It never lives in the config file itself.

use crate::seal::{random, Cipher};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const PREFIX: &str = "enc:v1:";
pub const DEFAULT_KEY_PATH: &str = "/var/lib/msp-console-key/master.key";
const INFO: &[u8] = b"msp-console config v1";

/// Which settings are secrets: every `*_SECRET`, SESSION_KEY, NVD_API_KEY, BLACKPOINT_API_TOKEN, SHODAN_API_KEY, and
/// DATABASE_URL, whose password makes the whole URL one. (A `_FILE` setting is a path, not one.)
pub fn is_secret(k: &str) -> bool {
    k.ends_with("_SECRET") || matches!(k, "SESSION_KEY" | "NVD_API_KEY" | "DATABASE_URL" | "BLACKPOINT_API_TOKEN" | "SHODAN_API_KEY")
}

pub fn is_encrypted(v: &str) -> bool { v.starts_with(PREFIX) }

/// Where the master key came from, for messages: never the key itself.
#[derive(Debug, Clone, PartialEq)]
pub enum KeySource { Env, EnvFile(PathBuf), Generated(PathBuf) }

impl KeySource {
    /// The file that holds the key, when there is one the operator must keep.
    pub fn path(&self) -> Option<&Path> { match self { KeySource::Env => None, KeySource::EnvFile(p) | KeySource::Generated(p) => Some(p) } }
}

pub struct ConfigKey { cipher: Cipher, pub source: KeySource }

impl std::fmt::Debug for ConfigKey { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("ConfigKey").field("source", &self.source).finish_non_exhaustive() } }

impl ConfigKey {
    fn from_bytes(master: &[u8], source: KeySource) -> Self { Self { cipher: Cipher::derive(None, master, INFO), source } }

    pub fn encrypt(&self, name: &str, plain: &str) -> String { format!("{PREFIX}{}", self.cipher.seal(name.as_bytes(), plain.as_bytes())) }

    /// The plaintext of `name`'s stored value. The error names the setting and never carries the value.
    pub fn decrypt(&self, name: &str, stored: &str) -> Result<String, String> {
        let bad = || format!("{name} in the config file can't be decrypted: the master key isn't the one it was saved with, or the value is damaged");
        let body = stored.strip_prefix(PREFIX).ok_or_else(bad)?;
        String::from_utf8(self.cipher.open(name.as_bytes(), body).ok_or_else(bad)?).map_err(|_| bad())
    }
}

/// 32 or more bytes: base64 of them, or the text itself.
pub fn parse_key(name: &str, text: &str) -> Result<Vec<u8>, String> {
    let t = text.trim();
    for e in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(b) = e.decode(t) && b.len() >= 32 { return Ok(b); }
    }
    if t.len() >= 32 { return Ok(t.as_bytes().to_vec()); }
    Err(format!("{name} must be 32 or more bytes, raw or base64"))
}

pub fn key_path(env: &HashMap<String, String>) -> PathBuf {
    PathBuf::from(env.get("MASTER_KEY_PATH").filter(|s| !s.trim().is_empty()).cloned().unwrap_or_else(|| DEFAULT_KEY_PATH.into()))
}

/// The master key, if one is set: CONSOLE_MASTER_KEY_FILE, then CONSOLE_MASTER_KEY, then the file at MASTER_KEY_PATH
/// (absent is None, not an error). Errors name the setting, never the key.
pub fn find(env: &HashMap<String, String>, read: &dyn Fn(&Path) -> std::io::Result<String>) -> Result<Option<ConfigKey>, String> {
    let get = |k: &str| env.get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if let Some(f) = get("CONSOLE_MASTER_KEY_FILE") {
        let text = read(Path::new(&f)).map_err(|_| format!("CONSOLE_MASTER_KEY_FILE ({f}) can't be read"))?;
        return Ok(Some(ConfigKey::from_bytes(&parse_key("CONSOLE_MASTER_KEY_FILE", &text)?, KeySource::EnvFile(f.into()))));
    }
    if let Some(v) = get("CONSOLE_MASTER_KEY") { return Ok(Some(ConfigKey::from_bytes(&parse_key("CONSOLE_MASTER_KEY", &v)?, KeySource::Env))); }
    let p = key_path(env);
    match read(&p) {
        Ok(text) => Ok(Some(ConfigKey::from_bytes(&parse_key(&format!("the master key file {}", p.display()), &text)?, KeySource::Generated(p)))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(format!("the master key file {} (MASTER_KEY_PATH) can't be read", p.display())),
    }
}

/// A new master key: 32 random bytes, written base64 to `path`, mode 0600, never over an existing file.
pub fn generate(path: &Path) -> Result<ConfigKey, String> {
    use std::io::Write;
    let key = random(32);
    let dir = path.parent().ok_or("MASTER_KEY_PATH has no directory")?;
    let cant = || format!("can't write the master key in {}: mount a writable volume there (MASTER_KEY_PATH), or set CONSOLE_MASTER_KEY", dir.display());
    std::fs::create_dir_all(dir).map_err(|_| cant())?;
    // create_new: a key someone already has is never replaced.
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
    let mut fh = o.open(path).map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { format!("a master key already exists at {}", path.display()) } else { cant() })?;
    if fh.write_all(format!("{}\n", STANDARD.encode(&key)).as_bytes()).and_then(|_| fh.sync_all()).is_err() {
        let _ = std::fs::remove_file(path);
        return Err(cant());
    }
    Ok(ConfigKey::from_bytes(&key, KeySource::Generated(path.to_path_buf())))
}
