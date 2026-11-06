//! The embedder: BAAI's bge-small-en-v1.5 on ONNX Runtime, inside this process (docs/design.md, "The embedder").
//! It turns an NVD description into the 384-dimension vector `vec_cve_description` holds (src/vectors.rs), so "similar
//! CVEs" can be answered from the console's own store. Nothing it reads or writes leaves the process: the model and
//! its tokenizer are files baked into the image at build time (pinned by SHA-256, checked again here at load), and
//! inference is a library call. CVE descriptions are public data; the embedder sends nothing anywhere regardless.
//!
//! **The model:** bge-small-en-v1.5 (MIT), as the int8 ONNX export most often used (Xenova's `model_quantized.onnx`,
//! per-channel dynamic quantisation of its weights; its fp32 export is byte for byte BAAI's own). It's a quarter the
//! size of the fp32 export. Measured on 30 made-up NVD-style descriptions (2026-11-05), the cosine between its vector
//! and fp32's for the same text is at least 0.9938 (mean 0.9962), and the nearest neighbour is the same for 29 of 30,
//! the 30th a tie (THIRD_PARTY.md has the method). Its vectors are stored under their own model key, [`MODEL_KEY`], so a
//! later model embeds beside it.
//!
//! **Pooling:** bge's own: the first token's (CLS) hidden state, L2-normalised, so every vector has length 1 and the
//! store's cosine distance is 1 - the dot product. **No query instruction:** bge prefixes a short *query* with
//! "Represent this sentence for searching relevant passages: " when it's matched against longer passages. "Similar
//! CVEs" compares a description with descriptions, which is symmetric, so both sides are embedded the same way, bare;
//! and the search reuses the CVE's stored vector, so nothing is embedded at query time at all.
//!
//! **Resources:** one ONNX Runtime session, one inference at a time (a mutex), on tokio's blocking pool, never on an
//! async worker. ONNX Runtime's own threads for one inference are EMBED_THREADS (default 2), and they don't spin
//! while idle. The int8 model is 34 MB on disk; the loaded session adds about 80 MB to the process, and an
//! inference at the full 512 tokens about 60 MB more while it runs (measured 2026-11-05).

use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Tensor;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tokenizers::{Tokenizer, TruncationParams};

/// The key the vectors are stored under: the model and its quantisation, since int8's vectors aren't fp32's.
pub const MODEL_KEY: &str = "bge-small-en-v1.5-int8";
/// Where the image keeps the model (MODEL_DIR overrides it).
pub const DEFAULT_DIR: &str = "/models/bge-small-en-v1.5-int8";
/// The files, and the SHA-256 each must have: the same pins scripts/fetch-model.sh downloads by (a test holds the two
/// to each other). A directory holding anything else is refused, because its vectors would be stored as this model's.
pub const FILES: &[(&str, &str)] = &[
    ("model.onnx", "6c9c6101a956d62dfb5e7190c538226c0c5bb9cb27b651234b6df063ee7dbfe4"),
    ("tokenizer.json", "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66"), // gitleaks:allow (a file hash, not a key)
];
/// The size of every vector it makes.
pub const DIMS: usize = crate::vectors::CVE_DIMS;
/// BERT's limit: a longer description is cut to its first 512 tokens (NVD's are almost always far shorter).
pub const MAX_TOKENS: usize = 512;
/// A description is cut to its first 16 KB before it's tokenised: 512 tokens are a few KB of English, so nothing
/// past this could reach the model, and the tokenizer never works through a giant string to find that out.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// The most EMBED_THREADS may ask for.
pub const MAX_THREADS: usize = 64;

/// The embedder's settings: EMBEDDER (on, the default, or off), MODEL_DIR and EMBED_THREADS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbedConfig { pub on: bool, pub model_dir: PathBuf, pub threads: usize }

impl Default for EmbedConfig {
    fn default() -> Self { Self { on: true, model_dir: PathBuf::from(DEFAULT_DIR), threads: 2 } }
}

/// The off sentences, for /api/status, the start log and the web app.
pub const OFF_BY_SETTING: &str = "similar-CVE search is off: the embedder is turned off (EMBEDDER=off)";

pub struct Embedder {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    /// Whether the graph takes token_type_ids (BERT exports usually do; all zeros for one sentence).
    type_ids: bool,
    /// The hidden states' output.
    output: String,
    pub threads: usize,
    /// Tests only: a text containing this fails, as a bad description would (`fail_on`).
    fault: Option<String>,
}

/// Why one description couldn't be embedded: a class to record and count (never the text), and a sentence for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed { pub class: &'static str, pub why: String }

impl Failed {
    fn new(class: &'static str, why: impl Into<String>) -> Self { Self { class, why: why.into() } }
}

/// `text` cut to at most MAX_TEXT_BYTES, on a character boundary.
pub fn capped(text: &str) -> &str {
    if text.len() <= MAX_TEXT_BYTES { return text; }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) { end -= 1; }
    &text[..end]
}

impl std::fmt::Debug for Embedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("Embedder").field("model", &MODEL_KEY).field("threads", &self.threads).finish_non_exhaustive() }
}

/// ONNX Runtime allows one environment per process: made once, telemetry off.
fn environment() -> Result<&'static ort::environment::Environment, String> {
    static ENV: OnceLock<Result<ort::environment::Environment, String>> = OnceLock::new();
    ENV.get_or_init(|| ort::init().with_name("msp-console").with_telemetry(false).build().map_err(|e| format!("ONNX Runtime didn't start: {e}")))
        .as_ref().map_err(Clone::clone)
}

/// A file's SHA-256, as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() }

impl Embedder {
    /// Load the pinned model from `dir`, checking each file's SHA-256 first. Blocking (it reads about 35 MB and builds
    /// the session): call it from a blocking thread. The error is a plain sentence that names the file, never its
    /// contents.
    pub fn load(dir: &Path, threads: usize) -> Result<Self, String> {
        let threads = threads.clamp(1, MAX_THREADS);
        let read = |name: &str, want: &str| -> Result<Vec<u8>, String> {
            let p = dir.join(name);
            let bytes = std::fs::read(&p).map_err(|e| format!("{} can't be read ({})", p.display(), e.kind()))?;
            let got = sha256_hex(&bytes);
            if got != want { return Err(format!("{} isn't the pinned {MODEL_KEY} file (SHA-256 {got}, expected {want})", p.display())); }
            Ok(bytes)
        };
        let model = read(FILES[0].0, FILES[0].1)?;
        let tok = read(FILES[1].0, FILES[1].1)?;
        let mut tokenizer = Tokenizer::from_bytes(&tok).map_err(|e| format!("the tokenizer doesn't load: {e}"))?;
        tokenizer.with_padding(None);
        tokenizer.with_truncation(Some(TruncationParams { max_length: MAX_TOKENS, ..Default::default() })).map_err(|e| format!("the tokenizer won't truncate: {e}"))?;
        let env = environment()?;
        // Graph optimisations off. Measured on this model (2026-11-05, Apple M-series, two threads): any level from 1
        // up made inference 2.7 times slower (15.6 ms a description against 5.8) and a 512-token description's peak
        // memory 1.09 GB against 193 MB, for the same vectors to 1e-7. The export is already the graph it should be.
        let session = Session::builder(env).map_err(|e| e.to_string())
            .and_then(|b| b.with_optimization_level(GraphOptimizationLevel::Disable).map_err(|e| e.to_string()))
            .and_then(|b| b.with_intra_threads(threads).map_err(|e| e.to_string()))
            .and_then(|b| b.with_inter_threads(1).map_err(|e| e.to_string()))
            .and_then(|b| b.with_intra_op_spinning(false).map_err(|e| e.to_string()))
            .and_then(|b| b.with_inter_op_spinning(false).map_err(|e| e.to_string()))
            .and_then(|mut b| b.commit_from_memory(&model).map_err(|e| e.to_string()))
            .map_err(|e| format!("ONNX Runtime can't load {MODEL_KEY}: {e}"))?;
        let names: Vec<String> = session.inputs().iter().map(|i| i.name().to_string()).collect();
        for need in ["input_ids", "attention_mask"] {
            if !names.iter().any(|n| n == need) { return Err(format!("the model has no {need} input")); }
        }
        let type_ids = names.iter().any(|n| n == "token_type_ids");
        let output = session.outputs().iter().map(|o| o.name().to_string()).find(|n| n == "last_hidden_state")
            .or_else(|| session.outputs().first().map(|o| o.name().to_string())).ok_or("the model has no output")?;
        Ok(Self { session: Mutex::new(session), tokenizer, type_ids, output, threads, fault: None })
    }

    /// Tests only: make any text containing `marker` fail, with the class "injected", to prove one bad description
    /// can't stop the rest.
    #[doc(hidden)]
    pub fn fail_on(mut self, marker: &str) -> Self { self.fault = Some(marker.into()); self }

    /// Embed each text: CLS pooling, L2-normalised, 384 values each, each text its own result, so one description
    /// that fails takes nothing else with it. Blocking: run it on a blocking thread (`embed`).
    ///
    /// One text per inference, never a padded batch: the int8 model quantises its activations with a scale taken from
    /// the whole input tensor, so in a batch a description's vector would move with whatever it was batched with
    /// (measured: 0.002 cosine). One at a time, a vector depends on its own text alone, so embedding it again, in any
    /// order, gives the same vector, and a typical description takes about 6 ms on two threads.
    pub fn embed_each(&self, texts: &[String]) -> Vec<Result<Vec<f32>, Failed>> {
        // A panic while the lock was held (inside ONNX Runtime's call, or ours) leaves the session as it was between
        // runs: carry on with it rather than turn the embedder off until a restart.
        let mut session = self.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        texts.iter().map(|text| self.one(&mut session, capped(text))).collect()
    }

    fn one(&self, session: &mut Session, text: &str) -> Result<Vec<f32>, Failed> {
        if self.fault.as_deref().is_some_and(|m| text.contains(m)) { return Err(Failed::new("injected", "a failure injected by a test")); }
        let e = self.tokenizer.encode(text, true).map_err(|e| Failed::new("tokenise", format!("a description couldn't be tokenised: {e}")))?;
        let n = e.get_ids().len();
        if n == 0 { return Err(Failed::new("tokenise", "a description made no tokens")); }
        let shape = vec![1i64, n as i64];
        let t = |v: Vec<i64>| Tensor::from_array((shape.clone(), v)).map_err(|e| Failed::new("input", format!("ONNX Runtime refused an input: {e}")));
        let wide = |x: &[u32]| x.iter().map(|v| *v as i64).collect::<Vec<i64>>();
        let mut inputs = vec![("input_ids", t(wide(e.get_ids()))?), ("attention_mask", t(wide(e.get_attention_mask()))?)];
        if self.type_ids { inputs.push(("token_type_ids", t(wide(e.get_type_ids()))?)); }
        let out = session.run(inputs).map_err(|e| Failed::new("inference", format!("inference failed: {e}")))?;
        let (dims, h) = out[self.output.as_str()].try_extract_tensor::<f32>().map_err(|e| Failed::new("output", format!("the model's output isn't f32 hidden states: {e}")))?;
        if dims.len() != 3 || dims[0] != 1 || dims[2] as usize != DIMS {
            return Err(Failed::new("output", format!("the model's output is {:?}, not [1, tokens, {DIMS}]", dims.iter().collect::<Vec<_>>())));
        }
        // CLS: the first token's hidden state.
        normalise(&h[..DIMS]).map_err(|why| Failed::new("no_direction", why))
    }

    /// `embed_each`, failing as a whole on the first text that fails: for callers that want all or nothing.
    pub fn embed_blocking(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        self.embed_each(texts).into_iter().map(|r| r.map_err(|f| f.why)).collect()
    }
}

/// Embed on tokio's blocking pool, so inference never holds an async worker; each text its own result. Dropping the
/// future (a cancelled run) leaves the texts to finish on their thread, and the result goes nowhere. Err only when the
/// thread itself stopped.
pub async fn embed(e: Arc<Embedder>, texts: Vec<String>) -> Result<Vec<Result<Vec<f32>, Failed>>, String> {
    tokio::task::spawn_blocking(move || e.embed_each(&texts)).await.map_err(|_| "the embedder's thread stopped".to_string())
}

/// Unit length, so cosine distance is 1 - the dot product; a vector of zeros (or anything not finite) is refused.
fn normalise(cls: &[f32]) -> Result<Vec<f32>, String> {
    let n = cls.iter().map(|x| (*x as f64) * (*x as f64)).sum::<f64>().sqrt();
    if !n.is_finite() || n == 0.0 { return Err("the model made a vector with no direction".into()); }
    Ok(cls.iter().map(|x| (*x as f64 / n) as f32).collect())
}

/// Whether similar-CVE search is on in this process, and why not: what /api/status, the start log, the job list and
/// `cve.similar` all go by.
#[derive(Clone, Debug)]
pub enum State { On(Arc<Embedder>), Off(String) }

impl State {
    pub fn model(&self) -> Result<&'static str, &str> { match self { State::On(_) => Ok(MODEL_KEY), State::Off(why) => Err(why) } }
    pub fn describe(&self) -> serde_json::Value {
        match self {
            State::On(e) => serde_json::json!({ "on": true, "model": MODEL_KEY, "threads": e.threads }),
            State::Off(why) => serde_json::json!({ "on": false, "model": MODEL_KEY, "why": why }),
        }
    }
}

/// Decide at start: off by setting; off when the store can't hold vectors (PostgreSQL without pgvector, in the store's
/// own words); off when the model won't load, saying why. In every case the console still serves.
pub async fn start(cfg: &EmbedConfig, pool: &crate::db::Pool) -> State {
    if !cfg.on { return State::Off(OFF_BY_SETTING.into()); }
    if let Err(why) = crate::vectors::available(pool).await { return State::Off(why); }
    let (dir, threads) = (cfg.model_dir.clone(), cfg.threads);
    match tokio::task::spawn_blocking(move || Embedder::load(&dir, threads)).await {
        Ok(Ok(e)) => State::On(Arc::new(e)),
        Ok(Err(why)) => State::Off(format!("similar-CVE search is off: the embedding model didn't load: {why} (set MODEL_DIR to where {MODEL_KEY} is, or EMBEDDER=off)")),
        Err(_) => State::Off("similar-CVE search is off: loading the embedding model stopped its thread".into()),
    }
}
