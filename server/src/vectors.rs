//! Vector search on the store: sqlite-vec on SQLite (migrations/sqlite/0003_vectors.sql), pgvector on PostgreSQL
//! (migrations/postgres/0003_vectors.sql) when the database server has it. The first use is "similar to this CVE" by
//! the meaning of NVD's description. CVE descriptions are public, so a vector of one is public too, but the table is
//! the console's like every other: the vectors go where the store goes and nowhere else.
//!
//! On SQLite it's always there (compiled in; the store refuses to open without it). On PostgreSQL without pgvector,
//! similar-CVE search is off: `available` says why, /api/status and the start log say so, and these calls refuse.

use crate::db::Pool;

/// The size of a description's vector: the small local sentence models'.
pub const CVE_DIMS: usize = 384;

/// pgvector isn't installed in this database: the extension is missing.
pub const EXTENSION_MISSING: &str = "similar-CVE search is off: this PostgreSQL database has no pgvector extension (install pgvector, run CREATE EXTENSION vector as a role allowed to, and restart the console)";
/// pgvector is installed, but the console hasn't made its table yet (it does at start).
pub const TABLE_MISSING: &str = "similar-CVE search is off: pgvector is installed, but the vector table isn't there yet (restart the console, which makes it at start)";

/// Whether vector search works on this store, or why not.
pub async fn available(pool: &Pool) -> Result<(), String> {
    match pool {
        Pool::Sqlite(_) => crate::db::vec_version(pool).await.map(|_| ()).map_err(|e| format!("similar-CVE search is off: sqlite-vec isn't in the connection ({e})")),
        Pool::Postgres(p) => match sqlx::query_as::<_, (bool, bool)>(
            "SELECT to_regclass('vec_cve_description') IS NOT NULL, EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector')").fetch_one(p).await {
            Ok((true, _)) => Ok(()),
            Ok((false, false)) => Err(EXTENSION_MISSING.into()),
            Ok((false, true)) => Err(TABLE_MISSING.into()),
            Err(e) => Err(format!("similar-CVE search can't be checked: {}", crate::db::why(&e))),
        },
    }
}

fn check(v: &[f32]) -> Result<(), String> {
    if v.len() != CVE_DIMS { return Err(format!("a CVE description vector has {CVE_DIMS} dimensions, not {}", v.len())); }
    if !v.iter().all(|x| x.is_finite()) { return Err("a vector's values must be finite numbers".into()); }
    if v.iter().all(|x| *x == 0.0) { return Err("the zero vector has no direction to compare".into()); }
    Ok(())
}

/// Store (or replace) a CVE's description vector made by `model`; another model's vector for the same CVE is left
/// alone, so one row per (model, CVE). Refuses a vector of the wrong size, one with a
/// value that isn't a finite number, and the zero vector, whose cosine distance to anything is undefined.
pub async fn put_cve(pool: &Pool, cve_id: &str, model: &str, v: &[f32]) -> Result<(), String> {
    check(v)?;
    let e = |e: sqlx::Error| crate::db::why(&e);
    match pool {
        Pool::Sqlite(p) => {
            // vec0 has no upsert: delete, then insert. The transaction opens with that write (db/sqlite.rs, "Transactions").
            let mut tx = p.begin().await.map_err(e)?;
            sqlx::query("DELETE FROM vec_cve_description WHERE model = $2 AND cve_id = $1").bind(cve_id).bind(model).execute(&mut *tx).await.map_err(e)?;
            sqlx::query("INSERT INTO vec_cve_description (cve_id, model, embedding) VALUES ($1, $2, $3)")
                .bind(cve_id).bind(model).bind(blob(v)).execute(&mut *tx).await.map_err(e)?;
            tx.commit().await.map_err(e)
        }
        Pool::Postgres(p) => {
            available(pool).await?;
            sqlx::query("INSERT INTO vec_cve_description (cve_id, model, embedding) VALUES ($1, $2, $3::vector)
                         ON CONFLICT (model, cve_id) DO UPDATE SET embedding = excluded.embedding")
                .bind(cve_id).bind(model).bind(text(v)).execute(p).await.map(|_| ()).map_err(e)
        }
    }
}

/// One CVE the embed job read: its id, the hash of the description it read, and NVD's lastModified when it read it.
#[derive(Debug, Clone, PartialEq)]
pub struct Read { pub cve_id: String, pub text_sha256: String, pub nvd_modified: Option<chrono::DateTime<chrono::Utc>> }

/// What one batch of the embed job comes to, written together by `put_embedded`.
#[derive(Debug, Default)]
pub struct Batch {
    /// New vectors, each with the description it was made from.
    pub made: Vec<(Read, Vec<f32>)>,
    /// lastModified moved, the description didn't: the record moves with it, the vector stays.
    pub unchanged: Vec<Read>,
    /// Descriptions that couldn't be embedded, and the class of the failure (never the text, never the error's words).
    pub failed: Vec<(Read, &'static str)>,
    /// Failed before, lastModified moved, the description didn't: still failed, not tried again.
    pub still_failing: Vec<Read>,
}

impl Batch { pub fn len(&self) -> usize { self.made.len() + self.unchanged.len() + self.failed.len() + self.still_failing.len() } pub fn is_empty(&self) -> bool { self.len() == 0 } }

/// The embed job's write for one batch, in one transaction: each new vector with its record in `cve_embedded` (and its
/// old failure gone); each lastModified that moved alone; each failure recorded in `cve_embed_failed`, its CVE's old
/// vector and record taken out (they described other words). All of it or none of it: a run cancelled anywhere in here
/// (its future dropped) rolls the transaction back, so a vector never lands without its record, or a record without
/// its vector.
pub async fn put_embedded(pool: &Pool, model: &str, b: &Batch) -> Result<(), String> {
    for (_, v) in &b.made { check(v)?; }
    if matches!(pool, Pool::Postgres(_)) { available(pool).await?; }
    let e = |e: sqlx::Error| crate::db::why(&e);
    let ts = |t: &Option<chrono::DateTime<chrono::Utc>>| t.map(crate::db::Ts);
    const RECORD: &str = "INSERT INTO cve_embedded (model, cve_id, text_sha256, nvd_modified) VALUES ($1, $2, $3, $4)
                          ON CONFLICT (model, cve_id) DO UPDATE SET text_sha256 = excluded.text_sha256, nvd_modified = excluded.nvd_modified, embedded_at = excluded.embedded_at";
    const MOVED: &str = "UPDATE cve_embedded SET nvd_modified = $3 WHERE model = $1 AND cve_id = $2";
    const FAILED: &str = "INSERT INTO cve_embed_failed (model, cve_id, text_sha256, nvd_modified, error_class) VALUES ($1, $2, $3, $4, $5)
                          ON CONFLICT (model, cve_id) DO UPDATE SET text_sha256 = excluded.text_sha256, nvd_modified = excluded.nvd_modified,
                            error_class = excluded.error_class, failed_at = excluded.failed_at";
    const STILL: &str = "UPDATE cve_embed_failed SET nvd_modified = $3 WHERE model = $1 AND cve_id = $2";
    const UNFAIL: &str = "DELETE FROM cve_embed_failed WHERE model = $1 AND cve_id = $2";
    const UNRECORD: &str = "DELETE FROM cve_embedded WHERE model = $1 AND cve_id = $2";
    const UNVECTOR: &str = "DELETE FROM vec_cve_description WHERE model = $1 AND cve_id = $2";
    crate::on_pool!(pool, p, pg => {
        let mut tx = p.begin().await.map_err(e)?;
        for (r, v) in &b.made {
            if pg {
                sqlx::query("INSERT INTO vec_cve_description (cve_id, model, embedding) VALUES ($1, $2, $3::vector)
                             ON CONFLICT (model, cve_id) DO UPDATE SET embedding = excluded.embedding")
                    .bind(&r.cve_id).bind(model).bind(text(v)).execute(&mut *tx).await.map_err(e)?;
            } else {
                // vec0 has no upsert: delete, then insert.
                sqlx::query(UNVECTOR).bind(model).bind(&r.cve_id).execute(&mut *tx).await.map_err(e)?;
                sqlx::query("INSERT INTO vec_cve_description (cve_id, model, embedding) VALUES ($1, $2, $3)").bind(&r.cve_id).bind(model).bind(blob(v)).execute(&mut *tx).await.map_err(e)?;
            }
            sqlx::query(RECORD).bind(model).bind(&r.cve_id).bind(&r.text_sha256).bind(ts(&r.nvd_modified)).execute(&mut *tx).await.map_err(e)?;
            sqlx::query(UNFAIL).bind(model).bind(&r.cve_id).execute(&mut *tx).await.map_err(e)?;
        }
        for r in &b.unchanged { sqlx::query(MOVED).bind(model).bind(&r.cve_id).bind(ts(&r.nvd_modified)).execute(&mut *tx).await.map_err(e)?; }
        for (r, class) in &b.failed {
            sqlx::query(UNVECTOR).bind(model).bind(&r.cve_id).execute(&mut *tx).await.map_err(e)?;
            sqlx::query(UNRECORD).bind(model).bind(&r.cve_id).execute(&mut *tx).await.map_err(e)?;
            sqlx::query(FAILED).bind(model).bind(&r.cve_id).bind(&r.text_sha256).bind(ts(&r.nvd_modified)).bind(*class).execute(&mut *tx).await.map_err(e)?;
        }
        for r in &b.still_failing { sqlx::query(STILL).bind(model).bind(&r.cve_id).bind(ts(&r.nvd_modified)).execute(&mut *tx).await.map_err(e)?; }
        tx.commit().await.map_err(e)
    })
}

/// How many of `model`'s descriptions are recorded as failed.
pub async fn failing(pool: &Pool, model: &str) -> Result<i64, String> {
    crate::on_pool!(pool, p, _ => sqlx::query_scalar::<_, i64>("SELECT count(*) FROM cve_embed_failed WHERE model = $1").bind(model).fetch_one(p).await)
        .map_err(|e| crate::db::why(&e))
}

/// Take out `model`'s vectors (and their records, and any failure recorded) for CVEs that no longer have a description to compare: NVD rejected
/// them (every rejected CVE reads alike: "Rejected reason: ..."), the description is gone, or the CVE is. One
/// transaction. How many went.
pub async fn remove_stale(pool: &Pool, model: &str) -> Result<usize, String> {
    let e = |e: sqlx::Error| crate::db::why(&e);
    let gone: Vec<String> = crate::on_pool!(pool, p, _ => sqlx::query_scalar(
        "SELECT r.cve_id FROM (SELECT cve_id FROM cve_embedded WHERE model = $1 UNION SELECT cve_id FROM cve_embed_failed WHERE model = $1) r
           LEFT JOIN sec_nvd_cve n ON n.cve_id = r.cve_id
          WHERE n.cve_id IS NULL OR n.rejected OR n.description IS NULL OR n.description = ''")
        .bind(model).fetch_all(p).await).map_err(e)?;
    if gone.is_empty() { return Ok(0); }
    crate::on_pool!(pool, p, _ => {
        let mut tx = p.begin().await.map_err(e)?;
        for id in &gone {
            sqlx::query("DELETE FROM vec_cve_description WHERE model = $1 AND cve_id = $2").bind(model).bind(id).execute(&mut *tx).await.map_err(e)?;
            sqlx::query("DELETE FROM cve_embedded WHERE model = $1 AND cve_id = $2").bind(model).bind(id).execute(&mut *tx).await.map_err(e)?;
            sqlx::query("DELETE FROM cve_embed_failed WHERE model = $1 AND cve_id = $2").bind(model).bind(id).execute(&mut *tx).await.map_err(e)?;
        }
        tx.commit().await.map_err(e)?;
    });
    Ok(gone.len())
}

/// Whether `cve_id` has a vector of `model` yet.
pub async fn has_cve(pool: &Pool, cve_id: &str, model: &str) -> Result<bool, String> {
    crate::on_pool!(pool, p, _ => sqlx::query_scalar::<_, i64>("SELECT count(*) FROM vec_cve_description WHERE model = $1 AND cve_id = $2")
        .bind(model).bind(cve_id).fetch_one(p).await).map(|n| n > 0).map_err(|e| crate::db::why(&e))
}

/// The `k` CVEs whose descriptions are nearest in meaning to `cve_id`'s, nearest first, with their cosine distance;
/// only vectors `model` made are compared, and the CVE itself is left out. A CVE with no vector of that model has
/// no neighbours.
pub async fn similar_cves(pool: &Pool, cve_id: &str, model: &str, k: usize) -> Result<Vec<(String, f64)>, String> {
    let e = |e: sqlx::Error| crate::db::why(&e);
    match pool {
        Pool::Sqlite(p) => {
            let mine: Option<Vec<u8>> = sqlx::query_scalar("SELECT embedding FROM vec_cve_description WHERE model = $2 AND cve_id = $1")
                .bind(cve_id).bind(model).fetch_optional(p).await.map_err(e)?;
            let Some(mine) = mine else { return Ok(vec![]) };
            // One more than asked for, because the nearest is the CVE itself.
            let rows: Vec<(String, f64)> = sqlx::query_as(
                "SELECT cve_id, distance FROM vec_cve_description WHERE embedding MATCH $1 AND k = $2 AND model = $3 ORDER BY distance")
                .bind(mine).bind(k as i64 + 1).bind(model).fetch_all(p).await.map_err(e)?;
            Ok(rows.into_iter().filter(|(id, _)| id != cve_id).take(k).collect())
        }
        Pool::Postgres(p) => {
            available(pool).await?;
            // The query vector first, so the search below orders by distance to a constant, which the HNSW index serves.
            let mine: Option<String> = sqlx::query_scalar("SELECT embedding::text FROM vec_cve_description WHERE model = $2 AND cve_id = $1")
                .bind(cve_id).bind(model).fetch_optional(p).await.map_err(e)?;
            let Some(mine) = mine else { return Ok(vec![]) };
            let mut tx = p.begin().await.map_err(e)?;
            pg_search_settings(&mut tx, k).await.map_err(e)?;
            let rows = sqlx::query_as(PG_SIMILAR).bind(mine).bind(model).bind(cve_id).bind(k as i64).fetch_all(&mut *tx).await.map_err(e)?;
            tx.commit().await.map_err(e)?;
            Ok(rows)
        }
    }
}

/// The nearest of one model's vectors to $1 (pgvector's text form), leaving out $3, nearest first, at most $4. `<=>` is
/// pgvector's cosine distance, the SQLite table's measure: 0 the same direction, 1 unrelated, 2 opposite. Ordered by
/// distance to a constant and nothing else, so the HNSW index answers it.
pub const PG_SIMILAR: &str = "SELECT cve_id, (embedding <=> $1::vector)::float8 FROM vec_cve_description
                               WHERE model = $2 AND cve_id <> $3 ORDER BY embedding <=> $1::vector LIMIT $4";

/// For this transaction: an HNSW index hands back its nearest candidates and the WHERE filters them afterwards, so a
/// model with few vectors among many could come back with fewer than k. pgvector 0.8 can keep scanning until k pass
/// (hnsw.iterative_scan, in strict distance order); every version gets a candidate list (hnsw.ef_search) at least
/// as long as what's asked for.
pub async fn pg_search_settings(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, k: usize) -> Result<(), sqlx::Error> {
    let version: Option<String> = sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = 'vector'").fetch_optional(&mut **tx).await?;
    let v: Vec<u32> = version.unwrap_or_default().split('.').map(|x| x.parse().unwrap_or(0)).collect();
    if (v.first().copied().unwrap_or(0), v.get(1).copied().unwrap_or(0)) >= (0, 8) {
        sqlx::query("SELECT set_config('hnsw.iterative_scan', 'strict_order', true)").execute(&mut **tx).await?;
    }
    let ef = (k + 1).clamp(100, 1000);
    sqlx::query("SELECT set_config('hnsw.ef_search', $1, true)").bind(ef.to_string()).execute(&mut **tx).await?;
    Ok(())
}

/// sqlite-vec's float32 blob: the values little-endian, one after another.
fn blob(v: &[f32]) -> Vec<u8> { v.iter().flat_map(|x| x.to_le_bytes()).collect() }
/// pgvector's text form, `[0.1,0.2,...]`, cast to vector in the query. Rust prints an f32 exactly enough to read back.
fn text(v: &[f32]) -> String { format!("[{}]", v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")) }
