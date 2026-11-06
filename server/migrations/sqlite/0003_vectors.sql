-- Vector search on the store (sqlite-vec, compiled in, so every install has it).
-- Its first use: "similar to this CVE", by the meaning of NVD's description (sec_nvd_cve.description). A shared
-- product (sec_nvd_cpe) already finds a CVE's siblings exactly; this finds the ones that read alike across products,
-- such as the same deserialisation flaw in two vendors' agents.
--
-- One row per CVE per model, so a second model can embed alongside the first and take over once it's complete. vec0
-- has no composite key, so `model` is the partition key (a query searches one model's vectors, and only those) and
-- `cve_id` a metadata column; vectors.rs::put_cve keeps (model, cve_id) unique by replacing within the model. The
-- size, 384, is the small local sentence models' (bge-small-en-v1.5, all-MiniLM-L6-v2), so a description can be
-- embedded inside the console and never has to leave it. Another model of another size is another table, in another
-- migration. Cosine distance: 0 is the same direction, 1 unrelated, 2 opposite.
--
-- Empty until the job that embeds descriptions lands; src/vectors.rs is how it's written and read.
CREATE VIRTUAL TABLE vec_cve_description USING vec0(
  model      TEXT PARTITION KEY,
  cve_id     TEXT,
  embedding  float[384] distance_metric=cosine
);
