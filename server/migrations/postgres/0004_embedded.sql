-- What the embed job has embedded (src/embed_job.rs): one row per CVE per model, beside that CVE's vector in
-- vec_cve_description, written in the same transaction, so a row here always has its vector and the reverse. The same
-- table as SQLite's (migrations/sqlite/0004_embedded.sql). It's made whether or not pgvector is there: without pgvector
-- the job doesn't run and the table stays empty.
-- text_sha256 is the SHA-256 of the description the vector was made from, and nvd_modified NVD's lastModified for the
-- CVE when it was read: the job looks again only at a CVE whose lastModified has moved, and makes a new vector only when
-- the description's hash moved too.
CREATE TABLE cve_embedded (
  model         text NOT NULL,
  cve_id        text NOT NULL,
  text_sha256   text NOT NULL,
  nvd_modified  timestamptz,
  embedded_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (model, cve_id)
);
