-- Descriptions the embed job couldn't embed (src/embed_job.rs): the same table as SQLite's
-- (migrations/sqlite/0005_embed_failed.sql). One row per CVE per model, with the class of the failure, never the text
-- or the error's words. The job skips a CVE here until its description changes, and a row here has no vector.
CREATE TABLE cve_embed_failed (
  model         text NOT NULL,
  cve_id        text NOT NULL,
  text_sha256   text NOT NULL,
  nvd_modified  timestamptz,
  error_class   text NOT NULL,
  failed_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (model, cve_id)
);
