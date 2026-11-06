-- Descriptions the embed job couldn't embed (src/embed_job.rs): one row per CVE per model, with the class of the
-- failure (tokenise, inference, output, no_direction ...), never the text or the error's words. The job skips a CVE
-- here until its description changes (lastModified moved and text_sha256 differs), so one bad description can't stop
-- the rest, or be retried on every run. A row here has no vector: a failure takes out the CVE's old vector and record.
CREATE TABLE cve_embed_failed (
  model         TEXT NOT NULL,
  cve_id        TEXT NOT NULL,
  text_sha256   TEXT NOT NULL,
  nvd_modified  TEXT,
  error_class   TEXT NOT NULL,
  failed_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (model, cve_id)
) STRICT;
