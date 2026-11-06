-- What the embed job has embedded (src/embed_job.rs): one row per CVE per model, beside that CVE's vector in
-- vec_cve_description, written in the same transaction, so a row here always has its vector and the reverse.
-- text_sha256 is the SHA-256 of the description the vector was made from, and nvd_modified NVD's lastModified for the
-- CVE when it was read: the job looks again only at a CVE whose lastModified has moved, and makes a new vector only when
-- the description's hash moved too (a new CVSS score alone doesn't change what a description means).
CREATE TABLE cve_embedded (
  model         TEXT NOT NULL,
  cve_id        TEXT NOT NULL,
  text_sha256   TEXT NOT NULL,
  nvd_modified  TEXT,
  embedded_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (model, cve_id)
) STRICT;
