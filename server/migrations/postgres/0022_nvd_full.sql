-- The full NVD dataset: the same tables as migrations/sqlite/0022_nvd_full.sql, in PostgreSQL's types.
CREATE TABLE sec_nvd_feed (
  feed           text PRIMARY KEY,
  sha256         text,
  feed_modified  timestamptz,
  loaded_at      timestamptz NOT NULL,
  cves           bigint NOT NULL DEFAULT 0,
  cpe_rows       bigint NOT NULL DEFAULT 0
);
CREATE TABLE nvd_stage_cve (
  cve_id         text PRIMARY KEY,
  cvss           double precision,
  severity       text,
  published      timestamptz,
  last_modified  timestamptz,
  rejected       boolean NOT NULL DEFAULT false,
  description    text
);
CREATE TABLE nvd_stage_cpe (
  cve_id   text NOT NULL,
  cpe      text NOT NULL,
  part     text NOT NULL,
  ranges   jsonb NOT NULL,
  PRIMARY KEY (cve_id, cpe)
);
ALTER TABLE sec_product ADD COLUMN source text NOT NULL DEFAULT 'curated';
ALTER TABLE sec_software_class ADD COLUMN method text;
ALTER TABLE sec_software_class ADD COLUMN confidence double precision;
