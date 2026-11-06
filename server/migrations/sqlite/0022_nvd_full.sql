-- The full NVD dataset: NVD's yearly JSON 2.0 feeds, then the modified feed (src/connectors/nvd_feed.rs), and the
-- automatic mapping of every installed program and running binary to an NVD product (src/cpe_map.rs).

-- Each feed loaded: its .meta's SHA-256 (of the uncompressed JSON) and lastModifiedDate, when, and what it held.
CREATE TABLE sec_nvd_feed (
  feed           TEXT PRIMARY KEY,                 -- '2002' ... '2026', 'modified'
  sha256         TEXT,
  feed_modified  TEXT,
  loaded_at      TEXT NOT NULL,
  cves           INTEGER NOT NULL DEFAULT 0,
  cpe_rows       INTEGER NOT NULL DEFAULT 0
) STRICT;
-- A feed being read, written as it streams in small transactions so no write waits on a download; swapped into
-- sec_nvd_cve and sec_nvd_cpe in one transaction once the download is whole and its hash checks. Empty between loads.
CREATE TABLE nvd_stage_cve (
  cve_id         TEXT PRIMARY KEY,
  cvss           REAL,
  severity       TEXT,
  published      TEXT,
  last_modified  TEXT,
  rejected       INTEGER NOT NULL DEFAULT 0,
  description    TEXT
) STRICT;
CREATE TABLE nvd_stage_cpe (
  cve_id   TEXT NOT NULL,
  cpe      TEXT NOT NULL,
  part     TEXT NOT NULL,
  ranges   TEXT NOT NULL,
  PRIMARY KEY (cve_id, cpe)
) STRICT, WITHOUT ROWID;

-- Where a product came from: curated (the seed, and migrations after it), auto (an NVD product the automatic mapping
-- named: product_key nvd:<vendor>:<product>). Windows itself is the msrc source's product msrc:windows, with no row here. Only curated
-- products carry match rules, and only they are read one by one from NVD's API.
ALTER TABLE sec_product ADD COLUMN source TEXT NOT NULL DEFAULT 'curated';
-- How each distinct install was classified: rule (curated), auto (one NVD product whose vendor is the publisher),
-- reviewed (a person's decision); and how sure that is (0 to 1).
ALTER TABLE sec_software_class ADD COLUMN method TEXT;
ALTER TABLE sec_software_class ADD COLUMN confidence REAL;
