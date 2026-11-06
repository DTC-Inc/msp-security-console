-- The console's own store: one SQLite file on the console's own volume.
-- Embedded in the binary and applied at start. One process writes it (one replica, by design).
--
-- Conventions, so every query can rely on them:
--   - a time is TEXT in ISO-8601 UTC with milliseconds, '2026-10-27T14:10:12.345Z', written by
--     strftime('%Y-%m-%dT%H:%M:%fZ','now') here and by db::ts() in Rust; one form, so text order is time order;
--   - a date is TEXT 'YYYY-MM-DD';
--   - JSON is TEXT holding JSON, read with ->> and json_each;
--   - a boolean is INTEGER 0 or 1.

-- ---- the scheduler: one row per job; the lease keeps a job single-writer, and a restart mid-run resumes it --------
CREATE TABLE job (
  name             TEXT PRIMARY KEY,
  every_secs       INTEGER NOT NULL,
  next_run_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  lease_holder     TEXT,
  lease_until      TEXT,
  cursor           TEXT,                      -- JSON: the job's own resume point
  last_started_at  TEXT,
  last_ok_at       TEXT,
  last_error       TEXT,                      -- a status and a short reason, never a URL or a secret
  last_detail      TEXT                       -- JSON
) STRICT;

-- ---- what the connectors collect (the installing MSP's own vendors) ----------------------------------------------
-- A client is a NinjaOne organization; its Halo client is linked by Halo's own ninjarmmid (confirmed) or by name (a
-- suggestion only: halo_matched_by = 'name', never used to scope anything a client sees). name_key is the name
-- lowercased with every run of anything but a-z and 0-9 made one space (db::name_key), for that suggestion.
CREATE TABLE client (
  org_id           INTEGER PRIMARY KEY,
  name             TEXT NOT NULL,
  name_key         TEXT NOT NULL,
  halo_client_id   INTEGER,
  halo_matched_by  TEXT,                      -- ninjarmm_id | name | NULL
  seen_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at       TEXT
) STRICT;
CREATE TABLE halo_client (
  halo_client_id   INTEGER PRIMARY KEY,
  name             TEXT NOT NULL,
  name_key         TEXT NOT NULL,
  ninjarmm_org_id  INTEGER,
  website_sites    TEXT,                      -- JSON [{url, hostname, apex}], normalised; never the raw text
  checked_at       TEXT,                      -- the last GET /Client/{id}
  seen_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at       TEXT
) STRICT;
CREATE INDEX ix_halo_client_name_key ON halo_client (name_key) WHERE deleted_at IS NULL;
CREATE TABLE device (
  device_id        INTEGER PRIMARY KEY,
  org_id           INTEGER NOT NULL,
  name             TEXT NOT NULL,
  device_class     TEXT NOT NULL,             -- server | desktop | laptop | other
  node_class       TEXT,
  os_name          TEXT,
  last_contact     TEXT,
  seen_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at       TEXT
) STRICT;
CREATE INDEX ix_device_org ON device (org_id) WHERE deleted_at IS NULL;
CREATE TABLE software (
  device_id        INTEGER NOT NULL,
  org_id           INTEGER NOT NULL,
  name             TEXT NOT NULL,
  publisher        TEXT NOT NULL DEFAULT '',
  version          TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (device_id, name, publisher, version)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_software_org ON software (org_id);
CREATE TABLE software_sync (
  org_id           INTEGER PRIMARY KEY,
  synced_at        TEXT NOT NULL,
  rows             INTEGER NOT NULL
) STRICT;

-- ---- the evidence model: one store, every row tagged with the source that saw it ---------------------------------
CREATE TABLE sec_product (
  product_key  TEXT PRIMARY KEY,
  label        TEXT NOT NULL,
  cpe          TEXT NOT NULL,                 -- NVD vendor:product, escapes as NVD writes them
  match        TEXT NOT NULL,                 -- JSON { name_re, publisher_re?, exclude_re?, version_from?, version_re? }
  sort_order   INTEGER NOT NULL DEFAULT 100,
  active       INTEGER NOT NULL DEFAULT 1
) STRICT;
-- Each distinct installed (name, publisher, version) and which product it is (NULL: not recognised). Rebuilt by the
-- match job; it's what keeps matching to one pass over distinct names, not over every device's every install.
CREATE TABLE sec_software_class (
  name             TEXT NOT NULL,
  publisher        TEXT NOT NULL DEFAULT '',
  version          TEXT NOT NULL DEFAULT '',
  product_key      TEXT,
  product_version  TEXT,
  PRIMARY KEY (name, publisher, version)
) STRICT, WITHOUT ROWID;
CREATE TABLE sec_kev (
  cve_id       TEXT PRIMARY KEY,
  vendor       TEXT,
  product      TEXT,
  name         TEXT,
  date_added   TEXT,                          -- YYYY-MM-DD
  due_date     TEXT,                          -- YYYY-MM-DD
  ransomware   INTEGER NOT NULL DEFAULT 0,
  description  TEXT
) STRICT;
CREATE TABLE sec_nvd_cve (
  cve_id         TEXT PRIMARY KEY,
  cvss           REAL,
  severity       TEXT,
  published      TEXT,
  last_modified  TEXT,
  rejected       INTEGER NOT NULL DEFAULT 0,
  description    TEXT
) STRICT;
CREATE TABLE sec_nvd_cpe (
  cve_id   TEXT NOT NULL,
  cpe      TEXT NOT NULL,                     -- vendor:product (applications) or o:vendor:product
  part     TEXT NOT NULL DEFAULT 'a',
  ranges   TEXT NOT NULL,                     -- JSON [{exact?, si?, se?, ei?, ee?}]
  PRIMARY KEY (cve_id, cpe)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_secnvdcpe_cpe ON sec_nvd_cpe (cpe);
-- Per device, product and version, which source saw it. Installed software reaches its CVEs through sec_pair_cve.
CREATE TABLE sec_evidence (
  device_id    INTEGER NOT NULL,
  product_key  TEXT    NOT NULL,
  version      TEXT    NOT NULL DEFAULT '',
  source       TEXT    NOT NULL,              -- ninja_software (this slice) | process | msrc | blackpoint | advisory
  attribution  TEXT,
  detail       TEXT,                          -- JSON
  seen_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (device_id, product_key, version, source)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_secev_product ON sec_evidence (product_key, version);
-- Every CVE of each vulnerable (product, version). Device x CVE is never stored.
CREATE TABLE sec_pair_cve (
  product_key  TEXT NOT NULL,
  version      TEXT NOT NULL,
  cve_id       TEXT NOT NULL,
  cvss         REAL,
  kev          INTEGER NOT NULL DEFAULT 0,
  published    TEXT,
  PRIMARY KEY (product_key, version, cve_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_secpc_cve ON sec_pair_cve (cve_id);
-- Sources that name CVEs directly, per device (msrc, blackpoint, advisory): empty until their slices.
CREATE TABLE sec_evidence_cve (
  device_id    INTEGER NOT NULL,
  cve_id       TEXT    NOT NULL,
  product_key  TEXT    NOT NULL,
  version      TEXT    NOT NULL DEFAULT '',
  source       TEXT    NOT NULL,
  attribution  TEXT,
  cvss         REAL,
  exploited    INTEGER NOT NULL DEFAULT 0,
  detail       TEXT,                          -- JSON
  PRIMARY KEY (device_id, cve_id, source, product_key)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_secevc_cve ON sec_evidence_cve (cve_id);
-- Device x CVE with every source that carries it: what every count and list reads.
CREATE VIEW sec_cve_evidence AS
  SELECT e.device_id, p.cve_id, e.product_key, e.version, e.source, e.attribution, e.detail, p.cvss, p.kev, 0 AS exploited
    FROM sec_evidence e JOIN sec_pair_cve p ON p.product_key = e.product_key AND p.version = e.version
   WHERE e.source IN ('ninja_software', 'process')
  UNION ALL
  SELECT c.device_id, c.cve_id, c.product_key, c.version, c.source, c.attribution, c.detail, COALESCE(n.cvss, c.cvss) AS cvss,
         (k.cve_id IS NOT NULL) AS kev, c.exploited
    FROM sec_evidence_cve c LEFT JOIN sec_nvd_cve n ON n.cve_id = c.cve_id LEFT JOIN sec_kev k ON k.cve_id = c.cve_id;
