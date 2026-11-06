-- The console's own store on PostgreSQL: the same tables, columns and view as migrations/sqlite/0001_store.sql, in
-- PostgreSQL's own types. Embedded in the binary and applied at start; sqlx holds an advisory lock around the
-- migrations, so replicas starting together apply each one once.
--
-- Conventions, so every query can rely on them (and decode them as it does on SQLite):
--   - a time is timestamptz (Rust's chrono::DateTime<Utc> on both stores);
--   - a date is date;
--   - JSON is jsonb;
--   - a boolean is boolean;
--   - an id or a count is bigint (Rust's i64), a score double precision (Rust's f64).

-- ---- the scheduler: one row per job; the lease makes each job single-writer across replicas -----------------------
CREATE TABLE job (
  name             text PRIMARY KEY,
  every_secs       integer NOT NULL,
  next_run_at      timestamptz NOT NULL DEFAULT now(),
  lease_holder     text,
  lease_until      timestamptz,
  cursor           jsonb,                     -- the job's own resume point
  last_started_at  timestamptz,
  last_ok_at       timestamptz,
  last_error       text,                      -- a status and a short reason, never a URL or a secret
  last_detail      jsonb
);

-- ---- what the connectors collect (the installing MSP's own vendors) ----------------------------------------------
-- A client is a NinjaOne organization; its Halo client is linked by Halo's own ninjarmmid (confirmed) or by name (a
-- suggestion only: halo_matched_by = 'name', never used to scope anything a client sees). name_key is the name
-- lowercased with every run of anything but a-z and 0-9 made one space (db::name_key), for that suggestion.
CREATE TABLE client (
  org_id           bigint PRIMARY KEY,
  name             text NOT NULL,
  name_key         text NOT NULL,
  halo_client_id   bigint,
  halo_matched_by  text,                      -- ninjarmm_id | name | NULL
  seen_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz
);
CREATE TABLE halo_client (
  halo_client_id   bigint PRIMARY KEY,
  name             text NOT NULL,
  name_key         text NOT NULL,
  ninjarmm_org_id  bigint,
  website_sites    jsonb,                     -- [{url, hostname, apex}], normalised; never the raw text
  checked_at       timestamptz,               -- the last GET /Client/{id}
  seen_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz
);
CREATE INDEX ix_halo_client_name_key ON halo_client (name_key) WHERE deleted_at IS NULL;
CREATE TABLE device (
  device_id        bigint PRIMARY KEY,
  org_id           bigint NOT NULL,
  name             text NOT NULL,
  device_class     text NOT NULL,             -- server | desktop | laptop | other
  node_class       text,
  os_name          text,
  last_contact     timestamptz,
  seen_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz
);
CREATE INDEX ix_device_org ON device (org_id) WHERE deleted_at IS NULL;
CREATE TABLE software (
  device_id        bigint NOT NULL,
  org_id           bigint NOT NULL,
  name             text NOT NULL,
  publisher        text NOT NULL DEFAULT '',
  version          text NOT NULL DEFAULT '',
  PRIMARY KEY (device_id, name, publisher, version)
);
CREATE INDEX ix_software_org ON software (org_id);
CREATE TABLE software_sync (
  org_id           bigint PRIMARY KEY,
  synced_at        timestamptz NOT NULL,
  rows             bigint NOT NULL
);

-- ---- the evidence model: one store, every row tagged with the source that saw it ---------------------------------
CREATE TABLE sec_product (
  product_key  text PRIMARY KEY,
  label        text NOT NULL,
  cpe          text NOT NULL,                 -- NVD vendor:product, escapes as NVD writes them
  match        jsonb NOT NULL,                -- { name_re, publisher_re?, exclude_re?, version_from?, version_re? }
  sort_order   integer NOT NULL DEFAULT 100,
  active       boolean NOT NULL DEFAULT TRUE
);
-- Each distinct installed (name, publisher, version) and which product it is (NULL: not recognised). Rebuilt by the
-- match job; it's what keeps matching to one pass over distinct names, not over every device's every install.
CREATE TABLE sec_software_class (
  name             text NOT NULL,
  publisher        text NOT NULL DEFAULT '',
  version          text NOT NULL DEFAULT '',
  product_key      text,
  product_version  text,
  PRIMARY KEY (name, publisher, version)
);
CREATE TABLE sec_kev (
  cve_id       text PRIMARY KEY,
  vendor       text,
  product      text,
  name         text,
  date_added   date,
  due_date     date,
  ransomware   boolean NOT NULL DEFAULT FALSE,
  description  text
);
CREATE TABLE sec_nvd_cve (
  cve_id         text PRIMARY KEY,
  cvss           double precision,
  severity       text,
  published      timestamptz,
  last_modified  timestamptz,
  rejected       boolean NOT NULL DEFAULT FALSE,
  description    text
);
CREATE TABLE sec_nvd_cpe (
  cve_id   text NOT NULL,
  cpe      text NOT NULL,                     -- vendor:product (applications) or o:vendor:product
  part     text NOT NULL DEFAULT 'a',
  ranges   jsonb NOT NULL,                    -- [{exact?, si?, se?, ei?, ee?}]
  PRIMARY KEY (cve_id, cpe)
);
CREATE INDEX ix_secnvdcpe_cpe ON sec_nvd_cpe (cpe);
-- Per device, product and version, which source saw it. Installed software reaches its CVEs through sec_pair_cve.
CREATE TABLE sec_evidence (
  device_id    bigint NOT NULL,
  product_key  text   NOT NULL,
  version      text   NOT NULL DEFAULT '',
  source       text   NOT NULL,               -- ninja_software (this slice) | process | msrc | blackpoint | advisory
  attribution  text,
  detail       jsonb,
  seen_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, product_key, version, source)
);
CREATE INDEX ix_secev_product ON sec_evidence (product_key, version);
-- Every CVE of each vulnerable (product, version). Device x CVE is never stored.
CREATE TABLE sec_pair_cve (
  product_key  text NOT NULL,
  version      text NOT NULL,
  cve_id       text NOT NULL,
  cvss         double precision,
  kev          boolean NOT NULL DEFAULT FALSE,
  published    text,
  PRIMARY KEY (product_key, version, cve_id)
);
CREATE INDEX ix_secpc_cve ON sec_pair_cve (cve_id);
-- Sources that name CVEs directly, per device (msrc, blackpoint, advisory): empty until their slices.
CREATE TABLE sec_evidence_cve (
  device_id    bigint NOT NULL,
  cve_id       text   NOT NULL,
  product_key  text   NOT NULL,
  version      text   NOT NULL DEFAULT '',
  source       text   NOT NULL,
  attribution  text,
  cvss         double precision,
  exploited    boolean NOT NULL DEFAULT FALSE,
  detail       jsonb,
  PRIMARY KEY (device_id, cve_id, source, product_key)
);
CREATE INDEX ix_secevc_cve ON sec_evidence_cve (cve_id);
-- Device x CVE with every source that carries it: what every count and list reads.
CREATE VIEW sec_cve_evidence AS
  SELECT e.device_id, p.cve_id, e.product_key, e.version, e.source, e.attribution, e.detail, p.cvss, p.kev, FALSE AS exploited
    FROM sec_evidence e JOIN sec_pair_cve p ON p.product_key = e.product_key AND p.version = e.version
   WHERE e.source IN ('ninja_software', 'process')
  UNION ALL
  SELECT c.device_id, c.cve_id, c.product_key, c.version, c.source, c.attribution, c.detail, COALESCE(n.cvss, c.cvss) AS cvss,
         (k.cve_id IS NOT NULL) AS kev, c.exploited
    FROM sec_evidence_cve c LEFT JOIN sec_nvd_cve n ON n.cve_id = c.cve_id LEFT JOIN sec_kev k ON k.cve_id = c.cve_id;
