-- Blackpoint CompassOne (src/connectors/blackpoint.rs): its tenants and the client each one is, its device
-- assets and the device each one is, its vulnerability findings and the devices that carry them, its open detections,
-- and its dark-web exposures. Only what the console shows.
--
-- The mapping (the rule for every vendor's clients, as for Halo): a tenant is a client only once a signed-in user confirms it (org_id with
-- mapped_by set). The connector only ever suggests (suggested_org_id, by the tenant's domain or name), and a
-- suggestion scopes nothing: no asset, finding or detection is tied to a client through it. A tenant someone marked
-- "not a client" has not_client = 1 and no org. A re-match never touches what a user decided.
CREATE TABLE bp_tenant (
  tenant_id         TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  name_key          TEXT NOT NULL,
  domain            TEXT,
  suggested_org_id  INTEGER,
  suggested_by      TEXT,                      -- domain | name | NULL
  org_id            INTEGER,                   -- confirmed by a user; NULL until then
  not_client        INTEGER NOT NULL DEFAULT 0,
  mapped_by         TEXT,                      -- who confirmed it (the signed-in user's email)
  mapped_at         TEXT,
  vm_licensed       INTEGER NOT NULL DEFAULT 0,
  open_detections   INTEGER NOT NULL DEFAULT 0,
  synced_at         TEXT,                      -- its assets last swept
  detections_at     TEXT,                      -- its detections last polled
  vulns_at          TEXT,                      -- its findings last listed
  seen_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  deleted_at        TEXT
) STRICT;
-- A device asset: the hostname, and the console's device it is (the hostname, inside the tenant's confirmed client).
CREATE TABLE bp_asset (
  asset_id      TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  hostname      TEXT,
  os_name       TEXT,
  last_seen_on  TEXT,
  device_id     INTEGER,
  synced_at     TEXT NOT NULL,
  deleted_at    TEXT
) STRICT;
CREATE INDEX ix_bp_asset_tenant ON bp_asset (tenant_id) WHERE deleted_at IS NULL;
CREATE TABLE bp_vulnerability (
  vuln_id         TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,
  cve_id          TEXT,
  name            TEXT,
  severity        TEXT,
  base_score      REAL,
  exploitability  TEXT,
  status          TEXT,
  prioritized     INTEGER NOT NULL DEFAULT 0,
  assets_amount   INTEGER,
  app_vendor      TEXT,
  app_name        TEXT,
  found_on        TEXT,
  last_seen_on    TEXT,
  linked_at       TEXT,                        -- its devices last read (one call per finding, budgeted)
  synced_at       TEXT NOT NULL
) STRICT;
CREATE INDEX ix_bp_vuln_tenant ON bp_vulnerability (tenant_id);
CREATE TABLE bp_vulnerability_asset (
  vuln_id       TEXT NOT NULL,
  asset_id      TEXT NOT NULL,
  tenant_id     TEXT NOT NULL,
  status        TEXT,
  last_seen_on  TEXT,
  PRIMARY KEY (vuln_id, asset_id)
) STRICT, WITHOUT ROWID;
-- An alert group: Blackpoint's detection. Open ones are polled every few minutes; one no longer returned as open is
-- marked closed (status 'closed').
CREATE TABLE bp_detection (
  detection_id    TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,
  status          TEXT NOT NULL,
  risk_score      INTEGER,
  alert_count     INTEGER,
  alert_types     TEXT,                        -- JSON array of strings
  hostname        TEXT,
  username        TEXT,
  detection_name  TEXT,
  rule_name       TEXT,
  created         TEXT,
  updated         TEXT,
  last_seen_open  TEXT,
  synced_at       TEXT NOT NULL
) STRICT;
CREATE INDEX ix_bp_detection_tenant ON bp_detection (tenant_id, status);
-- A dark-web exposure: the email, where it was seen (the breach's name), when, and what kind of data was exposed.
-- Nothing else is kept: never a password, a hash or any other secret, even when the vendor sends one.
CREATE TABLE bp_darkweb (
  exposure_id  TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  email        TEXT,
  source       TEXT,
  found_on     TEXT,                           -- YYYY-MM-DD
  kind         TEXT NOT NULL,                  -- password | username | email
  synced_at    TEXT NOT NULL,
  deleted_at   TEXT
) STRICT;
CREATE INDEX ix_bp_darkweb_tenant ON bp_darkweb (tenant_id) WHERE deleted_at IS NULL;
