-- Blackpoint CompassOne: the same tables as migrations/sqlite/0030_blackpoint.sql, in PostgreSQL's types.
-- A tenant is a client only once a signed-in user confirms it; the connector only suggests, and a suggestion scopes
-- nothing. Dark-web rows keep the email, source, date and kind only: never a password, a hash or another secret.
CREATE TABLE bp_tenant (
  tenant_id         text PRIMARY KEY,
  name              text NOT NULL,
  name_key          text NOT NULL,
  domain            text,
  suggested_org_id  bigint,
  suggested_by      text,
  org_id            bigint,
  not_client        boolean NOT NULL DEFAULT false,
  mapped_by         text,
  mapped_at         timestamptz,
  vm_licensed       boolean NOT NULL DEFAULT false,
  open_detections   bigint NOT NULL DEFAULT 0,
  synced_at         timestamptz,
  detections_at     timestamptz,
  vulns_at          timestamptz,
  seen_at           timestamptz NOT NULL DEFAULT now(),
  deleted_at        timestamptz
);
CREATE TABLE bp_asset (
  asset_id      text PRIMARY KEY,
  tenant_id     text NOT NULL,
  hostname      text,
  os_name       text,
  last_seen_on  timestamptz,
  device_id     bigint,
  synced_at     timestamptz NOT NULL,
  deleted_at    timestamptz
);
CREATE INDEX ix_bp_asset_tenant ON bp_asset (tenant_id) WHERE deleted_at IS NULL;
CREATE TABLE bp_vulnerability (
  vuln_id         text PRIMARY KEY,
  tenant_id       text NOT NULL,
  cve_id          text,
  name            text,
  severity        text,
  base_score      double precision,
  exploitability  text,
  status          text,
  prioritized     boolean NOT NULL DEFAULT false,
  assets_amount   bigint,
  app_vendor      text,
  app_name        text,
  found_on        timestamptz,
  last_seen_on    timestamptz,
  linked_at       timestamptz,
  synced_at       timestamptz NOT NULL
);
CREATE INDEX ix_bp_vuln_tenant ON bp_vulnerability (tenant_id);
CREATE TABLE bp_vulnerability_asset (
  vuln_id       text NOT NULL,
  asset_id      text NOT NULL,
  tenant_id     text NOT NULL,
  status        text,
  last_seen_on  timestamptz,
  PRIMARY KEY (vuln_id, asset_id)
);
CREATE TABLE bp_detection (
  detection_id    text PRIMARY KEY,
  tenant_id       text NOT NULL,
  status          text NOT NULL,
  risk_score      bigint,
  alert_count     bigint,
  alert_types     jsonb,
  hostname        text,
  username        text,
  detection_name  text,
  rule_name       text,
  created         timestamptz,
  updated         timestamptz,
  last_seen_open  timestamptz,
  synced_at       timestamptz NOT NULL
);
CREATE INDEX ix_bp_detection_tenant ON bp_detection (tenant_id, status);
CREATE TABLE bp_darkweb (
  exposure_id  text PRIMARY KEY,
  tenant_id    text NOT NULL,
  email        text,
  source       text,
  found_on     date,
  kind         text NOT NULL,
  synced_at    timestamptz NOT NULL,
  deleted_at   timestamptz
);
CREATE INDEX ix_bp_darkweb_tenant ON bp_darkweb (tenant_id) WHERE deleted_at IS NULL;
