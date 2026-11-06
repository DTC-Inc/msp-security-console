-- Internet exposure: the same tables as migrations/sqlite/0031_exposure.sql, in PostgreSQL's types.
CREATE TABLE device_wan (
  device_id   bigint PRIMARY KEY,
  org_id      bigint NOT NULL,
  public_ip   text NOT NULL,
  seen_at     timestamptz NOT NULL
);
CREATE INDEX ix_device_wan_ip ON device_wan (public_ip);
CREATE TABLE exposure_host (
  ip                      text PRIMARY KEY,
  found                   boolean NOT NULL DEFAULT false,
  looked_up_at            timestamptz,
  provider_updated_at     timestamptz,
  ports                   jsonb NOT NULL DEFAULT '[]',
  hostnames               jsonb NOT NULL DEFAULT '[]',
  tags                    jsonb NOT NULL DEFAULT '[]',
  vulns                   jsonb NOT NULL DEFAULT '[]',
  net_org                 text,
  isp                     text,
  error                   text,
  last_scan_requested_at  timestamptz,
  last_scan_completed_at  timestamptz
);
CREATE TABLE exposure_service (
  ip           text NOT NULL,
  port         bigint NOT NULL,
  transport    text NOT NULL,
  product      text,
  version      text,
  cpes         jsonb NOT NULL DEFAULT '[]',
  vulns        jsonb NOT NULL DEFAULT '[]',
  title        text,
  seen_at      timestamptz,
  nvd_cpe      text,
  nvd_version  text,
  nvd_cves     jsonb NOT NULL DEFAULT '[]',
  PRIMARY KEY (ip, port, transport)
);
CREATE TABLE exposure_site (
  halo_client_id  bigint NOT NULL,
  org_id          bigint,
  hostname        text NOT NULL,
  apex            text,
  ip              text NOT NULL DEFAULT '',
  classification  text NOT NULL,
  provider        text,
  reason          text,
  looked_up_at    timestamptz NOT NULL,
  PRIMARY KEY (halo_client_id, hostname, ip)
);
CREATE TABLE exposure_mark (
  ip         text PRIMARY KEY,
  edge       boolean NOT NULL,
  note       text,
  marked_by  text NOT NULL,
  marked_at  timestamptz NOT NULL
);
CREATE TABLE scan_policy (
  org_id          bigint PRIMARY KEY,
  frequency_days  bigint NOT NULL,
  set_by          text NOT NULL,
  set_at          timestamptz NOT NULL
);
CREATE TABLE scan_request (
  request_id    bigserial PRIMARY KEY,
  scan_id       text,
  ips           jsonb NOT NULL,
  status        text NOT NULL,
  credits_left  bigint,
  requested_at  timestamptz NOT NULL,
  checked_at    timestamptz,
  completed_at  timestamptz,
  error         text
);
