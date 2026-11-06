-- Windows itself: the same tables as migrations/sqlite/0020_windows.sql, in PostgreSQL's types.

ALTER TABLE device ADD COLUMN os_build text;

CREATE TABLE sec_msrc_doc (
  doc_id                text PRIMARY KEY,
  initial_release_date  timestamptz,
  current_release_date  timestamptz,
  fixes                 bigint NOT NULL DEFAULT 0,
  loaded_at             timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sec_msrc_fix (
  cve          text    NOT NULL,
  product_id   text    NOT NULL,
  product      text    NOT NULL,
  server       boolean NOT NULL,
  build_major  bigint  NOT NULL,
  fixed_build  text    NOT NULL,
  fixed_rev    bigint  NOT NULL,
  kb           text    NOT NULL,
  severity     text,
  exploited    boolean NOT NULL DEFAULT false,
  title        text,
  doc_id       text,
  PRIMARY KEY (cve, product_id)
);
CREATE INDEX ix_secmsrc_build ON sec_msrc_fix (build_major, server);

CREATE TABLE os_update_installed (
  device_id     bigint      NOT NULL,
  kb            text        NOT NULL,
  installed_at  timestamptz NOT NULL,
  PRIMARY KEY (device_id, kb)
);
CREATE TABLE os_patch (
  device_id  bigint NOT NULL,
  patch_id   text   NOT NULL,
  status     text   NOT NULL,
  kb         text,
  at         timestamptz,
  PRIMARY KEY (device_id, patch_id, status)
);

CREATE TABLE sec_windows_device (
  device_id          bigint PRIMARY KEY,
  server             boolean NOT NULL,
  build_major        bigint,
  rev                bigint,
  rev_source         text,
  state              text NOT NULL,
  needed_kb          text,
  needed_build       text,
  latest_kb          text,
  latest_build       text,
  cve_count          bigint,
  exploited_count    bigint,
  critical_count     bigint,
  update_pending_kb  text,
  update_failed_kb   text,
  update_failed_at   timestamptz
);
CREATE TABLE sec_windows_finding (
  device_id    bigint  NOT NULL,
  cve          text    NOT NULL,
  kb           text    NOT NULL,
  fixed_build  text    NOT NULL,
  severity     text,
  exploited    boolean NOT NULL DEFAULT false,
  title        text,
  PRIMARY KEY (device_id, cve)
);
CREATE INDEX ix_secwinf_cve ON sec_windows_finding (cve);
