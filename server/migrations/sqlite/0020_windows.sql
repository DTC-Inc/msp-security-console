-- Windows itself: Microsoft's monthly security updates (MSRC's CVRF documents), each Windows device's updates
-- from NinjaOne, and where every Windows device stands against them (src/windows.rs, src/connectors/msrc.rs,
-- src/connectors/ninja_os.rs). Data only: a CVE, a product, a KB, a build.

-- The device's build as NinjaOne reports it (os.buildNumber: "22631", no revision). Written by ninja_devices.
ALTER TABLE device ADD COLUMN os_build TEXT;

-- One row per month Microsoft published: a month is read again only when its revision date moves.
CREATE TABLE sec_msrc_doc (
  doc_id                TEXT PRIMARY KEY,          -- '2026-Oct'
  initial_release_date  TEXT,
  current_release_date  TEXT,                      -- Microsoft's revision
  fixes                 INTEGER NOT NULL DEFAULT 0,
  loaded_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;
-- Per (CVE, Windows product): the earliest build that fixes it, and the update (KB) that brings it.
CREATE TABLE sec_msrc_fix (
  cve          TEXT    NOT NULL,
  product_id   TEXT    NOT NULL,                   -- MSRC's ProductID
  product      TEXT    NOT NULL,                   -- 'Windows 11 Version 24H2 for x64-based Systems'
  server       INTEGER NOT NULL,
  build_major  INTEGER NOT NULL,                   -- 26100
  fixed_build  TEXT    NOT NULL,                   -- '10.0.26100.9445'
  fixed_rev    INTEGER NOT NULL,                   -- 9445
  kb           TEXT    NOT NULL,                   -- '5124008', without the KB prefix
  severity     TEXT,                               -- critical | important | moderate | low
  exploited    INTEGER NOT NULL DEFAULT 0,
  title        TEXT,
  doc_id       TEXT,
  PRIMARY KEY (cve, product_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_secmsrc_build ON sec_msrc_fix (build_major, server);

-- NinjaOne's OS patches, per device (the ninja_os_patches job). Installed Windows cumulative updates only (a device's
-- revision is the newest of them), kept 400 days; and the OS patches NinjaOne has waiting (APPROVED, MANUAL) or saw
-- fail (FAILED), by KB. Never a patch's free text.
CREATE TABLE os_update_installed (
  device_id     INTEGER NOT NULL,
  kb            TEXT    NOT NULL,
  installed_at  TEXT    NOT NULL,
  PRIMARY KEY (device_id, kb)
) STRICT, WITHOUT ROWID;
CREATE TABLE os_patch (
  device_id  INTEGER NOT NULL,
  patch_id   TEXT    NOT NULL,
  status     TEXT    NOT NULL,                     -- APPROVED | MANUAL (waiting) | FAILED
  kb         TEXT,
  at         TEXT,                                 -- when it failed (FAILED), or NinjaOne's time for it
  PRIMARY KEY (device_id, patch_id, status)
) STRICT, WITHOUT ROWID;

-- Every Windows device against those fixes (windows::match_all), replaced per run. The device row carries its state
-- (vulnerable | patched | unknown | untracked); findings are the vulnerable CVEs only.
CREATE TABLE sec_windows_device (
  device_id          INTEGER PRIMARY KEY,
  server             INTEGER NOT NULL,
  build_major        INTEGER,
  rev                INTEGER,
  rev_source         TEXT,                         -- build | updates (the newest installed cumulative update) | NULL
  state              TEXT NOT NULL,
  needed_kb          TEXT,                         -- the update that closes every open CVE
  needed_build       TEXT,
  latest_kb          TEXT,                         -- the newest fix Microsoft has published for this build
  latest_build       TEXT,
  cve_count          INTEGER,
  exploited_count    INTEGER,
  critical_count     INTEGER,
  update_pending_kb  TEXT,                         -- an update reaching needed_build, waiting in NinjaOne
  update_failed_kb   TEXT,                         -- one that failed in NinjaOne
  update_failed_at   TEXT
) STRICT;
CREATE TABLE sec_windows_finding (
  device_id    INTEGER NOT NULL,
  cve          TEXT    NOT NULL,
  kb           TEXT    NOT NULL,
  fixed_build  TEXT    NOT NULL,
  severity     TEXT,
  exploited    INTEGER NOT NULL DEFAULT 0,
  title        TEXT,
  PRIMARY KEY (device_id, cve)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_secwinf_cve ON sec_windows_finding (cve);
