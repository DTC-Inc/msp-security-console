-- Vendor advisories entered by hand ahead of NVD: a person's
-- rule for a CVE NVD doesn't cover yet. Which software it is about (`match`: regexes, case-insensitive, every one given
-- must hold: name_re and company_re against an installed program's name and publisher; product_re and path_re against
-- a running binary's, which the process match reads), the affected versions (`ranges`, matching.rs's Range), and the
-- fixed ones. Only 'active' rules apply. The match job turns them into `advisory` evidence (sec_evidence_cve), and a
-- save applies them at once.
--
-- What it holds: vendor facts and the staff member who entered or changed each one (an email, the console's own user);
-- no client data. Saving needs an admin, and every save is an audit line (src/admin.rs).
CREATE TABLE sec_advisory (
  advisory_id    TEXT PRIMARY KEY,
  cve_id         TEXT NOT NULL,
  title          TEXT NOT NULL,
  severity       TEXT,                          -- critical | high | medium | low
  cvss           REAL,
  exploited      INTEGER NOT NULL DEFAULT 0,
  url            TEXT,                          -- https only
  product_key    TEXT NOT NULL,
  product_label  TEXT,
  match          TEXT NOT NULL,                 -- JSON {name_re?, company_re?, product_re?, path_re?}
  ranges         TEXT NOT NULL,                 -- JSON [{exact?, si?, se?, ei?, ee?}]
  fixed_in       TEXT NOT NULL DEFAULT '[]',    -- JSON ["24.22.1", ...]
  remedy         TEXT,
  status         TEXT NOT NULL DEFAULT 'active',-- active | superseded
  added_by       TEXT,
  added_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  edited_by      TEXT,
  edited_at      TEXT,
  notes          TEXT                           -- who superseded or reactivated it, when, and why
) STRICT;
CREATE INDEX ix_secadv_cve ON sec_advisory (cve_id);
