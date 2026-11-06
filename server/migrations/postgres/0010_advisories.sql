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
  advisory_id    text PRIMARY KEY,
  cve_id         text NOT NULL,
  title          text NOT NULL,
  severity       text,                          -- critical | high | medium | low
  cvss           double precision,
  exploited      boolean NOT NULL DEFAULT FALSE,
  url            text,                          -- https only
  product_key    text NOT NULL,
  product_label  text,
  match          jsonb NOT NULL,                -- {name_re?, company_re?, product_re?, path_re?}
  ranges         jsonb NOT NULL,                -- [{exact?, si?, se?, ei?, ee?}]
  fixed_in       jsonb NOT NULL DEFAULT '[]',   -- ["24.22.1", ...]
  remedy         text,
  status         text NOT NULL DEFAULT 'active',-- active | superseded
  added_by       text,
  added_at       timestamptz NOT NULL DEFAULT now(),
  edited_by      text,
  edited_at      timestamptz,
  notes          text                           -- who superseded or reactivated it, when, and why
);
CREATE INDEX ix_secadv_cve ON sec_advisory (cve_id);
