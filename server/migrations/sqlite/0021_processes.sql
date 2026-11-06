-- Running processes: what the endpoint script (endpoint/process) saw running, read from its NinjaOne custom
-- field by the ninja_processes job, and what each binary is as a product (the process_match job).
--
-- What's kept of a binary: its name, SHA-256, up to five paths, file version, product, company, signer and signature
-- status, and how many instances ran. Never a command line (the script never collects one), never the user names it
-- ran as, never the services it hosts.

-- One device's binaries, replaced whole when a payload with a later collectedAt arrives.
CREATE TABLE device_process (
  device_id         INTEGER NOT NULL,
  key               TEXT    NOT NULL,              -- sha256:<hex>, or name:<binary> when it couldn't be hashed
  sha256            TEXT,
  name              TEXT    NOT NULL,
  paths             TEXT    NOT NULL DEFAULT '[]', -- JSON, up to five
  path_count        INTEGER NOT NULL DEFAULT 0,
  file_version      TEXT,
  product           TEXT,
  company           TEXT,
  signer            TEXT,
  signature_status  TEXT,
  trust             TEXT    NOT NULL,              -- invalid | unsigned | unchecked | unhashed | valid
  instance_count    INTEGER NOT NULL DEFAULT 0,
  collected_at      TEXT,
  PRIMARY KEY (device_id, key)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_devproc_sha ON device_process (sha256);
CREATE INDEX ix_devproc_product ON device_process (product, company, file_version);
-- Per device, the payload's header and the last read: when it was collected, when the device last ran the script,
-- the content hash and the bytes field's time it was read at, and the last error (a sentence, never the payload).
CREATE TABLE process_snapshot (
  device_id         INTEGER PRIMARY KEY,
  collected_at      TEXT,
  last_seen_at      TEXT,
  bytes_updated_at  TEXT,
  content_hash      TEXT,
  script_version    TEXT,
  binary_count      INTEGER,
  rows              INTEGER NOT NULL DEFAULT 0,
  trimmed           INTEGER NOT NULL DEFAULT 0,
  error             TEXT,
  synced_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;

-- Each distinct (product, company, file version) running, and which product it is: by a curated rule, by the
-- inventory's automatic map, by a person's decision (reviewed), or by a confident NVD match (cpe), with how sure.
CREATE TABLE sec_process_class (
  product          TEXT NOT NULL,
  company          TEXT NOT NULL DEFAULT '',
  file_version     TEXT NOT NULL DEFAULT '',
  product_key      TEXT NOT NULL,
  product_version  TEXT,
  method           TEXT NOT NULL,                  -- rule | auto | reviewed | cpe
  confidence       REAL NOT NULL,
  devices          INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (product, company, file_version)
) STRICT, WITHOUT ROWID;
CREATE INDEX ix_secpclass_key ON sec_process_class (product_key);

-- Names the automatic mapping wouldn't decide (no NVD product whose vendor is the publisher, or several), for a person
-- to decide: a running binary's product and company (kind 'process'), or an installed program's name and publisher
-- (kind 'software'). Never applied on its own; a signed-in user accepts one candidate or rejects the name, and the
-- match jobs apply that at their next run. Per name, whatever the version. Who decided is the user's sign-in, kept
-- with the decision as the audit log keeps it.
CREATE TABLE sec_map_review (
  kind        TEXT NOT NULL,                       -- process | software
  name        TEXT NOT NULL,
  company     TEXT NOT NULL DEFAULT '',
  candidates  TEXT NOT NULL DEFAULT '[]',          -- JSON [{vendor, product, key, vendor_match, confidence}]
  versions    TEXT NOT NULL DEFAULT '[]',          -- JSON
  devices     INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'pending',     -- pending | accepted | rejected
  cpe         TEXT,                                -- the accepted vendor:product
  decided_by  TEXT,
  decided_at  TEXT,
  first_seen  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_seen   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  PRIMARY KEY (kind, name, company)
) STRICT, WITHOUT ROWID;
