-- Running processes: the same tables as migrations/sqlite/0021_processes.sql, in PostgreSQL's types.
CREATE TABLE device_process (
  device_id         bigint  NOT NULL,
  key               text    NOT NULL,
  sha256            text,
  name              text    NOT NULL,
  paths             jsonb   NOT NULL DEFAULT '[]'::jsonb,
  path_count        bigint  NOT NULL DEFAULT 0,
  file_version      text,
  product           text,
  company           text,
  signer            text,
  signature_status  text,
  trust             text    NOT NULL,
  instance_count    bigint  NOT NULL DEFAULT 0,
  collected_at      timestamptz,
  PRIMARY KEY (device_id, key)
);
CREATE INDEX ix_devproc_sha ON device_process (sha256);
CREATE INDEX ix_devproc_product ON device_process (product, company, file_version);
CREATE TABLE process_snapshot (
  device_id         bigint PRIMARY KEY,
  collected_at      timestamptz,
  last_seen_at      timestamptz,
  bytes_updated_at  timestamptz,
  content_hash      text,
  script_version    text,
  binary_count      bigint,
  rows              bigint NOT NULL DEFAULT 0,
  trimmed           boolean NOT NULL DEFAULT false,
  error             text,
  synced_at         timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sec_process_class (
  product          text NOT NULL,
  company          text NOT NULL DEFAULT '',
  file_version     text NOT NULL DEFAULT '',
  product_key      text NOT NULL,
  product_version  text,
  method           text NOT NULL,
  confidence       double precision NOT NULL,
  devices          bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (product, company, file_version)
);
CREATE INDEX ix_secpclass_key ON sec_process_class (product_key);
CREATE TABLE sec_map_review (
  kind        text NOT NULL,
  name        text NOT NULL,
  company     text NOT NULL DEFAULT '',
  candidates  jsonb NOT NULL DEFAULT '[]'::jsonb,
  versions    jsonb NOT NULL DEFAULT '[]'::jsonb,
  devices     bigint NOT NULL DEFAULT 0,
  status      text NOT NULL DEFAULT 'pending',
  cpe         text,
  decided_by  text,
  decided_at  timestamptz,
  first_seen  timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, name, company)
);
