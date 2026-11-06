-- Internet exposure (src/connectors/shodan.rs, src/connectors/ninja_wan.rs): the public addresses clients'
-- servers and desktops reach the internet from (NinjaOne's view; laptops left out), the addresses clients' websites
-- resolve to, and what Shodan's own internet scan saw open on each.
-- Nothing is sent to a client's network except the scans a scan policy asks for.

-- Each device's public address, as NinjaOne last reported it (only public IPv4; private, CGNAT and the like dropped).
CREATE TABLE device_wan (
  device_id   INTEGER PRIMARY KEY,
  org_id      INTEGER NOT NULL,
  public_ip   TEXT NOT NULL,
  seen_at     TEXT NOT NULL
) STRICT;
CREATE INDEX ix_device_wan_ip ON device_wan (public_ip);
-- What Shodan knows of one address: found = 0 when it has nothing on it. Lists are JSON arrays.
CREATE TABLE exposure_host (
  ip                      TEXT PRIMARY KEY,
  found                   INTEGER NOT NULL DEFAULT 0,
  looked_up_at            TEXT,
  provider_updated_at     TEXT,
  ports                   TEXT NOT NULL DEFAULT '[]',
  hostnames               TEXT NOT NULL DEFAULT '[]',
  tags                    TEXT NOT NULL DEFAULT '[]',
  vulns                   TEXT NOT NULL DEFAULT '[]',
  net_org                 TEXT,
  isp                     TEXT,
  error                   TEXT,                -- a status and a short reason, never a URL (Shodan's key rides in it)
  last_scan_requested_at  TEXT,
  last_scan_completed_at  TEXT
) STRICT;
-- One open service on an address, and what the console's own NVD data says of its product and version.
CREATE TABLE exposure_service (
  ip           TEXT NOT NULL,
  port         INTEGER NOT NULL,
  transport    TEXT NOT NULL,
  product      TEXT,
  version      TEXT,
  cpes         TEXT NOT NULL DEFAULT '[]',
  vulns        TEXT NOT NULL DEFAULT '[]',     -- the CVEs Shodan attributes to this service's banner
  title        TEXT,
  seen_at      TEXT,
  nvd_cpe      TEXT,
  nvd_version  TEXT,
  nvd_cves     TEXT NOT NULL DEFAULT '[]',     -- the CVEs NVD's ranges put this version in
  PRIMARY KEY (ip, port, transport)
) STRICT, WITHOUT ROWID;
-- A client website's addresses and how each is read: client (its own WAN), shared (a CDN or shared host: nothing is
-- attributed to the client), dedicated (looked up like a WAN address), unknown or unresolved. Never scanned.
CREATE TABLE exposure_site (
  halo_client_id  INTEGER NOT NULL,
  org_id          INTEGER,
  hostname        TEXT NOT NULL,
  apex            TEXT,
  ip              TEXT NOT NULL DEFAULT '',
  classification  TEXT NOT NULL,
  provider        TEXT,
  reason          TEXT,
  looked_up_at    TEXT NOT NULL,
  PRIMARY KEY (halo_client_id, hostname, ip)
) STRICT, WITHOUT ROWID;
-- An address someone marked as an edge entry point: it's meant to face the internet (a VPN portal, a published web
-- server), so the exposure totals leave it out. Who marked it, and when, is kept.
CREATE TABLE exposure_mark (
  ip         TEXT PRIMARY KEY,
  edge       INTEGER NOT NULL,
  note       TEXT,
  marked_by  TEXT NOT NULL,
  marked_at  TEXT NOT NULL
) STRICT;
-- On-demand scans, per client: off unless an admin sets a frequency here. Who set it, and when, is kept.
CREATE TABLE scan_policy (
  org_id          INTEGER PRIMARY KEY,
  frequency_days  INTEGER NOT NULL,
  set_by          TEXT NOT NULL,
  set_at          TEXT NOT NULL
) STRICT;
-- Each scan asked of Shodan (one credit per address), and what it said.
CREATE TABLE scan_request (
  request_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id       TEXT,
  ips           TEXT NOT NULL,                 -- JSON array
  status        TEXT NOT NULL,
  credits_left  INTEGER,
  requested_at  TEXT NOT NULL,
  checked_at    TEXT,
  completed_at  TEXT,
  error         TEXT
) STRICT;
