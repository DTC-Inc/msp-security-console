-- Halo tickets raised from findings (src/ops/tickets.rs). One row per finding: its key ('detection:<id>' or
-- 'exposure:<ip>') is the primary key, so a second click finds the first ticket instead of making another. A row is
-- written 'pending' before Halo is called and becomes 'created' with Halo's ticket id. A call Halo refused, or that
-- never reached it, removes it; one whose answer was lost after it was sent leaves it 'unknown', so no second ticket.
-- Who raised it, and when, is kept; the ticket's text is Halo's, not kept here.
CREATE TABLE finding_ticket (
  finding_key     TEXT PRIMARY KEY,
  state           TEXT NOT NULL,               -- pending | created | unknown
  halo_ticket_id  INTEGER,
  halo_client_id  INTEGER NOT NULL,
  org_id          INTEGER,
  created_by      TEXT NOT NULL,
  created_at      TEXT NOT NULL
) STRICT;
