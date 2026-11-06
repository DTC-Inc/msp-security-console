-- Halo tickets raised from findings: the same table as migrations/sqlite/0032_tickets.sql.
CREATE TABLE finding_ticket (
  finding_key     text PRIMARY KEY,
  state           text NOT NULL,
  halo_ticket_id  bigint,
  halo_client_id  bigint NOT NULL,
  org_id          bigint,
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL
);
