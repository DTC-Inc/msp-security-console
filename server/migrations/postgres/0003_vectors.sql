-- Vector search on PostgreSQL: pgvector, when the server has it. The same table as SQLite's sqlite-vec one
-- (migrations/sqlite/0003_vectors.sql): one 384-dimension vector per CVE per model, cosine distance, empty until the job
-- that embeds descriptions lands.
--
-- pgvector is an extension the database server has to carry, and many managed servers don't, or don't let every role
-- create it. So this migration never fails for want of it: it tries, and without it the console starts with
-- similar-CVE search off and says so in its start log and on /api/status. To turn it on later, install pgvector, run
-- CREATE EXTENSION vector as a role allowed to, and restart the console: msp_console_vectors() below runs at every
-- start, and makes the table once the extension is there. The extension's types must be on the console's search_path
-- (they are when it's created in the console's own schema, or in public).
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pgvector is not available to this role (%): similar-CVE search stays off', SQLERRM;
END
$$;

-- True when the vector table is there, after making it if pgvector is installed and the table isn't yet; false when
-- pgvector isn't installed. The index is HNSW (pgvector 0.5 and later); an older pgvector gets the table without it.
CREATE FUNCTION msp_console_vectors() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  IF to_regclass('vec_cve_description') IS NOT NULL THEN RETURN TRUE; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN RETURN FALSE; END IF;
  EXECUTE 'CREATE TABLE IF NOT EXISTS vec_cve_description (
             model      text NOT NULL,
             cve_id     text NOT NULL,
             embedding  vector(384) NOT NULL,
             PRIMARY KEY (model, cve_id))';
  BEGIN
    EXECUTE 'CREATE INDEX IF NOT EXISTS ix_vec_cve_description ON vec_cve_description USING hnsw (embedding vector_cosine_ops)';
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'no HNSW index on vec_cve_description (%): searches read the whole table', SQLERRM;
  END;
  RETURN TRUE;
END
$$;

SELECT msp_console_vectors();
