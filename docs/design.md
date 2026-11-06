# MSP Security Console: design, rev 6

The design of the MSP Security Console: what it is, how it's built and why, how it's configured and deployed, and how it handles the data it holds. Each section says what the code does today; the issue numbers (`#n`) are this repository's.

What has changed, and why, in short:
- **The embedder runs inside the server** (bge-small-en-v1.5 on ONNX Runtime), so a CVE description never leaves the console ("The embedder", below). ONNX Runtime needs glibc and libstdc++, so the image is glibc on `distroless/cc`, not static musl.
- **The store is SQLite or PostgreSQL, picked at install.** SQLite is the default: one container with nothing else to run. PostgreSQL is for an MSP that wants more than one replica, or its own managed database.
- **The console is self-contained:** it keeps its own store, collects from the installing MSP's own vendors on its own scheduler, and is itself the API. Nothing it reads belongs to anyone else.
- **The server is Rust with Axum; sign-in is the installer's choice** (an identity-aware proxy, a trusted header, or the console's own OIDC sign-in); configuration comes from the environment or a guided first-run setup.

## What it is

A security console for any MSP, installed on its own and run against that MSP's own vendors. Its model:
- **The view:** clients → devices → software, and the CVEs that software carries.
- **The evidence:** what each source saw (installed, running, Windows updates, Blackpoint, advisories ahead of NVD, internet exposure).
- **The drill-down:** one drill-down from any record or count: every number is a link to the rows it counts.

## Stack, and the criteria behind it

- **Client:** a Solid web app on Vite, in `web/` (2026-11-05: React Native was stopped on every surface on 2026-10-30, and the house's web UIs are Solid). Phone apps, when they come, are their own decision.
  - It talks only to its own server and never holds a key.
  - **Tokens:** generated from the DTC design system's `design/console-tokens.css`, never copied by hand; a check fails if they drift.
- **Server:** Rust with Axum.
  - One binary that serves the web app's build beside `/api`, built against glibc, with SQLite and ONNX Runtime (the embedder's) linked into it.
- **Contract:** v1, with one source of truth: the Rust types (serde, unknown fields refused). From those:
  - `schemars` writes `packages/contract/contract.schema.json`;
  - a script generates the client's TypeScript types from that schema;
  - CI regenerates both and fails on any difference.
  - The shape is the evidence API's, including the list ops and filters, so every count opens its rows from day one.

## Repo, image, Kubernetes

- **Layout:**
  - `server/` (a Cargo crate: the binary, the contract types, the schema generator)
  - `web/` (the Solid web app)
  - `packages/contract` (the generated schema and types), `packages/tokens`
  - `deploy/k8s` (a kustomize base and components)
  - `Dockerfile`, `compose.yaml`, `docs/`
- **Image:** a multi-stage build.
  - Rust to a glibc binary on Debian 13 (`rust:1.99.1-trixie`), for amd64 or arm64. ONNX Runtime 1.31 is linked statically from pyke's prebuilt archive, which ort-sys checks against a SHA-256 in its own table (Cargo.lock pins ort-sys).
  - The embedding model is downloaded at build time from Hugging Face at pinned revisions, each file checked against a pinned SHA-256 (`scripts/fetch-model.sh`); a mismatch fails the build. It's baked in at `/models/bge-small-en-v1.5-int8`, read-only.
  - Vite builds the web app.
  - The runtime is `distroless/cc-debian13` (glibc and libstdc++, which ONNX Runtime needs; nothing else; Debian 13 because pyke's ONNX Runtime is built with GCC 14 and needs its libstdc++, which Debian 12's GCC 12 doesn't have), non-root (uid 65532), with a read-only root filesystem. The licences of what it carries beyond the console's own code are under `/licenses`: ONNX Runtime's and its third-party notices, the model's, and the tokenizer library's, each fetched at a pinned commit and SHA-256 (`scripts/fetch-licenses.sh`), with `THIRD_PARTY.md` saying which is which.
  - CI pushes it to GHCR, and deployments pin it by digest.
- **Kubernetes base:**
  - A Deployment (1 replica, `Recreate`, probes, limits), a Service, and a ReadWriteOnce PersistentVolumeClaim for the SQLite store at `/data`. With PostgreSQL, an overlay drops the claim and may run more replicas ("Deploying it yourself").
  - A ConfigMap for settings, and a Secret for secrets.
  - A NetworkPolicy: in from the auth layer only; out to DNS and 443.
  - Components for each way in: `cloudflared` (outbound-only tunnel), or an Ingress for an installer's own proxy or for `oidc`.

## Identity: the installer's choice

One trait, `Identity`: given a request, it returns who is signed in or refuses (401). Every `/api` call goes through it, failing closed. `AUTH_MODE` picks the implementation.

- **`proxy`:** a network auth layer in front of the app. `PROXY_KIND` picks how the server knows who's there.
  - **`cloudflare_access`:** the server verifies `Cf-Access-Jwt-Assertion` itself.
    - RS256 against the team's certs, cached and refetched on an unknown `kid`.
    - The application's audience tag, the team as issuer, the expiry.
    - The email, or a service token's common name, is the identity. Who may sign in is the Access policy's job (for example, one Entra group of technicians).
  - **`trusted_header`:** for a reverse proxy that authenticates and passes the user in a header (oauth2-proxy, Authelia, an Entra Application Proxy).
    - The server reads `TRUSTED_HEADER` (for example `X-Forwarded-Email`) only when the TCP peer is inside `TRUSTED_PROXY_CIDRS`, and refuses otherwise.
    - **The risk:** anyone who can reach the pod without passing the proxy can claim any identity. So this mode requires the CIDR list (no default), says so in its startup log line, and should sit behind the NetworkPolicy (in from the proxy only).
- **`oidc`:** the console's own sign-in, against Entra ID in any tenant (or any OIDC provider that puts groups or roles in its id_token).
  - **The flow:** authorization code with PKCE (S256), `state` and `nonce`. Discovery comes from `OIDC_ISSUER`, and the provider must call itself by that same issuer. It needs `OIDC_CLIENT_ID`, a client secret, and `PUBLIC_URL` (https; the redirect is `PUBLIC_URL/auth/callback`).
  - **The session:** an authenticated, encrypted cookie (XChaCha20-Poly1305, its key derived from `SESSION_KEY` with HKDF): `__Host-`, Secure, HttpOnly, SameSite=Lax, 8 hours. Replicas share nothing, and changing `SESSION_KEY` signs everyone out. The pending sign-in is a second sealed cookie (10 minutes), bound to its purpose so it can't pass for a session.
  - **The id_token** is checked against the provider's keys, the issuer, our client id as audience, the expiry, its not-before time (when it carries one) and our nonce.
  - **Access** needs `OIDC_ALLOWED_GROUP` in the token's `groups` or `roles`. When Entra leaves the groups out because the user has too many (its overage claim), the sign-in is refused and says to use an app role instead.
  - **Sign-out** is a POST from the console's own page (checked by `Origin`, or `Sec-Fetch-Site` where no `Origin` is sent), so another site can't sign someone out. It clears the cookie, and the page goes on to end the provider's session.
  - **Sessions are stateless:** the server keeps no list of who is signed in, so it can't end a session early. Removing someone from the allowed group takes effect when their cookie expires, up to 8 hours later. To cut everyone off at once, change `SESSION_KEY`.
  - **The return path:** only a path on this site, never another host.
### Admins

Everyone signed in reads everything. Only an **admin** changes the connectors' settings (Settings → Connectors) and the advisories; anyone else gets `403`, and the refusal is an audit line naming who. Admins are chosen by sign-in mode, and a setting for another mode refuses to start, so no one thinks it applies:
- **oidc:** `OIDC_ADMIN_GROUP`, a group or app role in the id_token (beside `OIDC_ALLOWED_GROUP`, which still decides who signs in at all). It's read at sign-in and kept in the session, so a change takes effect at the next sign-in, as membership does.
- **Cloudflare Access or a trusted header:** `ADMIN_EMAILS`, comma-separated addresses, compared without case.
- **Only this computer:** the local user is the admin.
- **None set:** no one is, and the start-up log says so. `GET /api/me` answers `admin`.

## Configuration: the environment, or a guided first run

- **Every setting has an environment variable,** and the same settings can live in a config file at `CONFIG_PATH` (default `/var/lib/msp-console/config.json`, on a mounted volume). **The environment always wins** over the file.
- **Every secret can come from `NAME` or `NAME_FILE`** (a mounted Secret), the file winning: the vendors' client secrets, `NVD_API_KEY`, `OIDC_CLIENT_SECRET`, `SESSION_KEY`, and `DATABASE_URL`, which carries the database's password and so is a secret as a whole. The SQLite store needs none.
- **Unconfigured, the console serves only the setup wizard.** That's when neither the environment nor the file sets any setting. Set one, and the console is either configured or refuses to start, naming what's missing. So the image itself sets none of them.
  - At boot it prints a one-time setup token to its log, once.
  - It serves the web app's files from `STATIC_DIR`. `/setup` and anything under it is the app's `index.html`, and the app shows the wizard. The app's assets are served as they are. Every other path redirects to `/setup`. `/healthz` answers, and `/readyz` says unconfigured.
  - Once configured, the wizard and its API are gone. A change goes through the environment or the file. An `/api` path the console doesn't have answers a JSON `404`, behind sign-in like the rest of `/api`, never the web app's `index.html`.
- **Only this computer (no sign-in).** For an owner trying the console on a laptop, with no proxy or HTTPS in front, sign-in has a fourth choice, "Only this computer (no sign-in)". It saves `AUTH_MODE=dev_insecure` alone, and anyone who can reach the port is signed in, so it's for a port bound to 127.0.0.1 (compose binds it there). It's offered only where start-up allows it: the state's `local_only` is true outside production and outside Kubernetes (no `KUBERNETES_SERVICE_HOST`). Elsewhere the wizard doesn't show it, and the Test and the save refuse it in a plain sentence. The image sets `MSP_ENV=production`, so trying it on one computer means `MSP_ENV=development` in `.env` first. With no sign-in, the console itself listens on 127.0.0.1 only, unless it runs in a container (there's a `/.dockerenv` or `/run/.containerenv`). In a container, 127.0.0.1 is the container's own loopback and the port mapping couldn't reach it, so it listens on every address and logs a warning at start: there, the port must be published on 127.0.0.1 alone, as `compose.yaml` does. Every other sign-in listens on every address.
- **The wizard has eight sections:** the database (a choice: "SQLite file on this volume", the default, with `DATABASE_PATH` and `BACKUP_KEEP`; or "PostgreSQL", with `DATABASE_URL` as a secret field and a note on TLS), sign-in (`AUTH_MODE` and that mode's settings, and `PUBLIC_URL`), NinjaOne (with the process-inventory field, `NINJA_PROCESS_FIELD`), HaloPSA (with its ticket settings, picked from Halo's own lists), NVD (with `NVD_FEEDS`, full or curated, and `NVD_FEED_URL`), Microsoft updates (`MSRC`, on or off, and `MSRC_URL`), Blackpoint (its address and API token) and Shodan (its API key, the month's scan credits, and who may set scan policies). Each has a live, read-only Test. A connector left empty stays off. CISA KEV is public and needs nothing. Settings only an operator would change (`KEV_URL`, `SCHEDULER`, `ACCESS_CERTS_URL`, the `_FILE` paths) aren't in the wizard. They're honoured when the environment sets them.

### The setup API

The wizard is a client of a small JSON API under `/api/setup`. Every call except `unlock` needs the setup cookie, and answers `401` without it.

| Call | What it does |
|---|---|
| `POST /api/setup/unlock` `{"token"}` | The right token answers `204` and sets the cookie `msp_setup`. It's sealed like the sign-in cookies (XChaCha20-Poly1305, its purpose bound in), under a key that lives only as long as the process. It lasts 30 minutes, and it's HttpOnly and SameSite=Strict. It's `Secure` unless the request came over plain http outside production. A wrong token is `401`. After ten, every unlock is `429` until a restart, which prints a new token. |
| `GET /api/setup/state` | Every setting the wizard knows, each with `set`, `env` (the environment sets it, so the wizard shows it read-only), `value` (filled only for settings that aren't secret), `secret` and `section`; the list of sections; and `local_only`, whether "Only this computer" may be chosen. A secret is only ever set or not. |
| `POST /api/setup/test` `{"section", "values"}` | A live, read-only check of one section. It answers `{"ok", "message", "status", "detail"}`. A secret left out of `values` falls back to the stored or environment one. |
| `POST /api/setup/save` `{"values"}` | It keeps the chosen sections' settings and drops the rest. For sign-in, that's only the chosen mode's settings, so a secret typed for another mode is never stored; for the database, only the chosen store's (a saved URL goes when the SQLite file is chosen, and the other way round). It also drops anything the environment sets. Then it checks the whole configuration with start-up's own rules, and that the store can be reached and written: the SQLite file's directory, or PostgreSQL as the database Test checks it. A problem is `400 {"error", "section"}`. Otherwise it writes the file (mode 0600, its secrets encrypted), answers `200 {"restarting": true, "master_key_path"}`, and exits so its supervisor restarts it configured. The web app polls `/readyz` until it answers. |

**What each Test does.** Each has a 15-second limit. A failure is a plain sentence with the vendor's HTTP status and that status's standard reason. It never includes the vendor's own error text (which can echo what it was sent), a URL, or a secret.
- **database:** for the SQLite file, its directory exists and takes a new file, and the file, if it's there, opens for writing. For PostgreSQL, the URL is checked by start-up's rules (TLS in production), the console connects and runs `SELECT 1`, makes a table inside a transaction it rolls back (proving the user may create tables in its schema, which a temporary table wouldn't), and says whether pgvector is installed, available to enable, or absent. Nothing is created or migrated, and a failure names what failed, never the URL, its host or its user.
- **sign-in:** for Cloudflare Access, it fetches the team's signing keys. For OIDC, it fetches the discovery document and checks that it names the configured issuer. For a trusted header, it checks the proxy's CIDRs by start-up's rules, with no network call. For no sign-in, it answers with its warning, or refuses in production or on Kubernetes.
- **NinjaOne:** a client-credentials token (scope `monitoring`), then one page of organizations.
- **HaloPSA:** a client-credentials token (scope `all`, and the tenant when `HALO_TENANT` is set) from `HALO_AUTH_URL`, or the base URL without `/api` plus `/auth/token`. Then one client, and the count of clients, and Halo's ticket types, statuses and priorities (those it lets the application read), for the ticket settings.
- **Blackpoint:** one page of tenants with the token, and the count.
- **Shodan:** the account information (`/api-info`), which spends nothing: the plan and the scan and query credits left.
- **NVD:** one CVE, with the `apiKey` header when a key is given. It answers the total and whether a key was used. A 403 or 404 with a key means NVD refused that key.

Every setup call writes an audit line (who `setup`; `setup.unlock`, `setup.state`, `setup.test.<section>` or `setup.save`; the status). The save's line lists the names of the settings it wrote, never their values.

### Settings → Connectors (admins, once configured)

The wizard's connector sections, after setup: every section the wizard registers except the database and sign-in, which change only by a new setup or the environment. The same rules: what the environment sets is shown read-only and never written; a secret is never shown, and one left blank keeps the saved one; Test is live and read-only; a stored or environment secret is never sent to an address the caller changed (`BOUND`).

| Call | What it does |
|---|---|
| `GET /api/admin/connectors` | Each connector's settings as `GET /api/setup/state` shows them, and `plaintext_secrets`: the names of secrets the file still holds unencrypted |
| `POST /api/admin/connectors/test` `{"section", "values"}` | The section's live Test, with what's stored, then what was sent, then the environment over both |
| `POST /api/admin/connectors/save` `{"section", "values", "off"?}` | Replaces that section's settings in the file (a setting sent is set, a plain one not sent is cleared, a secret not sent is kept; `off` clears the section), checks the whole file with start-up's own rules, encrypts every secret in it (re-encrypting any still in plaintext), writes it, and answers `{"restarting", "changed", "reencrypted"}` (names only). With nothing changed it writes nothing and doesn't restart |
| `POST /api/admin/advisories` `{"action", "advisory", "reason"}` | Save, supersede (a reason is required) or reactivate an advisory, then apply every advisory at once |

**A saved change restarts the console,** as setup's save does, rather than reloading the connector in place. Settings are read in one place, at start-up, with every refusal there; a connector's jobs, rate limiters and leases are built from them once; a restart is the one way all of them change together. A hot reload would be a second path for settings, a running job holding the old credentials under its lease, and, with several replicas on PostgreSQL, one replica on the new settings and the rest on the old. The jobs' cursors are in the store, so a restart resumes where they were. On Kubernetes, where settings come from the environment, the page shows them read-only; on several replicas, the config file must be on storage they share, or the settings set by environment.

Settings, and the wizard's review step, end with **what isn't connected yet**: each optional connector that's off, with one line on what turning it on adds (the section's `adds`).

Every call is an audit line naming the admin: `admin.connectors`, `admin.connectors.test.<section>`, `admin.connectors.save.<section>` with the names of the settings that changed and the secrets re-encrypted, never a value; `admin.advisories.<action>` with the advisory's id and CVE, never its title or rules.

### Secrets at rest

- **Each secret in the file is encrypted:** every `*_SECRET`, `SESSION_KEY`, `NVD_API_KEY` and `DATABASE_URL`. It's stored as `enc:v1:` and then base64url of a 24-byte nonce and the ciphertext. That's XChaCha20-Poly1305, under a key derived by HKDF-SHA256 from the master key (info `msp-console config v1`), with the setting's name as associated data, so a value can't be moved to another setting. The other settings stay readable.
- **The master key** is `CONSOLE_MASTER_KEY_FILE` or `CONSOLE_MASTER_KEY` (the file winning): 32 or more bytes, raw or base64. With neither, the first save that has a secret to write generates 32 random bytes, base64, into `MASTER_KEY_PATH` (default `/var/lib/msp-console-key/master.key`, mode 0600). It never replaces a key that's already there. The key never goes in the config file. On compose it's a volume of its own (`msp-console-key`), so the config and the key are backed up apart: whoever has both has the secrets, and losing the key means entering them again. On Kubernetes it's the Secret's `master-key`. The save's answer says where the key is, and the wizard tells the installer.
- **At start-up** the file's encrypted values are decrypted. The master key is looked for only when there's one to decrypt. If it can't decrypt (no key, the wrong key, a damaged value), it refuses to start, naming the setting, never the value.
- **A plaintext secret from before** still loads, with a warning at start-up naming the setting. Saving through setup again encrypts it, and so does moving it to the environment.
- **No secret appears** in a log line, an answer, `/api/status` or an audit record. The tests prove it: one runs the real binary through the whole wizard (right and wrong secrets, the save, the restart, a restart with the wrong key), then searches everything it wrote and answered for every secret used, the master key included.

## Self-contained: its own store, connectors and scheduler (rev 4)

- **Storage (rev 6): a SQLite file or a PostgreSQL database, the installer's choice.** Most MSPs want one container and nothing else to run, so the SQLite file stays the default. Some want more than one replica, or already run a managed PostgreSQL they back up and watch, and the console shouldn't make them keep a volume of its own for that. Both stores hold the same tables and answer the same contract, so the choice changes where the data lives and who backs it up, not what the console shows.
  - **Choosing:** `DATABASE_URL` (`postgres://…`, or `DATABASE_URL_FILE`) picks PostgreSQL. Otherwise it's the SQLite file at `DATABASE_PATH` (default `/data/console.db`). Both set from the same place (both by environment, or both in the config file) refuses to start; across the two, the environment's choice wins, as it does for every setting. The setup wizard asks the same question.
  - **One code path:** the queries are sqlx's, checked at run time, over one `Pool` that is either driver's (not sqlx's `Any`, which can't carry JSON, times or arrays faithfully). Where SQL is the same on both it's written once and compiled for each driver; where the dialects differ (reading JSON in bulk, an `IN` list, case-insensitive search, vectors, backups) it's written once per dialect, side by side. One Rust form for each kind of value: a time is `DateTime<Utc>`, a list for `IN` is `List`, JSON is `serde_json::Value`.
  - **The schema** is migrations embedded in the binary, one set per store (`server/migrations/sqlite`, `server/migrations/postgres`), applied at start. The SQLite set is the same three files as before PostgreSQL arrived, byte for byte (a test pins their checksums), so an existing store migrates cleanly. The product seed is the same text in both.
- **The SQLite store** is one file on the console's own volume. SQLite is linked into the binary, so the image still holds nothing else.
  - **One writer, by design.** On SQLite the console runs as one replica. Kubernetes uses `Recreate`, so an upgrade is a short gap rather than two processes on one file.
  - **The connection:** WAL (readers never wait for the writer), `foreign_keys=ON`, `busy_timeout` 5 s, `synchronous=NORMAL` (safe under WAL: a power cut can lose the last commits, never corrupt the file), and temporary tables in memory, because the root filesystem is read-only.
  - **It refuses to start** when `DATABASE_PATH`'s directory isn't writable (a volume that isn't mounted).
  - **One form for each kind of value:** a time is TEXT in ISO-8601 UTC with milliseconds (`2026-10-27T14:10:12.345Z`), so text order is time order; a date is `YYYY-MM-DD`; JSON is TEXT read with `->>` and `json_each`; a boolean is 0 or 1. The tables are `STRICT`.
  - **A daily copy:** the `backup` job runs `VACUUM INTO` to `/data/backup/console-<date>.db`, a consistent copy made while the console serves, and keeps the newest `BACKUP_KEEP` (default 7). Its last run is on `/api/status` with the other jobs.
  - **Vector search:** sqlite-vec 0.1.9 is compiled into the binary and registered as an auto-extension, so every connection has it and nothing is loaded from disk. The store refuses to open, before any migration, when a connection lacks it.
- **The PostgreSQL store** is a database the installer runs: their server, their backups, their monitoring.
  - **Types:** a time is `timestamptz`, a date `date`, JSON `jsonb`, a boolean `boolean`, an id `bigint`, a score `double precision`.
  - **TLS** is the URL's own `sslmode`. In production (`MSP_ENV=production`) the console must check the server's certificate: `verify-full` (the certificate, and that it names the URL's host), or `verify-ca` with the CA's certificate in `sslrootcert`. Everything else refuses to start, saying what to set: `disable`, `allow` and `prefer`, and `require` too, which encrypts but accepts any certificate for any host. Certificates are checked against the platform's roots unless `sslrootcert` names a CA. Outside production every mode is allowed, and anything short of a checked certificate is said at start and on `/api/status` (`store.tls.note`: "TLS without certificate check" for `require`). The first store's `DATABASE_SSLMODE` is refused rather than ignored, and says to use `sslmode` instead.
  - **One source of truth, the URL.** sqlx, like libpq, fills in whatever a URL leaves out from libpq's environment variables (`PGHOST`, `PGHOSTADDR`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGSSLMODE`, `PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`, `PGAPPNAME`, `PGOPTIONS`), and can't be told not to. Set, they'd change where or how the console connects without the URL saying so, so the console refuses to start while any of them is in its environment, naming it. In production the URL must also say `sslmode` itself.
  - **Never shown:** the URL is redacted in every debug form, and every error names `DATABASE_URL` and the kind of failure (the network, TLS, the user or password, no such database, a permission), never the host, the user or what the driver echoed back. A job's database failure on `/api/status` is its SQLSTATE and class, never the message, which can quote a value.
  - **Replicas:** more than one may run. Migrations take sqlx's advisory lock, so replicas starting together apply each once. Jobs are shared through their leases (below).
  - **Backups are the operator's.** The `backup` job isn't scheduled on PostgreSQL, `BACKUP_KEEP` is ignored with a warning, and `/api/status` says backups are yours: `pg_dump`, or the provider's snapshots.
  - **Vector search** is pgvector, when the server has it: `vector(384)`, cosine distance, an HNSW index. The search fetches the CVE's own vector first and orders by distance to it, so the index serves it (a test checks the plan on a seeded table). An HNSW index hands back its nearest candidates before the model filter applies, so pgvector 0.8 and later scan on until enough pass (`hnsw.iterative_scan`, in strict distance order), and every version gets a candidate list of at least 100 (`hnsw.ef_search`). Many managed servers don't carry it, or don't let every role enable it, so its migration never fails for want of it. Without it, similar-CVE search is off, and the start log and `/api/status` say so; everything else works. Installing pgvector later (`CREATE EXTENSION vector` as a role allowed to) and restarting turns it on: the console makes the table at start once the extension is there. The extension's types must be on the console's search path.
- **Vector search, on either store:** its first use is "similar to this CVE" by the meaning of NVD's description: `vec_cve_description` (one 384-dimension vector per CVE per model, so two models can coexist, cosine distance; `server/src/vectors.rs`). The `embed` job fills it, in-process ("The embedder", below), and records what it embedded from in `cve_embedded` (the description's SHA-256 and NVD's lastModified), written in the same transaction as each vector.
- **What differs between the stores,** beyond the above: search orders names the same way on both (SQLite's NOCASE: ASCII letters folded, then byte order, ties by the name's bytes), and matches case-insensitively for every letter on both (É matches é, ÄRZTE matches ärzte): ILIKE on PostgreSQL, and on SQLite `msp_fold`, Rust's Unicode lowercase, registered on every connection beside sqlite-vec and applied to both sides of `LIKE`; PostgreSQL's vector index is approximate (HNSW), where sqlite-vec reads every vector. Without similar-CVE search, PostgreSQL says which is missing: the extension, or (once it's installed) the table the next start makes. Nothing in the PostgreSQL schema or queries depends on `standard_conforming_strings`: the seed's backslashes are in `E''` strings, and the search's SQL has none.
- **The evidence model:** `sec_evidence`, `sec_pair_cve`, `sec_evidence_cve` and the `sec_cve_evidence` view; the product map (`sec_product`, seeded with 22 curated products), NVD and CISA KEV.
- **Contract v1** is `POST /api/evidence { op, params }`, answered in-process from the console's own store. Every op in the contract is answered ("The evidence API" below): the dispatcher's match is exhaustive, so an op added without an answer doesn't build.
- **Advisories ahead of NVD** (`sec_advisory`, migration 0010): a person's rule for a CVE NVD doesn't cover yet. It names the software (`match`: `name_re` and `company_re` against an installed program's name and publisher, or a running binary's name and company; `product_re` and `path_re` against a running binary alone; every one given must hold, case-insensitively), the affected versions (`ranges`, the same ranges NVD's are read into) and the fixed ones. The match job turns active advisories into `advisory` evidence on the devices whose installed software they name (`sec_evidence_cve`, `detail.via = "installed"`), and a save applies them at once. The process match (the windows-processes area) applies the same rules to running binaries with `advisory::Rules::hits`, writing its own rows, which the installed pass never touches. Superseding is a reviewed decision with a reason, kept in the advisory's notes with who and when.
- **Connectors:** one module per vendor (`server/src/connectors`), each with its settings, its own auth, a rate limiter, and its jobs. A connector is on when all its settings are there, off when none are, and a refusal to start when only some are.
  - **NinjaOne** (`NINJA_BASE_URL`, `NINJA_CLIENT_ID`, `NINJA_CLIENT_SECRET`): client credentials, scope monitoring (read-only). It reads organizations (the console's clients), devices (class from the node class and chassis) and installed software, one organization at a time with a cursor.
  - **HaloPSA** (`HALO_BASE_URL`, `HALO_CLIENT_ID`, `HALO_CLIENT_SECRET`, optional `HALO_AUTH_URL`, `HALO_TENANT`):
    - **What it reads:** clients, each one's NinjaOne link (`ninjarmmid`) and its websites (normalised; the raw text is never kept).
    - **The limit:** Halo's 700 requests per 5 minutes is the whole tenant's, so the console takes `HALO_REQUESTS_PER_5MIN` (default 150) and waits at least a minute after a 429.
    - **The mapping:** an org that exactly one Halo client links to is confirmed. A matching name is only a suggestion. The same rule holds for every vendor's clients: a vendor's own link confirms, a name only suggests.
  - **Blackpoint CompassOne** (`BLACKPOINT_BASE_URL`, `BLACKPOINT_API_TOKEN`, `src/connectors/blackpoint.rs`): read-only.
    - **What it reads:** tenants, each tenant's device assets, whether its vulnerability detail is licensed, its open detections (alert groups, every 10 minutes), and, for licensed tenants, its findings, the devices the important ones are on (one call each: attacked, prioritized, critical, high), and its dark-web exposures.
    - **The mapping (the same rule):** the connector only suggests a tenant's client, by its domain (one client whose Halo website shares it, where that Halo link is confirmed) or its name (one client, corporate suffixes aside). A suggestion scopes nothing; a signed-in person confirms it (or says "not a client") on the Blackpoint tenants page, and a re-match never touches that decision. Assets become devices by hostname inside a confirmed client only.
    - **Evidence:** each open finding on a matched device is `blackpoint` evidence, its product attributed by what's known of the device (`nvd-match` when the CVE's NVD product is already known on the device, else `bp-app`).
    - **The rate budget:** every answer's `x-ratelimit-remaining` and `x-ratelimit-reset` are read. Below a reserve (100; the detections poll keeps 1,000 for the daily sweeps) a call waits for a reset that's near, and otherwise the sweep stops and the rest is the next run's. A 429 pauses every call until its reset.
  - **Shodan** (`SHODAN_API_KEY`, optional `SHODAN_URL`, `SHODAN_SCAN_CREDITS_PER_MONTH` default 100, `SCAN_POLICY_ADMINS` for anyone beside the console's admins who may set scan policies, `src/connectors/shodan.rs`):
    - **Addresses:** each server's and desktop's public IPv4 from NinjaOne (devices-detailed's `publicIP`, read in the ninja_devices pass, so no extra calls; laptops and private, CGNAT and link-local addresses left out), and the addresses clients' websites resolve to (`/dns/resolve`, for clients whose Halo link is confirmed). A site's address is the client's own WAN, a shared host or CDN (by Shodan's org, ISP or ASN, or more than 10 other domains on it: nothing is attributed to the client), a dedicated server (looked up like a WAN address), or unknown.
    - **Passive first:** a lookup reads Shodan's own scan (`/shodan/host`), daily; services are matched against the console's NVD data by the CPE Shodan saw. An on-demand scan (`/shodan/scan`, a credit per address) is asked for only for a client whose scan policy an admin turned on, only when due, never for a website's address, and never beyond the month's credits or what Shodan says is left. Credits left are on Status (the job's detail). The key rides in the query string, so no URL is ever logged or stored.
    - **Edge entry points:** anyone signed in can mark an address as meant to face the internet; it counts in no total.
  - **Halo tickets from findings** (`HALO_TICKET_TYPE_ID`, `HALO_TICKET_STATUS_ID`, `HALO_TICKET_PRIORITY_ID`, all three or none, with Halo on; `src/ops/tickets.rs`): a signed-in person raises a ticket from a detection or an exposed address. The dialog shows the ticket exactly as it will be sent; the server sends it only with that preview's digest, once per finding (a claimed row, so a double click makes one ticket), only to a client whose Halo link is confirmed, through Halo's one limiter, and audits who did it. The setup wizard reads Halo's ticket types, statuses and priorities so the installer picks them; there are no defaults. The Halo API application needs permission to create tickets for this.
  - **CISA KEV** and **NVD** are public and always on. NVD is read whole, from its yearly feeds (`NVD_FEEDS=full`, the default; below), or with `NVD_FEEDS=curated` per curated product (CVE API 2.0, `virtualMatchString`), then only what changed. `NVD_API_KEY` (optional) raises the API's limit tenfold; the feeds need none.
  - **Microsoft's security updates (MSRC)** are public and on unless `MSRC=off` (below).
  - **Secrets** never reach a log, the database or `/api/status`. A vendor's error is its status and short reason, never a URL.
- **The scheduler** runs inside the server. Each job is a row in `job`.
  - **Claiming:** a process runs a job only after claiming its lease with one conditional `UPDATE … RETURNING` (due, and no live lease), renews the lease while it runs, and releases it with the result and the job's cursor. On SQLite, with one replica, the lease keeps a job from running twice at once. On PostgreSQL it's how replicas share the jobs: two claims at once can't both win, because PostgreSQL locks the row for the first and checks the second's condition again against what the first wrote. The lease's clock there is the database's (`now()`), so replicas whose clocks disagree still agree on when a lease ends. A test runs eight processes claiming one due job at once, twenty rounds, on both stores: one winner each round.
  - **Failure:** a process that dies mid-run holds the lease no longer than its 2 minutes; then another replica, or the same one restarted, runs the job again from its last cursor. A failed run keeps its cursor and is retried within 15 minutes.
  - **Visibility:** `GET /api/status` (signed in) lists each job's last success, last error and next run, and the store: which kind, whether similar-CVE search is on (and why not), and whose the backups are. `SCHEDULER=off` serves what's stored without collecting more.
- **The match job** classifies each distinct installed (name, publisher, version) once, writes `ninja_software` evidence per device, and compares each (product, version) installed or running with NVD's affected ranges into `sec_pair_cve`. A rejected CVE is no one's.

### Windows, running processes and the whole of NVD

Three more evidence sources.

- **Windows itself (`msrc`):** the `msrc` job reads MSRC's CVRF API (`api.msrc.microsoft.com/cvrf/v3.0`, public, no key; on unless `MSRC=off`): the last 24 months, newest first, each month again only when Microsoft revised it. Per (CVE, Windows product) it keeps the earliest build that fixes it and the KB that brings it (`sec_msrc_fix`). Build 26100 is Windows 11 24H2 and Server 2025, fixed at different revisions, so a match keys on (build, server), never the build alone.
  - **Each device's patch level:** NinjaOne's build number has no revision, so the `ninja_os_patches` job (with NinjaOne and MSRC both on, twice a day) reads the Windows cumulative updates each device installed (45 days the first time, then two days' overlap), and the OS patches NinjaOne has waiting or saw fail, by KB (`os_update_installed`, `os_patch`). A device's revision is its newest installed cumulative update that Microsoft's data names for its own build.
  - **The match** (both jobs end with it) writes `sec_windows_device` (vulnerable, patched, unknown, untracked) and `sec_windows_finding` (the open CVEs and each one's KB), and the `msrc` evidence: product `msrc:windows`, version the build, its CVEs as Microsoft names them. **A device whose patch level can't be read is `unknown`, never patched**; it still says when the update for its build is waiting or failed in NinjaOne. Nothing is matched before Microsoft's data is loaded.
  - **Ops:** `windows.devices` (patch state per device, worst first; totals per state; `state` narrows) and `windows.cves` (each open CVE with the KB that fixes it on each build and how many devices need it), each by `org_id`, `device_id` or everywhere.
- **Running processes (`process`):** optional. It needs the endpoint script (`endpoint/process`) deployed through the MSP's NinjaOne; without it the job says no device has the field, and nothing else.
  - **Reading:** the `ninja_processes` job (every 30 minutes) reads the field the script writes (`NINJA_PROCESS_FIELD`, default `processInventory`, and its companions `<field>CollectedAt`, `<field>Hash`, `<field>Bytes`) in two phases: the small companions for every device, then the payloads (`df=id in (…)`, 100 at a time) only for devices whose content hash moved. **A quiet run downloads no payloads.** A payload is base64 of gzipped JSON, schema 1; **an unknown schema is refused** (the device keeps its rows, and its snapshot says why), a payload decompressing past 16 MB is refused, and **an older payload never replaces a newer one**. A device that hasn't run the script for 30 days loses its rows.
  - **Kept:** per binary its name, SHA-256, up to five paths, file version, product, company, signer and signature, and its instance count (`device_process`). Never a command line (the script never collects one), the users it ran as, or the services it hosts.
  - **Classified** (`process_match`, every 30 minutes) per distinct (product, company, file version), with a confidence: a curated rule (1.0), the installed program's automatic map, a person's decision (1.0), or one NVD product whose vendor is the company (0.9). Windows' own binaries are left to `msrc`. Then the `process` evidence, and the match compares what's running with NVD.
  - **Ops:** `processes.list` (the binaries, worst signature first, then those with CVEs, then the rarest; by hash, text, client, device, product or trust; a hash or a device lists where it runs and from which paths).
- **The review list:** a name the automatic mapping won't decide (NVD has products by that name, but none or several whose vendor is the publisher), running or installed, waits in `sec_map_review` with its candidates and their confidence, and is matched to nothing until a person decides. `processes.review` lists them; `POST /api/review {kind, name, company, decision: accept | reject | reopen, cpe}` decides one: signed in, only one of the name's own candidates, confirmed on the page first, audited (`review.decide`, who and the decision, never the name), and idempotent, so a second click changes nothing. The match jobs apply it at their next run.
- **The whole of NVD is the default** (`NVD_FEEDS=full`); `NVD_FEEDS=curated` is the opt-out, for a console that reads only the curated products through NVD's API. What full costs, measured (below): the first load is about 39 seconds on a fast link, the SQLite file grows by about 389 MB, and the embedder then takes about 3 hours, in 30-second runs every 2 minutes, to embed the roughly 400,000 descriptions for similar-CVE search. Nothing waits for the embedder: every count and list answers as soon as a year is loaded.
- **The `nvd_feeds` job** (hourly) loads NVD's JSON 2.0 yearly feeds, 2002 to now, then applies the modified feed (after any year loads, and at least every 12 hours). A year is read again when the modified chain has a gap (not applied for 7 days) and weekly.
  - **Bounded memory:** nothing is parsed whole. The download is fed to a gzip decoder 4 KB at a time and a splitter hands over one CVE at a time; what it holds is about one decoded step and the CVE in progress. A test streams a 560 MiB feed through it and checks it held about 1 MB.
  - **Nothing half-written:** a feed streams into staging tables in small transactions (no other write waits on a download), and is swapped into `sec_nvd_cve` and `sec_nvd_cpe` in one transaction only when its size is the `.meta`'s gzSize, its gzip CRC checks, and its JSON's SHA-256 is the `.meta`'s. A corrupt, short or tampered download is refused and the stored data stays. A dropped download resumes with a Range request.
  - **Guards:** a year whose CVE count falls below half of what's stored is refused; a stored copy newer than the feed's is kept; a CVE a yearly file no longer lists goes only when it's no newer than the file.
  - **Resumable:** each feed is its own swap, recorded in `sec_nvd_feed`; a run starts no new year after 15 minutes, and a restart carries on with the next year due.
  - **The first load, measured:** measured on 2026-11-06 against nvd.nist.gov, in release on an Apple M-series laptop, into a fresh SQLite file: the 25 yearly feeds (2002 to 2026) and the modified feed, 236 MB gzipped and 2.9 GB of JSON, loaded in 39 seconds of wall time (the largest year, 2024, 4 seconds; the download is most of it, so a slower link takes longer, but each year is its own swap, so a cut link costs one year). 415,823 CVEs and 588,135 product rows; the SQLite file grew to 389 MB; the process's peak memory was 90 MB. The modified feed then applied 13,111 changes. Run it again with `tests/nvd_measure.rs` (ignored by default; it downloads the whole of NVD). In the console the job's 15-minute budget per hourly run is far more than this needs, so a first load finishes in its first run unless the link is slow.
- **Automatic mapping:** with NVD loaded, every installed program the curated list doesn't name is mapped when its core name (versions, architecture, locale and notes dropped) is exactly an NVD product's AND NVD's vendor is its publisher (`cpe_map.rs`; the names that must map and the ones that must not are tests). It becomes an `auto` product, `nvd:<vendor>:<product>` (`sec_product.source`), at the version field only, never a number from the name. A version numbered another way than the product's NVD ranges (a Store app's 11.x against ranges in 2023.x) isn't compared (`scheme_mismatch`). With `NVD_FEEDS=full`, the per-product API job isn't scheduled.

- **Its own vendors only:** every vendor the console reads is the installing MSP's own.

### The evidence API (contract v1)

Every answer is `{ v: 1, op, data, next_cursor, totals, as_of }`. Pages are keyset: the cursor is the last row's sort key, so a page holds still while the data refreshes; `limit` is at most 500, and a malformed cursor is refused. Filters, on every list op: `org_id`, `device_class`, `device_id`, `role` (NinjaOne's node class), `source[]`, `kev`, `critical` (CVSS 9+), `cvss_min`, `running_only`, `product_key`, `version` (`"(none)"` for the empty version), `cve_id`, `advisory_id`, `has`. `msa` is refused with a reason: no source the console reads says which clients are MSA clients.

**A count is a list's totals, and its rows the list.** Devices in scope are read once; evidence is read through `sec_cve_evidence` with the same source filter; every count is the size of the set the list op returns for the same filter. A test holds every count the views show against its list on a made-up fleet, on both stores (`server/tests/views.rs`). Three counting rules are deliberate ("Counting rules", below): a device's CVEs are distinct, a version's CVEs are every source's together, and "vulnerable" is the evidence tied to each device.

| Op | What it answers |
|---|---|
| `search` | A CVE id, or text: clients, advisories (as their CVE), products, devices; within the caller's scope |
| `cves.list`, `devices.list`, `clients.list` | The lists every count opens. `devices.list` with `has: "product"` is the devices with a product at all, vulnerable or not |
| `cve.get`, `cve.products`, `cve.devices`, `cve.similar` | One CVE: NVD, KEV, its advisories with the devices each names, devices by source; its products; its devices with the evidence behind each; the CVEs that read alike |
| `device.get`, `device.cves`, `device.products`, `device.software` | One device: what each source saw, its counts; its CVEs; its products with each one's CVEs; its whole installed-software list |
| `product.get`, `product.versions`, `product.devices`, `products.list` | One product, its versions (CVEs per version, every source's), its devices; and the Software tab |
| `client.get`, `clients.overview` | One client (what each source saw, its worst CVEs, every device and vulnerable product); the Clients tab |
| `coverage.list`, `coverage.devices` | Which sources saw which devices: per client, and the devices (`source` with `seen: false` is the gap; `has: "software"` the devices with an inventory) |
| `advisories.list` | Every advisory, active first, with the devices each names now |
| `version.cves` | One product version's CVEs as NVD's ranges put them, whatever runs it, each with the devices in scope carrying it: what a running binary's CVE count opens (`product_key` and `version` required) |
| `windows.devices`, `windows.cves` | Windows itself: each device's patch state, worst first, with totals per state; the open Windows CVEs, each with the update (KB) that fixes it per build and the devices that need it |
| `processes.list`, `processes.review` | The running binaries, one row each, with what product and version each is, how sure, and that version's CVEs; the names the automatic mapping wouldn't decide |
| `detections.list`, `detection.get` | Blackpoint's detections (open, or with `include_closed` every one), worst first, and one detection with its ticket |
| `blackpoint.tenants` | Blackpoint's tenants, each with the client it's confirmed as, or the console's suggestion |
| `darkweb.list` | Dark-web exposures: an address, where it was seen, when and what kind of data, never the exposed value |
| `exposure.list`, `exposure.get` | The public addresses clients' servers, desktops and websites reach the internet from, worst first (edge entry points only with `include_edge`); one address with its services, CVEs, devices, sites, edge mark, scan policies and ticket |

**`state` means something different on each op that takes it**, and an op that doesn't list a value refuses it (`400`, naming the op's own values). On every other op it's refused the same way, never ignored:

| Op | `state` is | Values |
|---|---|---|
| `windows.devices` | a device's Windows patch state | `vulnerable` (an open CVE Microsoft fixed in a later revision), `unknown` (its patch level can't be read: never counted as patched), `untracked` (a build Microsoft's data doesn't name), `patched` |
| `processes.list` | a binary's trust, from its signature | `invalid`, `unsigned`, `unchecked`, `unhashed`, `valid` |
| `processes.review` | a name's review | `pending`, `accepted`, `rejected` |

The totals on these ops are of the whole scope whatever `state` asks, so each total opens its own rows.

### The writes

Every change goes through a JSON call behind sign-in, refuses anything but a JSON body (another site's form can't send one), is the act of the signed-in person named in its audit line (who, the call, ids and setting names, never a value), and is confirmed in the web app before it's sent. Nothing else in the console writes: `POST /api/evidence` only reads.

| Call | Who may | What it changes | Audit line | A second click |
|---|---|---|---|---|
| `POST /api/setup/unlock`, `/api/setup/test`, `/api/setup/save` | whoever holds the setup token from the log, only while unconfigured | the config file (secrets encrypted) | `setup.unlock`, `setup.save` (the setting names) | a save is the whole config, so the same save is the same file |
| `POST /api/admin/connectors/test` | an admin | nothing: a live, read-only Test | `admin.connectors.test.<section>` (pass or fail, the vendor's status) | reads again |
| `POST /api/admin/connectors/save` | an admin | one connector's settings in the config file, then a restart | `admin.connectors.save.<section>` (the setting names) | nothing changed is nothing saved |
| `POST /api/admin/advisories` | an admin | an advisory entered ahead of NVD (save or retire) | `admin.advisories.save` and the like (the advisory and CVE ids) | keyed by advisory id |
| `POST /api/review` `{kind, name, company, decision, cpe}` | anyone signed in | a name's mapping decision: accept one of its own candidates, reject, or reopen | `review.decide` (who and the decision, never the name) | the same decision changes nothing |
| `POST /api/blackpoint/tenant` `{tenant_id, action, org_id?}` | anyone signed in | which client a Blackpoint tenant is (`confirm`), or no client (`not_client`), or neither (`clear`) | `blackpoint.tenant` (the tenant and client ids) | the same mapping again |
| `POST /api/exposure/edge` `{ip, edge, note?}` | anyone signed in | marks an address as an edge entry point, or unmarks it | `exposure.edge` (the address) | the same mark again |
| `POST /api/exposure/scan-policy` `{org_id, frequency_days}` | an admin, or one of `SCAN_POLICY_ADMINS` | a client's on-demand scans (every N days), or off (0) | `exposure.scan_policy` (the client and days) | the same policy again |
| `POST /api/tickets/preview` `{finding}` | anyone signed in | nothing: the Halo ticket as it would be sent, and its digest | `ticket.preview` (the finding) | reads again |
| `POST /api/tickets` `{finding, digest}` | anyone signed in, only with the preview's digest and a client whose Halo link is confirmed | raises one Halo ticket | `ticket.create` (the finding, Halo's ticket id, and `unknown` when the answer was lost) | one ticket per finding: the claim is a row, so a double click raises one. A refusal from Halo (4xx), or a call that never reached it, gives the claim back. A call whose answer was lost after it was sent (a timeout, a dropped connection, a 5xx, no ticket id) may have made the ticket, so the claim stays `unknown` and every retry is refused: "A ticket may already exist in Halo. Search Halo for '<the ticket's title>' before an admin releases this." Never a second ticket without someone checking |
| `POST /api/tickets/release` `{finding}` | an admin | after searching Halo and finding no ticket: gives back a claim left `unknown`, so the finding can be raised again | `ticket.release` (who, when, the finding's kind) | a second release finds nothing to release (404) |

**Scope** (`ops::Scope`): a caller's limits, never widened by its own filters. `org_id` pins one client: the call is answered for it, and one naming another client is refused (`403`, `refused: true`), never quietly answered for the pinned one; `require_org` refuses a call naming none. A device or a detection of another client is a `404`; `blackpoint.tenants` lists only the tenants confirmed as the pinned client, and only that client for the picker. An op over the whole fleet with no one client in it (`processes.review`, `ops::FLEET_OPS`) is refused to any scoped caller. `server/tests/scope.rs` holds this for every op the contract lists, read from its schema, on both stores: each op's pinned answer is the same before and after another client arrives with data in every source, and its unscoped answer must change, so an op whose client filter is dropped fails it. The console's own signed-in staff read the whole fleet; the scope is for a client portal, which reads only the console.

### The views

The web app's core views, each a path: **Clients** (`/clients`, worst first, by device class), a **client** (`/clients/<org>`, its CVEs at `/clients/<org>/cves`), a **device** (`/devices/<id>`), **Software** and a **product** (`/software`, `/software/<key>?version=`), **Coverage** (`/coverage`), the **rows behind a count** (`/rows/<devices|cves|clients|coverage|version-cves>?<filter>&label=`), **Advisories** (`/advisories`), **Windows** (`/windows`), **Running processes** and the **names to review** (`/processes`, `/processes/review`), **Detections** (`/detections`, one at `/detections/<id>`), **Blackpoint tenants** (`/blackpoint/tenants`), the **dark web** (`/darkweb`), **Exposure** (`/exposure`, one address at `/exposure/<ip>`) and **Settings** (`/settings`, admins: every connector the wizard registers, with the same fields, the same choices and the same Test). Every count is a link to exactly the rows it counts, filtered as it was counted and said in words on the list's own page; zero is the plain number, as there's nothing to open. NVD's whole catalogue for a product isn't on any device, so it's said, not linked. Tables become rows of labelled cards on a phone, with no sideways scroll at 360 px.

### The embedder

Similar-CVE search compares what CVEs mean, so each NVD description becomes a vector, and the console makes those vectors itself (`server/src/embed.rs`, `server/src/embed_job.rs`).
- **The model:** BAAI's `bge-small-en-v1.5` (MIT; 384 dimensions, the table's size; English; BERT, 33M parameters), as the int8 ONNX export most often used (Xenova's `model_quantized.onnx`, per-channel dynamic quantisation of BAAI's own fp32 export). BAAI publishes only fp32 (133 MB); int8 is 34 MB. Measured on 30 made-up NVD-style descriptions (2026-11-05), the cosine between its vector and fp32's for the same text is at least 0.9938 (mean 0.9962), and the nearest neighbour is the same for 29 of 30, the 30th a tie. The pins, the measurement and the licence text are in `THIRD_PARTY.md`. Vectors are stored under the model key `bge-small-en-v1.5-int8`, so a later model embeds beside it and takes over once it's complete.
- **Where it runs:** inside the server process, on ONNX Runtime 1.31 through the `ort` crate, with Hugging Face's `tokenizers` (pure Rust) in front. The model is a file in the image; at load the console checks both files' SHA-256s again and refuses anything else, because its vectors would be stored as this model's. Nothing is downloaded at run time, and ONNX Runtime's telemetry is off.
- **Text never leaves.** CVE descriptions are public data, but the embedder never sends anything anywhere regardless: inference is a library call in the console's own process, and the vectors go where the store goes and nowhere else.
- **How it embeds:** CLS pooling (the first token's hidden state) and L2 normalisation, as bge specifies, so every vector has length 1. A description is cut to its first 16 KB before it's tokenised, and past 512 tokens to its first 512 (NVD's are almost always far shorter). No query instruction: bge prefixes short *queries* with "Represent this sentence for searching relevant passages: " when they're matched against longer passages, but CVE-to-CVE similarity compares a description with descriptions, which is symmetric, so both sides are embedded bare. The search reuses the CVE's stored vector, so nothing is embedded when someone asks.
- **One description at a time.** The int8 model takes its activations' scale from the whole input tensor, so in a padded batch a description's vector moves with whatever it's batched with (measured: 0.002 cosine). One at a time, a vector depends on its own text alone, and embedding it again gives the same bytes.
- **Graph optimisations off.** Measured on this model: any of ONNX Runtime's optimisation levels made inference 2.7 times slower (15.6 ms a description against 5.8, on an Apple M-series CPU with two threads) and a 512-token description's peak memory 1.09 GB against 193 MB, for the same vectors to 1e-7.
- **Resources:** one ONNX Runtime session per process, one inference at a time (a panic mid-inference doesn't turn the embedder off: the next run carries on with the session), on tokio's blocking pool, never on an async worker. `EMBED_THREADS` (default 2, at most 64) caps ONNX Runtime's threads for an inference, and they don't spin while idle. The model adds 34 MB to the image. The loaded session adds about 80 MB to the process (measured in the image: 81 MB idle with the scheduler off, against 2 MB without the embedder). Measured on Linux (2026-11-05: the arm64 image in podman's Linux VM, read-only, `EMBED_THREADS=1`, embedding one 512-token description and a full batch of 32), the container's cgroup `memory.peak` was 136 MB (132 MB of it anonymous), about a quarter of the Kubernetes base's 512 MiB limit, so the limit stays. The Kubernetes base sets `EMBED_THREADS=1`, since its CPU limit is half a core. A catalogue of 20,000 descriptions is about two minutes of CPU at 6 ms each.
- **The `embed` job,** every 2 minutes (5 before the whole of NVD arrived; with about 400,000 descriptions at about 6 ms each, a 30-second run every 2 minutes embeds the first load in about 3 hours, against 7 at 5 minutes, and takes a quarter of a core meanwhile), under the scheduler's lease like every job (so one replica embeds at a time):
  - It first takes out the vectors of CVEs that NVD rejected, or whose description is gone.
  - Then, batch by batch (32 descriptions a batch, each embedded on its own, the batch written in one transaction), it embeds every CVE that has a description and no vector of the current model, and every CVE whose description changed. "Changed" is NVD's lastModified first (only those CVEs are looked at again), then the description's SHA-256: a new score moves lastModified without changing what the description means, and that CVE keeps its vector.
  - It stops when nothing is left or after 30 seconds (at the Kubernetes base's half a core, a longer run would hold the CPU from the other jobs, which run in turn, and from the API), so a first load (a catalogue's worth of CVEs) goes on over several runs while the other jobs get their turns. Its detail on `/api/status` is counts only: embedded, unchanged, failed, failing, removed, remaining, seconds.
  - A description that can't be embedded fails alone: it's recorded in `cve_embed_failed` with the class of the failure (tokenise, inference, output and the like; never the text or the error's words), its old vector goes, and the run carries on. It's tried again only when its description changes, by the same lastModified-then-hash test. `/api/status` counts this run's failures (`failed`, `failed_by_class`) and every failure on record (`failing`).
  - It's idempotent (a second run over the same descriptions makes nothing) and cancellable at any await: each batch's vectors and records are one transaction, so a run that loses its lease mid-batch leaves the earlier batches whole and nothing of that one.
- **Off:** `EMBEDDER=off` turns it off. It's also off, with the reason said at start and on `/api/status` (`embedder.on`, `embedder.why`), on PostgreSQL without pgvector (the store's own message) and when the model won't load (`MODEL_DIR` points elsewhere, or a file isn't the pinned one). Off, the console still serves everything else, the `embed` job isn't scheduled, and `cve.similar` answers no rows with `off` saying why. `MODEL_DIR` (default `/models/bge-small-en-v1.5-int8`) points at another copy of the same pinned files, for running outside the image.
- **The op, `cve.similar`:** `cve_id`, and `org_id` and `limit` (default 10, at most 50) like the other CVE ops. It answers the nearest CVEs by cosine distance, nearest first, never the CVE itself, each with NVD's score and severity, whether it's in KEV, and how many devices carry it (at that client when `org_id` is given). It's behind sign-in and audited like every op. A CVE the job hasn't reached answers no rows, with a `note` saying so. The web app's CVE page lists them under "Similar CVEs", or says in one sentence why there's no list.

## Data handling

- **Class:** client data. Device names, users, software, vulnerabilities and client names; no PHI, CUI or cardholder data.
- **Advisories** (`sec_advisory`): vendor facts (a CVE, its title, which software and versions), public data, and which staff member entered or last changed each one, with their notes. No client data: the devices an advisory names are evidence rows like every other source's. Saving needs an admin and writes an audit line.
- **Admin changes:** a connector's save is an audit line naming the admin and the settings changed, never a value; the settings themselves go where setup puts them (the config file, secrets encrypted).
- **What Blackpoint, Shodan and the tickets add**:

  | Store | Holds | Class | Minimum kept |
  |---|---|---|---|
  | `bp_tenant`, `bp_asset` | tenant names and domains, hostnames, OS names, who confirmed a mapping | client data | no IPs, MACs or agent details |
  | `bp_detection` | detection names, rule names, hostnames, the user named in the alert, risk scores | client data (security events) | no raw alert body or SOC notes |
  | `bp_vulnerability`, `bp_vulnerability_asset` | CVE ids, applications, severities, which assets | client data | no scan output |
  | `bp_darkweb` | an email address, the breach's name, a date, and the kind of data exposed | client data (personal: email addresses) | **never a password, hash or other secret**: only those four fields are read from Blackpoint's row. **Kept while Blackpoint lists it, then 30 days soft-deleted:** the daily `darkweb_purge` job deletes a row 30 days after Blackpoint stopped listing it, whether Blackpoint is still on or not. Readable by anyone signed in, within their scope |
  | `device_wan`, `exposure_host`, `exposure_service`, `exposure_site` | public IPs, open ports, banners' products and versions, hostnames, a website's hosting class | client data | the newest banner per port; no response bodies |
  | `exposure_mark`, `scan_policy`, `scan_request` | who marked or set what, and when; scans asked for | operational | |
  | `finding_ticket` | a finding's key, Halo's ticket id, who raised it, and whether the ticket is made, being made, or unknown | operational | the ticket's text stays in Halo |

  The Blackpoint token and the Shodan key are secrets like the others: encrypted in the config file, bound to their addresses in setup, never in a log, an answer or `/api/status`. Every write (a mapping, an edge mark, a scan policy, a ticket) is audited with who did it and ids only.
- **What the newer sources add**:
  - **Windows updates** (`sec_msrc_fix`, `os_update_installed`, `os_patch`, `sec_windows_*`): public data (Microsoft's) and client data (which KB each device installed, has waiting or failed). KBs and times only, never a patch's free text. Installs are kept 400 days, failures 90.
  - **Running processes** (`device_process`, `process_snapshot`): client data. A binary's name, hash, up to five paths, version, product, company and signature. A path can carry a Windows user's profile folder name (C:\Users\<name>\...), so it's shown only behind sign-in, like device names, and never logged. Never a command line, the users a process ran as, or the services it hosts. A device's rows go 30 days after it last ran the script.
  - **Review decisions** (`sec_map_review`): a product name, its NVD candidates, and who decided (the signed-in user's email, as the audit log has it) and when.
  - **The whole of NVD** (`sec_nvd_*`, the staging tables): public data. On SQLite it grows the file by about 390 MB (measured, above).
- **The embedder:** CVE descriptions are public data (NVD's), but the embedder never sends anything out regardless: the model is a file in the image and inference runs in the console's own process ("The embedder").
- **In transit:** TLS at every hop (Access to the pod, the pod to every vendor). On SQLite the store is a local file, with no database link to protect. On PostgreSQL the link carries client data, so production requires TLS that checks the server's certificate: `sslmode=verify-full`, or `verify-ca` with the CA in `sslrootcert`. `require` is refused there, because it encrypts but accepts any certificate, so it can't tell the database from something in between. Managed PostgreSQL (Azure, RDS, Cloud SQL) publishes its CA for this.
- **At rest:** the store holds client data, so it must be encrypted at rest. On SQLite that's the volume's job (the file and its copies). On PostgreSQL it's the database server's: a managed service's storage encryption (on by default on the major clouds), or an encrypted disk under a server you run, and the same for its backups and snapshots.
  - **Kubernetes:** give the PVC an encrypted storage class. On AKS, Azure managed disks are encrypted at rest by default (platform-managed keys); elsewhere, choose a class that encrypts.
  - **compose:** keep Docker's volumes on an encrypted disk (LUKS, BitLocker, FileVault).
  - **On the volume,** the database, its WAL and the copies are mode 0600, the console user's alone. In Kubernetes, `fsGroup` gives that user the volume.
  - **Snapshots are replaced, not accumulated;** a device or client gone from NinjaOne is marked deleted.
- **Backups and recovery:**
  - **On PostgreSQL** they're the operator's: `pg_dump`, or the provider's snapshots and point-in-time recovery. The console makes none.
  - **The daily copies** of the SQLite file (`/data/backup`, 7 by default) undo a bad write or a broken file. They are on the same volume, so they don't survive losing it: snapshot the volume too (Azure disk snapshots, or the installer's own).
  - **To restore,** stop the console, put a copy in place as `console.db` (removing `console.db-wal` and `console.db-shm`), and start it.
  - **Nothing in the store is the only copy:** every row comes from a vendor. A lost store with no copy is rebuilt by the jobs, at the cost of a day's collection.
- **Least privilege:**
  - Read-only vendor credentials (NinjaOne's monitoring scope; a Halo API user without write roles).
  - On PostgreSQL, a role of the console's own, on a database of its own: it owns that database's schema (or has `CREATE` on it), and nothing on any other database. It needs no superuser and no `CREATEDB` or `CREATEROLE`. pgvector is enabled once by a role allowed to (or the role is allowed to enable it), not by giving the console more.
  - The pod's NetworkPolicy, and namespace RBAC.
  - Who can sign in is an Access policy (decision 4).
- **Audit of reads:** one JSON line per request (identity, op, ids, row count, time) to stdout, which AKS keeps in Log Analytics. Phase 2 moves it to an append-only, hash-chained table.
  - **Never in a log:** a device name, a user name, a key or a token.
- **Where it lives, and who can reach it:**
  - On SQLite, in one file on the console's own volume, which only the console's pod mounts and only its user can read. On PostgreSQL, in the database `DATABASE_URL` names, which the console's role and the server's administrators can read; the NetworkPolicy lets the pod reach it on 5432. Vendor credentials and the database URL live only in the environment, mounted files or the config file (encrypted), never in the database or its copies.

## Deploying it yourself

- **compose (one host):** `compose.yaml` runs the console, its store on the `msp-console-data` volume (put Docker's volumes on an encrypted disk). The connectors' settings go in the wizard or in `.env`. The demo profile adds made-up vendors (`dev/mock-vendors.ts`).
  - **PostgreSQL instead:** the file has a commented `postgres` service for development only: pgvector's image with its self-signed certificate turned on, reached with `sslmode=require` under `MSP_ENV=development`, since nothing checks that certificate and production refuses that. For production, the database needs a certificate for its host name from a CA whose certificate the console has (`sslmode=verify-full&sslrootcert=<path>`), or use a managed PostgreSQL and its published CA. The file says how.
  - **Guided:** start it, read the setup token from `docker compose logs`, open `/setup`, and work through the wizard. The settings go in the `msp-console-config` volume, and the master key in `msp-console-key`. Or skip setup by putting the settings in `.env`.
  - **`proxy` + `cloudflare_access`:** run `cloudflared` beside it (a commented-out service in the file), with the Access application's audience tag and team domain.
  - **`proxy` + `trusted_header`:** put your proxy in front on the same network, and set `TRUSTED_PROXY_CIDRS` to its address only.
  - **`oidc`:** register an app in Entra. TLS is the installer's: the console speaks plain HTTP, behind a reverse proxy or ingress that terminates TLS (Caddy, Traefik, nginx). The registration:
    - a Web redirect URI `https://<host>/auth/callback`;
    - a client secret;
    - under Token configuration, a groups claim (security groups, as group IDs), or an app role assigned to the technicians.
    Then set `OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ALLOWED_GROUP` (the group's object id, or the role's value), `SESSION_KEY` (32+ random characters) and `PUBLIC_URL=https://<host>`.
    A sign-in lasts 8 hours, and removing someone from the group takes effect when it ends; changing `SESSION_KEY` signs everyone out at once.
- **Kubernetes:** `deploy/k8s/base` plus one component for the way in. An overlay sets the image digest, the PVC's storage class (an encrypted one), the ConfigMap (the connectors' URLs and ids) and the Secret: `ninja-client-secret`, `halo-client-secret`, `nvd-api-key` (each optional), and `master-key` (needed only with a config file that holds encrypted secrets), mounted as files. The NetworkPolicy allows HTTPS out and nothing else; the overlay narrows it.
  - **`components/cloudflared`:** for Cloudflare Access; outbound only, no Ingress.
  - **`components/ingress`:** for `trusted_header` behind the cluster's own auth proxy, or for `oidc`. With `trusted_header`, `TRUSTED_PROXY_CIDRS` is the ingress controller's pod range, and the NetworkPolicy admits only that.
  - **PostgreSQL, and more than one replica:** put the URL in the Secret as `database-url`, and patch the base in the overlay: no `DATABASE_PATH`, no data volume or claim, `DATABASE_URL_FILE`, more replicas and `RollingUpdate` (only with PostgreSQL: the SQLite file has one writer), and 5432 out. For example:
    ```yaml
    resources: [../base]
    patches:
      - patch: |-
          apiVersion: apps/v1
          kind: Deployment
          metadata: { name: msp-security-console }
          spec:
            replicas: 2
            strategy: { type: RollingUpdate }
            template:
              spec:
                containers:
                  - name: server
                    env:
                      - { name: DATABASE_PATH, $patch: delete }
                      - { name: DATABASE_URL_FILE, value: /var/run/secrets/msp-console/database-url }
                    volumeMounts:
                      - { mountPath: /data, $patch: delete }
                volumes:
                  - { name: data, $patch: delete }
      - patch: |-
          $patch: delete
          apiVersion: v1
          kind: PersistentVolumeClaim
          metadata: { name: msp-security-console-data }
      - target: { kind: ConfigMap, name: msp-security-console }
        patch: |-
          - { op: remove, path: /data/BACKUP_KEEP }
      - target: { kind: NetworkPolicy, name: msp-security-console }
        patch: |-
          - { op: add, path: /spec/egress/-, value: { ports: [{ port: 5432, protocol: TCP }] } }
    ```
    Narrow the 5432 rule to the database's address where the cluster's policy can. The URL's sslmode is `verify-full` (or `verify-ca` with `sslrootcert`; mount the CA's certificate from a Secret or ConfigMap), and the database's backups are yours.
  - **Guided setup on Kubernetes:** leave the wizard's settings out of the ConfigMap, mount a writable volume at `CONFIG_PATH`, put `master-key` in the Secret, and read the token from `kubectl logs`. Never an emptyDir for either: a pod restart would lose it. Most installers will use the overlay's ConfigMap and Secret instead.

## Counting rules

Three rules are deliberate, because the obvious way to count gets each wrong. A test holds each on a made-up fleet.
1. **A device's CVE count** is its distinct CVEs. Summing each product's count would count a CVE carried by two products on one device twice.
2. **A version's CVEs** (`product.versions`) are the union of NVD's and the direct sources', not the larger of the two counts.
3. **A product's vulnerable devices** (`product.get`), and a device's CVEs for a product (`product.devices`), come from the evidence tied to each device, not from a product-wide map or the maximum across versions.

And one definition: "Servers" counts by device class, while "Servers exploited" counts by role. They differ: a desktop-class device can have the server role, and the reverse.

## Decisions

Settled:
1. **Server language:** Rust with Axum.
2. **Servers are counted by device class.**
3. **The store:** SQLite or PostgreSQL, the installer's choice, SQLite the default.
4. **A standalone product for any MSP,** run against its own vendors, with one way in of the installer's choosing (a tunnel, an ingress, or the console's own sign-in).

Still open: distribution (how the image is published).
