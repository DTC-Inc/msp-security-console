# MSP Security Console

A portable security console for an MSP: every client's devices, the software installed and running on them, the CVEs that software carries, and what every source saw (NinjaOne inventory, running processes, Microsoft updates, Blackpoint, vendor advisories, internet exposure), with one drill-down from any number or record.

A standalone product for any MSP, run against that MSP's own vendors: nothing it reads belongs to anyone else, and nothing it holds leaves it.

- **Server:** Rust with Axum, one binary in one container. Its store is one SQLite file on its own volume by default, with vector search compiled in (sqlite-vec), or a PostgreSQL database you run, for more than one replica or a managed database (vector search there is pgvector, when the server has it). It collects from the installing MSP's own NinjaOne (devices, installed software, OS patches, and, with the endpoint script, running processes) and HaloPSA, and from the whole of NVD (its yearly feeds), CISA KEV and Microsoft's monthly security updates (MSRC), on a scheduler inside the server, and it is the API.
- **Similar CVEs:** the server embeds NVD's descriptions itself, with BAAI's bge-small-en-v1.5 (MIT) on ONNX Runtime in its own process; the model is baked into the image, pinned by SHA-256, and nothing is sent anywhere. Each CVE's page lists the CVEs that read like it. `EMBEDDER=off` turns it off, and `EMBED_THREADS` (default 2) caps the CPU it takes. Licences: [THIRD_PARTY.md](THIRD_PARTY.md); how it works: [docs/design.md](docs/design.md), "The embedder".
- **The whole of NVD, by default** (`NVD_FEEDS=full`): every installed or running program is compared, not only a curated list. Measured: the first load takes about 39 seconds on a fast link and grows the SQLite file by about 389 MB, and the embedder takes about 3 hours to embed its descriptions for similar-CVE search; the console answers meanwhile. `NVD_FEEDS=curated` reads only the curated products through NVD's API.
- **Every count drills down:** each number on every view opens exactly the rows it counts. Advisories entered ahead of NVD are matched against installed software at once.
- **Admins:** everyone signed in reads everything; admins (`OIDC_ADMIN_GROUP` with OIDC, `ADMIN_EMAILS` behind a proxy, the local user on one computer) change the connectors in Settings and the advisories. A connector change restarts the console with it, as setup does.
- **Client:** a Solid web app (Vite), on the DTC design tokens, served by the server from the same origin.
- **Runs in:** Docker (compose for a laptop or one host) and Kubernetes (a kustomize base; you bring the overlay).

## Why this exists

An MSP's security picture is spread across its RMM, its PSA, its MDR, NVD, CISA's KEV list and Microsoft's updates, and each answers a different question. This console puts them in one evidence store, every row tagged with the source that saw it, so one question ("which of my clients' devices carry this CVE, and who says so?") has one answer, and every number on every page opens the rows behind it. It runs as one container on a laptop or a cluster, against the MSP's own vendors, with one web app in the browser. The design is [docs/design.md](docs/design.md).

Branches: `dev` for integration, `main` for releases.

## Run it

- **On one host (compose):** the commands below are Docker's, and Podman's are the same with `podman` in place of `docker` (`podman compose up --build -d`, `podman compose logs console`, `podman compose down`).
  - **Guided:** `docker compose up --build -d`, then `docker compose logs console` for the one-time setup token, then http://localhost:8080/setup. The wizard walks through the database, how people sign in (behind Cloudflare Access, behind your own proxy that names the user in a header, or the console's own Entra sign-in; the registration steps are in docs/design.md) and the connectors, testing each live. Secrets are saved encrypted, under a master key kept on its own volume.
  - **Trying it on one computer:** put `MSP_ENV=development` in `.env`, then run the guided setup and choose "Only this computer (no sign-in)". Anyone who can reach port 8080 is signed in, which compose binds to 127.0.0.1 only. Production and Kubernetes refuse this choice.
  - **By environment:** put the settings in `.env`; they always win over what setup saved. The names, per mode, are in [docs/design.md](docs/design.md).
  - **A look with made-up data and no sign-in:** `docker compose --profile demo up --build -d`, then http://localhost:8081.
  - **To stop it:** `docker compose down` (the volumes, and so the data and the saved settings, stay).
  - **On PostgreSQL instead of the SQLite file:** give the console `DATABASE_URL=postgres://console:<password>@<host>:5432/console?sslmode=verify-full` (in `.env`, or the wizard's database step), adding `&sslrootcert=<path>` when the platform's roots don't sign the server's certificate. In production the console checks the certificate: it accepts only `verify-full`, or `verify-ca` with `sslrootcert`. The database's backups are yours. `compose.yaml` has a commented `postgres` service for development (`MSP_ENV=development`, `sslmode=require` against a self-signed certificate), and says what production needs instead.
- **On Kubernetes:** `deploy/k8s/base` plus one way in, `components/cloudflared` (outbound only) or `components/ingress`. Your overlay supplies:
  - the namespace and the image by digest (CI writes the digest into the run summary);
  - the ConfigMap: the connectors' URLs and client ids, `AUTH_MODE`, and the mode's settings;
  - the PVC's storage class: an encrypted one, since the store holds your clients' inventory (on AKS, managed disks are encrypted by default);
  - the Secret `msp-security-console`: `ninja-client-secret`, `halo-client-secret`, `nvd-api-key`, `blackpoint-api-token`, `shodan-api-key`, `tunnel-token` for cloudflared, and OIDC's secrets in that mode.
  The server refuses to start while the chosen mode is missing a setting. With PostgreSQL, the overlay puts `database-url` in the Secret, drops the PVC and `DATABASE_PATH`, and may raise the replicas and switch to `RollingUpdate`; [docs/design.md](docs/design.md) has the patch.
- **Develop:**
  - The made-up vendors: `bun run dev:mock` (port 8090).
  - The model, once, to a cache outside the repo: `scripts/fetch-model.sh` (about 35 MB, checked against its pinned SHA-256s).
  - The server: `cargo run --manifest-path server/Cargo.toml --bin msp-console` with `MODEL_DIR=$HOME/.cache/msp-console/models/bge-small-en-v1.5-int8` (or `EMBEDDER=off`) `AUTH_MODE=dev_insecure DATABASE_PATH=$HOME/scratch/msp-console/console.db` (or `DATABASE_URL=postgres://…` for PostgreSQL) `STATIC_DIR=web/dist NINJA_BASE_URL=http://127.0.0.1:8090/ninja NINJA_CLIENT_ID=demo NINJA_CLIENT_SECRET=demo HALO_BASE_URL=http://127.0.0.1:8090/halo/api HALO_CLIENT_ID=demo HALO_CLIENT_SECRET=demo NVD_URL=http://127.0.0.1:8090/nvd KEV_URL=http://127.0.0.1:8090/kev.json NVD_FEED_URL=http://127.0.0.1:8090/nvd-feeds MSRC_URL=http://127.0.0.1:8090/msrc`.
  - The web app: `cd web && bun run dev`, then http://localhost:5173. Vite sends `/api`, `/auth`, `/healthz` and `/readyz` to the server on :8080 (`CONSOLE_URL` points it elsewhere), so the app talks to its own server as it does in production. `bun run build:web` builds it into `web/dist`, which the server serves with `STATIC_DIR=web/dist`.
- **Test:**
  - `cargo test --manifest-path server/Cargo.toml` (sign-in in every mode, the admin role and Settings → Connectors, every count against the list it opens on a made-up fleet, scope, advisories, the contract at the door, the audit line, configuration, setup, matching; and on a fresh store per test: migrations, the connection's settings, the scheduler and its lease under contention, the daily backup, vector search and its refusal without sqlite-vec, Halo's limit, the tracer end to end against made-up vendors). The store's tests run on a SQLite file each, with nothing to start, and again on PostgreSQL when `TEST_DATABASE_URL` names a server (a database of their own each, dropped afterwards). Without it they print SKIPPED; with `REQUIRE_DB=1`, as in CI, they must run. A throwaway server: `podman run -d --name pg-test -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 docker.io/pgvector/pgvector:pg17`, then `TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres`. The embedder's tests run the real model through ONNX Runtime, from `MODEL_DIR` or the cache `scripts/fetch-model.sh` fills; without it they print SKIPPED, and with `REQUIRE_MODEL=1`, as in CI, they must run.
  - `bun run test` (the generated contract types, the tokens; the web app's API client, the setup wizard's rules, and a production build of its own).
  - `bun run typecheck` (the web app), and `bun run contract:check` and `bun run tokens:check`, which fail on drift.

## Layout

`web/` the Solid web app: search, the clients and their devices, the software, coverage, the rows behind every count, a CVE, the advisories, Blackpoint's detections, tenants and dark-web exposures, internet exposure, Windows updates, running processes and the names to review, the jobs' status, Settings (admins), and the setup wizard at `/setup` · `server/` the Rust server (Axum) and contract v1's source · `packages/contract` the schema and the client's types, generated · `packages/tokens` the DTC tokens, generated · `deploy/k8s` the Kubernetes base · `endpoint/` the scripts an MSP deploys to its devices (process inventory for NinjaOne; [endpoint/README.md](endpoint/README.md)) · `docs/design.md` the design.

## NVD

This product uses the NVD API but is not endorsed or certified by the NVD.

## License

Open source, under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
