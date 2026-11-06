# MSP Security Console: one container. The Rust server builds against glibc, with SQLite (compiled from
# sqlx's bundled source) and ONNX Runtime (the embedder's, linked statically from pyke's prebuilt archive, which ort-sys
# pins by SHA-256) both inside the binary; Vite builds the Solid web app; the embedding model is downloaded at build
# time and checked against pinned SHA-256s (scripts/fetch-model.sh), so nothing is downloaded at run time. The runtime
# is distroless/cc: glibc and libstdc++, which ONNX Runtime needs, and nothing else; non-root, run with a read-only
# root filesystem. Both are Debian 13 (trixie): pyke's ONNX Runtime 1.31 is built with GCC 14 and calls libstdc++ symbols
# GCC 12's lacks (GLIBCXX_3.4.32 and .33: std::string's _M_replace_cold, __cxa_call_terminate), so on Debian 12 it
# doesn't link, and a Debian 12 runtime couldn't load it. Its writable places are volumes: /data, holding the SQLite
# store (with PostgreSQL, DATABASE_URL, nothing is kept there), /var/lib/msp-console, where the guided setup saves
# its settings, and /var/lib/msp-console-key, where the first save makes the master key that encrypts those
# settings' secrets (its own volume, so the two are backed up apart). Base images are pinned by digest (multi-platform indexes, so amd64 and
# arm64 build from the same line); bump them on purpose.
FROM docker.io/library/rust:1.99.1-trixie@sha256:bc2c4c21d4467cdbbac0ee7b95a6deb742a3467dfe0ff7647916c4b42ca56372 AS server
WORKDIR /src/server
COPY server/Cargo.toml server/Cargo.lock server/build.rs ./
COPY server/src ./src
# The schema is embedded in the binary (sqlx::migrate!), so the migrations are part of the build.
COPY server/migrations ./migrations
# Fewer parallel rustc jobs on a small builder (a laptop's podman VM ran out of memory at the default).
ARG CARGO_BUILD_JOBS
# ort-sys's build script fetches ONNX Runtime 1.31's static library for this platform from pyke's CDN and refuses it
# unless its SHA-256 is the one in ort-sys's own table (Cargo.lock pins ort-sys). It links libstdc++ dynamically,
# which distroless/cc carries (Debian 13's, the same as this builder's).
RUN cargo build --release --locked --bin msp-console
# The volumes' mount points, owned by the console's user: a fresh Docker named volume copies its mount point, owner
# included, while a mount point the image lacks comes up root-owned and unwritable.
# The key's directory is made inside a parent and copied as an entry, so its 0700 survives: COPY of a directory copies
# its contents, and the destination it creates is 0755.
RUN mkdir -p /out/data /out/config /out/keyparent/msp-console-key && chmod 700 /out/keyparent/msp-console-key

# The embedding model: two files from Hugging Face at pinned revisions, each checked against its pinned SHA-256; a
# mismatch fails the build. Read-only to everyone, writable by no one at run time (the root filesystem is read-only).
# And the licences that travel with what the image carries (ONNX Runtime's, with its third-party notices; the model's;
# the tokenizer library's), each at a pinned commit and SHA-256 the same way (scripts/fetch-licenses.sh).
FROM docker.io/library/rust:1.99.1-trixie@sha256:bc2c4c21d4467cdbbac0ee7b95a6deb742a3467dfe0ff7647916c4b42ca56372 AS model
COPY scripts/fetch-model.sh scripts/fetch-licenses.sh /
RUN sh /fetch-model.sh /models/bge-small-en-v1.5-int8 && chmod 755 /models /models/bge-small-en-v1.5-int8 && chmod 444 /models/bge-small-en-v1.5-int8/*
COPY THIRD_PARTY.md /licenses/THIRD_PARTY.md
RUN sh /fetch-licenses.sh /licenses && find /licenses -type d -exec chmod 755 {} + && find /licenses -type f -exec chmod 444 {} +

# The licence of every Rust crate linked into the binary, from Cargo.lock, by cargo-about (pinned, installed --locked).
# Any crate whose licence isn't on server/about.toml's list fails the build (--fail).
FROM docker.io/library/rust:1.99.1-trixie@sha256:bc2c4c21d4467cdbbac0ee7b95a6deb742a3467dfe0ff7647916c4b42ca56372 AS crates
RUN cargo install --locked cargo-about --version 0.9.3 --features cli
WORKDIR /src/server
COPY server/Cargo.toml server/Cargo.lock server/build.rs server/about.toml server/about.hbs ./
COPY server/src ./src
RUN mkdir -p /licenses && cargo about generate --locked --fail about.hbs -o /licenses/rust-crates.txt

FROM docker.io/oven/bun:1.4.3@sha256:ec06c3b6cea04192ae6770c434f668ca41d343ad19fa6472216c7b48be39c598 AS web
WORKDIR /src
COPY package.json bun.lock ./
COPY web/package.json web/
COPY packages/contract/package.json packages/contract/
COPY packages/tokens/package.json packages/tokens/
RUN bun install --frozen-lockfile
COPY web web
COPY packages packages
# The Solid app, built by Vite into web/dist; the DTC tokens become its stylesheet at build time.
RUN cd web && bun --bun vite build
# The licence of every JavaScript package the bundle carries, from bun.lock, each package's own text (a minified bundle
# drops the notices MIT asks to travel with it). Any licence off scripts/web-licenses.ts's list fails the build.
COPY scripts/web-licenses.ts scripts/
RUN mkdir -p /licenses && bun scripts/web-licenses.ts --out=/licenses/web.txt

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1
COPY --from=server /src/server/target/release/msp-console /msp-console
COPY --from=web /src/web/dist /web
COPY --from=model /models /models
# The licences of what's in the image beyond the console's own code: /licenses/THIRD_PARTY.md says what each is.
COPY --from=model /licenses /licenses
COPY --from=crates /licenses/rust-crates.txt /licenses/rust-crates.txt
COPY --from=web /licenses/web.txt /licenses/web.txt
COPY --from=server --chown=65532:65532 /out/data /data
COPY --from=server --chown=65532:65532 /out/config /var/lib/msp-console
COPY --from=server --chown=65532:65532 /out/keyparent/ /var/lib/
# No setting the wizard asks for is set here: any one of them makes the console configured (or refusing), and the guided
# setup would never be served. DATABASE_PATH's default is already /data/console.db, and MODEL_DIR's is the model above.
ENV MSP_ENV=production PORT=8080 STATIC_DIR=/web CONFIG_PATH=/var/lib/msp-console/config.json
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/msp-console"]
