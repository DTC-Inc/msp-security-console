// The wizard's rules: what the environment sets is shown, never sent; secrets are never prefilled, and a blank one is
// never sent; a skipped connector sends nothing; and the save payload is every step's settings together.
import { expect, test } from "bun:test";
import type { SetupState } from "../api";
import { AUTH_MODES, visibleModes, fieldView, fieldsOf, initialDraft, missing, modeAllowed, modeFrom, newSessionKey, reviewValue, savePayload, section, sectionValues, AUTH_FIELDS,
  KEY_BACKUP_NOTE, masterKeyNote, STORE_FIELDS, STORES, DATABASE_TLS_NOTE, isSecret, storeFrom, storeLocked, storeOf, type Draft } from "./wizard";

const st = (keys: SetupState["keys"]): SetupState => ({ keys, sections: ["database", "auth", "ninja", "halo", "nvd"] });
const draft = (values: Record<string, string>, mode: Draft["mode"] = null, skipped: Draft["skipped"] = {}): Draft => ({ values, mode, skipped });
const field = (key: string) => [...Object.values(AUTH_FIELDS).flat(), ...Object.values(STORE_FIELDS).flat(), ...["ninja", "halo", "nvd", "msrc"].flatMap((s) => section(s as any).fields)].find((f) => f.key === key)!;

const server = st({
  DATABASE_PATH: { set: true, env: true, value: "/data/console.db" },
  PUBLIC_URL: { set: true, env: false, value: "https://security.example.com" },
  NINJA_BASE_URL: { set: true, env: true, value: "https://app.ninjarmm.com" },
  NINJA_CLIENT_SECRET: { set: true, env: false, value: null },
  OIDC_CLIENT_SECRET: { set: true, env: false, value: "should-never-show" }, // a server bug: a secret's value is still never used
  HALO_CLIENT_SECRET: { set: true, env: true, value: null },
});

test("the first draft prefills saved non-secret values, never a secret's, and nothing the environment sets", () => {
  const d = initialDraft(server);
  expect(d.values).toEqual({ PUBLIC_URL: "https://security.example.com" });
  expect(Object.keys(d.values)).not.toContain("OIDC_CLIENT_SECRET");
  expect(Object.keys(d.values)).not.toContain("DATABASE_PATH");
});

test("a field the environment sets is read-only, marked, and a secret one shows no value", () => {
  expect(fieldView(server, draft({}), field("DATABASE_PATH"))).toEqual({ locked: true, value: "/data/console.db", note: "Set by environment" });
  expect(fieldView(server, draft({}), field("HALO_CLIENT_SECRET"))).toEqual({ locked: true, value: "", note: "Set by environment" });
  expect(fieldView(server, draft({}), field("NINJA_CLIENT_SECRET"))).toEqual({ locked: false, value: "", note: "Saved; leave blank to keep" });
  expect(fieldView(server, draft({}), field("OIDC_CLIENT_SECRET")).value).toBe("");
  expect(fieldView(st({}), draft({}), field("NVD_API_KEY"))).toEqual({ locked: false, value: "", note: null });
});

test("the save never sends an environment-set key, a blank, or a blank secret; a typed secret is sent", () => {
  const d = draft({
    DATABASE_PATH: "/elsewhere.db",      // the environment sets it: dropped even though typed
    BACKUP_KEEP: "  ",                   // blank: the server's default
    PUBLIC_URL: " https://security.example.com ",
    OIDC_ISSUER: "https://login.example.com/tenant/v2.0", OIDC_CLIENT_ID: "client-1", OIDC_CLIENT_SECRET: "",
    OIDC_ALLOWED_GROUP: "group-1", SESSION_KEY: "k".repeat(40),
    NINJA_BASE_URL: "https://typed.example.com", NINJA_CLIENT_ID: "ninja-id", NINJA_CLIENT_SECRET: "",
    HALO_BASE_URL: "https://halo.example.com/api", HALO_CLIENT_ID: "halo-id", HALO_CLIENT_SECRET: "typed-but-env",
    NVD_API_KEY: "nvd-key",
  }, "oidc");
  expect(savePayload(server, d)).toEqual({
    AUTH_MODE: "oidc", PUBLIC_URL: "https://security.example.com",
    OIDC_ISSUER: "https://login.example.com/tenant/v2.0", OIDC_CLIENT_ID: "client-1", OIDC_ALLOWED_GROUP: "group-1", SESSION_KEY: "k".repeat(40),
    NINJA_CLIENT_ID: "ninja-id",
    HALO_BASE_URL: "https://halo.example.com/api", HALO_CLIENT_ID: "halo-id",
    NVD_API_KEY: "nvd-key",
  });
});

test("a skipped connector sends nothing, and needs nothing", () => {
  const d = draft({ NVD_API_KEY: "typed-then-skipped", HALO_CLIENT_ID: "halo-id" }, "cloudflare_access", { nvd: true, halo: true });
  const p = savePayload(st({}), d);
  expect(p).not.toHaveProperty("NVD_API_KEY");
  expect(p).not.toHaveProperty("HALO_CLIENT_ID");
  expect(missing(st({}), d, "halo")).toEqual([]);
  expect(missing(st({}), draft({ HALO_CLIENT_ID: "halo-id" }), "halo")).toEqual(["Halo's API address", "Client secret"]);
});

test("only the chosen sign-in's settings are sent, with AUTH_MODE and PROXY_KIND", () => {
  const values = { ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com", ACCESS_AUD: "aud", TRUSTED_HEADER: "X-Email", OIDC_CLIENT_ID: "stale" };
  expect(sectionValues(st({}), draft(values, "cloudflare_access"), "auth")).toEqual({ AUTH_MODE: "proxy", PROXY_KIND: "cloudflare_access", ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com", ACCESS_AUD: "aud" });
  expect(sectionValues(st({}), draft(values, "trusted_header"), "auth")).toEqual({ AUTH_MODE: "proxy", PROXY_KIND: "trusted_header", TRUSTED_HEADER: "X-Email" });
  expect(missing(st({}), draft(values, "trusted_header"), "auth")).toEqual(["The proxy's addresses (CIDRs, comma-separated)"]);
  expect(missing(st({}), draft({}), "auth")).toEqual(["how people sign in"]);
});

test("a sign-in the environment fixes is chosen for you, not sent, and limits the choices", () => {
  const s = st({ AUTH_MODE: { set: true, env: true, value: "proxy" }, PROXY_KIND: { set: false, env: false, value: null } });
  expect(modeAllowed(s, "oidc")).toBe(false);
  expect(modeAllowed(s, "trusted_header")).toBe(true);
  expect(sectionValues(s, draft({ TRUSTED_HEADER: "X-Email", TRUSTED_PROXY_CIDRS: "10.0.5.0/24" }, "trusted_header"), "auth"))
    .toEqual({ PROXY_KIND: "trusted_header", TRUSTED_HEADER: "X-Email", TRUSTED_PROXY_CIDRS: "10.0.5.0/24" });
  const both = st({ AUTH_MODE: { set: true, env: true, value: "oidc" }, PROXY_KIND: { set: false, env: false, value: null } });
  expect(modeFrom(both)).toBe("oidc");
  expect(initialDraft(both).mode).toBe("oidc");
});

test("a saved or environment secret counts as filled in; a typed blank doesn't", () => {
  expect(missing(server, draft({ NINJA_CLIENT_ID: "ninja-id" }), "ninja")).toEqual([]); // base URL from env, secret saved
  expect(missing(st({}), draft({ NINJA_BASE_URL: "https://app.ninjarmm.com", NINJA_CLIENT_ID: "id", NINJA_CLIENT_SECRET: "   " }), "ninja")).toEqual(["Client secret"]);
});

test("the review never shows a secret's value", () => {
  expect(reviewValue(server, draft({ NINJA_CLIENT_SECRET: "typed" }), field("NINJA_CLIENT_SECRET"))).toBe("A new value, entered");
  expect(reviewValue(server, draft({}), field("NINJA_CLIENT_SECRET"))).toBe("Saved; kept as it is");
  expect(reviewValue(server, draft({}), field("HALO_CLIENT_SECRET"))).toBe("Set by environment");
  expect(reviewValue(st({}), draft({}), field("NVD_API_KEY"))).toBe("Not set");
  expect(reviewValue(server, draft({}), field("DATABASE_PATH"))).toBe("/data/console.db (set by environment)");
  expect(reviewValue(st({}), draft({}), field("DATABASE_PATH"))).toBe("/data/console.db (the default)");
});

test("a made session key is long enough for the server's rule, and different each time", () => {
  const a = newSessionKey(), b = newSessionKey();
  expect(a.length).toBeGreaterThanOrEqual(32);
  expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(a).not.toBe(b);
});

test("“Only this computer” is offered only where the server allows it, and sends AUTH_MODE=dev_insecure alone", () => {
  const laptop: SetupState = { ...st({}), local_only: true };
  const shared: SetupState = { ...st({}), local_only: false };
  expect(visibleModes(laptop).map((m) => m.id)).toEqual(["cloudflare_access", "trusted_header", "oidc", "local"]);
  expect(visibleModes(shared).map((m) => m.id)).toEqual(["cloudflare_access", "trusted_header", "oidc"]);
  expect(visibleModes(st({})).map((m) => m.id)).not.toContain("local"); // a server that doesn't say: not offered
  expect(modeAllowed(shared, "local")).toBe(false);
  expect(AUTH_MODES.find((m) => m.id === "local")!.hint).toContain("anyone who can reach this port is signed in");
  const d = draft({ PUBLIC_URL: "https://security.example.com", TRUSTED_HEADER: "X-Email", SESSION_KEY: "k".repeat(40) }, "local");
  expect(sectionValues(laptop, d, "auth")).toEqual({ AUTH_MODE: "dev_insecure" });
  expect(missing(laptop, d, "auth")).toEqual([]);
  expect(savePayload(laptop, d)).not.toHaveProperty("PROXY_KIND");
  expect(initialDraft({ ...st({ AUTH_MODE: { set: true, env: false, value: "dev_insecure" } }), local_only: true }).mode).toBe("local");
});

test("the master key's place is said after the save, from its answer, and never guessed before it", () => {
  expect(KEY_BACKUP_NOTE).toContain("backed up");
  expect(KEY_BACKUP_NOTE).not.toMatch(/\//); // no path on the review step: only the save knows where
  expect(masterKeyNote("/srv/keys/master.key")).toContain("The master key is at /srv/keys/master.key.");
  expect(masterKeyNote(null)).toBeNull();      // the environment's key, or nothing secret saved: nothing to keep
  expect(masterKeyNote(undefined)).toBeNull();
  expect(masterKeyNote("  ")).toBeNull();
});

test("the database is the SQLite file by default, or PostgreSQL, and only the chosen one's settings are sent", () => {
  expect(STORES.map((x) => x.id)).toEqual(["sqlite", "postgres"]);
  expect(STORES[0].label).toBe("SQLite file on this volume");
  expect(storeOf(st({}), initialDraft(st({})))).toBe("sqlite");
  expect(fieldsOf("database", null, "sqlite").map((f) => f.key)).toEqual(["DATABASE_PATH", "BACKUP_KEEP"]);
  expect(fieldsOf("database", null, "postgres").map((f) => f.key)).toEqual(["DATABASE_URL"]);
  const typed = { DATABASE_PATH: "/srv/console.db", BACKUP_KEEP: "14", DATABASE_URL: "postgres://u:p@db.example.com/console?sslmode=require" };
  expect(sectionValues(st({}), { ...draft(typed), store: "sqlite" }, "database")).toEqual({ DATABASE_PATH: "/srv/console.db", BACKUP_KEEP: "14" });
  expect(sectionValues(st({}), { ...draft(typed), store: "postgres" }, "database")).toEqual({ DATABASE_URL: "postgres://u:p@db.example.com/console?sslmode=require" });
  // The SQLite file at its default, with nothing saved: nothing to send.
  expect(sectionValues(st({}), { ...draft({}), store: "sqlite" }, "database")).toEqual({});
});

test("the database URL is a secret: never prefilled, never shown, required for PostgreSQL, kept when left blank", () => {
  expect(isSecret("DATABASE_URL")).toBe(true);
  expect(field("DATABASE_URL").kind).toBe("secret");
  const saved = st({ DATABASE_URL: { set: true, env: false, value: "postgres://should-never-show" } });
  expect(storeFrom(saved)).toBe("postgres");
  const d = initialDraft(saved);
  expect(d.values).toEqual({});
  expect(d.store).toBe("postgres");
  expect(fieldView(saved, d, field("DATABASE_URL"))).toEqual({ locked: false, value: "", note: "Saved; leave blank to keep" });
  expect(missing(saved, d, "database")).toEqual([]);
  expect(missing(st({}), { ...draft({ DATABASE_URL: "  " }), store: "postgres" }, "database")).toEqual(["Database URL"]);
  // Blank: the saved URL stays, so nothing is sent; the review says so, never the value.
  expect(sectionValues(saved, d, "database")).toEqual({});
  expect(reviewValue(saved, d, field("DATABASE_URL"))).toBe("Saved; kept as it is");
  expect(reviewValue(saved, { ...d, values: { DATABASE_URL: "postgres://new" } }, field("DATABASE_URL"))).toBe("A new value, entered");
  expect(DATABASE_TLS_NOTE).toContain("sslmode=verify-full");
  expect(DATABASE_TLS_NOTE).toContain("verify-ca with sslrootcert");
});

test("choosing the SQLite file over a saved URL sends the path, its default when blank, so the URL is let go", () => {
  const saved = st({ DATABASE_URL: { set: true, env: false, value: null } });
  expect(sectionValues(saved, { ...draft({}), store: "sqlite" }, "database")).toEqual({ DATABASE_PATH: "/data/console.db" });
  expect(sectionValues(saved, { ...draft({ DATABASE_PATH: "/srv/c.db" }), store: "sqlite" }, "database")).toEqual({ DATABASE_PATH: "/srv/c.db" });
  expect(savePayload(saved, { ...draft({}), store: "sqlite", mode: "local" })).not.toHaveProperty("DATABASE_URL");
});

test("a store the environment sets is fixed, and nothing about it is sent", () => {
  const envUrl = st({ DATABASE_URL: { set: true, env: true, value: null } });
  expect(storeLocked(envUrl)).toBe("postgres");
  // A stale choice in the draft doesn't override the environment's.
  expect(storeOf(envUrl, { ...draft({ DATABASE_PATH: "/x.db" }), store: "sqlite" })).toBe("postgres");
  expect(sectionValues(envUrl, { ...draft({ DATABASE_PATH: "/x.db", DATABASE_URL: "postgres://typed" }), store: "sqlite" }, "database")).toEqual({});
  expect(fieldView(envUrl, draft({}), field("DATABASE_URL"))).toEqual({ locked: true, value: "", note: "Set by environment" });
  expect(missing(envUrl, draft({}), "database")).toEqual([]);
  const envPath = st({ DATABASE_PATH: { set: true, env: true, value: "/data/console.db" } });
  expect(storeLocked(envPath)).toBe("sqlite");
  expect(sectionValues(envPath, { ...draft({ DATABASE_URL: "postgres://typed" }), store: "postgres" }, "database")).toEqual({});
});

test("what isn't connected yet: skipped or half-filled optional sections, each with what it adds", async () => {
  const { notConnected, SECTIONS } = await import("./wizard");
  const state = { keys: { NINJA_BASE_URL: { set: true, env: false, value: "https://app.ninjarmm.com" }, NINJA_CLIENT_ID: { set: true, env: false, value: "id" },
    NINJA_CLIENT_SECRET: { set: true, env: false, value: null } }, sections: [] } as any;
  const off = notConnected(state).map((x) => x.id);
  expect(off).not.toContain("ninja");
  expect(off).toContain("halo");
  expect(notConnected(state, { values: {}, mode: null, skipped: { ninja: true } }).map((x) => x.id)).toContain("ninja");
  for (const x of SECTIONS.filter((x) => x.optional)) expect(x.adds ?? x.intro).toBeTruthy();
});

test("a choice shows its option's label, says when it's the default, and only another choice is sent", () => {
  expect(reviewValue(st({}), draft({}), field("NVD_FEEDS"))).toBe("All of NVD (its yearly feeds), so every installed program is compared (the default)");
  expect(reviewValue(st({}), draft({ NVD_FEEDS: "curated" }), field("NVD_FEEDS"))).toBe("Only the curated products, through NVD's API");
  expect(reviewValue(st({ MSRC: { set: true, env: false, value: "off" } }), draft({}), field("MSRC"))).toBe("Off: leave Windows itself out");
  expect(savePayload(st({}), draft({ MSRC: "off", NINJA_PROCESS_FIELD: "myInventory" }, null, { ninja: false }))).toMatchObject({ MSRC: "off" });
  expect(section("msrc").optional).toBe(true);
  expect(field("NINJA_PROCESS_FIELD").hint).toContain("endpoint/README.md");
});
