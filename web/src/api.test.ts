// The API client against a stand-in server: what it sends, the 401 → sign-in redirect, and every failure as a sentence.
import { afterEach, expect, test } from "bun:test";
import * as api from "./api";

type Call = { url: string; init?: RequestInit };
function server(answer: (c: Call) => Response | Promise<Response>) {
  const calls: Call[] = [], went: string[] = [];
  api.useEnv({
    fetch: async (url, init) => { const c = { url, init }; calls.push(c); return answer(c); },
    assign: (u) => { went.push(u); },
    here: () => "/clients/7?name=Example%20Dental",
    sleep: async () => {},
  });
  return { calls, went };
}
const json = (status: number, b: unknown) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
afterEach(() => api.useEnv());

test("evidence posts contract v1's { op, params } to its own server and passes the answer through", async () => {
  const s = server(() => json(200, { v: 1, op: "cves.list", data: [{ cve_id: "CVE-2026-0001" }], next_cursor: "abc", totals: { cves: 1 } }));
  const a = await api.evidence("cves.list", { org_id: 7, kev: true });
  expect(s.calls).toHaveLength(1);
  expect(s.calls[0].url).toBe("/api/evidence");
  expect(s.calls[0].init?.method).toBe("POST");
  expect(JSON.parse(String(s.calls[0].init?.body))).toEqual({ op: "cves.list", params: { org_id: 7, kev: true } });
  expect(a.data).toEqual([{ cve_id: "CVE-2026-0001" }]);
  expect(a.next_cursor).toBe("abc");
  expect(a.error).toBeUndefined();
});

test("a 401 with a login address sends the browser to sign in, coming back to the same view", async () => {
  const s = server(() => json(401, { error: "sign in first", login: "/auth/login" }));
  const a = await api.evidence("search", { q: "example" });
  expect(s.went).toEqual([`/auth/login?return_to=${encodeURIComponent("/clients/7?name=Example%20Dental")}`]);
  expect(a.error).toBe(api.SIGNING_IN);
});

test("a 401 behind a proxy (no login address) says to reload, and goes nowhere", async () => {
  const s = server(() => json(401, { error: "sign in first", login: null }));
  const a = await api.evidence("search", { q: "example" });
  expect(s.went).toEqual([]);
  expect(a.error).toBe(api.EXPIRED);
});

test("a login address that isn't this server's own path is never followed", async () => {
  const s = server(() => json(401, { error: "sign in first", login: "//evil.example.com/login" }));
  await api.me();
  expect(s.calls).toHaveLength(1);
  expect(s.went).toEqual([]);
});

test("/api/me also redirects on 401, and answers who is signed in otherwise", async () => {
  let n = 0;
  const s = server(() => (n++ === 0 ? json(401, { error: "sign in first", login: "/auth/login" }) : json(200, { email: "pat@example.com", logout: "/auth/logout" })));
  expect((await api.me()).error).toBe(api.SIGNING_IN);
  expect(s.went).toHaveLength(1);
  expect((await api.me()).data).toEqual({ email: "pat@example.com", logout: "/auth/logout" });
  expect(s.calls.map((c) => c.url)).toEqual(["/api/me", "/api/me"]);
});

test("an error body's own sentence comes through, with the rest of the answer", async () => {
  server(() => json(503, { v: 1, op: "devices.list", error: "the console's database didn't answer" }));
  const a = await api.evidence("devices.list");
  expect(a.error).toContain("database didn't answer");
  expect(a.op).toBe("devices.list");
});

test("an error without a body, a body that isn't JSON, and no answer at all are each a plain sentence", async () => {
  server(() => new Response("<html>bad gateway</html>", { status: 502 }));
  expect((await api.evidence("search", { q: "x" })).error).toBe("The console answered 502 without saying why.");
  server(() => { throw new TypeError("network down"); });
  expect((await api.evidence("search", { q: "x" })).error).toBe(api.OFFLINE);
  expect((await api.status()).error).toBe(api.OFFLINE);
  server(() => json(503, { error: "the console's database didn't answer" }));
  expect((await api.status()).error).toBe("the console's database didn't answer");
});

test("sign out is a POST, then on to where the server says", async () => {
  const s = server(() => json(200, { to: "https://login.example.com/logout?client_id=x" }));
  await api.signOut("/auth/logout");
  expect(s.calls[0]).toMatchObject({ url: "/auth/logout", init: { method: "POST" } });
  expect(s.went).toEqual(["https://login.example.com/logout?client_id=x"]);
  const t = server(() => json(403, { error: "sign out from the console itself" }));
  await api.signOut("/auth/logout");
  expect(t.went).toEqual(["/"]);
});

test("setup: unlock sends the trimmed token; a wrong one, too many, and a lapsed cookie each say what to do", async () => {
  const s = server(() => new Response(null, { status: 204 }));
  expect(await api.unlock("  abc123  ")).toEqual({ data: undefined });
  expect(JSON.parse(String(s.calls[0].init?.body))).toEqual({ token: "abc123" });
  server(() => json(401, { error: "That isn't the setup token." }));
  expect(await api.unlock("nope")).toEqual({ error: "That isn't the setup token.", locked: true });
  server(() => json(429, { error: "Too many wrong setup tokens." }));
  expect((await api.unlock("nope")).error).toBe("Too many wrong setup tokens.");
  server(() => json(401, { error: "unlock setup first" }));
  expect(await api.setupState()).toEqual({ error: api.SETUP_LOCKED, locked: true });
});

test("setup: save's refusal names its section; test answers pass through", async () => {
  server(() => json(400, { error: "OIDC_ISSUER must be https", section: "auth" }));
  expect(await api.save({ OIDC_ISSUER: "http://login.example.com" })).toEqual({ error: "OIDC_ISSUER must be https", section: "auth" });
  const t = server(() => json(200, { ok: false, message: "NinjaOne refused the client credentials.", status: 401, detail: null }));
  const r = await api.testSection("ninja", { NINJA_CLIENT_ID: "id" });
  expect(JSON.parse(String(t.calls[0].init?.body))).toEqual({ section: "ninja", values: { NINJA_CLIENT_ID: "id" } });
  expect(r.data).toEqual({ ok: false, message: "NinjaOne refused the client credentials.", status: 401, detail: null });
});

test("after a save, /readyz is polled until it answers 200, and gives up after its tries", async () => {
  let n = 0;
  const s = server(() => new Response("", { status: ++n < 4 ? 503 : 200 }));
  expect(await api.waitForReady(10)).toBe(true);
  expect(s.calls.map((c) => c.url)).toEqual(["/readyz", "/readyz", "/readyz", "/readyz"]);
  const never = server(() => { throw new TypeError("restarting"); });
  expect(await api.waitForReady(5)).toBe(false);
  expect(never.calls).toHaveLength(5);
});

test("setup on a console that's already configured says so, rather than asking for a token", async () => {
  const signIn = server(() => json(401, { error: "sign in first", login: "/auth/login" }));
  expect(await api.setupState()).toEqual({ error: api.CONFIGURED, configured: true });
  expect(signIn.went).toEqual([]); // setup never follows a sign-in redirect
  server(() => json(404, { error: "there's no such API call" }));
  expect(await api.setupState()).toEqual({ error: api.CONFIGURED, configured: true });
  server(() => json(401, { error: "unlock setup first, with the token from the console's log" }));
  expect(await api.setupState()).toEqual({ error: api.SETUP_LOCKED, locked: true }); // setup's own 401 names no login
});

test("the store's line on the Status page says which store, whether similar-CVE search is on, and whose the backups are", () => {
  expect(api.storeLine({ kind: "sqlite", vectors: { on: true }, backups: "the console's own" })).toBe("SQLite file · vectors on · backups: the console's own");
  expect(api.storeLine({ kind: "postgresql", vectors: { on: false, why: "similar-CVE search is off: this PostgreSQL database has no pgvector extension" }, backups: "yours" }))
    .toBe("PostgreSQL · vectors off (this PostgreSQL database has no pgvector extension) · backups: yours");
  expect(api.embedderLine({ on: true, model: "bge-small-en-v1.5-int8", threads: 2 })).toBe("on · bge-small-en-v1.5-int8, in this console, 2 threads");
  expect(api.embedderLine({ on: false, model: "bge-small-en-v1.5-int8", why: "similar-CVE search is off: the embedder is turned off (EMBEDDER=off)" }))
    .toBe("off: the embedder is turned off (EMBEDDER=off)");
});
