// The app talks only to its own server, same origin, and never holds a vendor's key. One call shape for evidence:
// contract v1's { op, params }. Every failure comes back as a plain sentence in `error`, never a throw.
import type { Answer, EvidenceRequest, ReviewDecision } from "@msp/contract";

// What the client needs from the browser, so tests can stand in for it.
export type Env = {
  fetch: (input: string, init?: RequestInit) => Promise<Response>;
  /** Send the browser somewhere else. */
  assign: (url: string) => void;
  /** Where the browser is now: path and query. */
  here: () => string;
  sleep: (ms: number) => Promise<void>;
};

const browser: Env = {
  fetch: (input, init) => globalThis.fetch(input, init),
  assign: (url) => window.location.assign(url),
  here: () => window.location.pathname + window.location.search,
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};
let env: Env = browser;
/** Replace parts of the browser (tests); with no argument, back to the real one. */
export function useEnv(e?: Partial<Env>): void { env = e ? { ...browser, ...e } : browser; }

export const OFFLINE = "The console didn't answer. Check your connection, then try again.";
export const EXPIRED = "Your sign-in has expired. Reload the page to sign in again.";
export const SIGNING_IN = "Signing you in…";

async function body(res: Response): Promise<any> {
  try { return await res.json(); } catch { return null; }
}

// Not signed in: when the console signs people in itself (OIDC) the server says where, and the browser goes there,
// coming back to this same view. Behind a proxy (Cloudflare Access, a trusted header) a reload signs in again.
function signIn(b: any): boolean {
  const login = b?.login;
  if (typeof login !== "string" || !login.startsWith("/") || login.startsWith("//")) return false;
  env.assign(`${login}?return_to=${encodeURIComponent(env.here())}`);
  return true;
}

/** The message a failed answer carries: the server's own sentence when it sent one. */
function failure(res: Response, b: any): string {
  if (typeof b?.error === "string" && b.error.trim()) return b.error;
  return `The console answered ${res.status} without saying why.`;
}

export async function evidence<T = any>(op: EvidenceRequest["op"], params: EvidenceRequest["params"] = {}): Promise<Answer<T>> {
  let res: Response;
  try {
    res = await env.fetch("/api/evidence", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify({ op, params }) });
  } catch { return { v: 1, op, error: OFFLINE }; }
  const b = await body(res);
  if (res.status === 401) return { v: 1, op, error: signIn(b) ? SIGNING_IN : EXPIRED };
  if (!res.ok || b === null) return { v: 1, op, ...(b ?? {}), error: failure(res, b) };
  return b as Answer<T>;
}

/** A GET of the console's own JSON, behind sign-in. */
async function getJson<T>(path: string): Promise<{ data?: T; error?: string }> {
  let res: Response;
  try { res = await env.fetch(path, { credentials: "same-origin" }); } catch { return { error: OFFLINE }; }
  const b = await body(res);
  if (res.status === 401) return { error: signIn(b) ? SIGNING_IN : EXPIRED };
  if (!res.ok || b === null) return { error: failure(res, b) };
  return { data: b as T };
}

/** Who is signed in; `admin` decides whether Settings and the advisory editor are theirs to change. */
export type Me = { email: string; admin?: boolean; logout: string | null };
export const me = () => getJson<Me>("/api/me");

export type Job = { job: string; last_ok_at: string | null; last_error: string | null; next_run_at: string; running: boolean; detail: Record<string, unknown> | null };
/** The store: which kind, whether it can hold vectors (and why not), and whose the backups are. */
export type StoreStatus = { kind: "sqlite" | "postgresql"; vectors: { on: boolean; why?: string }; backups: string };
/** The embedder behind similar-CVE search: on (its model, its threads), or off and why. */
export type EmbedderStatus = { on: boolean; model: string; threads?: number; why?: string };
export const status = () => getJson<{ jobs: Job[]; store?: StoreStatus; embedder?: EmbedderStatus }>("/api/status");
/** The store in one line, for the Status page: "PostgreSQL · vectors off (…) · backups: yours: …". */
export function storeLine(x: StoreStatus): string {
  const kind = x.kind === "postgresql" ? "PostgreSQL" : "SQLite file";
  const why = x.vectors.why?.replace(/^similar-CVE search is off: /, "");
  return `${kind} · ${x.vectors.on ? "vectors on" : `vectors off${why ? ` (${why})` : ""}`} · backups: ${x.backups}`;
}
/** Similar-CVE search in one line: "on · bge-small-en-v1.5-int8, in this console, 2 threads", or "off: why". */
export function embedderLine(x: EmbedderStatus): string {
  if (x.on) return `on · ${x.model}, in this console${x.threads ? `, ${x.threads} ${x.threads === 1 ? "thread" : "threads"}` : ""}`;
  return `off: ${(x.why ?? "no reason given").replace(/^similar-CVE search is off: /, "")}`;
}

// ---- Admin calls (Settings → Connectors, advisories): behind sign-in like the rest, and a 403 for anyone but an admin.

/** A JSON POST of the console's own, behind sign-in: the answer, or the server's own sentence for why not. */
async function postJson<T>(path: string, b: unknown): Promise<{ data?: T; error?: string; status?: number; section?: string | null }> {
  let res: Response;
  try { res = await env.fetch(path, { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify(b) }); }
  catch { return { error: OFFLINE }; }
  const x = await body(res);
  if (res.status === 401) return { error: signIn(x) ? SIGNING_IN : EXPIRED, status: 401 };
  if (!res.ok || x === null) return { error: failure(res, x), status: res.status, section: x?.section ?? null };
  return { data: x as T, status: res.status };
}
/** Each connector's settings, as Settings shows them (the setup state's shape, for the connectors' sections alone). */
export type ConnectorsState = SetupState & { plaintext_secrets: string[] };
export const adminConnectors = () => getJson<ConnectorsState>("/api/admin/connectors");
export const adminTest = (section: string, values: Record<string, string>) => postJson<TestResult>("/api/admin/connectors/test", { section, values });
/** A connector's save: what changed (names), the plaintext secrets it encrypted, and whether the console restarts. */
export type AdminSaved = { restarting: boolean; changed: string[]; reencrypted: string[] };
export const adminSave = (section: string, values: Record<string, string>, off = false) => postJson<AdminSaved>("/api/admin/connectors/save", { section, values, off });
export type AdvisoryAction = "save" | "supersede" | "reactivate";
export const saveAdvisory = (action: AdvisoryAction, advisory: Record<string, unknown>, reason = "") =>
  postJson<{ ok: boolean; advisory_id: string; applied: { advisory_rows: number } }>("/api/admin/advisories", { action, advisory, reason });

// Sign out: a POST from this page (the server refuses one from anywhere else), then on to where it says, which is the
// provider's own sign-out when the console signed you in itself.
export async function signOut(to: string): Promise<void> {
  const r = await env.fetch(to, { method: "POST", credentials: "same-origin" }).catch(() => null);
  const next = r?.ok ? (await body(r))?.to : null;
  env.assign(typeof next === "string" ? next : "/");
}

// ---- The setup wizard's calls (only while the console is unconfigured). No sign-in redirect: the setup cookie,
// from the token, is the only key, and a 401 means the token is needed again.

export type KeyState = { set: boolean; env: boolean; value: string | null };
/** `local_only`: whether "Only this computer" (no sign-in) may be chosen, outside production and Kubernetes. */
export type SetupState = { keys: Record<string, KeyState>; sections: string[]; local_only?: boolean };
export type TestResult = { ok: boolean; message: string; status: number | null; detail: Record<string, unknown> | null };
export type SetupAnswer<T> = { data?: T; error?: string; locked?: boolean; configured?: boolean; section?: string | null };

export const SETUP_LOCKED = "Your setup session has ended. Enter the setup token again to carry on.";
export const CONFIGURED = "This console is already set up. Its settings change by environment, or in the config file.";

async function setupCall<T>(path: string, init: RequestInit): Promise<SetupAnswer<T>> {
  let res: Response;
  try { res = await env.fetch(path, { credentials: "same-origin", ...init }); } catch { return { error: OFFLINE }; }
  if (res.status === 204) return { data: undefined };
  const b = await body(res);
  // A configured console has no setup: its sign-in answers (a 401 naming where to sign in), or a 404 once signed in.
  if ((res.status === 401 && b && "login" in b) || res.status === 404) return { error: CONFIGURED, configured: true };
  if (res.status === 401) return { error: path.endsWith("/unlock") ? (b?.error ?? "That isn't the setup token.") : SETUP_LOCKED, locked: true };
  if (res.status === 429) return { error: b?.error ?? "Too many wrong setup tokens. Restart the console for a new one, printed to its log.", locked: true };
  if (!res.ok || b === null) return { error: failure(res, b), section: b?.section ?? null };
  return { data: b as T };
}
const post = (b: unknown): RequestInit => ({ method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) });

export const unlock = (token: string) => setupCall<void>("/api/setup/unlock", post({ token: token.trim() }));
export const setupState = () => setupCall<SetupState>("/api/setup/state", { method: "GET" });
export const testSection = (section: string, values: Record<string, string>) => setupCall<TestResult>("/api/setup/test", post({ section, values }));
/** The save's answer: `master_key_path` is where the master key is, when the save used a key file (null when the key
 * is the environment's, or nothing secret was saved). */
export type Saved = { restarting: boolean; master_key_path?: string | null };
export const save = (values: Record<string, string>) => setupCall<Saved>("/api/setup/save", post({ values }));

/** After a save: /readyz every second until it answers 200, for up to `tries` seconds. */
export async function waitForReady(tries = 60): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    const r = await env.fetch("/readyz", { cache: "no-store" }).catch(() => null);
    if (r?.status === 200) return true;
    await env.sleep(1000);
  }
  return false;
}
export const goHome = () => env.assign("/");

// ---- A person's decision on a name the automatic mapping wouldn't decide (the review list): signed in, confirmed in
// the page first, audited by the server, and idempotent, so a second click changes nothing.
export type Decided = { status: string; cpe: string | null; unchanged: boolean };
export async function decide(d: ReviewDecision): Promise<{ data?: Decided; error?: string }> {
  let res: Response;
  try { res = await env.fetch("/api/review", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify(d) }); }
  catch { return { error: OFFLINE }; }
  const b = await body(res);
  if (res.status === 401) return { error: signIn(b) ? SIGNING_IN : EXPIRED };
  if (!res.ok || b === null) return { error: failure(res, b) };
  return { data: b as Decided };
}
