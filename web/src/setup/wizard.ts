// The setup wizard's model, apart from its screens: which settings each step asks for, what the server already knows
// (set by the environment, or saved), and the payloads for Test and Save. The rules that matter:
//   - a setting the environment sets is shown, never sent;
//   - a secret is never prefilled, and a blank one is never sent (the stored or environment one stays);
//   - a skipped connector sends nothing;
//   - the database is one store or the other: only the chosen one's settings are sent.
import type { KeyState, SetupState } from "../api";

export type Kind = "text" | "url" | "secret" | "number" | "choice";
/** A choice's options: the first is the default, sent only when another is chosen. */
export type Option = { value: string; label: string };
/** `choices`: the key in the section's last Test result whose list ([{id, name}]) the field picks from, when it has one.
 * `options`: a `choice` field's fixed options. */
export type Field = { key: string; label: string; kind: Kind; hint?: string; placeholder?: string; required?: boolean; autocomplete?: string; choices?: string; options?: Option[] };

export type AuthMode = "cloudflare_access" | "trusted_header" | "oidc" | "local";
export const AUTH_MODES: { id: AuthMode; label: string; hint: string }[] = [
  { id: "cloudflare_access", label: "Cloudflare Access", hint: "Cloudflare Access sits in front of the console, and the console checks Access's token itself." },
  { id: "trusted_header", label: "Another proxy that names the user in a header",
    hint: "Believed only from the proxy's own addresses. Anyone who can reach the console another way could claim to be anyone, so allow traffic in from the proxy alone." },
  { id: "oidc", label: "The console's own sign-in with Entra ID (OIDC)",
    hint: "Register an app in Entra with the redirect URI https://<this console>/auth/callback, a client secret, and group claims (or an app role). This console's address is required for this mode. A sign-in lasts 8 hours, so removing someone from the group takes effect when theirs ends; changing the session key signs everyone out at once." },
  { id: "local", label: "Only this computer (no sign-in)",
    hint: "No sign-in: anyone who can reach this port is signed in. Use it only on this computer, with the port bound to 127.0.0.1." },
];
/** AUTH_MODE and PROXY_KIND for each of the wizard's choices. "Only this computer" is AUTH_MODE=dev_insecure. */
export function authSettings(m: AuthMode): [string, string | null] {
  return m === "oidc" ? ["oidc", null] : m === "local" ? ["dev_insecure", null] : ["proxy", m];
}
/** The choices to show: "Only this computer" only where the server says it's allowed (outside production and Kubernetes). */
export const visibleModes = (s: SetupState | null) => AUTH_MODES.filter((m) => m.id !== "local" || s?.local_only === true);

export const DEFAULT_DATABASE_PATH = "/data/console.db";

/** Where the console keeps its data: a SQLite file on its own volume (the default), or a PostgreSQL database. */
export type Store = "sqlite" | "postgres";
export const STORES: { id: Store; label: string; hint: string }[] = [
  { id: "sqlite", label: "SQLite file on this volume",
    hint: "The console makes and keeps one file on its own volume, and a copy of it daily in backup/ beside it. Nothing else to run. One copy of the console at a time. The file holds your clients' inventory: put the volume on an encrypted disk." },
  { id: "postgres", label: "PostgreSQL",
    hint: "A PostgreSQL database you run or rent, for more than one copy of the console or a managed database. The console makes its own tables in it. Backups are yours (pg_dump, or your provider's snapshots). Similar-CVE search needs the pgvector extension; without it, everything else works." },
];
/** What the server's database step says before anything is chosen, about TLS. */
export const DATABASE_TLS_NOTE = "Ask for TLS in the URL with sslmode=verify-full, which encrypts the link and checks the server's certificate (add sslrootcert=<path to its CA's certificate> when the platform's roots don't sign it; managed PostgreSQL publishes its CA). In production the console accepts only verify-full, or verify-ca with sslrootcert: require encrypts but takes any certificate, so it's for trying the console on one computer.";
/** The store the server already holds: PostgreSQL when a URL is set (environment or saved), else the SQLite file. */
export function storeFrom(s: SetupState | null): Store { return keyState(s, "DATABASE_URL").set ? "postgres" : "sqlite"; }
/** The store the environment fixes, if it fixes one: a URL or a path set by environment can't be changed here. */
export function storeLocked(s: SetupState | null): Store | null {
  return keyState(s, "DATABASE_URL").env ? "postgres" : keyState(s, "DATABASE_PATH").env ? "sqlite" : null;
}

const ADMIN_EMAILS: Field = { key: "ADMIN_EMAILS", label: "Admins' addresses (comma-separated)", kind: "text", placeholder: "you@example.com",
  hint: "Who may change the connectors and advisories after setup, as your proxy names them. Everyone signed in can read everything." };
const PUBLIC_URL: Field = { key: "PUBLIC_URL", label: "This console's address", kind: "url", placeholder: "https://security.example.com",
  hint: "Where people open the console. Optional behind a proxy; required for the console's own sign-in." };

export const AUTH_FIELDS: Record<AuthMode, Field[]> = {
  cloudflare_access: [
    { key: "ACCESS_TEAM_DOMAIN", label: "Team domain", kind: "text", placeholder: "yourteam.cloudflareaccess.com", required: true },
    { key: "ACCESS_AUD", label: "Application audience (AUD) tag", kind: "text", required: true, hint: "On the Access application's overview in Cloudflare's dashboard." },
    PUBLIC_URL, ADMIN_EMAILS,
  ],
  trusted_header: [
    { key: "TRUSTED_HEADER", label: "Header", kind: "text", placeholder: "X-Forwarded-Email", required: true, hint: "The header your proxy puts the signed-in user's email address in." },
    { key: "TRUSTED_PROXY_CIDRS", label: "The proxy's addresses (CIDRs, comma-separated)", kind: "text", placeholder: "10.0.5.0/24", required: true },
    PUBLIC_URL, ADMIN_EMAILS,
  ],
  oidc: [
    { key: "OIDC_ISSUER", label: "Issuer", kind: "url", placeholder: "https://login.microsoftonline.com/<tenant-id>/v2.0", required: true },
    { key: "OIDC_CLIENT_ID", label: "Client id", kind: "text", required: true },
    { key: "OIDC_CLIENT_SECRET", label: "Client secret", kind: "secret", required: true },
    { key: "OIDC_ALLOWED_GROUP", label: "Allowed group (object id)", kind: "text", required: true, hint: "Only members of this group can sign in." },
    { key: "OIDC_ADMIN_GROUP", label: "Admin group (object id, or an app role)", kind: "text", hint: "Its members may change the connectors and advisories after setup. Everyone else reads." },
    { key: "SESSION_KEY", label: "Session key (32 or more random characters)", kind: "secret", required: true, hint: "Seals the sign-in cookie. Changing it later signs everyone out." },
    { ...PUBLIC_URL, required: true, hint: "Where people open the console, as https://. Entra sends people back to it after they sign in." },
  ],
  local: [],
};

export type SectionId = "database" | "auth" | "ninja" | "halo" | "nvd" | "msrc" | "blackpoint" | "shodan";
/** `adds`: for an optional connector, one line on what turning it on adds (the "what isn't connected yet" summary). */
export type Section = { id: SectionId; title: string; intro: string; optional: boolean; fields: Field[]; adds?: string };

export const STORE_FIELDS: Record<Store, Field[]> = {
  sqlite: [
    { key: "DATABASE_PATH", label: "Database file", kind: "text", placeholder: DEFAULT_DATABASE_PATH, hint: `Leave it blank for the default, ${DEFAULT_DATABASE_PATH}.` },
    { key: "BACKUP_KEEP", label: "Daily copies to keep", kind: "number", placeholder: "7", hint: "Leave it blank to keep the newest 7." },
  ],
  postgres: [
    { key: "DATABASE_URL", label: "Database URL", kind: "secret", required: true, placeholder: "postgres://console:<password>@db.example.com:5432/console?sslmode=verify-full",
      hint: "It carries the password, so it's kept as a secret: encrypted when saved, never shown again. The user needs to be able to create tables in its schema." },
  ],
};

export const SECTIONS: Section[] = [
  { id: "database", title: "Database", optional: false,
    intro: "Where the console keeps its data: your clients' devices, software and the CVEs they carry. The console makes its own tables and keeps them up to date.",
    fields: [] },
  { id: "auth", title: "Sign-in", optional: false, intro: "Choose how people sign in to the console.", fields: [] },
  { id: "ninja", title: "NinjaOne", optional: true, adds: "Your clients, their devices and their installed software: without it the console has no fleet to match CVEs against.",
    intro: "The console reads your organizations, devices and installed software from NinjaOne, read-only. Create an API client in NinjaOne (client credentials, scope monitoring) and enter it here.",
    fields: [
      { key: "NINJA_BASE_URL", label: "NinjaOne address", kind: "url", placeholder: "https://app.ninjarmm.com", required: true, hint: "Your region's NinjaOne address, the one you sign in at." },
      { key: "NINJA_CLIENT_ID", label: "Client id", kind: "text", required: true },
      { key: "NINJA_CLIENT_SECRET", label: "Client secret", kind: "secret", required: true },
      { key: "NINJA_PROCESS_FIELD", label: "Process inventory field", kind: "text", placeholder: "processInventory",
        hint: "The NinjaOne custom field the console's endpoint script writes running processes to (endpoint/README.md says how to create it and deploy the script). Leave it blank for the script's own name, processInventory, or enter off to leave running processes out." },
    ] },
  { id: "halo", title: "HaloPSA", optional: true, adds: "Each client's Halo record and websites, linked to its NinjaOne organization.",
    intro: "The console reads your clients, their NinjaOne links and their websites from HaloPSA. Create an API application in Halo (client credentials, permission to read clients) and enter it here.",
    fields: [
      { key: "HALO_BASE_URL", label: "Halo's API address", kind: "url", placeholder: "https://yourcompany.halopsa.com/api", required: true },
      { key: "HALO_CLIENT_ID", label: "Client id", kind: "text", required: true },
      { key: "HALO_CLIENT_SECRET", label: "Client secret", kind: "secret", required: true },
      { key: "HALO_AUTH_URL", label: "Token address", kind: "url", placeholder: "https://yourcompany.halopsa.com/auth/token", hint: "Only when your Halo issues tokens somewhere other than beside its API." },
      { key: "HALO_TENANT", label: "Tenant", kind: "text", hint: "Only for Halo's hosted instances that ask for one." },
      // Tickets raised from findings: all three, or none to leave tickets off. Test the connection to pick from Halo's own lists.
      { key: "HALO_TICKET_TYPE_ID", label: "Ticket type for findings", kind: "number", choices: "ticket_types",
        hint: "For tickets raised from a detection or an exposed address. Test the connection to choose from Halo's own ticket types. Leave all three ticket settings blank to keep tickets off; the API application then needs no permission to create tickets." },
      { key: "HALO_TICKET_STATUS_ID", label: "Ticket status", kind: "number", choices: "statuses" },
      { key: "HALO_TICKET_PRIORITY_ID", label: "Ticket priority", kind: "number", choices: "priorities" },
    ] },
  { id: "nvd", title: "NVD", optional: true, adds: "Faster CVE updates from NVD: it works without a key, more slowly.",
    intro: "The console reads CVE scores and descriptions from NIST's National Vulnerability Database, which works without a key. A free API key from NVD lets it read faster.",
    fields: [{ key: "NVD_API_KEY", label: "NVD API key", kind: "secret", required: true },
      { key: "NVD_FEEDS", label: "How much of NVD", kind: "choice",
        options: [{ value: "full", label: "All of NVD (its yearly feeds), so every installed program is compared" }, { value: "curated", label: "Only the curated products, through NVD's API" }],
        hint: "All of NVD is about 400 MB to download the first time, over a few hourly runs, and keeps itself current from NVD's daily changes. It needs no key." }] },
  { id: "msrc", title: "Microsoft updates", optional: true, adds: "Which Windows CVEs each device still has open, and the update that fixes each.",
    intro: "The console reads Microsoft's monthly security updates (MSRC, public, no key) to say which Windows CVEs each device still has open, and the update (KB) that fixes each. Each device's patch level comes from NinjaOne.",
    fields: [{ key: "MSRC", label: "Microsoft's security updates", kind: "choice",
      options: [{ value: "on", label: "On: read Microsoft's updates" }, { value: "off", label: "Off: leave Windows itself out" }] }] },
  { id: "blackpoint", title: "Blackpoint", optional: true, adds: "Blackpoint's detections, vulnerability findings and dark-web exposures, by client.",
    intro: "The console reads your Blackpoint CompassOne tenants, their devices, open detections, vulnerability findings and dark-web exposures, read-only. Create an API token in CompassOne and enter it here. Dark-web rows keep only the address, where it was seen, when and what kind of data, never the exposed value.",
    fields: [
      { key: "BLACKPOINT_BASE_URL", label: "CompassOne API address", kind: "url", placeholder: "https://api.blackpointcyber.com", required: true },
      { key: "BLACKPOINT_API_TOKEN", label: "API token", kind: "secret", required: true },
    ] },
  { id: "shodan", title: "Shodan", optional: true, adds: "What the internet sees of your clients' public addresses and websites.",
    intro: "The console looks up your clients' public addresses and their websites' servers in Shodan's own internet scan, which sends nothing to their networks. On-demand scans cost Shodan's scan credits, so they stay off until an admin turns them on for a client. The test reads your account's credits, and spends none.",
    fields: [
      { key: "SHODAN_API_KEY", label: "Shodan API key", kind: "secret", required: true },
      { key: "SHODAN_SCAN_CREDITS_PER_MONTH", label: "Scan credits the console may spend a month", kind: "number", placeholder: "100", hint: "Leave it blank for 100; 0 asks for no scans at all." },
      { key: "SCAN_POLICY_ADMINS", label: "Who else may turn on scans (sign-in emails, comma-separated)", kind: "text", placeholder: "lead@example.com",
        hint: "The console's admins can always set a client's scan policy. These people can too, for scans alone." },
    ] },
];
export const section = (id: SectionId) => SECTIONS.find((s) => s.id === id)!;

/** The wizard's draft: what the person typed, the store and sign-in they chose, and which connectors they skipped. */
export type Draft = { values: Record<string, string>; mode: AuthMode | null; store?: Store; skipped: Partial<Record<SectionId, boolean>> };
/** The draft's store: the environment's when it fixes one, else what was chosen, else the SQLite file. */
export const storeOf = (s: SetupState | null, d: Draft): Store => storeLocked(s) ?? d.store ?? "sqlite";

const NONE: KeyState = { set: false, env: false, value: null };
export const keyState = (s: SetupState | null, key: string): KeyState => s?.keys?.[key] ?? NONE;

/** The sign-in the server already holds (environment or saved), as one of the wizard's three. */
export function modeFrom(s: SetupState | null): AuthMode | null {
  const mode = keyState(s, "AUTH_MODE").value, kind = keyState(s, "PROXY_KIND").value;
  if (mode === "oidc") return "oidc";
  if (mode === "dev_insecure") return "local";
  if (mode === "proxy" && (kind === "cloudflare_access" || kind === "trusted_header")) return kind;
  return null;
}
/** Whether the environment fixes any part of the sign-in. */
export const modeLocked = (s: SetupState | null) => keyState(s, "AUTH_MODE").env || keyState(s, "PROXY_KIND").env;
/** Whether a sign-in can be chosen: one the environment rules out can't be. */
export function modeAllowed(s: SetupState | null, m: AuthMode): boolean {
  const mode = keyState(s, "AUTH_MODE"), kind = keyState(s, "PROXY_KIND");
  const [wantMode, wantKind] = authSettings(m);
  if (m === "local" && s?.local_only !== true) return false;
  if (mode.env && mode.value !== wantMode) return false;
  if (kind.env && wantKind && kind.value !== wantKind) return false;
  return true;
}

/** A fresh draft: the server's non-secret values prefilled (never a secret's), and its sign-in chosen. */
export function initialDraft(s: SetupState | null): Draft {
  const values: Record<string, string> = {};
  for (const [k, st] of Object.entries(s?.keys ?? {})) if (!st.env && typeof st.value === "string" && !isSecret(k)) values[k] = st.value;
  return { values, mode: modeFrom(s), store: storeFrom(s), skipped: {} };
}

const SECRET_KEYS = new Set(SECTIONS.flatMap((x) => x.fields).concat(Object.values(AUTH_FIELDS).flat(), Object.values(STORE_FIELDS).flat())
  .filter((f) => f.kind === "secret").map((f) => f.key));
export const isSecret = (key: string) => SECRET_KEYS.has(key) || key.endsWith("_SECRET") || ["SESSION_KEY", "NVD_API_KEY", "DATABASE_URL", "BLACKPOINT_API_TOKEN", "SHODAN_API_KEY"].includes(key);

/** The fields a step shows, for the sign-in and the store chosen. */
export function fieldsOf(id: SectionId, mode: AuthMode | null, store: Store = "sqlite"): Field[] {
  if (id === "auth") return mode ? AUTH_FIELDS[mode] : [];
  if (id === "database") return STORE_FIELDS[store];
  return section(id).fields;
}

/** How a field shows: read-only from the environment, a secret already saved, or open. */
export type FieldView = { locked: boolean; value: string; note: string | null };
export function fieldView(s: SetupState | null, d: Draft, f: Field): FieldView {
  const st = keyState(s, f.key);
  if (st.env) return { locked: true, value: f.kind === "secret" ? "" : st.value ?? "", note: "Set by environment" };
  if (f.kind === "secret") return { locked: false, value: d.values[f.key] ?? "", note: st.set ? "Saved; leave blank to keep" : null };
  return { locked: false, value: d.values[f.key] ?? "", note: null };
}

/** Whether a field has a value from anywhere: typed, saved, or the environment. */
function present(s: SetupState | null, d: Draft, f: Field): boolean {
  const st = keyState(s, f.key);
  return st.env || (f.kind === "secret" && st.set) || !!d.values[f.key]?.trim();
}

/** What a step still needs before it can go on, as the fields' labels. A skipped connector needs nothing. */
export function missing(s: SetupState | null, d: Draft, id: SectionId): string[] {
  if (section(id).optional && d.skipped[id]) return [];
  if (id === "auth" && !d.mode) return modeLocked(s) && !visibleModes(s).some((m) => modeAllowed(s, m.id)) ? [] : ["how people sign in"];
  return fieldsOf(id, d.mode, storeOf(s, d)).filter((f) => f.required && !present(s, d, f)).map((f) => f.label);
}

/** One step's settings to send: never one the environment sets, never a blank, and a blank secret means keep. */
export function sectionValues(s: SetupState | null, d: Draft, id: SectionId): Record<string, string> {
  const out: Record<string, string> = {};
  if (section(id).optional && d.skipped[id]) return out;
  if (id === "auth" && d.mode) {
    const [mode, kind] = authSettings(d.mode);
    if (!keyState(s, "AUTH_MODE").env) out.AUTH_MODE = mode;
    if (kind && !keyState(s, "PROXY_KIND").env) out.PROXY_KIND = kind;
  }
  for (const f of fieldsOf(id, d.mode, storeOf(s, d))) {
    if (keyState(s, f.key).env) continue;
    const v = (d.values[f.key] ?? "").trim();
    if (v) out[f.key] = v;
  }
  // The SQLite file chosen over a saved PostgreSQL URL: the path is sent, its default when blank, so the server knows the
  // URL is to go. (Without a saved URL, nothing sent already means the file at its default.)
  if (id === "database" && storeOf(s, d) === "sqlite" && !storeLocked(s) && !out.DATABASE_PATH && keyState(s, "DATABASE_URL").set) out.DATABASE_PATH = DEFAULT_DATABASE_PATH;
  return out;
}

/** The whole save: every step's settings together. */
export function savePayload(s: SetupState | null, d: Draft): Record<string, string> {
  return Object.assign({}, ...SECTIONS.map((x) => sectionValues(s, d, x.id)));
}

/** The optional connectors that aren't connected: skipped, or missing a setting they need. The review step and
 * Settings → Connectors both end with this, each with what turning it on adds. Every section registered here counts. */
export function notConnected(s: SetupState | null, d?: Draft): Section[] {
  const draft: Draft = d ?? initialDraft(s);
  return SECTIONS.filter((x) => x.optional && (draft.skipped[x.id] || missing(s, { ...draft, skipped: { ...draft.skipped, [x.id]: false } }, x.id).length > 0));
}

/** How a setting reads on the review step: never a secret's value. */
export function reviewValue(s: SetupState | null, d: Draft, f: Field): string {
  const st = keyState(s, f.key);
  if (st.env) return f.kind === "secret" || !st.value ? "Set by environment" : `${st.value} (set by environment)`;
  const v = (d.values[f.key] ?? "").trim();
  if (f.kind === "secret") return v ? "A new value, entered" : st.set ? "Saved; kept as it is" : "Not set";
  if (f.kind === "choice") {
    const o = f.options?.find((x) => x.value === (v || st.value)) ?? f.options?.[0];
    return o ? `${o.label}${!v && !st.value ? " (the default)" : ""}` : "Not set";
  }
  if (v) return v;
  if (f.key === "DATABASE_PATH") return `${DEFAULT_DATABASE_PATH} (the default)`;
  if (f.key === "BACKUP_KEEP") return "7 (the default)";
  return "Not set";
}

/** The list a field picks from, from its section's last Test (Halo's ticket types, statuses, priorities), or none. */
export function choicesOf(f: Field, detail: Record<string, unknown> | null | undefined): { id: number; name: string }[] {
  const l = f.choices ? detail?.[f.choices] : undefined;
  return Array.isArray(l) ? l.filter((x): x is { id: number; name: string } => typeof x?.id === "number" && typeof x?.name === "string") : [];
}
/** A Test's detail as one line: its plain values only (the lists a field picks from are shown as the field's choices). */
export const detailLine = (d: Record<string, unknown> | null | undefined) =>
  Object.entries(d ?? {}).filter(([, v]) => v !== null && typeof v !== "object").map(([k, v]) => `${k.replaceAll("_", " ")}: ${String(v)}`).join(" · ");

/** A random session key, from the browser's own random source: 48 characters of base64url. */
export function newSessionKey(): string {
  const b = new Uint8Array(36);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The wizard's steps, in order. */
export const STEPS = ["token", "database", "auth", "ninja", "halo", "nvd", "msrc", "blackpoint", "shodan", "review", "restart"] as const;
export type Step = (typeof STEPS)[number];
export const STEP_TITLES: Record<Step, string> = { token: "Setup token", database: "Database", auth: "Sign-in", ninja: "NinjaOne", halo: "HaloPSA", nvd: "NVD", msrc: "Microsoft updates", blackpoint: "Blackpoint", shodan: "Shodan", review: "Review and save", restart: "Restarting" };

/** The review step's word on the master key, before anything is saved: no path, since only the save knows it. */
export const KEY_BACKUP_NOTE = "The secrets you save are encrypted with the console's master key. Unless CONSOLE_MASTER_KEY or CONSOLE_MASTER_KEY_FILE is set, the first save makes one, on a volume of its own (a Secret on Kubernetes), and the next step says where. Keep that key safe and backed up: without it the console can't read its saved secrets, and they have to be entered again.";

/** The Restarting step's word on the master key: where the save says it is, or nothing when it used none of its own. */
export function masterKeyNote(path: string | null | undefined): string | null {
  const p = (path ?? "").trim();
  return p ? `The master key is at ${p}. Back it up now, apart from the config: without it the console can't read its saved secrets, and they have to be entered again.` : null;
}
