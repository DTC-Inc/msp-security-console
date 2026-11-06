// What the Windows and running-processes views say, apart from their screens, so the tests hold the words to the data.

export type FixState = { update_pending_kb: string | null; update_failed_kb: string | null; update_failed_at: string | null };
export type Known = { product_key: string | null; product_label: string | null; product_version: string | null; method: string | null; confidence: number | null };

/** A Windows device's patch states, worst first, as the server orders them. */
export const STATES: { id: string; label: string; fill: string; says: string }[] = [
  { id: "vulnerable", label: "needs an update", fill: "x-sev-critical-fill", says: "Its patch level is below an update Microsoft has published for a CVE on it." },
  { id: "unknown", label: "patch level unknown", fill: "x-sev-medium-fill", says: "Windows, but its patch level can't be read: NinjaOne lists no cumulative update Microsoft's data names. Never counted as patched." },
  { id: "untracked", label: "not covered", fill: "x-neutral-fill", says: "A Windows build Microsoft's last two years of updates don't cover (a retired release)." },
  { id: "patched", label: "up to date", fill: "x-ok-fill", says: "Up to date for every CVE Microsoft has published for its build." },
];
export const stateOf = (id: string) => STATES.find((s) => s.id === id) ?? STATES[1];
export const kb = (k: string) => `KB${k}`;
const day = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "");
/** What NinjaOne says about the fix: waiting, or failed and when. */
export function fixNote(d: FixState): string {
  const parts: string[] = [];
  if (d.update_pending_kb) parts.push(`${kb(d.update_pending_kb)} is waiting in NinjaOne`);
  if (d.update_failed_kb) parts.push(`${kb(d.update_failed_kb)} failed${d.update_failed_at ? ` on ${day(d.update_failed_at)}` : ""}`);
  return parts.join(" · ");
}

/** A running binary's signature, as the endpoint script classes it. */
export const TRUST: Record<string, { label: string; fill: string }> = {
  invalid: { label: "signature invalid", fill: "x-trust-invalid-fill" }, unsigned: { label: "unsigned", fill: "x-trust-unsigned-fill" },
  unchecked: { label: "signature not checked", fill: "x-trust-unchecked-fill" }, unhashed: { label: "not hashed", fill: "x-trust-unhashed-fill" },
  valid: { label: "signed", fill: "x-ok-fill" },
};
const METHOD: Record<string, string> = { rule: "by the product list", auto: "as the installed program is", reviewed: "as a person decided", cpe: "by NVD's name and vendor" };
/** How the console knows what a binary is, in words. */
export function known(b: Known): string {
  if (!b.product_key) return "Not matched to a product";
  const what = `${b.product_label ?? b.product_key}${b.product_version ? ` ${b.product_version}` : ""}`;
  return `${what}, ${METHOD[b.method ?? ""] ?? "matched"}${b.confidence != null && b.confidence < 1 ? ` (${Math.round(b.confidence * 100)}% sure)` : ""}`;
}
/** NVD's vendor:product as words: underscores as spaces, escapes dropped. */
export const readable = (cpe: string) => cpe.replace(/\\(.)/g, "$1").replace(/_/g, " ");
