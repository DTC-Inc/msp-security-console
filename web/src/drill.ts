// Every count opens exactly the rows it counts: a count is a link to a list from the evidence API, filtered exactly as
// the count was counted, at /rows/<kind>?<filter>. The filter is one stable string (sorted keys, false and empty parts dropped), so a link reads the same however it was
// made, and a copied one reopens the same list.
import type { Params, ReadOp } from "@msp/contract";

export const LIST_KINDS = ["devices", "cves", "clients", "coverage", "version-cves"] as const;
export type ListKind = (typeof LIST_KINDS)[number];
/** The op behind each kind of list. `coverage` is the devices with the sources that saw each; `version-cves` is one
 * product version's CVEs as NVD's ranges put them, whatever runs it (a running binary's CVE count). */
export const LIST_OP: Record<ListKind, ReadOp> = { devices: "devices.list", cves: "cves.list", clients: "clients.list", coverage: "coverage.devices", "version-cves": "version.cves" };
/** The sources the console's software counts are made of: installed, and running. */
export const INV = ["ninja_software", "process"] as const;

export type Filter = Partial<Record<keyof Params, unknown>>;
const NUMS = new Set(["org_id", "device_id", "cvss_min"]);
const BOOLS = new Set(["kev", "critical", "running_only", "seen", "msa"]);
const KEYS = new Set(["org_id", "device_id", "cve_id", "product_key", "version", "advisory_id", "source", "device_class", "role", "kev", "critical", "cvss_min", "running_only", "has", "seen"]);

/** A filter as one stable string. */
export function rowsKey(f: Filter): string {
  const u = new URLSearchParams();
  for (const k of Object.keys(f).sort()) {
    const v = (f as Record<string, unknown>)[k];
    if (v == null || v === "" || v === false || (Array.isArray(v) && !v.length)) continue;
    u.set(k, Array.isArray(v) ? v.join(",") : v === true ? "1" : String(v));
  }
  return u.toString();
}
/** The string back into the evidence API's params; a key the list doesn't know is dropped. */
export function rowsParams(q: string | URLSearchParams): Params {
  const out: Record<string, unknown> = {};
  for (const [k, v] of new URLSearchParams(q)) {
    if (!KEYS.has(k) || v === "") continue;
    out[k] = k === "source" ? v.split(",") : NUMS.has(k) ? Number(v) : BOOLS.has(k) ? v === "1" : v;
  }
  return out as Params;
}
/** Where a count leads: its list, with its filter and the words for it. */
export function rowsHref(kind: ListKind, f: Filter, label?: string): string {
  const k = rowsKey(f);
  const l = label ? `${k ? "&" : ""}label=${encodeURIComponent(label)}` : "";
  return `/rows/${kind}${k || l ? "?" : ""}${k}${l}`;
}

const SRC_WORDS: Record<string, string> = { ninja_software: "installed", process: "running", msrc: "Windows updates", blackpoint: "Blackpoint", advisory: "advisories" };
/** The filter in words, for the list's own page. */
export function filterWords(p: Params): string {
  const w: string[] = [];
  if (p.source) w.push(`from ${p.source.map((s) => SRC_WORDS[s] ?? s).join(" or ")}`);
  if (p.kev) w.push("actively exploited (CISA KEV)");
  if (p.critical) w.push("critical (CVSS 9 or more)");
  if (p.cvss_min != null) w.push(`CVSS ${p.cvss_min} or more`);
  if (p.device_class) w.push(`${p.device_class}s`);
  if (p.role) w.push(`role ${p.role}`);
  if (p.running_only) w.push("running");
  if (p.has === "product") w.push("installed, vulnerable or not");
  if (p.has === "software") w.push(p.seen === false ? "without a software inventory" : "with a software inventory");
  else if (p.seen != null && p.source) w.push(p.seen ? "seen" : "not seen");
  if (p.product_key) w.push(`product ${p.product_key}`);
  if (p.version != null) w.push(`version ${p.version === "(none)" ? "none" : p.version}`);
  if (p.cve_id) w.push(p.cve_id);
  if (p.advisory_id) w.push(`named by advisory ${p.advisory_id}`);
  if (p.device_id) w.push(`device ${p.device_id}`);
  if (p.org_id) w.push(`client ${p.org_id}`);
  return w.join(" · ");
}

// Where a record leads.
export const deviceHref = (id: number) => `/devices/${id}`;
export function productHref(key: string, version?: string | null): string {
  return `/software/${encodeURIComponent(key)}${version != null && version !== "" ? `?version=${encodeURIComponent(version)}` : ""}`;
}
/** A version as a link carries it: the empty version is "(none)". */
export const versionParam = (v: string) => (v === "" ? "(none)" : v);
