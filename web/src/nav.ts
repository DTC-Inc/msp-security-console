// Where things are: every view has a path, so back and forward work and a copied link reopens it. The server answers
// index.html for any path it doesn't own.
export const homeHref = (q?: string) => (q ? `/?${new URLSearchParams({ q })}` : "/");
export function clientHref(org: number, name?: string, kev?: boolean): string {
  const u = new URLSearchParams();
  if (name) u.set("name", name);
  if (kev) u.set("kev", "1");
  const qs = u.toString();
  return `/clients/${org}${qs ? `?${qs}` : ""}`;
}
export function cveHref(id: string, org?: number, name?: string): string {
  const u = new URLSearchParams();
  if (org) u.set("org", String(org));
  if (org && name) u.set("name", name);
  const qs = u.toString();
  return `/cves/${encodeURIComponent(id)}${qs ? `?${qs}` : ""}`;
}
export const isCveId = (s: string) => /^CVE-\d{4}-\d{4,}$/i.test(s);
export const orgOf = (s: string | undefined) => { const n = Number(s); return Number.isInteger(n) && n > 0 ? n : null; };

/** The first app (before 2026-11-05) kept its view in the hash (#v=client&org=…): a link saved from it opens the same view here. */
export function fromOldHash(hash: string): string | null {
  if (!hash.startsWith("#v=")) return null;
  const u = new URLSearchParams(hash.slice(1));
  const org = orgOf(u.get("org") ?? undefined), name = u.get("name") ?? undefined, id = u.get("id") ?? "";
  if (u.get("v") === "client" && org) return clientHref(org, name);
  if (u.get("v") === "cve" && isCveId(id)) return cveHref(id.toUpperCase(), org ?? undefined, name);
  if (u.get("v") === "home") return homeHref(u.get("q") ?? undefined);
  return null;
}

/** Windows itself: every Windows device and its open CVEs, or one client's, or one device's; `state` narrows the devices. */
export function windowsHref(o: { org?: number; name?: string; device?: number; state?: string; cve?: string } = {}): string {
  const u = new URLSearchParams();
  if (o.org) u.set("org", String(o.org));
  if (o.org && o.name) u.set("name", o.name);
  if (o.device) u.set("device", String(o.device));
  if (o.state) u.set("state", o.state);
  if (o.cve) u.set("cve", o.cve);
  const qs = u.toString();
  return `/windows${qs ? `?${qs}` : ""}`;
}
/** Running processes: a search (a SHA-256, or text), a client, one device, or a trust class. */
export function processesHref(o: { q?: string; org?: number; device?: number; trust?: string } = {}): string {
  const u = new URLSearchParams();
  if (o.q) u.set("q", o.q);
  if (o.org) u.set("org", String(o.org));
  if (o.device) u.set("device", String(o.device));
  if (o.trust) u.set("trust", o.trust);
  const qs = u.toString();
  return `/processes${qs ? `?${qs}` : ""}`;
}
