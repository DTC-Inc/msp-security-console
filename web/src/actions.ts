// The Blackpoint, exposure and ticket writes (server/src/ops/actions.rs): JSON calls behind the same sign-in as the
// evidence API, each a signed-in person's own act, audited with who did it. Every failure is a plain sentence in
// `error`, never a throw. Reads go through api.ts's evidence().
import { EXPIRED, OFFLINE } from "./api";

export type Features = { blackpoint: boolean; shodan: boolean; tickets: boolean; halo_ticket_url: string | null; scan_admin: boolean; ticket_admin?: boolean };
export type Result<T> = { data?: T; error?: string };

async function call<T>(path: string, init?: RequestInit): Promise<Result<T>> {
  let res: Response;
  try { res = await globalThis.fetch(path, { credentials: "same-origin", ...init }); } catch { return { error: OFFLINE }; }
  let b: any = null;
  try { b = await res.json(); } catch { /* not JSON */ }
  if (res.status === 401) return { error: EXPIRED };
  if (!res.ok) return { error: typeof b?.error === "string" ? b.error : `The console answered ${res.status} without saying why.` };
  return { data: b as T };
}
const post = <T>(path: string, body: unknown) => call<T>(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

/** Which of Blackpoint, Shodan and Halo tickets are on, and whether you may set scan policies. */
export const features = () => call<Features>("/api/features");

export type TenantAction = "confirm" | "not_client" | "clear";
export const mapTenant = (tenant_id: string, action: TenantAction, org_id?: number) =>
  post<{ ok: true; assets_matched: number }>("/api/blackpoint/tenant", { tenant_id, action, ...(org_id ? { org_id } : {}) });

export const markEdge = (ip: string, edge: boolean, note?: string) => post<{ ok: true }>("/api/exposure/edge", { ip, edge, ...(note ? { note } : {}) });
export const setScanPolicy = (org_id: number, frequency_days: number) => post<{ ok: true }>("/api/exposure/scan-policy", { org_id, frequency_days });

/** The ticket exactly as it would be sent, or the ticket this finding already has. */
export type Preview = {
  finding?: string; client?: string; halo_client_id?: number; digest?: string;
  payload?: { summary: string; details_html: string; client_id: number; tickettype_id: number; status_id: number; priority_id: number };
  existing?: { state: "pending" | "created" | "unknown"; halo_ticket_id: number | null; message?: string; title?: string };
};
export const previewTicket = (finding: string) => post<Preview>("/api/tickets/preview", { finding });
export const createTicket = (finding: string, digest: string) => post<{ ok: true; halo_ticket_id: number; created: boolean }>("/api/tickets", { finding, digest });
/** An admin, having checked Halo has no ticket for a finding whose answer was lost: release its claim. */
export const releaseTicket = (finding: string) => post<{ ok: true; released: true }>("/api/tickets/release", { finding });

/** Halo's own page for a ticket, when Halo's address is known. */
export const ticketHref = (f: Features | undefined, id: number | null | undefined) => (f?.halo_ticket_url && id ? `${f.halo_ticket_url}${id}` : null);

/** The text of a ticket's HTML details, as Halo will show it: tags dropped, entities read, one line per paragraph. */
export function detailsText(html: string): string {
  return html.replace(/<br\s*\/?>/gi, "\n").replace(/<\/p>\s*/gi, "\n").replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&amp;/g, "&").replace(/\n{2,}/g, "\n").trim();
}
