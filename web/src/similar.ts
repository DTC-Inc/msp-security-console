// "Similar CVEs" on a CVE's page (cve.similar): the CVEs whose NVD descriptions mean nearly the same, from the
// console's own embedder. What the panel shows, decided here so it can be tested without a browser: the list, or one
// plain sentence (the feature is off, this CVE isn't compared yet, or the call failed).
import type { Answer } from "@msp/contract";

export type Similar = { cve_id: string; distance: number; cvss: number | null; severity: string | null; kev: boolean; devices: number };
export type SimilarView = { rows: Similar[] } | { sentence: string };

/** "similar-CVE search is off: the embedder is turned off (EMBEDDER=off)" → "Similar CVEs are off: the embedder is turned off (EMBEDDER=off)." */
export function sentence(s: string): string {
  const t = s.trim().replace(/^similar-CVE search is off: /, "Similar CVEs are off: ");
  const first = t.charAt(0).toUpperCase() + t.slice(1);
  return /[.!?]$/.test(first) ? first : `${first}.`;
}

export function similarView(a: Answer<Similar[]>): SimilarView {
  if (a.off) return { sentence: sentence(a.off) };
  if (a.error) return { sentence: a.error };
  const rows = a.data ?? [];
  if (rows.length) return { rows };
  return { sentence: sentence(a.note ?? "no other CVE reads like this one yet") };
}

/** Cosine distance as a technician reads it: how alike, in percent (0 → 100% alike, 1 → unrelated). */
export const alike = (distance: number) => `${Math.max(0, Math.round((1 - distance) * 100))}% alike`;
