// Advisories ahead of NVD, apart from their screen: how a range reads, and the form's text back into the API's shape.
export type Range = { exact?: string; si?: string; se?: string; ei?: string; ee?: string };
export type Advisory = { advisory_id: string; cve_id: string; title: string; severity: string | null; cvss: number | null; exploited: boolean; url: string | null;
  product_key: string; product_label: string | null; match: Record<string, string>; ranges: Range[]; fixed_in: string[]; remedy: string | null; status: string;
  added_by: string | null; added_at: string | null; edited_by: string | null; edited_at: string | null; notes: string | null; devices: number };

/** "8.5.0 up to 8.6 (not included)", "exactly 1.2". */
export function rangeText(r: Range): string {
  if (r.exact) return `exactly ${r.exact}`;
  const from = r.si ? `from ${r.si}` : r.se ? `above ${r.se}` : "";
  const to = r.ee ? `below ${r.ee}` : r.ei ? `up to ${r.ei}` : "";
  return [from, to].filter(Boolean).join(" ") || "every version";
}
/** The form's ranges, one a line: "8.5.0 - 8.6" (from, up to but not including), "- 8.6", "8.5.0 -", or "= 1.2". */
export function parseRanges(text: string): { ranges: Range[]; bad: string[] } {
  const ranges: Range[] = [], bad: string[] = [];
  for (const l of text.split(/\n|;/).map((x) => x.trim()).filter(Boolean)) {
    const eq = l.match(/^=\s*(\S+)$/);
    if (eq) { ranges.push({ exact: eq[1] }); continue; }
    const m = l.match(/^(\S*)\s*-\s*(\S*)$/);
    if (m && (m[1] || m[2])) { ranges.push({ ...(m[1] ? { si: m[1] } : {}), ...(m[2] ? { ee: m[2] } : {}) }); continue; }
    bad.push(l);
  }
  return { ranges, bad };
}
export const rangesTextOf = (rs: Range[]) => rs.map((r) => (r.exact ? `= ${r.exact}` : `${r.si ?? ""} - ${r.ee ?? r.ei ?? ""}`.trim())).join("\n");

export type Form = Record<"advisory_id" | "cve_id" | "title" | "severity" | "cvss" | "url" | "product_key" | "product_label" | "name_re" | "company_re" | "product_re" | "path_re" | "ranges" | "fixed_in" | "remedy", string> & { exploited: boolean };
export const emptyForm = (): Form => ({ advisory_id: "", cve_id: "", title: "", severity: "", cvss: "", url: "", product_key: "", product_label: "", name_re: "", company_re: "",
  product_re: "", path_re: "", ranges: "", fixed_in: "", remedy: "", exploited: false });
export function formOf(a: Advisory): Form {
  return { advisory_id: a.advisory_id, cve_id: a.cve_id, title: a.title, severity: a.severity ?? "", cvss: a.cvss == null ? "" : String(a.cvss), url: a.url ?? "",
    product_key: a.product_key, product_label: a.product_label ?? "", name_re: a.match.name_re ?? "", company_re: a.match.company_re ?? "", product_re: a.match.product_re ?? "",
    path_re: a.match.path_re ?? "", ranges: rangesTextOf(a.ranges), fixed_in: a.fixed_in.join(", "), remedy: a.remedy ?? "", exploited: a.exploited };
}
/** The form as the save sends it; the server checks every field again and says what's wrong. */
export function payload(f: Form): { advisory: Record<string, unknown>; bad: string[] } {
  const { ranges, bad } = parseRanges(f.ranges);
  const match = Object.fromEntries((["name_re", "company_re", "product_re", "path_re"] as const).map((k) => [k, f[k].trim()]).filter(([, v]) => v));
  return { bad: bad.map((b) => `“${b}” isn't a range: write it as 8.5.0 - 8.6, or = 1.2`), advisory: {
    advisory_id: f.advisory_id.trim(), cve_id: f.cve_id.trim().toUpperCase(), title: f.title.trim(), severity: f.severity || null, cvss: f.cvss.trim() === "" ? null : Number(f.cvss),
    exploited: f.exploited, url: f.url.trim() || null, product_key: f.product_key.trim(), product_label: f.product_label.trim() || null, match, ranges,
    fixed_in: f.fixed_in.split(/[,\s]+/).filter(Boolean), remedy: f.remedy.trim() || null } };
}
