// The Similar CVEs panel: the list when there is one, one plain sentence when there isn't, and why.
import { expect, test } from "bun:test";
import { alike, sentence, similarView } from "./similar";

const row = { cve_id: "CVE-2026-0002", distance: 0.07, cvss: 8.8, severity: "HIGH", kev: true, devices: 3 };

test("off: no list, and the console's reason as a sentence", () => {
  expect(similarView({ v: 1, op: "cve.similar", data: [], off: "similar-CVE search is off: the embedder is turned off (EMBEDDER=off)" }))
    .toEqual({ sentence: "Similar CVEs are off: the embedder is turned off (EMBEDDER=off)." });
  expect(similarView({ v: 1, op: "cve.similar", data: [], off: "similar-CVE search is off: this PostgreSQL database has no pgvector extension (install pgvector, run CREATE EXTENSION vector as a role allowed to, and restart the console)" }))
    .toEqual({ sentence: "Similar CVEs are off: this PostgreSQL database has no pgvector extension (install pgvector, run CREATE EXTENSION vector as a role allowed to, and restart the console)." });
});

test("on: the rows, or the note when this CVE isn't compared yet", () => {
  expect(similarView({ v: 1, op: "cve.similar", data: [row] })).toEqual({ rows: [row] });
  expect(similarView({ v: 1, op: "cve.similar", data: [], note: "this CVE hasn't been compared yet: the embed job makes its vector once NVD's description of it is in the store" }))
    .toEqual({ sentence: "This CVE hasn't been compared yet: the embed job makes its vector once NVD's description of it is in the store." });
  expect(similarView({ v: 1, op: "cve.similar", error: "The console didn't answer. Check your connection, then try again." }))
    .toEqual({ sentence: "The console didn't answer. Check your connection, then try again." });
});

test("a sentence ends once, and distance reads as how alike", () => {
  expect(sentence("already a sentence.")).toBe("Already a sentence.");
  expect(alike(0.07)).toBe("93% alike");
  expect(alike(1.2)).toBe("0% alike");
});
