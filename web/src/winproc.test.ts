// The Windows and running-processes views' words, against the data the server sends, and their addresses.
import { expect, test } from "bun:test";
import { STATES, TRUST, fixNote, known, readable, stateOf } from "./winproc";
import { processesHref, windowsHref } from "./nav";

test("a device's states read worst first, and unknown is never up to date", () => {
  expect(STATES.map((s) => s.id)).toEqual(["vulnerable", "unknown", "untracked", "patched"]);
  expect(stateOf("unknown").says).toContain("Never counted as patched");
  expect(stateOf("bogus").id).toBe("unknown");
});

test("NinjaOne's word on the fix: waiting, failed and when, or nothing", () => {
  expect(fixNote({ update_pending_kb: "5900002", update_failed_kb: null, update_failed_at: null })).toBe("KB5900002 is waiting in NinjaOne");
  expect(fixNote({ update_pending_kb: null, update_failed_kb: "5900001", update_failed_at: "2026-10-20T03:00:00Z" })).toMatch(/^KB5900001 failed on /);
  expect(fixNote({ update_pending_kb: null, update_failed_kb: null, update_failed_at: null })).toBe("");
});

test("what a binary is, how the console knows, and how sure", () => {
  expect(known({ product_key: "chrome", product_label: "Google Chrome", product_version: "120.0", method: "rule", confidence: 1 })).toBe("Google Chrome 120.0, by the product list");
  expect(known({ product_key: "nvd:acme:widget", product_label: "Widget", product_version: "2.1", method: "cpe", confidence: 0.9 })).toBe("Widget 2.1, by NVD's name and vendor (90% sure)");
  expect(known({ product_key: null, product_label: null, product_version: null, method: null, confidence: null })).toBe("Not matched to a product");
  expect(Object.keys(TRUST)).toEqual(["invalid", "unsigned", "unchecked", "unhashed", "valid"]);
  expect(readable("veeam:veeam_backup_\\&_replication")).toBe("veeam:veeam backup & replication");
});

test("every view and filter has an address", () => {
  expect(windowsHref()).toBe("/windows");
  expect(windowsHref({ org: 7, name: "Alpha Dental", state: "vulnerable" })).toBe("/windows?org=7&name=Alpha+Dental&state=vulnerable");
  expect(windowsHref({ device: 701 })).toBe("/windows?device=701");
  expect(processesHref({ q: "a".repeat(64) })).toBe(`/processes?q=${"a".repeat(64)}`);
  expect(processesHref({ org: 7, trust: "unsigned" })).toBe("/processes?org=7&trust=unsigned");
});
