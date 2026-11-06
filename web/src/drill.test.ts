// The drill links: a filter round-trips into the evidence API's params, a link reads the same however it was made.
import { expect, test } from "bun:test";
import { filterWords, productHref, rowsHref, rowsKey, rowsParams, versionParam } from "./drill";

test("a filter is one string whatever its key order, and comes back as the API's params", () => {
  const f = { org_id: 7, kev: true, source: ["ninja_software", "process"], device_class: "server" };
  const k = rowsKey(f);
  expect(k).toBe(rowsKey({ device_class: "server", source: ["ninja_software", "process"], kev: true, org_id: 7 }));
  expect(rowsParams(k)).toEqual({ device_class: "server", kev: true, org_id: 7, source: ["ninja_software", "process"] } as any);
  expect(rowsKey({ org_id: 7, kev: false, msa: undefined, device_class: "", source: [] })).toBe(rowsKey({ org_id: 7 }));
  expect(rowsParams("seen=0&has=software&org_id=8&label=x&nonsense=1")).toEqual({ seen: false, has: "software", org_id: 8 } as any);
});

test("a count's link names its list, its filter and its words", () => {
  expect(rowsHref("devices", { org_id: 7, kev: true }, "Alpha › exploited")).toBe("/rows/devices?kev=1&org_id=7&label=Alpha%20%E2%80%BA%20exploited");
  expect(rowsHref("cves", {})).toBe("/rows/cves");
  expect(productHref("notepadpp", "8.5.7")).toBe("/software/notepadpp?version=8.5.7");
  expect(versionParam("")).toBe("(none)");
  expect(filterWords(rowsParams("kev=1&source=ninja_software,process&device_class=server"))).toBe("from installed or running · actively exploited (CISA KEV) · servers");
});
