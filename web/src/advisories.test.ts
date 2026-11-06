import { expect, test } from "bun:test";
import { emptyForm, formOf, parseRanges, payload, rangeText, rangesTextOf } from "./advisories";

test("ranges read as words and round-trip through the form", () => {
  expect(rangeText({ si: "8.5.0", ee: "8.6" })).toBe("from 8.5.0 below 8.6");
  expect(rangeText({ exact: "1.2" })).toBe("exactly 1.2");
  const { ranges, bad } = parseRanges("8.5.0 - 8.6\n= 1.2\n- 3.0\nnonsense");
  expect(ranges).toEqual([{ si: "8.5.0", ee: "8.6" }, { exact: "1.2" }, { ee: "3.0" }]);
  expect(bad).toEqual(["nonsense"]);
  expect(parseRanges(rangesTextOf(ranges)).ranges).toEqual(ranges);
});

test("the form sends what the API takes, and an edit opens with what's saved", () => {
  const f = { ...emptyForm(), advisory_id: " EX-1 ", cve_id: "cve-2026-1234", title: "T", product_key: "notepadpp", name_re: "^Notepad", ranges: "8.5 - 8.6", fixed_in: "8.6, 9.0", cvss: "7.5" };
  const p = payload(f);
  expect(p.bad).toEqual([]);
  expect(p.advisory).toMatchObject({ advisory_id: "EX-1", cve_id: "CVE-2026-1234", match: { name_re: "^Notepad" }, ranges: [{ si: "8.5", ee: "8.6" }], fixed_in: ["8.6", "9.0"], cvss: 7.5 });
  const back = formOf({ ...(p.advisory as any), severity: null, status: "active", added_by: null, added_at: null, edited_by: null, edited_at: null, notes: null, devices: 0, url: null, remedy: null, product_label: null });
  expect(back.ranges).toBe("8.5 - 8.6");
  expect(back.fixed_in).toBe("8.6, 9.0");
});
