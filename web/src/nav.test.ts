// Paths for every view, and the first app's hash links still opening the same view.
import { expect, test } from "bun:test";
import { clientHref, cveHref, fromOldHash, homeHref } from "./nav";
import { tokensCss } from "./tokens-css";
import { tokens } from "@msp/tokens";

test("every view has a path that carries what it needs", () => {
  expect(homeHref("example dental")).toBe("/?q=example+dental");
  expect(clientHref(7, "Example Dental", true)).toBe("/clients/7?name=Example+Dental&kev=1");
  expect(cveHref("CVE-2026-0001", 7, "Example Dental")).toBe("/cves/CVE-2026-0001?org=7&name=Example+Dental");
  expect(cveHref("CVE-2026-0001")).toBe("/cves/CVE-2026-0001");
});

test("an old #v= link opens the same view; anything else is left alone", () => {
  expect(fromOldHash("#v=client&org=7&name=Example+Dental")).toBe("/clients/7?name=Example+Dental");
  expect(fromOldHash("#v=cve&id=cve-2026-0001&org=7")).toBe("/cves/CVE-2026-0001?org=7");
  expect(fromOldHash("#v=home&q=example")).toBe("/?q=example");
  expect(fromOldHash("#v=client&org=-1")).toBeNull();
  expect(fromOldHash("#main")).toBeNull();
});

test("the tokens become CSS custom properties for light, dark by system, and dark by choice, with no var() left", () => {
  const css = tokensCss(tokens);
  expect(css).toContain(`--dtc-bg: ${tokens.light.bg};`);
  expect(css).toContain(`--dtc-x-kev-fill: ${tokens.light["x-kev-fill"]};`);
  expect(css).toContain('@media (prefers-color-scheme: dark) {\n:root:not([data-theme="light"])');
  expect(css).toContain(':root[data-theme="dark"]');
  expect(css.split(`--dtc-bg: ${tokens.dark.bg};`)).toHaveLength(3); // once under the system's dark, once under the chosen dark
  expect(css).not.toMatch(/var\(/);
});
