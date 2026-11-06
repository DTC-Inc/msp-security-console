// The image's /licenses/web.txt (scripts/web-licenses.ts): every runtime package the bundle carries, each with an
// allowed licence and its own text, read from what's installed at the lockfile's versions.
import { expect, test } from "bun:test";
import { resolve } from "path";
import { allowed, collect, render } from "../../scripts/web-licenses";

test("the bundle's packages are found through the lockfile, each with its licence text", () => {
  const list = collect(resolve(import.meta.dir, "../.."));
  expect(list.map((p) => p.name)).toEqual(["@solidjs/router", "csstype", "seroval", "seroval-plugins", "solid-js"]);
  for (const p of list) { expect(p.license).toBe("MIT"); expect(p.text).toContain("Permission is hereby granted"); }
  const text = render(list);
  expect(text).toContain("- solid-js@1.9.17: MIT");
  expect(text).not.toContain("vite@"); // a build tool, not in the bundle
});

test("a licence off the list fails; a choice passes on either side, and AND needs both", () => {
  expect(allowed("MIT")).toBe(true);
  expect(allowed("(MIT OR GPL-3.0-only)")).toBe(true);
  expect(allowed("GPL-3.0-only")).toBe(false);
  expect(allowed("MIT AND GPL-2.0-only")).toBe(false);
  expect(allowed("Apache-2.0 AND ISC")).toBe(true);
  expect(allowed("")).toBe(false);
});
