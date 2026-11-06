// The tokens the app themes with: both schemes carry the roles the screens use, resolved to plain values (the web
// app makes its CSS custom properties from them), and the console's own x roles are there under x-*.
import { test, expect } from "bun:test";
import { tokens } from "./index";
import { parse } from "./gen";

test("both schemes have the roles the screens use, as plain values", () => {
  for (const s of ["light", "dark"] as const) for (const k of ["fg", "fg-muted", "bg", "panel", "line", "accent", "on-accent", "bad", "ok", "x-kev-fill", "x-src-advisory", "x-sev-high"]) {
    expect(tokens[s][k]).toBeTruthy(); expect(tokens[s][k]).not.toMatch(/var\(/);
  }
  expect(tokens.light.accent).not.toBe(tokens.dark.accent);
});
test("the generator resolves a scheme's var() references and lets dark override light", () => {
  const t = parse(":root { --dtc-a: #111; --dtc-b: var(--dtc-a); } @media (prefers-color-scheme: dark) { :root { --dtc-a: #eee; } }");
  expect(t.light).toEqual({ a: "#111", b: "#111" }); expect(t.dark).toEqual({ a: "#eee", b: "#eee" });
});
