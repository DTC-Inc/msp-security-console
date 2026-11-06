// The DTC tokens (packages/tokens, generated from the DTC design system) as CSS custom properties, --dtc-<role>, and
// the console's own roles as --dtc-x-<role>. Built into the stylesheet at build time (vite.config.ts), so the page
// has its colours before any script runs. Light is the default; dark follows the system unless the viewer chose
// Light, and a chosen Dark wins over a light system. Nothing here holds a colour: every value comes from the tokens.
export type Tokens = Record<string, string>;

const decls = (t: Tokens) => Object.entries(t).map(([k, v]) => `  --dtc-${k}: ${v};`).join("\n");

export function tokensCss(t: { light: Tokens; dark: Tokens }): string {
  return [
    `:root {\n  color-scheme: light;\n${decls(t.light)}\n}`,
    `@media (prefers-color-scheme: dark) {\n:root:not([data-theme="light"]) {\n  color-scheme: dark;\n${decls(t.dark)}\n}\n}`,
    `:root[data-theme="dark"] {\n  color-scheme: dark;\n${decls(t.dark)}\n}`,
    "",
  ].join("\n");
}
