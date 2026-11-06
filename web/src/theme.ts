// The viewer's theme: Light, Dark, or System (the default), kept in this browser's storage. public/theme.js applies a
// stored choice before the page paints; this sets it afterwards. Storage can be missing or blocked: the choice then
// lasts until the page closes, and the page still works.
export type ThemeChoice = "light" | "dark" | "system";
export const THEME_KEY = "msp-console-theme";

export function readTheme(): ThemeChoice {
  try {
    const t = window.localStorage.getItem(THEME_KEY);
    return t === "light" || t === "dark" ? t : "system";
  } catch { return "system"; }
}

export function applyTheme(t: ThemeChoice): void {
  const root = document.documentElement;
  if (t === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t);
  try {
    if (t === "system") window.localStorage.removeItem(THEME_KEY); else window.localStorage.setItem(THEME_KEY, t);
  } catch { /* no storage: the choice lasts until the page closes */ }
}

// What the console shows for each evidence source, and which token colours it.
export const SRC: Record<string, { label: string; role: string }> = {
  ninja_software: { label: "installed", role: "x-src-installed" }, process: { label: "running", role: "x-src-process" },
  msrc: { label: "Windows update", role: "x-src-msrc" }, blackpoint: { label: "Blackpoint", role: "x-src-blackpoint" },
  advisory: { label: "advisory", role: "x-src-advisory" },
};
export const cvssRole = (n: number | null | undefined) => n == null ? "fg-muted" : n >= 9 ? "bad" : n >= 7 ? "x-sev-high" : n >= 4 ? "x-sev-medium" : "fg-muted";
export const role = (r: string) => `var(--dtc-${r})`;
