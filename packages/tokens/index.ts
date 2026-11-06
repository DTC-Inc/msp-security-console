// The DTC tokens, resolved per colour scheme, plus the console's own x roles (x-roles.json).
import base from "./tokens.json";
import x from "./x-roles.json";

export type Scheme = "light" | "dark";
export type Tokens = Record<string, string>;
export const tokens: Record<Scheme, Tokens> = {
  light: { ...(base as any).light, ...Object.fromEntries(Object.entries((x as any).light).map(([k, v]) => [`x-${k}`, v as string])) },
  dark: { ...(base as any).dark, ...Object.fromEntries(Object.entries((x as any).dark).map(([k, v]) => [`x-${k}`, v as string])) },
};
