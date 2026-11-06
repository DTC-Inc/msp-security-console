// The web client: Solid on Vite. The DTC tokens become a stylesheet at build time (virtual:dtc-tokens.css); in
// development the server's own paths go to it on :8080, so the app talks to its server as it does in production.
import { defineConfig, type Plugin } from "vite";
import solid from "vite-plugin-solid";
import { tokens } from "@msp/tokens";
import { tokensCss } from "./src/tokens-css.ts";

const ID = "virtual:dtc-tokens.css";
function dtcTokens(): Plugin {
  return {
    name: "dtc-tokens",
    resolveId: (id) => (id === ID ? `\0${ID}` : undefined),
    load: (id) => (id === `\0${ID}` ? tokensCss(tokens) : undefined),
  };
}

const server = process.env.CONSOLE_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [solid(), dtcTokens()],
  server: { proxy: Object.fromEntries(["/api", "/auth", "/healthz", "/readyz"].map((p) => [p, { target: server }])) },
  build: { outDir: "dist", emptyOutDir: true, target: "es2022" },
});
