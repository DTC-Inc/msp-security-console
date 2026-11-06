// The production build, into a directory of its own: index.html is there, loads its script and stylesheet from files
// (the console's CSP allows no inline script), and the stylesheet carries the DTC tokens.
import { expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "fs";
import { join, resolve } from "path";
import { tmpdir } from "os";

test("vite build writes index.html, its script and its tokens stylesheet", () => {
  const out = mkdtempSync(join(tmpdir(), "msp-web-build-"));
  try {
    const r = Bun.spawnSync(["bun", "--bun", "vite", "build", "--outDir", out, "--emptyOutDir", "--logLevel", "error"], { cwd: resolve(import.meta.dir, "..") });
    expect(r.exitCode, r.stderr.toString()).toBe(0);
    const index = join(out, "index.html");
    expect(existsSync(index)).toBe(true);
    const html = readFileSync(index, "utf8");
    expect(html).toMatch(/<script type="module" crossorigin src="\/assets\/index-[\w-]+\.js"><\/script>/);
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/); // every script is a file
    expect(existsSync(join(out, "theme.js"))).toBe(true);
    const css = readdirSync(join(out, "assets")).filter((f) => f.endsWith(".css"));
    expect(css).toHaveLength(1);
    expect(readFileSync(join(out, "assets", css[0]), "utf8")).toContain("--dtc-bg:");
    // NVD's notice is in the app's footer, word for word.
    const js = readdirSync(join(out, "assets")).filter((f) => f.endsWith(".js")).map((f) => readFileSync(join(out, "assets", f), "utf8")).join("");
    expect(js).toContain("This product uses the NVD API but is not endorsed or certified by the NVD.");
  } finally { rmSync(out, { recursive: true, force: true }); }
}, 60_000);
