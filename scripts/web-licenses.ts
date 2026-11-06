// The licences of the JavaScript the web app's bundle carries, generated from bun.lock at image build time into
// /licenses/web.txt (the Dockerfile's web stage), the way cargo-about does for the Rust crates. The packages are the
// web app's runtime dependencies (`dependencies`, and the peers they need), followed through the lockfile; dev tools
// (Vite, TypeScript, the Solid compiler) build the bundle but aren't in it. Each package's licence is read from its
// own package.json, its text from its own LICENSE file, and its version checked against the lockfile's. Any licence
// not on ALLOWED, a package without a licence file, or a version that isn't the lockfile's fails the run (exit 1).
//
//   bun scripts/web-licenses.ts [--out=<file>]    from the repo root, after `bun install --frozen-lockfile`
import { existsSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "fs";
import { basename, dirname, join, resolve } from "path";

/** The same list as server/about.toml's, plus 0BSD. A choice (A OR B) passes on any one; A AND B needs both. */
export const ALLOWED = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0", "0BSD"];

type Entry = [string, string, { dependencies?: Record<string, string>; peerDependencies?: Record<string, string>; optionalPeers?: string[] }, string];
export type Package = { name: string; version: string; license: string; text: string };

/** bun.lock is JSON with trailing commas. */
export function readLock(text: string): { workspaces: Record<string, { dependencies?: Record<string, string> }>; packages: Record<string, Entry> } {
  return JSON.parse(text.replace(/,(\s*[}\]])/g, "$1"));
}

/** Whether an SPDX expression is allowed: every AND part, and at least one side of each OR. */
export function allowed(expr: string): boolean {
  const e = expr.trim().replace(/^\((.*)\)$/, "$1");
  if (/ OR /i.test(e)) return e.split(/ OR /i).some((x) => allowed(x));
  if (/ AND /i.test(e)) return e.split(/ AND /i).every((x) => allowed(x));
  return ALLOWED.includes(e.replace(/[()]/g, "").trim());
}

/** Node's lookup: the nearest node_modules/<name> from a directory up. */
function locate(name: string, from: string): string | null {
  for (let dir = from; ; dir = dirname(dir)) {
    if (basename(dir) !== "node_modules") {
      const c = join(dir, "node_modules", name);
      if (existsSync(join(c, "package.json"))) return realpathSync(c);
    }
    if (dirname(dir) === dir) return null;
  }
}

/** The web app's runtime packages, each with its licence and text, in name order. Throws on the first problem. */
export function collect(root: string): Package[] {
  const lock = readLock(readFileSync(join(root, "bun.lock"), "utf8"));
  const web = lock.workspaces["web"];
  if (!web) throw new Error("bun.lock has no web workspace");
  const out = new Map<string, Package>();
  const queue: [string, string][] = Object.entries(web.dependencies ?? {})
    .filter(([, v]) => !v.startsWith("workspace:")).map(([n]) => [n, join(root, "web")]);
  while (queue.length) {
    const [name, from] = queue.shift()!;
    if (out.has(name)) continue;
    const entry = lock.packages[name];
    if (!entry) throw new Error(`${name} isn't in bun.lock`);
    const version = entry[0].slice(entry[0].lastIndexOf("@") + 1);
    const dir = locate(name, from);
    if (!dir) throw new Error(`${name} isn't installed: run bun install --frozen-lockfile first`);
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    if (pkg.version !== version) throw new Error(`${name} is installed at ${pkg.version}, not the lockfile's ${version}`);
    const license = typeof pkg.license === "string" ? pkg.license : pkg.license?.type ?? "";
    if (!license) throw new Error(`${name}@${version} names no licence`);
    if (!allowed(license)) throw new Error(`${name}@${version} is ${license}, which isn't allowed (${ALLOWED.join(", ")})`);
    const file = readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.(md|txt))?$/i.test(f));
    if (!file) throw new Error(`${name}@${version} ships no licence file`);
    out.set(name, { name, version, license, text: readFileSync(join(dir, file), "utf8").trim() });
    const meta = entry[2] ?? {};
    const optional = new Set(meta.optionalPeers ?? []);
    for (const d of [...Object.keys(meta.dependencies ?? {}), ...Object.keys(meta.peerDependencies ?? {}).filter((p) => !optional.has(p))]) queue.push([d, dir]);
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function render(list: Package[]): string {
  const head = `The JavaScript in the web app's bundle (/web), and each package's licence. Generated from bun.lock by\nscripts/web-licenses.ts when the image was built.\n\n${list.map((p) => `- ${p.name}@${p.version}: ${p.license}`).join("\n")}\n`;
  return head + list.map((p) => `\n${"=".repeat(78)}\n${p.name}@${p.version} (${p.license})\n${"=".repeat(78)}\n\n${p.text}\n`).join("");
}

if (import.meta.main) {
  const outArg = process.argv.slice(2).find((a) => a.startsWith("--out="))?.slice(6);
  try {
    const text = render(collect(resolve(import.meta.dir, "..")));
    if (outArg) { writeFileSync(outArg, text); console.log(`wrote ${outArg}`); } else process.stdout.write(text);
  } catch (e) {
    console.error(`web licences: ${(e as Error).message}`);
    process.exit(1);
  }
}
