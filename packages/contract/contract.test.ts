// The client's types come from the server's schema, and stay in step with it.
import { test, expect } from "bun:test";
import { generate } from "./gen";
import { readFileSync } from "fs";
import { resolve } from "path";

test("src/index.ts is exactly what the schema generates", () => {
  expect(readFileSync(resolve(import.meta.dir, "src/index.ts"), "utf8")).toBe(generate());
});
test("every op and the list filters are in the client's types", () => {
  const t = generate();
  for (const s of ['"devices.list"', '"clients.list"', '"cve.get"', "org_id?: number", "source?: Source[]", "device_class?: DeviceClass", "has?: Has", "op: ReadOp"]) expect(t).toContain(s);
});
