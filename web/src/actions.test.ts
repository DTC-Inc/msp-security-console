// The Blackpoint, exposure and ticket calls, and the wizard's new sections: what's sent, how a failure reads, and that
// a secret is never prefilled or sent blank.
import { afterEach, expect, test } from "bun:test";
import { createTicket, detailsText, mapTenant, previewTicket, ticketHref } from "./actions";
import { EXPIRED, OFFLINE } from "./api";
import { choicesOf, detailLine, initialDraft, isSecret, savePayload, section, sectionValues, STEPS } from "./setup/wizard";

const real = globalThis.fetch;
afterEach(() => { globalThis.fetch = real; });
function answer(status: number, body: unknown, seen: { url: string; init?: RequestInit }[] = []) {
  globalThis.fetch = (async (url: string, init?: RequestInit) => { seen.push({ url, init }); return new Response(JSON.stringify(body), { status }); }) as typeof fetch;
  return seen;
}

test("a write is JSON to its own path, and the server's sentence is the error", async () => {
  const seen = answer(200, { ok: true, assets_matched: 2 });
  expect((await mapTenant("t-1", "confirm", 7)).data?.assets_matched).toBe(2);
  expect(seen[0].url).toBe("/api/blackpoint/tenant");
  expect(JSON.parse(String(seen[0].init?.body))).toEqual({ tenant_id: "t-1", action: "confirm", org_id: 7 });
  expect(new Headers(seen[0].init?.headers).get("content-type")).toBe("application/json");
  answer(409, { error: "the finding changed since you looked: review the ticket again before sending it" });
  expect((await createTicket("detection:g-1", "abc")).error).toStartWith("the finding changed");
  answer(401, {});
  expect((await previewTicket("detection:g-1")).error).toBe(EXPIRED);
  globalThis.fetch = (async () => { throw new Error("down"); }) as unknown as typeof fetch;
  expect((await previewTicket("detection:g-1")).error).toBe(OFFLINE);
});

test("the ticket's details read as Halo will show them, and its link needs Halo's address", () => {
  expect(detailsText("<p><b>Security alert.</b></p>\n<p>Device: A &lt;b&gt;<br>User: x &amp; y</p>")).toBe("Security alert.\nDevice: A <b>\nUser: x & y");
  const f = { blackpoint: true, shodan: true, tickets: true, halo_ticket_url: "https://halo.example.com/tickets?id=", scan_admin: false };
  expect(ticketHref(f, 5001)).toBe("https://halo.example.com/tickets?id=5001");
  expect(ticketHref({ ...f, halo_ticket_url: null }, 5001)).toBeNull();
  expect(ticketHref(f, null)).toBeNull();
});

test("Blackpoint and Shodan are wizard steps; their secrets are secrets; a skipped one sends nothing", () => {
  expect(STEPS.indexOf("blackpoint")).toBeGreaterThan(STEPS.indexOf("nvd"));
  expect(STEPS.indexOf("shodan")).toBeLessThan(STEPS.indexOf("review"));
  expect(isSecret("BLACKPOINT_API_TOKEN") && isSecret("SHODAN_API_KEY")).toBe(true);
  const server = { keys: { BLACKPOINT_API_TOKEN: { set: true, env: false, value: null }, SHODAN_URL: { set: true, env: true, value: "https://shodan.example.com" } }, sections: [] };
  const d = initialDraft(server);
  expect(d.values.BLACKPOINT_API_TOKEN).toBeUndefined();
  d.values = { BLACKPOINT_BASE_URL: "https://bp.example.com", BLACKPOINT_API_TOKEN: "  ", SHODAN_API_KEY: "k", SHODAN_URL: "https://elsewhere.example.com" };
  expect(sectionValues(server, d, "blackpoint")).toEqual({ BLACKPOINT_BASE_URL: "https://bp.example.com" });
  expect(sectionValues(server, d, "shodan")).toEqual({ SHODAN_API_KEY: "k" });
  d.skipped = { shodan: true };
  expect(savePayload(server, d).SHODAN_API_KEY).toBeUndefined();
  expect(section("shodan").optional && section("blackpoint").optional).toBe(true);
});

test("Halo's ticket settings pick from Halo's own lists, and the Test's line leaves the lists out", () => {
  const f = section("halo").fields.find((x) => x.key === "HALO_TICKET_PRIORITY_ID")!;
  const detail = { clients: 3, priorities: [{ id: 3, name: "Medium" }, { id: "x", name: "bad" }], statuses: [{ id: 1, name: "New" }] };
  expect(choicesOf(f, detail)).toEqual([{ id: 3, name: "Medium" }]);
  expect(choicesOf(f, null)).toEqual([]);
  expect(detailLine(detail)).toBe("clients: 3");
  expect(detailLine({ plan: "dev", scan_credits: 95, query_credits: 200 })).toBe("plan: dev · scan credits: 95 · query credits: 200");
});
