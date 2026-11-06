// Stand-ins for the vendors the console collects from, for local runs (compose's "demo" profile): NinjaOne, HaloPSA,
// CISA KEV, NVD (its API and its yearly feeds), Microsoft's security updates (MSRC), NinjaOne's OS patches and
// process-inventory field, Blackpoint CompassOne and Shodan, answering the calls the connectors make with a small made-up fleet. No client data: every client,
// device and CVE here is invented. Same shapes as server/tests/store.rs's stubs, with a little more to look at. It also
// answers the setup wizard's Test calls: a client secret of "wrong" is refused, as is any NVD key but "demo-nvd-key".
const PORT = Number(process.env.PORT ?? 8090);
const orgs = [{ id: 1, name: "Alpha Dental" }, { id: 2, name: "Beta Orthodontics" }, { id: 3, name: "Gamma Family Practice" }];
// Public addresses are from the documentation ranges (RFC 5737), so none is anyone's.
const devices = [
  { id: 101, organizationId: 1, systemName: "FRONTDESK-1", nodeClass: "WINDOWS_WORKSTATION", os: { name: "Windows 11 Pro", buildNumber: "26100" }, chassis: "DESKTOP", publicIP: "203.0.113.10" },
  { id: 102, organizationId: 1, systemName: "XRAY-PC", nodeClass: "WINDOWS_WORKSTATION", os: { name: "Windows 10 Pro", buildNumber: "19045" }, chassis: "DESKTOP", publicIP: "203.0.113.10" },
  { id: 103, organizationId: 1, systemName: "ALPHA-DC", nodeClass: "WINDOWS_SERVER", os: { name: "Windows Server 2025 Standard", buildNumber: "26100" }, publicIP: "203.0.113.10" },
  { id: 201, organizationId: 2, systemName: "BETA-LT-1", nodeClass: "WINDOWS_WORKSTATION", os: { name: "Windows 11 Pro", buildNumber: "26100" }, chassis: "LAPTOP", publicIP: "198.51.100.20" },
  { id: 301, organizationId: 3, systemName: "GAMMA-RECEPTION", nodeClass: "WINDOWS_WORKSTATION", os: { name: "Windows 11 Pro", buildNumber: "26100" }, chassis: "DESKTOP", publicIP: "198.51.100.30" },
];
const software: Record<number, { deviceId: number; name: string; publisher: string; version: string }[]> = {
  1: [{ deviceId: 101, name: "Google Chrome", publisher: "Google LLC", version: "120.0.6099.71" },
      { deviceId: 102, name: "Google Chrome", publisher: "Google LLC", version: "120.0.6099.71" },
      { deviceId: 102, name: "7-Zip 22.01 (x64)", publisher: "Igor Pavlov", version: "22.01" },
      { deviceId: 103, name: "Notepad++ (64-bit x64)", publisher: "Notepad++ Team", version: "8.5.7" }],
  2: [{ deviceId: 201, name: "Google Chrome", publisher: "Google LLC", version: "131.0.6778.86" }],
  3: [{ deviceId: 301, name: "7-Zip 22.01 (x64)", publisher: "Igor Pavlov", version: "22.01" }],
};
const halo = [{ id: 10, name: "Alpha Dental", ninjarmmid: 1, website: "http://www.alphadental.example/" },
              { id: 20, name: "Beta Orthodontics", ninjarmmid: 2, website: "betaortho.example" }, { id: 30, name: "Gamma Family Practice" }];
const cfg = (cpe: string, range: Record<string, string>) => [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: `cpe:2.3:a:${cpe}:*:*:*:*:*:*:*:*`, ...range }] }] }];
const cve = (id: string, cvss: number, sev: string, desc: string, configurations: any) =>
  ({ cve: { id, published: "2026-09-15T10:00:00.000", lastModified: "2026-10-01T10:00:00.000", vulnStatus: "Analyzed", descriptions: [{ lang: "en", value: desc }],
     metrics: { cvssMetricV31: [{ type: "Primary", cvssData: { baseScore: cvss, baseSeverity: sev } }] }, configurations } });
const nvd: Record<string, any[]> = {
  "google:chrome": [cve("CVE-2026-90100", 8.8, "HIGH", "A made-up use-after-free in Chrome before 121 lets a crafted page run code.", cfg("google:chrome", { versionEndExcluding: "121.0.6167.85" })),
                    cve("CVE-2026-90101", 6.5, "MEDIUM", "A made-up Chrome flaw before 125 leaks memory to a crafted page.", cfg("google:chrome", { versionEndExcluding: "125.0" }))],
  "7-zip:7-zip": [cve("CVE-2026-90200", 7.8, "HIGH", "A made-up 7-Zip archive bug before 24.07 runs code when an archive is opened.", cfg("7-zip:7-zip", { versionEndExcluding: "24.07" }))],
  // A name the automatic mapping won't decide: NVD's "example helper" is another vendor's, so it waits for review.
  "acme:example_helper": [cve("CVE-2026-90500", 7.5, "HIGH", "A made-up flaw in another vendor's Example Helper before 2.0.", cfg("acme:example_helper", { versionEndExcluding: "2.0" }))],
  "notepad-plus-plus:notepad\\+\\+": [cve("CVE-2026-90300", 5.5, "MEDIUM", "A made-up Notepad++ 8.5.7 crash on a crafted file.", cfg("notepad-plus-plus:notepad\\+\\+", { versionStartIncluding: "8.5.7", versionEndIncluding: "8.5.7" }))],
};
const kev = { vulnerabilities: [{ cveID: "CVE-2026-90100", vendorProject: "Google", product: "Chromium", vulnerabilityName: "Made-up Chromium use-after-free", dateAdded: "2026-10-01", dueDate: "2026-10-22", knownRansomwareCampaignUse: "Known", shortDescription: "Made up for the demo." }] };
// Blackpoint: three tenants (Alpha's domain is its website's, Beta's name is its own, Gamma is no one's), assets,
// open detections, one licensed tenant's findings, and a dark-web row that carries a password the console must drop.
const bpTenants = [{ id: "t-alpha", name: "Alpha Dental Group", domain: "alphadental.example" }, { id: "t-beta", name: "Beta Orthodontics, P.C." }, { id: "t-gamma", name: "Gamma Holdings" }];
const bpAssets: Record<string, any[]> = { "t-alpha": [{ id: "as-1", hostname: "FRONTDESK-1", osName: "Windows 11" }, { id: "as-2", hostname: "ALPHA-DC" }], "t-beta": [{ id: "as-3", hostname: "BETA-LT-1" }] };
const bpGroups: Record<string, any[]> = {
  "t-alpha": [{ id: "g-1", riskScore: 88, alertCount: 4, alertTypes: ["EDR"], created: "2026-11-05T14:00:00Z", alert: { hostname: "FRONTDESK-1", username: "frontdesk", action: "Encoded PowerShell launched from Office", ruleName: "ps-encoded" } }],
  "t-beta": [{ id: "g-2", riskScore: 35, alertCount: 1, alertTypes: ["Identity"], created: "2026-11-04T09:30:00Z", alert: { hostname: "BETA-LT-1", username: "beta.user", action: "Sign-in from a new country" } }],
};
const bpVulns = [{ id: "v-1", cveId: "CVE-2026-90100", severity: "HIGH", baseScore: 8.8, exploitability: "Attacked", prioritized: true, assetsAmount: 1, applicationVendor: "Google", applicationName: "Chrome", status: "open" }];
const bpDarkweb = [{ id: "dw-1", email: "frontdesk@alphadental.example", breachName: "Made-up Breach 2025", passwordExposed: true, password: "not-kept-demo-password", breachCreatedAt: "2025-06-01T00:00:00Z" }];
const pageOf = (data: any[]) => ({ data, meta: { currentPage: 1, totalPages: 1, totalItems: data.length } });
// Shodan: Alpha's office line with RDP and an old OpenSSH open, and its website on a dedicated server.
const shodanHosts: Record<string, any> = {
  "203.0.113.10": { ports: [22, 3389], org: "Example ISP", hostnames: ["gw.alphadental.example"], last_update: "2026-09-01T00:00:00.000000", vulns: ["CVE-2026-90100"],
    data: [{ port: 22, transport: "tcp", product: "OpenSSH", version: "8.2p1", cpe23: ["cpe:2.3:a:openbsd:openssh:8.2p1"] }, { port: 3389, transport: "tcp", product: "Remote Desktop Protocol" }] },
  "198.51.100.30": { ports: [443], org: "Example ISP", data: [{ port: 443, transport: "tcp", product: "nginx" }] },
  "192.0.2.50": { ports: [80, 443], org: "Example Hosting", hostnames: ["www.alphadental.example"], data: [{ port: 443, transport: "tcp", product: "Apache httpd", version: "2.4.49" }] },
};
const dns: Record<string, string> = { "www.alphadental.example": "192.0.2.50", "alphadental.example": "192.0.2.50", "betaortho.example": "192.0.2.60" };
let tickets = 7000;
// Microsoft's updates: one made-up month. Build 26100 is Windows 11 24H2 and Server 2025, fixed at different revisions.
const msrcIndex = { value: [{ ID: "2026-Oct", InitialReleaseDate: "2026-10-13T07:00:00Z", CurrentReleaseDate: "2026-10-20T01:00:00Z" }] };
const fix = (kb: string, build: string, ids: string[]) => ({ Description: { Value: kb }, ProductID: ids, Type: 2, FixedBuild: build });
const msrcOct = {
  ProductTree: { FullProductName: [{ ProductID: "1", Value: "Windows 11 Version 24H2 for x64-based Systems" }, { ProductID: "2", Value: "Windows Server 2025" }] },
  Vulnerability: [
    { CVE: "CVE-2026-90400", Title: { Value: "A made-up Windows kernel elevation of privilege" },
      Threats: [{ Type: 1, Description: { Value: "Exploited:Yes" }, ProductID: ["1"] }, { Type: 3, Description: { Value: "Critical" }, ProductID: ["1", "2"] }],
      Remediations: [fix("5900001", "10.0.26100.9711", ["1"]), fix("5900002", "10.0.26100.33650", ["2"])] },
    { CVE: "CVE-2026-90401", Title: { Value: "A made-up Windows print spooler spoofing flaw" },
      Threats: [{ Type: 3, Description: { Value: "Important" }, ProductID: ["1"] }], Remediations: [fix("5900000", "10.0.26100.9445", ["1"])] },
  ],
};
const at = Math.floor(Date.now() / 1000) - 86400;
const cu = (deviceId: number, kb: string) => ({ id: `${deviceId}-${kb}`, deviceId, name: `2026-10 Cumulative Update for Windows (KB${kb})`, kbNumber: `KB${kb}`, status: "INSTALLED", installedAt: at });
// 101 has the September update (vulnerable to the exploited one), 201 both (patched), 301 nothing Microsoft's data names
// (its patch level unknown), 103 the server, its October update approved and waiting.
const installs = [cu(101, "5900000"), cu(201, "5900000"), cu(201, "5900001")];
const failed = [{ id: "f1", deviceId: 101, name: "2026-10 Cumulative Update for Windows (KB5900001)", kbNumber: "KB5900001", status: "FAILED", installedAt: at }];
const pendingOs = [{ id: "p1", deviceId: 103, name: "2026-10 Cumulative Update for Windows Server 2025 (KB5900002)", kbNumber: "KB5900002", timestamp: at }];
// The endpoint script's field (endpoint/process): 101 runs an old Chrome, an unsigned tool and Windows' own svchost.
const sha = (c: string) => c.repeat(64);
const bin = (name: string, product: string, company: string, fileVersion: string, signatureStatus: string, c: string) =>
  ({ key: `sha256:${sha(c)}`, sha256: sha(c), name, paths: [`C:\\Program Files\\Example\\${name}`], pathCount: 1, fileVersion, product, company, signer: company, signatureStatus, count: 1 });
const processDoc = { schema: 1, scriptVersion: "1.3.3", collectedAt: new Date(at * 1000).toISOString(), binaryCount: 3,
  binaries: [bin("chrome.exe", "Google Chrome", "Google LLC", "120.0.6099.71", "Valid", "a"), bin("helper.exe", "Example Helper", "Example Tools", "1.0.0", "NotSigned", "b"),
             bin("svchost.exe", "Microsoft® Windows® Operating System", "Microsoft Corporation", "10.0.26100.1", "Valid", "c")] };
const processPayload = Buffer.from(Bun.gzipSync(new TextEncoder().encode(JSON.stringify(processDoc)))).toString("base64");
const processHash = new Bun.CryptoHasher("sha256").update(processPayload).digest("hex");
// NVD's yearly feeds: the made-up CVEs in their year's file, every other year empty; the modified feed empty.
function nvdFeed(name: string) {
  const items = Object.values(nvd).flat().filter((v: any) => v.cve.id.startsWith(`CVE-${name}-`));
  const text = JSON.stringify({ format: "NVD_CVE", version: "2.0", vulnerabilities: name === "modified" ? [] : items });
  const gz = Bun.gzipSync(new TextEncoder().encode(text));
  return { gz, meta: `lastModifiedDate:2026-11-01T03:00:00-04:00\r\ngzSize:${gz.length}\r\nsha256:${new Bun.CryptoHasher("sha256").update(text).digest("hex").toUpperCase()}\r\n` };
}
const json = (v: any, status = 200) => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
Bun.serve({ port: PORT, async fetch(req) {
  const u = new URL(req.url), p = u.pathname, q = u.searchParams;
  if (p.endsWith("/oauth/token") || p.endsWith("/auth/token")) {
    const form = new URLSearchParams(await req.text());
    if (form.get("client_secret") === "wrong") return json({ error: "invalid_client" }, 401);
    return json({ access_token: "demo-bearer", expires_in: 3600 });
  }
  if (p === "/ninja/v2/organizations") return json(orgs);
  if (p === "/ninja/v2/queries/computer-systems") return json({ results: devices.filter((d) => d.chassis).map((d) => ({ deviceId: d.id, chassisType: d.chassis })), cursor: null });
  if (p === "/ninja/v2/devices-detailed") return json(q.get("after") === "0" ? devices.map(({ chassis, ...d }) => ({ ...d, lastContact: Date.now() / 1000 })) : []);
  if (p === "/ninja/v2/queries/software") return json({ results: software[Number((q.get("df") ?? "").replace("org=", ""))] ?? [], cursor: null });
  if (p === "/halo/api/TicketType") return json([{ id: 31, name: "Security Alert" }, { id: 1, name: "Incident" }]);
  if (p === "/halo/api/Status") return json([{ id: 1, name: "New" }, { id: 2, name: "In Progress" }, { id: 9, name: "Closed" }]);
  if (p === "/halo/api/Priority") return json([{ id: "p1-guid", priorityid: 1, name: "P1" }, { id: "p3-guid", priorityid: 3, name: "P3" }]);
  if (p === "/halo/api/Tickets" && req.method === "POST") return json([{ id: ++tickets }]);
  if (p.startsWith("/blackpoint/")) {
    if (req.headers.get("authorization") === "Bearer wrong") return json({ message: "Invalid authorization token" }, 401);
    const t = req.headers.get("x-tenant-id") ?? "";
    const limits = { "content-type": "application/json", "x-ratelimit-remaining": "3900", "x-ratelimit-reset": "60" };
    const ok = (v: any) => new Response(JSON.stringify(v), { headers: limits });
    if (p === "/blackpoint/v1/tenants") return ok(pageOf(bpTenants));
    if (p === "/blackpoint/v1/vulnerability-management/vulnerabilities/stats/count-by-severity") return t === "t-alpha" ? ok({ data: { HIGH: 1 } }) : json({ message: "Requestor does not have required entitlements" }, 403);
    if (p === "/blackpoint/v1/assets") return ok(pageOf(bpAssets[t] ?? []));
    if (p === "/blackpoint/v1/alert-groups") { const g = bpGroups[t] ?? []; return ok({ items: g, take: 100, skip: 0, total: g.length }); }
    if (p === "/blackpoint/v1/vulnerability-management/vulnerabilities") return ok(pageOf(t === "t-alpha" ? bpVulns : []));
    if (/^\/blackpoint\/v1\/vulnerability-management\/vulnerabilities\/[^/]+\/assets$/.test(p)) return ok(pageOf([{ id: "as-1", status: "open" }]));
    if (p === "/blackpoint/v1/vulnerability-management/darkweb/scan/exposures") return ok(pageOf(t === "t-alpha" ? bpDarkweb : []));
  }
  if (p.startsWith("/shodan/")) {
    if (q.get("key") === "wrong") return json({ error: "Please provide a valid API key" }, 401);
    if (p === "/shodan/api-info") return json({ plan: "demo", scan_credits: 100, query_credits: 100 });
    const h = p.match(/^\/shodan\/shodan\/host\/(.+)$/); if (h) return shodanHosts[h[1]] ? json(shodanHosts[h[1]]) : json({ error: "No information available for that IP." }, 404);
    if (p === "/shodan/dns/resolve") return json(Object.fromEntries((q.get("hostnames") ?? "").split(",").map((n) => [n, dns[n] ?? null])));
    if (p === "/shodan/shodan/scan" && req.method === "POST") return json({ id: "demo-scan", count: 1, credits_left: 99 });
    if (p.startsWith("/shodan/shodan/scan/")) return json({ id: "demo-scan", status: "DONE" });
  }
  if (p === "/ninja/v2/queries/os-patch-installs") return json({ results: q.get("status") === "FAILED" ? failed : installs, cursor: null });
  if (p === "/ninja/v2/queries/os-patches") return json({ results: q.get("status") === "APPROVED" ? pendingOs : [], cursor: null });
  if (p === "/ninja/v2/queries/custom-fields-detailed") {
    const fields = q.get("fields") ?? "";
    if (fields.startsWith("processInventoryCollectedAt")) return json({ results: [{ deviceId: 101, fields: [
      { name: "processInventoryCollectedAt", value: processDoc.collectedAt }, { name: "processInventoryHash", value: { text: processHash } },
      { name: "processInventoryBytes", value: processPayload.length, updated: at }] }], cursor: null });
    if (fields.startsWith("processInventory,") && (q.get("df") ?? "").includes("101"))
      return json({ results: [{ deviceId: 101, fields: [{ name: "processInventory", value: { text: processPayload, html: `<p>${processPayload}</p>` }, updated: at }] }], cursor: null });
    return json({ results: [], cursor: null });
  }
  if (p === "/msrc/updates") return json(msrcIndex);
  if (p === "/msrc/cvrf/2026-Oct") return json(msrcOct);
  const feed = p.match(/^\/nvd-feeds\/nvdcve-2\.0-(\d{4}|modified)\.(meta|json\.gz)$/);
  if (feed) {
    const f = nvdFeed(feed[1]);
    return feed[2] === "meta" ? new Response(f.meta) : new Response(f.gz, { headers: { "content-type": "application/gzip" } });
  }
  if (p === "/halo/api/Client") return json({ record_count: halo.length, clients: halo.map(({ id, name }) => ({ id, name })) });
  const hc = p.match(/^\/halo\/api\/Client\/(\d+)$/); if (hc) return json(halo.find((h) => h.id === Number(hc[1])) ?? {});
  if (p === "/kev.json") return json(kev);
  if (p === "/nvd") {
    const key = req.headers.get("apiKey");
    if (key !== null && key !== "demo-nvd-key") return json({ message: "Invalid apiKey" }, 404);   // what NVD answers a bad key
    const m = q.get("virtualMatchString");
    const v = m === null ? Object.values(nvd).flat() : nvd[m.replace("cpe:2.3:a:", "")] ?? [];
    const per = Number(q.get("resultsPerPage") ?? 2000);
    return json({ totalResults: v.length, resultsPerPage: per, vulnerabilities: v.slice(0, per) });
  }
  return json({ error: "not a stub" }, 404);
} });
console.log(`mock vendors on ${PORT}`);
