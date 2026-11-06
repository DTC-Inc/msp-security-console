// Internet exposure (exposure.list): each public address clients' servers and desktops egress from, and each website's
// own server, with what Shodan's internet scan saw open there, worst first. Edge entry points (meant to face the
// internet) count in no total and show only on request. One address (exposure.get): its services, each port's rule,
// its CVEs with KEV's word, the devices behind it, its edge mark, its client's scan policy, and its Halo ticket.
import { A, useParams, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, Match, Show, Switch } from "solid-js";
import { features, markEdge, setScanPolicy } from "../actions";
import { evidence } from "../api";
import { cveHref } from "../nav";
import { cvssRole, role } from "../theme";
import { Busy, Err, Muted, Panel, Tag, plural } from "../ui";
import TicketButton from "./TicketDialog";

type Port = { port: number; transport: string; severity: string | null };
type Address = {
  ip: string; org_ids: number[]; clients: string[]; servers: number; desktops: number; website: boolean; sites: string[]; found: boolean | null;
  looked_up_at: string | null; provider_updated_at: string | null; net_org: string | null; isp: string | null; error: string | null; hostnames: string[];
  cve_count: number; kev_count: number; max_cvss: number | null; unscored: number; severity: string | null; rule_severity: string | null; risky_ports: number;
  edge: boolean; edge_note: string | null; edge_by: string | null; edge_at: string | null; finding: string; halo_ticket_id: number | null;
  scan: { days: number | null; requested_at: string | null; completed_at: string | null; pending: string | null } | null;
  policies: { org_id: number; frequency_days: number; set_by: string; set_at: string }[];
  open_ports?: Port[]; kev_cves?: string[];
  services?: { port: number; transport: string; product: string | null; version: string | null; title: string | null; cve_count: number; kev_count: number;
               rule: { label: string; severity: string; why: string } | null }[];
  cves?: { cve_id: string; cvss: number | null; severity: string | null; description: string | null; kev: { name: string | null; ransomware: boolean } | null; sources: string[]; ports: string[] }[];
  devices?: { device_id: number; name: string; device_class: string; org_id: number }[];
};
type Totals = { addresses: number; edge: number; looked_up: number; kev: number; critical: number; high: number; with_cves: number; websites: number };
type Filter = "all" | "kev" | "critical" | "high" | "with_cves" | "websites";
const FILTERS: { id: Filter; label: (t: Totals) => string; test: (a: Address) => boolean }[] = [
  { id: "all", label: (t) => plural(t.addresses, "address", "addresses"), test: () => true },
  { id: "kev", label: (t) => `${t.kev} with a known-exploited CVE`, test: (a) => a.kev_count > 0 },
  { id: "critical", label: (t) => `${t.critical} critical`, test: (a) => a.severity === "critical" },
  { id: "high", label: (t) => `${t.high} high`, test: (a) => a.severity === "high" },
  { id: "with_cves", label: (t) => `${t.with_cves} with CVEs`, test: (a) => a.cve_count > 0 },
  { id: "websites", label: (t) => `${t.websites} website servers`, test: (a) => a.website },
];
const SEV_ROLE: Record<string, string> = { critical: "bad", high: "x-sev-high", medium: "x-sev-medium", unscored: "x-sev-medium" };
const sevRole = (s: string | null) => (s ? SEV_ROLE[s] ?? "fg-muted" : "fg-muted");
export const addressHref = (ip: string) => `/exposure/${encodeURIComponent(ip)}`;
const when = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "never");

export default function Exposure() {
  const [q, setQ] = useSearchParams<{ org?: string; edge?: string; show?: Filter }>();
  const org = () => { const n = Number(q.org); return Number.isInteger(n) && n > 0 ? n : undefined; };
  const [d] = createResource(() => ({ org: org(), edge: q.edge === "1" }),
    (x) => evidence<Address[]>("exposure.list", { ...(x.org ? { org_id: x.org } : {}), ...(x.edge ? { include_edge: true } : {}), limit: 500 }));
  const show = () => q.show ?? "all";
  const rows = createMemo(() => (d()?.data ?? []).filter(FILTERS.find((f) => f.id === show())!.test));
  const t = () => d()?.totals as Totals | undefined;
  const scope = () => (org() ? (d()?.data?.[0]?.clients?.[0] ?? `client ${org()}`) : null);
  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li aria-current={scope() ? undefined : "page"}><A href="/exposure">Exposure</A></li>
      <Show when={scope()}><li aria-current="page">{scope()}</li></Show></ol></nav>
    <Panel page title={scope() ? `Internet exposure: ${scope()}` : "Internet exposure"}>
      <p class="muted">What Shodan's own internet scan has seen open on clients' addresses and on their websites' servers. A CVE here is from the version a service announced: a lead to check, not proof.</p>
      <Show when={t()}>{(x) => <div class="toolbar" role="group" aria-label="Show">
        <For each={FILTERS}>{(f) => <button type="button" class={show() === f.id ? "" : "quiet"} aria-pressed={show() === f.id}
          onClick={() => setQ({ show: f.id === "all" ? undefined : f.id }, { replace: true })}>{f.label(x())}</button>}</For>
        <label class="check"><input type="checkbox" checked={q.edge === "1"} onChange={(e) => setQ({ edge: e.currentTarget.checked ? "1" : undefined }, { replace: true })} />
          Show {plural(x().edge, "edge entry point")} too</label>
      </div>}</Show>
      <Switch>
        <Match when={d.loading && !d.latest}><Busy text="Loading the addresses…" /></Match>
        <Match when={d()?.error}><Err text={d()!.error!} /></Match>
        <Match when={rows().length === 0}><p>{(d()?.data ?? []).length ? "No addresses match that." : "No addresses yet. They appear once NinjaOne has reported devices' public addresses and Shodan has been asked about them."}</p></Match>
        <Match when={rows().length}>
          <ul class="rows"><For each={rows()}>{(a) => <li class="row">
            <span class="grow">
              <A class="mono" href={addressHref(a.ip)}>{a.ip}</A>
              <Show when={a.severity}><Tag text={a.severity!} fill={sevRole(a.severity)} /></Show>
              <Show when={a.edge}><Tag text="edge entry point" fill="fg-muted" /></Show>
              <Muted>{a.clients.join(", ") || "no client"} · {a.website ? `website: ${a.sites.join(", ")}` : `${plural(a.servers, "server")}, ${plural(a.desktops, "desktop")}`}</Muted>
            </span>
            <span class="chips"><For each={(a.open_ports ?? []).slice(0, 6)}>{(p) => <span class="chip" style={{ color: role(sevRole(p.severity)) }}>{p.port}/{p.transport}</span>}</For></span>
            <span class="num">{a.found === false ? "nothing seen" : <Show when={a.cve_count > 0} fallback={plural(a.cve_count, "CVE")}>
              <A href={addressHref(a.ip)} aria-label={`${a.ip}: its ${plural(a.cve_count, "CVE")}`}>{plural(a.cve_count, "CVE")}</A></Show>}</span>
            <span class="score" style={{ color: role(cvssRole(a.max_cvss)) }} title="Highest CVSS score">{a.max_cvss ?? "—"}</span>
          </li>}</For></ul>
        </Match>
      </Switch>
    </Panel>
  </>;
}

export function AddressPage() {
  const params = useParams<{ ip: string }>();
  const ip = () => decodeURIComponent(params.ip);
  const [d, { refetch }] = createResource(ip, (x) => evidence<Address>("exposure.get", { ip: x }));
  const [f] = createResource(features);
  const [msg, setMsg] = createSignal<{ ok: boolean; text: string } | null>(null);
  const [note, setNote] = createSignal("");
  const [days, setDays] = createSignal("30");
  async function edge(on: boolean) {
    setMsg(null);
    const a = await markEdge(ip(), on, note().trim() || undefined);
    setMsg(a.error ? { ok: false, text: a.error } : { ok: true, text: on ? "Marked as an edge entry point: it no longer counts in the totals." : "No longer an edge entry point." });
    if (!a.error) refetch();
  }
  async function policy(org: number, n: number) {
    setMsg(null);
    const a = await setScanPolicy(org, n);
    setMsg(a.error ? { ok: false, text: a.error } : { ok: true, text: n ? `This client's addresses are scanned every ${plural(n, "day")} now, within the month's credits.` : "On-demand scans are off for this client." });
    if (!a.error) refetch();
  }
  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li><A href="/exposure">Exposure</A></li><li aria-current="page" class="mono">{ip()}</li></ol></nav>
    <Switch>
      <Match when={d.loading && !d.latest}><Busy text={`Loading ${ip()}…`} /></Match>
      <Match when={d()?.error}><Err text={d()!.error!} /></Match>
      <Match when={!d()?.data}><Err text={`${ip()} isn't a current client address.`} /></Match>
      <Match when={d()?.data}>{(a) => <>
        <Panel page title={a().ip} right={<TicketButton finding={a().finding} ticket={a().halo_ticket_id} features={f()?.data} onRaised={() => refetch()} />}>
          <p>
            <Show when={a().severity}><Tag text={a().severity!} fill={sevRole(a().severity)} /> </Show>
            {a().clients.join(", ") || "No client"} · {a().website ? `the server behind ${a().sites.join(", ")}` : `${plural(a().servers, "server")} and ${plural(a().desktops, "desktop")} reach the internet from here`}
          </p>
          <p class="muted">{a().found === false ? "Shodan has nothing on this address." : `Shodan's data from ${when(a().provider_updated_at)}, looked up ${when(a().looked_up_at)}.`}
            {a().net_org ? ` Network: ${a().net_org}.` : ""}{a().error ? ` The last lookup failed: ${a().error}.` : ""}</p>
          <div aria-live="polite"><Show when={msg()}>{(m) => <p class={`msg ${m().ok ? "ok" : "bad"}`}>{m().text}</p>}</Show></div>
        </Panel>
        <Panel title="Open services">
          <Show when={(a().services ?? []).length} fallback={<p>No open services seen.</p>}>
            <ul class="rows"><For each={a().services}>{(s) => <li class="row">
              <span class="grow"><strong class="mono">{s.port}/{s.transport}</strong> {[s.product, s.version].filter(Boolean).join(" ") || "unidentified"}
                <Show when={s.rule}><Muted>{s.rule!.label}: {s.rule!.why}</Muted></Show></span>
              <Show when={s.kev_count}><Tag text={`${s.kev_count} KEV`} fill="x-kev-fill" /></Show>
              <span class="num">{plural(s.cve_count, "CVE")}</span>
              <Show when={s.rule}><span style={{ color: role(sevRole(s.rule!.severity)) }}>{s.rule!.severity}</span></Show>
            </li>}</For></ul>
          </Show>
        </Panel>
        <Panel title="CVEs">
          <Show when={(a().cves ?? []).length} fallback={<p>No CVEs known for what's open here.</p>}>
            <ul class="rows"><For each={a().cves}>{(c) => <li class="row">
              <span class="grow"><A class="mono" href={cveHref(c.cve_id)}>{c.cve_id}</A><Show when={c.kev}><Tag text="KEV" fill="x-kev-fill" /></Show>
                <Muted>{c.ports.join(", ")} · {c.sources.map((s) => (s === "nvd" ? "NVD's ranges" : "Shodan")).join(" and ")}</Muted></span>
              <span class="score" style={{ color: role(cvssRole(c.cvss)) }}>{c.cvss ?? "—"}</span>
            </li>}</For></ul>
          </Show>
        </Panel>
        <Show when={(a().devices ?? []).length}><Panel title="Devices behind it">
          <ul class="rows"><For each={a().devices}>{(x) => <li class="row"><span class="grow">{x.name}</span><Muted>{x.device_class}</Muted></li>}</For></ul>
        </Panel></Show>
        <Panel title="Edge entry point">
          <p class="muted">Mark an address that's meant to face the internet (a VPN portal, a published server), so it stops counting as exposure. It's still looked up.</p>
          <Show when={a().edge} fallback={<div class="field">
            <label for="edge-note">Why it's meant to face the internet <span class="muted">(optional)</span></label>
            <div class="search"><input id="edge-note" type="text" maxLength={300} value={note()} onInput={(e) => setNote(e.currentTarget.value)} />
              <button type="button" onClick={() => edge(true)}>Mark as an edge entry point</button></div>
          </div>}>
            <p>Marked by {a().edge_by}{a().edge_note ? `: ${a().edge_note}` : ""}. <button type="button" class="link" onClick={() => edge(false)}>Unmark it</button></p>
          </Show>
        </Panel>
        <Show when={a().scan && f()?.data?.shodan}><Panel title="On-demand scans">
          <p class="muted">Off unless an admin turns them on for the client. Each scan of an address costs one of Shodan's monthly scan credits.</p>
          <p>{a().scan!.days ? `Scanned every ${plural(a().scan!.days!, "day")}.` : "Off for this client."}
            {a().scan!.requested_at ? ` Last asked for ${when(a().scan!.requested_at)}${a().scan!.pending ? ` (${a().scan!.pending!.toLowerCase()})` : ""}.` : ""}</p>
          <Show when={f()?.data?.scan_admin} fallback={<p class="muted">Only an admin can change this.</p>}>
            <For each={a().org_ids}>{(o) => <div class="search">
              <label class="sr-only" for={`days-${o}`}>Days between scans</label>
              <input id={`days-${o}`} type="number" min="1" max="365" value={days()} onInput={(e) => setDays(e.currentTarget.value)} />
              <button type="button" onClick={() => policy(o, Number(days()) || 30)}>Scan every {days() || "30"} days</button>
              <Show when={a().scan!.days}><button type="button" class="quiet" onClick={() => policy(o, 0)}>Turn off</button></Show>
            </div>}</For>
          </Show>
        </Panel></Show>
      </>}</Match>
    </Switch>
  </>;
}
