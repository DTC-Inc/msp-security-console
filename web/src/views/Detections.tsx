// Blackpoint's open detections (detections.list), worst first, across clients or for one (?org=) or one tenant
// (?tenant=), and one detection (detection.get) with its Halo ticket. Every count above the list filters the rows it
// counts. A detection whose tenant isn't a confirmed client says so, and links to the tenants page to confirm it.
import { A, useParams, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, For, Match, Show, Switch } from "solid-js";
import { features } from "../actions";
import { evidence } from "../api";
import { cvssRole, role } from "../theme";
import { Busy, Err, Muted, Panel, Tag, plural } from "../ui";
import TicketButton from "./TicketDialog";

export type Detection = {
  detection_id: string; tenant_id: string; tenant_name: string; org_id: number | null; client: string | null; status: string; open: boolean;
  risk_score: number | null; alert_count: number | null; alert_types: string[]; hostname: string | null; username: string | null;
  detection_name: string | null; rule_name: string | null; created: string | null; updated: string | null; last_seen_open: string | null;
  device_id: number | null; device_name: string | null; finding: string; halo_ticket_id: number | null;
};
type Totals = { open: number; clients: number; high_risk: number; unmapped: number; without_ticket: number };
type Filter = "all" | "high_risk" | "unmapped" | "without_ticket";

const FILTERS: { id: Filter; label: (t: Totals) => string; test: (d: Detection) => boolean }[] = [
  { id: "all", label: (t) => `${plural(t.open, "open detection")}`, test: () => true },
  { id: "high_risk", label: (t) => `${t.high_risk} high risk (80+)`, test: (d) => (d.risk_score ?? 0) >= 80 },
  { id: "unmapped", label: (t) => `${t.unmapped} not tied to a client`, test: (d) => d.org_id == null },
  { id: "without_ticket", label: (t) => `${t.without_ticket} without a ticket`, test: (d) => d.halo_ticket_id == null },
];
const riskRole = (r: number | null) => cvssRole(r == null ? null : r / 10);
const when = (s: string | null) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");
export const detectionHref = (id: string) => `/detections/${encodeURIComponent(id)}`;

export default function Detections() {
  const [q, setQ] = useSearchParams<{ org?: string; tenant?: string; closed?: string; show?: Filter }>();
  const org = () => { const n = Number(q.org); return Number.isInteger(n) && n > 0 ? n : undefined; };
  const [d] = createResource(() => ({ org: org(), tenant: q.tenant, closed: q.closed === "1" }),
    (x) => evidence<Detection[]>("detections.list", { ...(x.org ? { org_id: x.org } : {}), ...(x.tenant ? { tenant_id: x.tenant } : {}), ...(x.closed ? { include_closed: true } : {}), limit: 500 }));
  const show = () => q.show ?? "all";
  const rows = createMemo(() => (d()?.data ?? []).filter((r) => FILTERS.find((f) => f.id === show())!.test(r) && (show() === "all" || r.open)));
  const totals = () => d()?.totals as Totals | undefined;
  const scope = () => (org() ? (d()?.data?.[0]?.client ?? `client ${org()}`) : q.tenant ? (d()?.data?.[0]?.tenant_name ?? "this tenant") : null);

  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li aria-current={scope() ? undefined : "page"}><A href="/detections">Detections</A></li>
      <Show when={scope()}><li aria-current="page">{scope()}</li></Show></ol></nav>
    <Panel page title={scope() ? `Detections: ${scope()}` : "Detections"} right={<span class="chips"><A href="/blackpoint/tenants">Blackpoint tenants</A><A href="/darkweb">Dark web</A></span>}>
      <p class="muted">Blackpoint's open detections, polled every few minutes. A detection whose tenant isn't a confirmed client shows its tenant until someone confirms which client it is.</p>
      <Show when={totals()}>{(t) => <div class="toolbar" role="group" aria-label="Show">
        <For each={FILTERS}>{(f) => <button type="button" class={show() === f.id ? "" : "quiet"} aria-pressed={show() === f.id}
          onClick={() => setQ({ show: f.id === "all" ? undefined : f.id }, { replace: true })}>{f.label(t())}</button>}</For>
        <label class="check"><input type="checkbox" checked={q.closed === "1"} onChange={(e) => setQ({ closed: e.currentTarget.checked ? "1" : undefined }, { replace: true })} />Closed in the last 30 days too</label>
      </div>}</Show>
      <Switch>
        <Match when={d.loading && !d.latest}><Busy text="Loading the detections…" /></Match>
        <Match when={d()?.error}><Err text={d()!.error!} /></Match>
        <Match when={rows().length === 0}><p>{(d()?.data ?? []).length ? "No detections match that." : "No open detections. Blackpoint hasn't reported any, or its connector hasn't run yet."}</p></Match>
        <Match when={rows().length}>
          <ul class="rows"><For each={rows()}>{(r) => <li class="row">
            <span class="grow">
              <A href={detectionHref(r.detection_id)}>{r.detection_name ?? r.rule_name ?? (r.alert_types.join(", ") || "Blackpoint detection")}</A>
              <Show when={!r.open}><Tag text="closed" fill="fg-muted" /></Show>
              <Muted>{r.device_name ?? r.hostname ?? "no device named"} · {r.client ?? `${r.tenant_name} (not tied to a client)`}</Muted>
            </span>
            <Show when={r.halo_ticket_id}><Muted>ticket {r.halo_ticket_id}</Muted></Show>
            <span class="num">{when(r.created)}</span>
            <span class="score" style={{ color: role(riskRole(r.risk_score)) }} title="Blackpoint's risk score">{r.risk_score ?? "—"}</span>
          </li>}</For></ul>
        </Match>
      </Switch>
    </Panel>
  </>;
}

export function DetectionPage() {
  const params = useParams<{ id: string }>();
  const [d, { refetch }] = createResource(() => decodeURIComponent(params.id), (id) => evidence<Detection>("detection.get", { detection_id: id }));
  const [f] = createResource(features);
  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li><A href="/detections">Detections</A></li><li aria-current="page">This detection</li></ol></nav>
    <Switch>
      <Match when={d.loading}><Busy text="Loading the detection…" /></Match>
      <Match when={d()?.error}><Err text={d()!.error!} /></Match>
      <Match when={!d()?.data}><Err text="That detection isn't in the console." /></Match>
      <Match when={d()?.data}>{(x) => <Panel page title={x().detection_name ?? x().rule_name ?? "Blackpoint detection"}
          right={<TicketButton finding={x().finding} ticket={x().halo_ticket_id} features={f()?.data} onRaised={() => refetch()} />}>
        <dl class="facts">
          <dt>Status</dt><dd>{x().open ? "Open" : "Closed"}</dd>
          <dt>Risk score</dt><dd style={{ color: role(riskRole(x().risk_score)) }}>{x().risk_score ?? "—"}</dd>
          <dt>Client</dt><dd><Show when={x().org_id} fallback={<>Not tied to a client yet: <A href="/blackpoint/tenants">confirm which client {x().tenant_name} is</A></>}>
            <A href={`/detections?org=${x().org_id}`}>{x().client}</A></Show></dd>
          <dt>Blackpoint tenant</dt><dd><A href={`/detections?tenant=${encodeURIComponent(x().tenant_id)}`}>{x().tenant_name}</A></dd>
          <dt>Device</dt><dd>{x().device_name ?? x().hostname ?? "—"}<Show when={x().device_name == null && x().hostname}><Muted> (not matched to a NinjaOne device)</Muted></Show></dd>
          <dt>User</dt><dd>{x().username ?? "—"}</dd>
          <dt>Types</dt><dd>{x().alert_types.join(", ") || "—"}</dd>
          <dt>Rule</dt><dd>{x().rule_name ?? "—"}</dd>
          <dt>Alerts in the group</dt><dd>{x().alert_count ?? "—"}</dd>
          <dt>Created</dt><dd>{when(x().created)}</dd>
          <dt>Last updated</dt><dd>{when(x().updated)}</dd>
        </dl>
      </Panel>}</Match>
    </Switch>
  </>;
}
