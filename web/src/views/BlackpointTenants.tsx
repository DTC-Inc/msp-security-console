// Which client each Blackpoint tenant is (blackpoint.tenants). The connector only suggests, by the tenant's domain or
// name; nothing is tied to a client until someone here confirms it, chooses another client, or says it's no client.
// Unmapped tenants come first, then suggested, then decided. Each count filters the list.
import { A, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, createSignal, For, Match, Show, Switch } from "solid-js";
import { mapTenant, type TenantAction } from "../actions";
import { evidence } from "../api";
import { Busy, Err, Muted, Panel, plural } from "../ui";

type Tenant = {
  tenant_id: string; name: string; domain: string | null; state: "unmapped" | "suggested" | "confirmed" | "not_client"; org_id: number | null; client: string | null;
  mapped_by: string | null; mapped_at: string | null; suggested_org_id: number | null; suggested_client: string | null; suggested_by: "domain" | "name" | null;
  vm_licensed: boolean; open_detections: number; assets: number; assets_matched: number;
};
type State = Tenant["state"] | "all";
const LABEL: Record<State, string> = { all: "tenants", unmapped: "unmapped", suggested: "suggested", confirmed: "confirmed", not_client: "not a client" };

export default function BlackpointTenants() {
  const [q, setQ] = useSearchParams<{ show?: State }>();
  const [d, { refetch }] = createResource(() => evidence<Tenant[]>("blackpoint.tenants"));
  const [msg, setMsg] = createSignal<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = createSignal<string | null>(null);
  const show = () => q.show ?? "all";
  const rows = createMemo(() => (d()?.data ?? []).filter((t) => show() === "all" || t.state === show()));
  const clients = () => ((d() as any)?.clients ?? []) as { org_id: number; name: string }[];
  const count = (s: State) => (s === "all" ? d()?.totals?.tenants : d()?.totals?.[s]) ?? 0;

  async function act(t: Tenant, action: TenantAction, org?: number) {
    setBusy(t.tenant_id); setMsg(null);
    const a = await mapTenant(t.tenant_id, action, org);
    setBusy(null);
    if (a.error) { setMsg({ ok: false, text: `${t.name}: ${a.error}` }); return; }
    const who = action === "confirm" ? `is ${clients().find((c) => c.org_id === org)?.name ?? "that client"} now; ${plural(a.data!.assets_matched, "asset")} across tenants tied to devices` : action === "not_client" ? "is marked as no client" : "is undecided again";
    setMsg({ ok: true, text: `${t.name} ${who}.` });
    refetch();
  }

  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li><A href="/detections">Detections</A></li><li aria-current="page">Blackpoint tenants</li></ol></nav>
    <Panel page title="Blackpoint tenants">
      <p class="muted">A tenant becomes a client only when someone here confirms it. Until then its detections show under the tenant, and its devices' findings aren't counted as anyone's.</p>
      <Show when={d()?.totals}><div class="toolbar" role="group" aria-label="Show">
        <For each={["all", "unmapped", "suggested", "confirmed", "not_client"] as State[]}>{(s) =>
          <button type="button" class={show() === s ? "" : "quiet"} aria-pressed={show() === s} onClick={() => setQ({ show: s === "all" ? undefined : s }, { replace: true })}>{count(s)} {LABEL[s]}</button>}</For>
      </div></Show>
      <div aria-live="polite"><Show when={msg()}>{(m) => <p class={`msg ${m().ok ? "ok" : "bad"}`}>{m().text}</p>}</Show></div>
      <Switch>
        <Match when={d.loading && !d.latest}><Busy text="Loading the tenants…" /></Match>
        <Match when={d()?.error}><Err text={d()!.error!} /></Match>
        <Match when={rows().length === 0}><p>{(d()?.data ?? []).length ? "No tenants match that." : "No Blackpoint tenants yet. They appear once the Blackpoint connector has run."}</p></Match>
        <Match when={rows().length}>
          <ul class="rows"><For each={rows()}>{(t) => {
            let pick!: HTMLSelectElement;
            return <li class="row tenant">
              <span class="grow">
                <strong>{t.name}</strong><Show when={t.domain}><Muted>{t.domain}</Muted></Show>
                <span class="muted">
                  <Switch>
                    <Match when={t.state === "confirmed"}>{t.client}, confirmed by {t.mapped_by}</Match>
                    <Match when={t.state === "not_client"}>Not a client, said {t.mapped_by}</Match>
                    <Match when={t.state === "suggested"}>Suggested: {t.suggested_client} (by {t.suggested_by === "domain" ? "its website's domain" : "its name"})</Match>
                    <Match when>No client suggested</Match>
                  </Switch>
                  {` · ${plural(t.assets, "asset")}, ${t.assets_matched} tied to devices · `}
                  <A href={`/detections?tenant=${encodeURIComponent(t.tenant_id)}`}>{plural(t.open_detections, "open detection")}</A>
                </span>
              </span>
              <span class="actions tight">
                <Show when={t.state === "suggested"}>
                  <button type="button" disabled={busy() === t.tenant_id} onClick={() => act(t, "confirm", t.suggested_org_id!)}>Confirm {t.suggested_client}</button>
                </Show>
                <Show when={t.state === "unmapped" || t.state === "suggested"}>
                  <label class="sr-only" for={`pick-${t.tenant_id}`}>Client for {t.name}</label>
                  <select id={`pick-${t.tenant_id}`} ref={pick}><option value="">Another client…</option>
                    <For each={clients()}>{(c) => <option value={c.org_id}>{c.name}</option>}</For></select>
                  <button type="button" class="quiet" disabled={busy() === t.tenant_id}
                    onClick={() => { const o = Number(pick.value); if (o) void act(t, "confirm", o); else setMsg({ ok: false, text: `Choose a client for ${t.name} first.` }); }}>Use this client</button>
                  <button type="button" class="quiet" disabled={busy() === t.tenant_id} onClick={() => act(t, "not_client")}>Not a client</button>
                </Show>
                <Show when={t.state === "confirmed" || t.state === "not_client"}>
                  <button type="button" class="quiet" disabled={busy() === t.tenant_id} onClick={() => act(t, "clear")}>Undo</button>
                </Show>
              </span>
            </li>;
          }}</For></ul>
        </Match>
      </Switch>
    </Panel>
  </>;
}
