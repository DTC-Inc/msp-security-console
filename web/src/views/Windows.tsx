// Windows itself: which Windows devices still need a Microsoft update, and which CVEs are open on the OS with the
// update (KB) that fixes each. Everywhere, for one client (?org=), or one device (?device=). Every count opens its rows:
// a state's count narrows the devices to it, a device's CVE count opens that device.
import { A, useSearchParams } from "@solidjs/router";
import { createEffect, createSignal, For, on, Show } from "solid-js";
import { evidence } from "../api";
import { cveHref, orgOf, windowsHref } from "../nav";
import { cvssRole, role } from "../theme";
import { Busy, Err, Muted, Panel, Tag, plural } from "../ui";
import { STATES, fixNote, kb, stateOf } from "../winproc";

type Device = { device_id: number; name: string; org_id: number; org_name: string | null; device_class: string; os_name: string | null; server: boolean; build: string | null;
  rev_source: string | null; state: string; needed_kb: string | null; needed_build: string | null; latest_kb: string | null; cve_count: number | null; exploited_count: number | null;
  critical_count: number | null; update_pending_kb: string | null; update_failed_kb: string | null; update_failed_at: string | null };
type Cve = { cve_id: string; title: string | null; severity: string | null; exploited: boolean; kev: boolean; cvss: number | null; devices: number; kbs: { kb: string; fixed_build: string; devices: number }[] };



export default function Windows() {
  const [search, setSearch] = useSearchParams<{ org?: string; name?: string; device?: string; state?: string; cve?: string }>();
  const org = () => orgOf(search.org);
  const device = () => orgOf(search.device);
  const state = () => (STATES.some((s) => s.id === search.state) ? search.state : undefined);
  const cve = () => (search.cve && /^CVE-\d{4}-\d+$/i.test(search.cve) ? search.cve.toUpperCase() : undefined);
  const scope = () => ({ ...(org() ? { org_id: org()! } : {}), ...(device() ? { device_id: device()! } : {}), ...(cve() ? { cve_id: cve()! } : {}) });
  const [devs, setDevs] = createSignal<Device[]>([]);
  const [totals, setTotals] = createSignal<Record<string, number> | null>(null);
  const [cves, setCves] = createSignal<Cve[]>([]);
  const [cveTotals, setCveTotals] = createSignal<Record<string, number> | null>(null);
  const [next, setNext] = createSignal<{ d: string | null; c: string | null }>({ d: null, c: null });
  const [err, setErr] = createSignal("");
  const [busy, setBusy] = createSignal(true);
  let ask = 0;
  const loadDevices = async (cursor?: string) => {
    const mine = ask;
    const a = await evidence<Device[]>("windows.devices", { ...scope(), ...(state() ? { state: state() } : {}), limit: 100, ...(cursor ? { cursor } : {}) });
    if (mine !== ask) return;
    if (a.error) { setErr(a.error); return; }
    setDevs((r) => (cursor ? [...r, ...(a.data ?? [])] : a.data ?? []));
    setTotals(a.totals ?? null);
    setNext((n) => ({ ...n, d: a.next_cursor ?? null }));
  };
  const loadCves = async (cursor?: string) => {
    const mine = ask;
    const a = await evidence<Cve[]>("windows.cves", { ...scope(), limit: 100, ...(cursor ? { cursor } : {}) });
    if (mine !== ask) return;
    if (a.error) { setErr(a.error); return; }
    setCves((r) => (cursor ? [...r, ...(a.data ?? [])] : a.data ?? []));
    setCveTotals(a.totals ?? null);
    setNext((n) => ({ ...n, c: a.next_cursor ?? null }));
  };
  createEffect(on([org, device, state, cve], async () => {
    ask++; setErr(""); setBusy(true); setDevs([]); setCves([]); setTotals(null); setCveTotals(null);
    await Promise.all([loadDevices(), loadCves()]);
    setBusy(false);
  }));
  const where = () => (device() ? devs()[0]?.name ?? `Device ${device()}` : search.name || (org() ? `Client ${org()}` : "Every client")) + (cve() ? `, ${cve()} open` : "");
  const narrow = (s?: string) => windowsHref({ org: org() ?? undefined, name: search.name, device: device() ?? undefined, state: s, cve: cve() });

  return <>
    <nav aria-label="Where you are"><ol class="crumbs">
      <li><A href="/">Search</A></li>
      <li><A href={windowsHref()}>Windows updates</A></li>
      <Show when={org() || device() || cve()}><li aria-current="page">{where()}</li></Show>
    </ol></nav>
    <Show when={err()}><Err text={err()} /></Show>
    <Show when={busy() && !devs().length}><Busy text="Loading Windows devices…" /></Show>

    <Panel page title={`Windows updates: ${where()}`} right={<Show when={totals()}><Muted>{plural(totals()!.devices ?? 0, "Windows device")}</Muted></Show>}>
      <p class="muted">From Microsoft's monthly security updates and each device's updates in NinjaOne. A device whose patch level can't be read is never counted as up to date.</p>
      <Show when={totals()}>
        <ul class="chips" aria-label="Devices by state" style={{ "list-style": "none", padding: "0", margin: "8px 0" }}>
          <For each={STATES}>{(s) => <li>
            <A href={narrow(state() === s.id ? undefined : s.id)} class="chip" aria-current={state() === s.id ? "true" : undefined} title={s.says}>
              {s.label}: {totals()![s.id] ?? 0}
            </A>
          </li>}</For>
        </ul>
      </Show>
      <Show when={!busy() && !err() && devs().length === 0}>
        <p>{state() ? `No Windows device here is “${stateOf(state()!).label}”.` : "No Windows devices here yet. They appear once NinjaOne's devices and Microsoft's updates have been read."}</p>
      </Show>
      <ul class="rows"><For each={devs()}>{(d) => <li class="row">
        <span class="grow">
          <A href={windowsHref({ device: d.device_id })}>{d.name}</A>
          <Show when={!org() && !device()}><Muted> · <A href={windowsHref({ org: d.org_id, name: d.org_name ?? undefined })}>{d.org_name ?? `Client ${d.org_id}`}</A></Muted></Show>
          <div class="muted">{d.os_name ?? "Windows"}{d.build ? ` · build ${d.build}` : ""}{d.rev_source === "updates" ? " (from its installed updates)" : ""}</div>
          <Show when={d.state === "vulnerable" && d.needed_kb}><div class="muted">Needs {kb(d.needed_kb!)} ({d.needed_build}){fixNote(d) ? ` · ${fixNote(d)}` : ""}</div></Show>
          <Show when={d.state !== "vulnerable" && fixNote(d)}><div class="muted">{fixNote(d)}</div></Show>
        </span>
        <Tag text={stateOf(d.state).label} fill={stateOf(d.state).fill} />
        <span class="num"><Show when={d.cve_count} fallback={<Muted>—</Muted>}>
          <A href={windowsHref({ device: d.device_id })} aria-label={`${plural(d.cve_count!, "open CVE")} on ${d.name}`}>{plural(d.cve_count!, "CVE")}</A>
        </Show></span>
      </li>}</For></ul>
      <Show when={next().d}><div class="actions"><button type="button" onClick={() => loadDevices(next().d!)}>More devices</button></div></Show>
    </Panel>

    <Panel title="Open Windows CVEs" right={<Show when={cveTotals()}><Muted>{`${plural(cveTotals()!.cves ?? 0, "CVE")} on ${plural(cveTotals()!.devices ?? 0, "device")} · exploited first`}</Muted></Show>}>
      <Show when={!busy() && !err() && cves().length === 0}><p>No open Windows CVEs here: every device Microsoft's data covers has the updates it needs, or its patch level can't be read (see above).</p></Show>
      <ul class="rows"><For each={cves()}>{(c) => <li class="row">
        <span class="grow">
          <A class="mono" href={cveHref(c.cve_id, org() ?? undefined, search.name)}>{c.cve_id}</A>
          <Show when={c.exploited}><Tag text="exploited" fill="x-kev-fill" /></Show>
          <Show when={c.kev}><Tag text="KEV" fill="x-ransomware-fill" /></Show>
          <Show when={c.title}><div class="muted">{c.title}</div></Show>
          <div class="muted">Fixed by {c.kbs.map((k) => `${kb(k.kb)} (${k.fixed_build}${c.kbs.length > 1 ? `, ${plural(k.devices, "device")}` : ""})`).join(", ")}</div>
        </span>
        <span class="num"><Show when={c.devices > 0} fallback={plural(c.devices, "device")}>
          <A href={windowsHref({ org: org() ?? undefined, name: search.name, device: device() ?? undefined, cve: c.cve_id })} aria-label={`The ${plural(c.devices, "device")} with ${c.cve_id} open`}>{plural(c.devices, "device")}</A>
        </Show></span>
        <span class="score" style={{ color: role(cvssRole(c.cvss)) }} title="CVSS score">{c.cvss ?? (c.severity ?? "—")}</span>
      </li>}</For></ul>
      <Show when={next().c}><div class="actions"><button type="button" onClick={() => loadCves(next().c!)}>More CVEs</button></div></Show>
    </Panel>
    <Show when={state()}><p><button type="button" class="link" onClick={() => setSearch({ state: undefined })}>Show every state</button></p></Show>
  </>;
}
