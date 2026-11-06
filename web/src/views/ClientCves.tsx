// One client's CVEs (cves.list by org_id), worst first: exploited and KEV, then the score. "Only KEV" asks the server
// for the CISA KEV ones alone; "Load more" follows its cursor. A CVE opens within the client, so its counts are the
// client's.
import { A, useParams, useSearchParams } from "@solidjs/router";
import { createEffect, createSignal, For, on, Show } from "solid-js";
import { evidence } from "../api";
import { cveHref, orgOf } from "../nav";
import { cvssRole, role } from "../theme";
import { Busy, Err, Muted, Panel, SourceChips, Tag, plural } from "../ui";
import { Count } from "./parts";

type Row = { cve_id: string; sources: string[]; devices: number; running_devices: number; kev: boolean; exploited: boolean; cvss: number | null };

export default function ClientCves() {
  const params = useParams<{ org: string }>();
  const [search, setSearch] = useSearchParams<{ name?: string; kev?: string }>();
  const org = () => orgOf(params.org);
  const name = () => search.name || `Client ${params.org}`;
  const kev = () => search.kev === "1";
  const [rows, setRows] = createSignal<Row[]>([]);
  const [next, setNext] = createSignal<string | null>(null);
  const [total, setTotal] = createSignal<number | null>(null);
  const [err, setErr] = createSignal("");
  const [busy, setBusy] = createSignal(true);
  let ask = 0;
  const load = async (cursor?: string) => {
    const o = org(); if (!o) return;
    const mine = ++ask;
    setBusy(true); setErr("");
    const a = await evidence<Row[]>("cves.list", { org_id: o, limit: 100, ...(kev() ? { kev: true } : {}), ...(cursor ? { cursor } : {}) });
    if (mine !== ask) return; // a newer question (another client, the filter changed) has the floor
    setBusy(false);
    if (a.error) { setErr(a.error); return; }
    setRows((r) => (cursor ? [...r, ...(a.data ?? [])] : a.data ?? []));
    setNext(a.next_cursor ?? null);
    setTotal(a.totals?.cves ?? null);
  };
  createEffect(on([org, kev], () => { setRows([]); setNext(null); setTotal(null); void load(); }));

  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li aria-current="page">{name()}</li></ol></nav>
    <Show when={org()} fallback={<Err text="That isn't a client's address. Search for the client instead." />}>
      <Panel page title={`${name()}: CVEs`} right={<Show when={total() != null}><Muted>{`${plural(total()!, "CVE")}${kev() ? " in CISA KEV" : ""} · worst first`}</Muted></Show>}>
        <div class="toolbar">
          <label class="check"><input type="checkbox" checked={kev()} onChange={(e) => setSearch({ kev: e.currentTarget.checked ? "1" : undefined }, { replace: true })} />
            Only known exploited (CISA KEV)</label>
        </div>
        <Show when={err()}><Err text={err()} /></Show>
        <Show when={!busy() && !err() && rows().length === 0}>
          <p>{kev() ? "None of this client's CVEs are in CISA's known-exploited list." : "No CVEs on this client's devices."}</p>
        </Show>
        <ul class="rows"><For each={rows()}>{(c) => <li class="row">
          <span class="grow">
            <A class="mono" href={cveHref(c.cve_id, org()!, search.name)}>{c.cve_id}</A>
            <Show when={c.exploited}><Tag text="exploited" fill="x-kev-fill" /></Show>
            <Show when={c.kev}><Tag text="KEV" fill="x-ransomware-fill" /></Show>
          </span>
          <SourceChips sources={c.sources} />
          <span class="num"><Count n={c.devices} of="devices" f={{ org_id: org()!, cve_id: c.cve_id }} label={`${search.name ?? `Client ${org()}`} › devices with ${c.cve_id}`}>{plural(c.devices, "device")}</Count></span>
          <span class="score" style={{ color: role(cvssRole(c.cvss)) }} title="CVSS score">{c.cvss ?? "—"}</span>
        </li>}</For></ul>
        <Show when={busy()} fallback={<Show when={next()}><div class="actions"><button type="button" onClick={() => load(next()!)}>Load more</button></div></Show>}>
          <Busy text={rows().length ? "Loading more…" : "Loading this client's CVEs…"} />
        </Show>
      </Panel>
    </Show>
  </>;
}
