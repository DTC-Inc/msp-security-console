// Running processes, from the endpoint script's NinjaOne field: every binary running, one row each, worst first (a
// broken or missing signature, then those with CVEs, then the rarest), with what product and version it is and how
// sure the console is. Search by SHA-256 or text; a hash, or one device, lists where it runs and from which paths.
import { A, useSearchParams } from "@solidjs/router";
import { createEffect, createSignal, For, on, Show } from "solid-js";
import { evidence } from "../api";
import { orgOf, processesHref } from "../nav";
import { rowsHref, versionParam } from "../drill";
import { cvssRole, role } from "../theme";
import { Busy, Err, Muted, Panel, Tag, plural } from "../ui";
import { TRUST, known } from "../winproc";

type Place = { device_id: number; device_name: string; org_id: number; org_name: string | null; paths: string[]; file_version: string | null; instance_count: number };
type Binary = { key: string; sha256: string | null; name: string; product: string | null; company: string | null; file_version: string | null; signer: string | null; trust: string;
  devices: number; clients: number; fleet_devices: number; product_key: string | null; product_label: string | null; product_version: string | null; method: string | null;
  confidence: number | null; cve_count: number | null; kev_count: number | null; max_cvss: number | null; device_list?: Place[] };


export default function Processes() {
  const [search, setSearch] = useSearchParams<{ q?: string; org?: string; device?: string; trust?: string }>();
  const [q, setQ] = createSignal(search.q ?? "");
  const org = () => orgOf(search.org), device = () => orgOf(search.device);
  const trust = () => (search.trust && TRUST[search.trust] ? search.trust : undefined);
  const [rows, setRows] = createSignal<Binary[]>([]);
  const [totals, setTotals] = createSignal<Record<string, number> | null>(null);
  const [next, setNext] = createSignal<string | null>(null);
  const [err, setErr] = createSignal("");
  const [busy, setBusy] = createSignal(true);
  let ask = 0;
  const load = async (cursor?: string) => {
    const mine = ++ask;
    setBusy(true); setErr("");
    const a = await evidence<Binary[]>("processes.list", { ...(search.q ? { q: search.q } : {}), ...(org() ? { org_id: org()! } : {}), ...(device() ? { device_id: device()! } : {}),
      ...(trust() ? { state: trust() } : {}), limit: 100, ...(cursor ? { cursor } : {}) });
    if (mine !== ask) return;
    setBusy(false);
    if (a.error) { setErr(a.error); return; }
    setRows((r) => (cursor ? [...r, ...(a.data ?? [])] : a.data ?? []));
    setTotals(a.totals ?? null);
    setNext(a.next_cursor ?? null);
  };
  createEffect(on([() => search.q, org, device, trust], () => { setRows([]); void load(); }));
  const submit = (e: Event) => { e.preventDefault(); setSearch({ q: q().trim() || undefined }); };

  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li aria-current="page">Running processes</li></ol></nav>
    <Panel page title="Running processes" right={<A href="/processes/review">Names to review</A>}>
      <form class="search" role="search" onSubmit={submit}>
        <label for="pq" class="sr-only">A SHA-256, or part of a binary's name, product, company or signer</label>
        <input id="pq" type="search" value={q()} onInput={(e) => setQ(e.currentTarget.value)} placeholder="A SHA-256, or a name, product, company or signer" autocomplete="off" />
        <button type="submit">Search</button>
      </form>
      <div class="toolbar">
        <label class="check" for="ptrust">Signature</label>
        <select id="ptrust" value={trust() ?? ""} onChange={(e) => setSearch({ trust: e.currentTarget.value || undefined })}>
          <option value="">Any</option>
          <For each={Object.entries(TRUST)}>{([k, t]) => <option value={k}>{t.label}</option>}</For>
        </select>
        <Show when={totals()}>{(t) => <Muted>{`${plural(t().binaries ?? 0, "binary", "binaries")} · ${plural(t().devices_reporting ?? 0, "device")} reporting`
          + `${t().devices_not_reporting ? ` · ${plural(t().devices_not_reporting, "device")} not reporting for 3 days` : ""}${t().devices_failing ? ` · ${plural(t().devices_failing, "device")} whose last report couldn't be read` : ""}`}</Muted>}</Show>
      </div>
      <Show when={err()}><Err text={err()} /></Show>
      <Show when={!busy() && !err() && rows().length === 0}>
        <p>{search.q || trust() ? "Nothing running matches." : "No running processes yet. They come from the endpoint script (endpoint/README.md says how to deploy it), read from NinjaOne every 30 minutes."}</p>
      </Show>
      <ul class="rows"><For each={rows()}>{(b) => <li class="row">
        <span class="grow">
          <Show when={b.sha256} fallback={<strong>{b.name}</strong>}><A href={processesHref({ q: b.sha256! })}><strong>{b.name}</strong></A></Show>
          <Tag text={(TRUST[b.trust] ?? TRUST.unchecked).label} fill={(TRUST[b.trust] ?? TRUST.unchecked).fill} />
          <div class="muted">{[b.product, b.company, b.file_version].filter(Boolean).join(" · ") || "No product details"}</div>
          <div class="muted">{known(b)}</div>
          <Show when={b.sha256}><div class="muted mono" style={{ "overflow-wrap": "anywhere" }}>{b.sha256}</div></Show>
          <Show when={b.device_list}>
            <ul class="rows"><For each={b.device_list}>{(p) => <li class="row">
              <span class="grow"><A href={processesHref({ device: p.device_id })}>{p.device_name}</A><Muted> · {p.org_name ?? `Client ${p.org_id}`}</Muted>
                <For each={p.paths}>{(path) => <div class="muted mono" style={{ "overflow-wrap": "anywhere" }}>{path}</div>}</For></span>
            </li>}</For></ul>
          </Show>
        </span>
        <span class="num"><Show when={b.sha256 && !b.device_list} fallback={plural(b.devices, "device")}>
          <A href={processesHref({ q: b.sha256! })} aria-label={`The ${plural(b.devices, "device")} running ${b.name}`}>{plural(b.devices, "device")}</A></Show><Show when={b.fleet_devices <= 3}><div class="muted">rare</div></Show></span>
        <span class="num"><Show when={b.cve_count != null} fallback={<Muted>not checked</Muted>}>
          <Show when={b.cve_count} fallback={<Muted>no CVEs</Muted>}>
            <A href={rowsHref("version-cves", { product_key: b.product_key, version: versionParam(b.product_version ?? "") }, `${b.product_label ?? b.name} ${b.product_version ?? ""} › CVEs`)}
              style={{ color: role(cvssRole(b.max_cvss)) }}>{plural(b.cve_count!, "CVE")}</A>
            <Show when={b.kev_count}><div><A href={rowsHref("version-cves", { product_key: b.product_key, version: versionParam(b.product_version ?? ""), kev: true }, `${b.product_label ?? b.name} ${b.product_version ?? ""} › actively exploited CVEs`)}>
              <Tag text={`${b.kev_count} KEV`} fill="x-ransomware-fill" /></A></div></Show></Show>
        </Show></span>
      </li>}</For></ul>
      <Show when={busy()} fallback={<Show when={next()}><div class="actions"><button type="button" onClick={() => load(next()!)}>Load more</button></div></Show>}>
        <Busy text={rows().length ? "Loading more…" : "Loading running processes…"} />
      </Show>
    </Panel>
  </>;
}
