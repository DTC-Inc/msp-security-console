// One client (client.get): its devices, what each source saw there, its worst CVEs, every device worst first and every
// product with a vulnerable version, each count opening the rows behind it.
import { A, useParams, useSearchParams } from "@solidjs/router";
import { createResource, For, Match, Show, Switch } from "solid-js";
import { evidence } from "../api";
import { deviceHref, productHref } from "../drill";
import { cveHref, orgOf } from "../nav";
import { SRC } from "../theme";
import { SOURCES } from "./sources";
import { Busy, Err, Muted, Panel } from "../ui";
import { Count, CountTo, Crumbs, KevTag, Sources, Table, Tile, Tiles, Worst, num } from "./parts";

type BySource = Record<string, { devices_seen: number; devices_with_cves: number; cves: number; kev_devices: number }>;
type DevRow = { device_id: number; device_name: string; device_class: string; role: string | null; os_name: string | null; cves: number; kev_cves: number; max_cvss: number | null;
  vulnerable_products: number; software: number; sources: string[] };
type ProdRow = { product_key: string; label: string; devices: number; kev_devices: number; max_cvss: number | null; versions: string[] };
type ClientData = { org_id: number; org_name: string | null; devices: number; devices_with_cves: number; cves: number; inventoried: number; by_source: BySource;
  worst: { cve_id: string; sources: string[]; kev: boolean; exploited: boolean; cvss: number | null; devices: number }[]; device_rows: DevRow[]; products: ProdRow[] };

export default function Client() {
  const params = useParams<{ org: string }>();
  const [sp] = useSearchParams<{ name?: string }>();
  const org = () => orgOf(params.org);
  const [d] = createResource(() => org() ?? false, (o) => evidence<ClientData>("client.get", { org_id: o }));
  const name = () => d()?.data?.org_name ?? sp.name ?? `Client ${params.org}`;
  return <>
    <Crumbs trail={[["Clients", "/clients"], [name()]]} />
    <Switch>
      <Match when={!org()}><Err text="That isn't a client's address. Find the client on the Clients tab instead." /></Match>
      <Match when={d.loading}><Busy text="Loading the client…" /></Match>
      <Match when={d()?.error}><Err text={d()!.error!} /></Match>
      <Match when={d()?.data}>{(c) => { const o = () => c().org_id; return <>
        <Panel page title={name()} right={<A href={`/clients/${o()}/cves?name=${encodeURIComponent(name())}`}>All its CVEs</A>}>
          <Tiles>
            <Tile k="Devices"><Count n={c().devices} of="coverage" f={{ org_id: o() }} label={`${name()} › every device`} /></Tile>
            <Tile k="With CVEs"><Count n={c().devices_with_cves} of="devices" f={{ org_id: o() }} label={`${name()} › devices with CVEs`} /></Tile>
            <Tile k="CVEs"><Count n={c().cves} of="cves" f={{ org_id: o() }} label={`${name()} › CVEs`} /></Tile>
            <Tile k="Software inventory"><Count n={c().inventoried} of="coverage" f={{ org_id: o(), has: "software" }} label={`${name()} › devices with a software inventory`} /></Tile>
          </Tiles>
        </Panel>
        <Panel title="What each source saw">
          <Table caption="Each source at this client" rows={SOURCES.filter((s) => c().by_source[s]).map((s) => [s, c().by_source[s]] as const)} cols={[
            { label: "Source", cell: ([s]) => <span>{SRC[s]?.label ?? s}</span> },
            { label: "Devices seen", num: true, cell: ([s, b]) => <Count n={b.devices_seen} of="coverage" f={{ org_id: o(), source: [s], seen: true }} label={`${name()} › devices ${SRC[s]?.label ?? s} saw`} /> },
            { label: "With CVEs", num: true, cell: ([s, b]) => <Count n={b.devices_with_cves} of="devices" f={{ org_id: o(), source: [s] }} label={`${name()} › devices with CVEs from ${SRC[s]?.label ?? s}`} /> },
            { label: "CVEs", num: true, cell: ([s, b]) => <Count n={b.cves} of="cves" f={{ org_id: o(), source: [s] }} label={`${name()} › CVEs from ${SRC[s]?.label ?? s}`} /> },
            { label: "Exploited", num: true, cell: ([s, b]) => <Count n={b.kev_devices} of="devices" f={{ org_id: o(), source: [s], kev: true }} label={`${name()} › devices with exploited CVEs from ${SRC[s]?.label ?? s}`} /> },
          ]} />
        </Panel>
        <Show when={c().worst.length}>
          <Panel title="Worst CVEs">
            <Table caption="The client's worst CVEs" rows={c().worst} cols={[
              { label: "CVE", cell: (w) => <span><A class="mono" href={cveHref(w.cve_id, o(), name())}>{w.cve_id}</A> <KevTag on={w.kev} /></span> },
              { label: "Sources", cell: (w) => <Sources sources={w.sources} /> },
              { label: "Devices", num: true, cell: (w) => <Count n={w.devices} of="devices" f={{ org_id: o(), cve_id: w.cve_id }} label={`${name()} › devices with ${w.cve_id}`} /> },
              { label: "CVSS", num: true, cell: (w) => <span>{w.cvss ?? "—"}</span> },
            ]} />
          </Panel>
        </Show>
        <Panel title="Devices" right={<Muted>worst first</Muted>}>
          <Show when={c().device_rows.length} fallback={<p>No devices at this client yet.</p>}>
            <Table caption="The client's devices" rows={c().device_rows} cols={[
              { label: "Device", cell: (r) => <span><A href={deviceHref(r.device_id)}><strong>{r.device_name}</strong></A><div class="muted">{r.device_class}{r.os_name ? ` · ${r.os_name}` : ""}</div></span> },
              { label: "CVEs", num: true, cell: (r) => <Count n={r.cves} of="cves" f={{ device_id: r.device_id }} label={`${r.device_name} › CVEs`} /> },
              { label: "Exploited", num: true, cell: (r) => <Count n={r.kev_cves} of="cves" f={{ device_id: r.device_id, kev: true }} label={`${r.device_name} › actively exploited CVEs`} style={{ color: r.kev_cves ? "var(--dtc-bad)" : undefined, "font-weight": "700" }} /> },
              { label: "Worst", num: true, cell: (r) => <Worst cvss={r.max_cvss} f={{ device_id: r.device_id }} label={r.device_name} /> },
              { label: "Vulnerable products", num: true, cell: (r) => <CountTo n={r.vulnerable_products} href={deviceHref(r.device_id)} label={`${r.device_name}: its vulnerable software, on its page`} /> },
              { label: "Software", num: true, cell: (r) => <CountTo n={r.software} href={`${deviceHref(r.device_id)}#software`} label={`${r.device_name}: its installed software, on its page`} /> },
              { label: "Seen by", cell: (r) => <Sources sources={r.sources} /> },
            ]} />
          </Show>
        </Panel>
        <Show when={c().products.length}>
          <Panel title="Vulnerable software here">
            <Table caption="Products with a vulnerable version at this client" rows={c().products} cols={[
              { label: "Product", cell: (p) => <A href={productHref(p.product_key)}><strong>{p.label}</strong></A> },
              { label: "Devices", num: true, cell: (p) => <Count n={p.devices} of="devices" f={{ org_id: o(), product_key: p.product_key }} label={`${name()} › devices with vulnerable ${p.label}`} /> },
              { label: "Exploited", num: true, cell: (p) => <Count n={p.kev_devices} of="devices" f={{ org_id: o(), product_key: p.product_key, kev: true }} label={`${name()} › devices with actively exploited ${p.label}`} /> },
              { label: "Worst", num: true, cell: (p) => <Worst cvss={p.max_cvss} f={{ org_id: o(), product_key: p.product_key }} label={`${name()} › ${p.label}`} /> },
              { label: "Versions", cell: (p) => <span class="mono"><For each={p.versions.slice(0, 6)}>{(v, i) => <>{i() > 0 && ", "}<A href={productHref(p.product_key, v)}>{v || "none"}</A></>}</For>{p.versions.length > 6 ? " …" : ""}</span> },
            ]} />
          </Panel>
        </Show>
        <p class="muted">{num(c().devices)} devices; counts from every source the console reads.</p>
      </>; }}</Match>
    </Switch>
  </>;
}
