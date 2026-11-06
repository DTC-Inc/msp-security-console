// One device: what each source saw on it, its vulnerable software, its CVEs worst first, and its whole installed
// software list from NinjaOne (device.get, .products, .cves, .software).
import { A, useParams } from "@solidjs/router";
import { createResource, Match, Show, Switch } from "solid-js";
import { evidence } from "../api";
import { productHref, versionParam } from "../drill";
import { clientHref, cveHref } from "../nav";
import { SRC } from "../theme";
import { SOURCES } from "./sources";
import { Busy, Err, Muted, Panel } from "../ui";
import { Count, Crumbs, KevTag, PagedFoot, Sources, Table, Tile, Tiles, Worst, num, usePaged } from "./parts";

type DeviceData = { device_id: number; device_name: string; org_id: number; org_name: string | null; device_class: string; role: string | null; os_name: string | null;
  last_contact: string | null; cves: number; kev_cves: number; max_cvss: number | null; software: number; products: number;
  by_source: Record<string, { products: number; cves: number; kev: number }> };
type Prod = { product_key: string; label: string; version: string; sources: string[]; cves: number; kev: boolean; max_cvss: number | null };
type Cve = { cve_id: string; sources: string[]; kev: boolean; exploited: boolean; cvss: number | null };
type Soft = { name: string; publisher: string; version: string; product_key: string | null; product_label: string | null };

export default function Device() {
  const params = useParams<{ id: string }>();
  const id = () => { const n = Number(params.id); return Number.isInteger(n) && n > 0 ? n : null; };
  const [d] = createResource(() => id() ?? false, (i) => evidence<DeviceData>("device.get", { device_id: i }));
  const [prods] = createResource(() => id() ?? false, (i) => evidence<Prod[]>("device.products", { device_id: i }));
  const [soft] = createResource(() => id() ?? false, (i) => evidence<Soft[]>("device.software", { device_id: i }));
  const cves = usePaged<Cve>(() => "device.cves", () => (id() ? { device_id: id()! } : false));
  return <Switch>
    <Match when={!id()}><Err text="That isn't a device's address." /></Match>
    <Match when={d.loading}><Busy text="Loading the device…" /></Match>
    <Match when={d()?.error}><Err text={d()!.error!} /></Match>
    <Match when={d()?.data}>{(x) => <>
      <Crumbs trail={[["Clients", "/clients"], [x().org_name ?? `Client ${x().org_id}`, clientHref(x().org_id, x().org_name ?? undefined)], [x().device_name]]} />
      <Panel page title={x().device_name} right={<Muted>{[x().device_class, x().role, x().os_name].filter(Boolean).join(" · ")}</Muted>}>
        <Tiles>
          <Tile k="CVEs"><Count n={x().cves} of="cves" f={{ device_id: x().device_id }} label={`${x().device_name} › CVEs`} /></Tile>
          <Tile k="Actively exploited"><Count n={x().kev_cves} of="cves" f={{ device_id: x().device_id, kev: true }} label={`${x().device_name} › actively exploited CVEs`} /></Tile>
          <Tile k="Worst"><Worst cvss={x().max_cvss} f={{ device_id: x().device_id }} label={x().device_name} /></Tile>
          <Tile k="Products seen"><a href="#products">{num(x().products)}</a></Tile>
          <Tile k="Installed software"><a href="#software">{num(x().software)}</a></Tile>
        </Tiles>
        <Table caption="What each source saw on this device" rows={SOURCES.filter((s) => x().by_source[s]).map((s) => [s, x().by_source[s]] as const)} cols={[
          { label: "Source", cell: ([s]) => <span>{SRC[s]?.label ?? s}</span> },
          { label: "Products", num: true, cell: ([, b]) => <Show when={b.products} fallback={<span>{num(b.products)}</span>}><a href="#products" title="This device's products, below">{num(b.products)}</a></Show> },
          { label: "CVEs", num: true, cell: ([s, b]) => <Count n={b.cves} of="cves" f={{ device_id: x().device_id, source: [s] }} label={`${x().device_name} › CVEs from ${SRC[s]?.label ?? s}`} /> },
          { label: "Exploited", num: true, cell: ([s, b]) => <Count n={b.kev} of="cves" f={{ device_id: x().device_id, source: [s], kev: true }} label={`${x().device_name} › exploited CVEs from ${SRC[s]?.label ?? s}`} /> },
        ]} />
      </Panel>
      <Panel title="Software with CVEs, and what else was seen">
        <span id="products" />
        <Show when={prods()?.data} fallback={<Show when={prods()?.error} fallback={<Busy />}><Err text={prods()!.error!} /></Show>}>{(ps) =>
          <Show when={ps().length} fallback={<p>No source has named a product on this device yet.</p>}>
            <Table caption="Products on this device" rows={ps()} cols={[
              { label: "Product", cell: (p) => <A href={productHref(p.product_key, p.version)}><strong>{p.label}</strong> <span class="mono">{p.version}</span></A> },
              { label: "Sources", cell: (p) => <Sources sources={p.sources} /> },
              { label: "CVEs", num: true, cell: (p) => <Count n={p.cves} of="cves" f={{ device_id: x().device_id, product_key: p.product_key, version: versionParam(p.version) }} label={`${x().device_name} › ${p.label} ${p.version} CVEs`} /> },
              { label: "", cell: (p) => <KevTag on={p.kev} /> },
            ]} />
          </Show>}
        </Show>
      </Panel>
      <Panel title="CVEs" right={<Muted>worst first</Muted>}>
        <Table caption="This device's CVEs" rows={cves.rows()} cols={[
          { label: "CVE", cell: (c) => <span><A class="mono" href={cveHref(c.cve_id)}>{c.cve_id}</A> <KevTag on={c.kev} /></span> },
          { label: "Sources", cell: (c) => <Sources sources={c.sources} /> },
          { label: "CVSS", num: true, cell: (c) => <span>{c.cvss ?? "—"}</span> },
        ]} />
        <PagedFoot list={cves} empty="No CVEs on this device." loading="Loading its CVEs…" />
      </Panel>
      <Panel title="Installed software">
        <span id="software" />
        <Show when={soft()?.data} fallback={<Show when={soft()?.error} fallback={<Busy />}><Err text={soft()!.error!} /></Show>}>{(s) =>
          <Show when={s().length} fallback={<p>NinjaOne hasn't given a software inventory for this device yet.</p>}>
            <Table caption="Installed software, recognised products first" rows={s()} cols={[
              { label: "Name", cell: (r) => <span>{r.name}</span> },
              { label: "Version", cell: (r) => <span class="mono">{r.version || "—"}</span> },
              { label: "Publisher", cell: (r) => <span class="muted">{r.publisher || "—"}</span> },
              { label: "Recognised as", cell: (r) => r.product_key ? <A href={productHref(r.product_key)}>{r.product_label ?? r.product_key}</A> : <span class="muted">not a product the console tracks</span> },
            ]} />
          </Show>}
        </Show>
      </Panel>
    </>}</Match>
  </Switch>;
}
