// One product (product.get, .versions, .devices): where it's installed, which versions, and which devices carry its
// CVEs, optionally at one version.
import { A, useParams, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, For, Match, Show, Switch } from "solid-js";
import { evidence } from "../api";
import { deviceHref, productHref, versionParam } from "../drill";
import { clientHref } from "../nav";
import { Busy, Err, Muted, Panel } from "../ui";
import { Count, Crumbs, KevTag, PagedFoot, Sources, Table, Tile, Tiles, num, usePaged } from "./parts";

type P = { product_key: string; label: string; cpe: string | null; versions: number; devices: number; vulnerable_devices: number; cves: number; clients: number; known_cves: number; known_kev: number };
type V = { version: string; sources: string[]; devices: number; running_devices: number; cves: number; kev: boolean; cvss: number | null };
type D = { device_id: number; device_name: string; org_id: number; org_name: string | null; versions: string[]; sources: string[]; cves: number; kev: boolean };

export default function Product() {
  const params = useParams<{ key: string }>();
  const [sp] = useSearchParams<{ version?: string }>();
  const key = () => decodeURIComponent(params.key);
  const f = createMemo(() => ({ product_key: key(), ...(sp.version != null ? { version: versionParam(sp.version) } : {}) }));
  const [d] = createResource(f, (x) => evidence<P>("product.get", x));
  const [vs] = createResource(() => ({ product_key: key() }), (x) => evidence<V[]>("product.versions", x));
  const devs = usePaged<D>(() => "product.devices", () => f());
  const label = () => d()?.data?.label ?? key();
  return <>
    <Crumbs trail={[["Software", "/software"], ...(sp.version != null ? [[label(), productHref(key())] as [string, string], [sp.version || "no version"] as [string]] : [[label()] as [string]])]} />
    <Switch>
      <Match when={d.loading}><Busy text="Loading the product…" /></Match>
      <Match when={d()?.error}><Err text={d()!.error!} /></Match>
      <Match when={d()?.data}>{(p) => <>
        <Panel page title={`${p().label}${sp.version != null ? ` ${sp.version}` : ""}`} right={<Muted>{p().cpe ?? ""}</Muted>}>
          <Tiles>
            <Tile k="Installed on"><Count n={p().devices} of="devices" f={{ ...f(), has: "product" }} label={`${p().label} › installed on`} /></Tile>
            <Tile k="Vulnerable devices"><Count n={p().vulnerable_devices} of="devices" f={f()} label={`${p().label} › devices on a vulnerable version`} /></Tile>
            <Tile k="CVEs on devices"><Count n={p().cves} of="cves" f={f()} label={`${p().label} › CVEs`} /></Tile>
            <Tile k="Clients"><Count n={p().clients} of="clients" f={f()} label={`${p().label} › clients with a vulnerable version`} /></Tile>
            <Tile k="In NVD" sub="its whole catalogue, on any device or none">{num(p().known_cves)}</Tile>
          </Tiles>
        </Panel>
        <Panel title="Versions">
          <Show when={vs()?.data} fallback={<Busy />}>{(rows) => <Table caption="Its versions" rows={rows()} cols={[
            { label: "Version", cell: (v) => <A class="mono" href={productHref(key(), versionParam(v.version))}>{v.version || "none"}</A> },
            { label: "Sources", cell: (v) => <Sources sources={v.sources} /> },
            { label: "Devices", num: true, cell: (v) => <Count n={v.devices} of="devices" f={{ product_key: key(), version: versionParam(v.version), has: "product" }} label={`${p().label} ${v.version} › installed on`} /> },
            { label: "Running on", num: true, cell: (v) => <Count n={v.running_devices} of="devices" f={{ product_key: key(), version: versionParam(v.version), has: "product", source: ["process"] }} label={`${p().label} ${v.version} › running on`} /> },
            { label: "CVEs", num: true, cell: (v) => <span><Count n={v.cves} of="cves" f={{ product_key: key(), version: versionParam(v.version) }} label={`${p().label} ${v.version} › CVEs`} /> <KevTag on={v.kev} /></span> },
            { label: "Worst", num: true, cell: (v) => <span>{v.cvss ?? "—"}</span> },
          ]} />}</Show>
        </Panel>
        <Panel title="Devices" right={<Muted>exploited first</Muted>}>
          <Table caption="Devices with it" rows={devs.rows()} cols={[
            { label: "Device", cell: (x) => <A href={deviceHref(x.device_id)}><strong>{x.device_name}</strong></A> },
            { label: "Client", cell: (x) => <A href={clientHref(x.org_id, x.org_name ?? undefined)}>{x.org_name ?? x.org_id}</A> },
            { label: "Versions", cell: (x) => <span class="mono"><For each={x.versions}>{(v, i) => <>{i() > 0 && ", "}{v || "none"}</>}</For></span> },
            { label: "Sources", cell: (x) => <Sources sources={x.sources} /> },
            { label: "CVEs", num: true, cell: (x) => <span><Count n={x.cves} of="cves" f={{ ...f(), device_id: x.device_id }} label={`${x.device_name} › ${p().label} CVEs`} /> <KevTag on={x.kev} /></span> },
          ]} />
          <PagedFoot list={devs} empty="No device has it now." loading="Loading the devices…" />
        </Panel>
      </>}</Match>
    </Switch>
  </>;
}
