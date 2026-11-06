// The Clients tab: every client, worst first (devices with actively exploited software, then any vulnerable), with
// the counts its row shows, each opening exactly the rows it counts (clients.overview). The class picker narrows every
// count to one kind of device.
import { A, useSearchParams } from "@solidjs/router";
import { createMemo, Show } from "solid-js";
import { clientHref } from "../nav";
import type { Filter } from "../drill";
import { Panel, Muted, plural } from "../ui";
import { ClassPicker, Count, CountTo, PagedFoot, Table, Tile, Tiles, Worst, num, usePaged } from "./parts";

type Row = { org_id: number; org_name: string | null; devices: number; servers: number; desktops: number; laptops: number; vulnerable_devices: number; kev_devices: number;
  critical_devices: number; running_devices: number; kev_servers: number; vuln_servers: number; vuln_desktops: number; vuln_laptops: number; max_cvss: number | null };

export default function Clients() {
  const [sp, setSp] = useSearchParams<{ class?: string }>();
  const cls = () => sp.class ?? "";
  const base = createMemo<Filter>(() => (cls() ? { device_class: cls() } : {}));
  const list = usePaged<Row>(() => "clients.overview", () => base() as any);
  const t = () => list.totals();
  const name = (r: Row) => r.org_name ?? `Client ${r.org_id}`;
  return <>
    <h1 class="sr-only">Clients</h1>
    <Panel title="Clients" right={<ClassPicker id="clients-class" value={cls()} onChange={(v) => setSp({ class: v || undefined }, { replace: true })} />}>
      <p class="muted">Worst first: devices with actively exploited software, then any vulnerable software. Every number opens the rows it counts.</p>
      <Show when={t().clients != null}>
        <Tiles>
          <Tile k="Clients"><Show when={t().clients} fallback={num(t().clients)}><a href="#clients-list" title="Every client, in the table below">{num(t().clients)}</a></Show></Tile>
          <Tile k="Devices"><Count n={t().devices} of="coverage" f={base()} label="Every device" /></Tile>
          <Tile k="Vulnerable devices"><Count n={t().vulnerable_devices} of="devices" f={base()} label="Devices with vulnerable software" /></Tile>
          <Tile k="Actively exploited"><Count n={t().kev_devices} of="devices" f={{ ...base(), kev: true }} label="Devices with actively exploited software" /></Tile>
          <Tile k="Clients exploited"><Count n={t().kev_clients} of="clients" f={{ ...base(), kev: true }} label="Clients with actively exploited software" /></Tile>
        </Tiles>
      </Show>
      <span id="clients-list" />
      <Table caption="Clients and their counts" rows={list.rows()} cols={[
        { label: "Client", cell: (r) => <A href={clientHref(r.org_id, name(r))}><strong>{name(r)}</strong></A> },
        { label: "Devices", num: true, cell: (r) => <CountTo n={r.devices} href={clientHref(r.org_id, name(r))} label={`${name(r)}: its devices`} /> },
        { label: "Exploited", num: true, cell: (r) => <Count n={r.kev_devices} of="devices" f={{ ...base(), org_id: r.org_id, kev: true }} label={`${name(r)} › devices with actively exploited software`} style={{ color: r.kev_devices ? "var(--dtc-bad)" : undefined, "font-weight": "700" }} /> },
        { label: "Vulnerable", num: true, cell: (r) => <Count n={r.vulnerable_devices} of="devices" f={{ ...base(), org_id: r.org_id }} label={`${name(r)} › devices with vulnerable software`} /> },
        { label: "Critical", num: true, cell: (r) => <Count n={r.critical_devices} of="devices" f={{ ...base(), org_id: r.org_id, critical: true }} label={`${name(r)} › devices with a critical CVE (CVSS 9+)`} /> },
        { label: "Running", num: true, cell: (r) => <Count n={r.running_devices} of="devices" f={{ ...base(), org_id: r.org_id, running_only: true }} label={`${name(r)} › devices running a vulnerable version`} /> },
        { label: "Servers · desktops · laptops", num: true, cell: (r) => <span>
          <Count n={r.vuln_servers} of="devices" f={{ org_id: r.org_id, device_class: "server" }} label={`${name(r)} › vulnerable servers`} /> · <Count n={r.vuln_desktops} of="devices" f={{ org_id: r.org_id, device_class: "desktop" }} label={`${name(r)} › vulnerable desktops`} /> · <Count n={r.vuln_laptops} of="devices" f={{ org_id: r.org_id, device_class: "laptop" }} label={`${name(r)} › vulnerable laptops`} />
        </span> },
        { label: "Servers exploited", num: true, cell: (r) => <Count n={r.kev_servers} of="devices" f={{ org_id: r.org_id, kev: true, device_class: "server" }} label={`${name(r)} › servers with actively exploited software`} /> },
        { label: "Worst", num: true, cell: (r) => <Worst cvss={r.max_cvss} f={{ ...base(), org_id: r.org_id }} label={name(r)} /> },
      ]} />
      <PagedFoot list={list} empty={cls() ? "No clients have devices of this kind." : "No clients yet. They arrive with the first NinjaOne sweep."} loading="Loading the clients…" />
      <Show when={list.rows().length && t().clients}><Muted>{`${plural(list.rows().length, "client")} of ${t().clients} shown`}</Muted></Show>
    </Panel>
  </>;
}
