// The Software tab: every product the map knows that a source saw, worst first (products.list), each count opening its
// rows. NVD's catalogue for the product is its whole list, not anything on a device, so it's said, not linked.
import { A, useSearchParams } from "@solidjs/router";
import { createMemo } from "solid-js";
import { productHref, type Filter } from "../drill";
import { Panel } from "../ui";
import { ClassPicker, Count, PagedFoot, Table, Worst, num, usePaged } from "./parts";

type Row = { product_key: string; label: string; cpe: string; installed_devices: number; vulnerable_devices: number; kev_devices: number; critical_devices: number;
  running_devices: number; clients: number; max_cvss: number | null; known_cves: number; known_kev: number };

export default function Software() {
  const [sp, setSp] = useSearchParams<{ class?: string }>();
  const base = createMemo<Filter>(() => (sp.class ? { device_class: sp.class } : {}));
  const list = usePaged<Row>(() => "products.list", () => base() as any);
  return <>
    <h1 class="sr-only">Software</h1>
    <Panel title="Software" right={<ClassPicker id="software-class" value={sp.class ?? ""} onChange={(v) => setSp({ class: v || undefined }, { replace: true })} />}>
      <p class="muted">Installed software matched against NVD and CISA's known-exploited list, worst first.</p>
      <Table caption="Products" rows={list.rows()} cols={[
        { label: "Product", cell: (r) => <span><A href={productHref(r.product_key)}><strong>{r.label}</strong></A><div class="muted mono">{r.cpe}</div></span> },
        { label: "Installed on", num: true, cell: (r) => <Count n={r.installed_devices} of="devices" f={{ ...base(), product_key: r.product_key, has: "product" }} label={`${r.label} › installed on`} /> },
        { label: "Vulnerable", num: true, cell: (r) => <Count n={r.vulnerable_devices} of="devices" f={{ ...base(), product_key: r.product_key }} label={`${r.label} › devices on a vulnerable version`} /> },
        { label: "Exploited", num: true, cell: (r) => <Count n={r.kev_devices} of="devices" f={{ ...base(), product_key: r.product_key, kev: true }} label={`${r.label} › devices with an actively exploited CVE`} style={{ color: r.kev_devices ? "var(--dtc-bad)" : undefined, "font-weight": "700" }} /> },
        { label: "Critical", num: true, cell: (r) => <Count n={r.critical_devices} of="devices" f={{ ...base(), product_key: r.product_key, critical: true }} label={`${r.label} › devices with a critical CVE (CVSS 9+)`} /> },
        { label: "Running", num: true, cell: (r) => <Count n={r.running_devices} of="devices" f={{ ...base(), product_key: r.product_key, running_only: true }} label={`${r.label} › running a vulnerable version`} /> },
        { label: "Clients", num: true, cell: (r) => <Count n={r.clients} of="clients" f={{ ...base(), product_key: r.product_key }} label={`${r.label} › clients with a vulnerable version`} /> },
        { label: "Worst", num: true, cell: (r) => <Worst cvss={r.max_cvss} f={{ ...base(), product_key: r.product_key }} label={r.label} /> },
        { label: "In NVD", num: true, cell: (r) => <span class="muted" title="NVD's whole catalogue for this product, on any device or none">{num(r.known_cves)} ({num(r.known_kev)} KEV)</span> },
      ]} />
      <PagedFoot list={list} empty="No recognised software yet. It appears once NinjaOne's inventory has been matched." loading="Loading the software…" />
    </Panel>
  </>;
}
