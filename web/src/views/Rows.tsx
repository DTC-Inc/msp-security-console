// The rows behind a count: the list the number came from, filtered exactly as it was
// counted, its filter said in words. Its own counts open their rows in turn.
import { A, useLocation, useParams, useSearchParams } from "@solidjs/router";
import { createMemo, For, Match, Show, Switch } from "solid-js";
import { cveHref, clientHref } from "../nav";
import { LIST_KINDS, LIST_OP, deviceHref, filterWords, productHref, rowsParams, type ListKind } from "../drill";
import { Err, Muted, Panel, plural } from "../ui";
import { Count, CountTo, Crumbs, KevTag, PagedFoot, Sources, Table, Worst, num, usePaged } from "./parts";

type Dev = { device_id: number; device_name: string; org_id: number; org_name: string | null; device_class: string; role: string | null; sources: string[]; versions: string[];
  cves: number; kev_cves: number; max_cvss: number | null; worst: { cve_id: string; cvss: number | null; kev: boolean }[]; software?: number; os_name?: string | null };
type Cve = { cve_id: string; sources: string[]; devices: number; running_devices: number; kev: boolean; exploited: boolean; cvss: number | null };
type Cli = { org_id: number; org_name: string | null; devices: number; kev_devices: number; max_cvss: number | null };

export default function Rows() {
  const params = useParams<{ kind: string }>();
  const [sp] = useSearchParams<{ label?: string }>();
  const loc = useLocation();
  const kind = () => params.kind as ListKind;
  const known = () => (LIST_KINDS as readonly string[]).includes(params.kind);
  const p = createMemo(() => rowsParams(loc.search));
  const list = usePaged<any>(() => LIST_OP[kind()] ?? "devices.list", () => (known() ? p() : false));
  const cveF = createMemo(() => Object.fromEntries(Object.entries(p()).filter(([k]) => ["source", "product_key", "version", "kev", "critical", "cvss_min"].includes(k))));
  const cves = () => kind() === "cves" || kind() === "version-cves";
  const unit = () => (cves() ? "CVE" : kind() === "clients" ? "client" : "device");
  const total = () => list.totals()[kind() === "coverage" ? "devices" : cves() ? "cves" : kind()];
  return <>
    <Crumbs trail={[["Clients", "/clients"], [sp.label || "List"]]} />
    <Show when={known()} fallback={<Err text="There's no such list. Open it from a number on any page." />}>
      <Panel page title={sp.label || "The rows behind a number"} right={<Show when={total() != null}><Muted>{plural(total()!, unit())}</Muted></Show>}>
        <p class="muted">The rows behind the number you opened, filtered as it was counted: {filterWords(p()) || "everything"}.</p>
        <Switch>
          <Match when={kind() === "devices" || kind() === "coverage"}>
            <Table<Dev> caption="Devices" rows={list.rows()} cols={[
              { label: "Device", cell: (x) => <A href={deviceHref(x.device_id)}><strong>{x.device_name}</strong></A> },
              { label: "Client", cell: (x) => <A href={clientHref(x.org_id, x.org_name ?? undefined)}>{x.org_name ?? x.org_id}</A> },
              { label: "Class", cell: (x) => <span class="muted">{x.device_class}{x.role ? ` · ${x.role}` : ""}</span> },
              ...(kind() === "coverage" ? [{ label: "Software", num: true, cell: (x: Dev) => <CountTo n={x.software} href={`${deviceHref(x.device_id)}#software`} label={`${x.device_name}: its installed software`} /> }] :
                p().has === "product" ? [{ label: "Versions", cell: (x: Dev) => <span class="mono"><For each={x.versions}>{(v, i) => <>{i() > 0 && ", "}<A href={productHref(p().product_key!, v)}>{v || "none"}</A></>}</For></span> }] : [
                { label: "CVEs", num: true, cell: (x: Dev) => <Count n={x.cves} of="cves" f={{ ...cveF(), device_id: x.device_id }} label={`${x.device_name} › CVEs`} /> },
                { label: "Exploited", num: true, cell: (x: Dev) => <Count n={x.kev_cves} of="cves" f={{ ...cveF(), device_id: x.device_id, kev: true }} label={`${x.device_name} › actively exploited CVEs`} style={{ color: x.kev_cves ? "var(--dtc-bad)" : undefined, "font-weight": "700" }} /> },
                { label: "Worst", num: true, cell: (x: Dev) => <Worst cvss={x.max_cvss} f={{ ...cveF(), device_id: x.device_id }} label={x.device_name} /> },
                { label: "Worst CVEs", cell: (x: Dev) => <span class="chips"><For each={x.worst}>{(c) => <A class="chip mono" href={cveHref(c.cve_id)}>{c.cve_id}{c.cvss != null ? ` · ${c.cvss}` : ""}</A>}</For></span> },
              ]),
              { label: "Sources", cell: (x) => <Sources sources={x.sources} /> },
            ]} />
          </Match>
          <Match when={cves()}>
            <Table<Cve> caption="CVEs" rows={list.rows()} cols={[
              { label: "CVE", cell: (x) => <span><A class="mono" href={cveHref(x.cve_id)}>{x.cve_id}</A> <KevTag on={x.kev} /></span> },
              { label: "Sources", cell: (x) => <Sources sources={x.sources} /> },
              { label: "Devices", num: true, cell: (x) => <Count n={x.devices} of="devices" f={{ ...p(), cve_id: x.cve_id }} label={`${x.cve_id} › devices`} /> },
              { label: "Running on", num: true, cell: (x) => <Count n={x.running_devices} of="devices" f={{ ...p(), cve_id: x.cve_id, source: ["process"] }} label={`${x.cve_id} › devices running it`} /> },
              { label: "CVSS", num: true, cell: (x) => <span>{x.cvss ?? "—"}</span> },
            ]} />
          </Match>
          <Match when={kind() === "clients"}>
            <Table<Cli> caption="Clients" rows={list.rows()} cols={[
              { label: "Client", cell: (x) => <A href={clientHref(x.org_id, x.org_name ?? undefined)}><strong>{x.org_name ?? x.org_id}</strong></A> },
              { label: "Devices", num: true, cell: (x) => <Count n={x.devices} of="devices" f={{ ...p(), org_id: x.org_id }} label={`${x.org_name} › ${sp.label || "devices"}`} /> },
              { label: "With exploited CVEs", num: true, cell: (x) => <Count n={x.kev_devices} of="devices" f={{ ...p(), org_id: x.org_id, kev: true }} label={`${x.org_name} › devices with actively exploited software`} /> },
              { label: "Worst", num: true, cell: (x) => <Worst cvss={x.max_cvss} f={{ ...p(), org_id: x.org_id }} label={x.org_name ?? ""} /> },
            ]} />
          </Match>
        </Switch>
        <PagedFoot list={list} empty="Nothing matches this filter now: the data may have changed since the number was counted." loading="Loading the rows…" />
      </Panel>
    </Show>
  </>;
}
