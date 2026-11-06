// Coverage: which sources saw which devices (coverage.list). Each client's devices, how many each source saw, and the
// gap, each opening its devices. A gap is a device a source should see and didn't: no agent, or one that's stale.
import { A } from "@solidjs/router";
import { For, Show } from "solid-js";
import { clientHref } from "../nav";
import { SRC } from "../theme";
import { Panel } from "../ui";
import { Count, PagedFoot, Table, Tile, Tiles, usePaged, type Col } from "./parts";
import { SOURCES } from "./sources";

type Row = { org_id: number; org_name: string | null; devices: number; inventoried: number; by_source: Record<string, number> };

export default function Coverage() {
  const list = usePaged<Row>(() => "coverage.list", () => ({}));
  const t = () => list.totals() as unknown as { clients?: number; devices?: number; inventoried?: number; by_source?: Record<string, number> };
  const name = (r: Row) => r.org_name ?? `Client ${r.org_id}`;
  const sourceCols: Col<Row>[] = SOURCES.map((s) => ({ label: SRC[s]?.label ?? s, num: true, cell: (r: Row) => <span>
    <Count n={r.by_source[s]} of="coverage" f={{ org_id: r.org_id, source: [s], seen: true }} label={`${name(r)} › devices ${SRC[s]?.label ?? s} saw`} />
    <Show when={r.devices - (r.by_source[s] ?? 0) > 0}><span class="muted"> · <Count n={r.devices - (r.by_source[s] ?? 0)} of="coverage" f={{ org_id: r.org_id, source: [s], seen: false }} label={`${name(r)} › devices ${SRC[s]?.label ?? s} didn't see`}>{`${r.devices - (r.by_source[s] ?? 0)} not`}</Count></span></Show>
  </span> }));
  return <>
    <h1 class="sr-only">Coverage</h1>
    <Panel title="Coverage: which sources saw which devices">
      <p class="muted">For each client, how many of its devices each source has seen, and how many it hasn't. A source that sees nothing at a client is usually not deployed or not connected there.</p>
      <Show when={t().devices != null}>
        <Tiles>
          <Tile k="Devices"><Count n={t().devices} of="coverage" f={{}} label="Every device" /></Tile>
          <Tile k="With a software inventory"><Count n={t().inventoried} of="coverage" f={{ has: "software" }} label="Devices with a software inventory" /></Tile>
          <For each={SOURCES}>{(s) => <Tile k={`Seen by ${SRC[s]?.label ?? s}`}><Count n={t().by_source?.[s]} of="coverage" f={{ source: [s], seen: true }} label={`Devices ${SRC[s]?.label ?? s} saw`} /></Tile>}</For>
        </Tiles>
      </Show>
      <Table caption="Coverage by client" rows={list.rows()} cols={[
        { label: "Client", cell: (r) => <A href={clientHref(r.org_id, name(r))}><strong>{name(r)}</strong></A> },
        { label: "Devices", num: true, cell: (r) => <Count n={r.devices} of="coverage" f={{ org_id: r.org_id }} label={`${name(r)} › every device`} /> },
        { label: "Inventory", num: true, cell: (r) => <Count n={r.inventoried} of="coverage" f={{ org_id: r.org_id, has: "software" }} label={`${name(r)} › devices with a software inventory`} /> },
        ...sourceCols,
      ]} />
      <PagedFoot list={list} empty="No devices yet. They arrive with the first NinjaOne sweep." loading="Loading coverage…" />
    </Panel>
  </>;
}
