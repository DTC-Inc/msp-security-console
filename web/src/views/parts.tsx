// The pieces the core views share: a count that opens its rows, a table that becomes cards on a phone, tiles, the
// class picker, and a paged list from the evidence API.
import { A } from "@solidjs/router";
import type { Params, ReadOp } from "@msp/contract";
import { createEffect, createSignal, For, on, Show, type JSX } from "solid-js";
import { evidence } from "../api";
import { rowsHref, type Filter, type ListKind } from "../drill";
import { SRC, cvssRole, role } from "../theme";
import { Busy, Err, Tag } from "../ui";

export const num = (n: number | null | undefined) => (n == null ? "—" : n.toLocaleString());

/** A count: a link to exactly the rows it counts, or the plain number when it's zero (there's nothing to open). */
export function Count(p: { n: number | null | undefined; of: ListKind; f: Filter; label: string; children?: JSX.Element; style?: JSX.CSSProperties }) {
  return <Show when={Number(p.n) > 0} fallback={<span style={p.style}>{p.children ?? num(p.n)}</span>}>
    <A href={rowsHref(p.of, p.f, p.label)} title={p.label} style={p.style}>{p.children ?? num(p.n)}<span class="sr-only">: {p.label}</span></A>
  </Show>;
}
/** A count that opens a page rather than a list (a client's devices open its page). Zero is the plain number. */
export function CountTo(p: { n: number | null | undefined; href: string; label: string }) {
  return <Show when={Number(p.n) > 0} fallback={<span>{num(p.n)}</span>}><A href={p.href} title={p.label}>{num(p.n)}<span class="sr-only">: {p.label}</span></A></Show>;
}
/** The worst score, opening the CVEs that score it. */
export function Worst(p: { cvss: number | null | undefined; f: Filter; label: string }) {
  return <Show when={p.cvss != null} fallback={<span class="muted">—</span>}>
    <Count n={1} of="cves" f={{ ...p.f, cvss_min: p.cvss }} label={`${p.label}: CVEs scoring ${p.cvss}`} style={{ color: role(cvssRole(p.cvss)), "font-weight": "700" }}>{p.cvss}</Count>
  </Show>;
}

export type Col<T> = { label: string; num?: boolean; cell: (r: T) => JSX.Element };
/** A table from a tablet up; on a phone each row is a card, every cell labelled. */
export function Table<T>(p: { rows: T[]; cols: Col<T>[]; caption: string }) {
  return <table class="grid">
    <caption class="sr-only">{p.caption}</caption>
    <thead><tr><For each={p.cols}>{(c) => <th scope="col" classList={{ num: !!c.num }}>{c.label}</th>}</For></tr></thead>
    <tbody><For each={p.rows}>{(r) => <tr><For each={p.cols}>{(c) => <td data-label={c.label} classList={{ num: !!c.num }}>{c.cell(r)}</td>}</For></tr>}</For></tbody>
  </table>;
}

/** A row of numbers above a table, each opening what it counts. */
export function Tiles(p: { children: JSX.Element }) { return <div class="tiles">{p.children}</div>; }
export function Tile(p: { k: string; children: JSX.Element; sub?: string }) {
  return <div class="tile"><div class="tile-k">{p.k}</div><div class="tile-v">{p.children}</div><Show when={p.sub}><div class="muted">{p.sub}</div></Show></div>;
}

export function Sources(p: { sources: string[] | undefined }) {
  return <span class="chips"><For each={p.sources ?? []}>{(s) => <span class="chip" style={{ color: role(SRC[s]?.role ?? "fg-muted") }}>{SRC[s]?.label ?? s}</span>}</For></span>;
}
export const KevTag = (p: { on: boolean | undefined }) => <Show when={p.on}><Tag text="KEV" fill="x-kev-fill" /></Show>;

export const CLASSES = [["", "All devices"], ["server", "Servers"], ["desktop", "Desktops"], ["laptop", "Laptops"], ["other", "Other"]] as const;
/** Which kind of device the view counts. */
export function ClassPicker(p: { value: string; onChange: (v: string) => void; id: string }) {
  return <label class="check" for={p.id}>Devices
    <select id={p.id} value={p.value} onChange={(e) => p.onChange(e.currentTarget.value)}>
      <For each={CLASSES}>{([v, l]) => <option value={v}>{l}</option>}</For>
    </select>
  </label>;
}

/** A list from the evidence API, a page at a time: its rows, its totals, and "Load more" while there's a cursor. */
export function usePaged<T>(op: () => ReadOp, params: () => Params | false, limit = 100) {
  const [rows, setRows] = createSignal<T[]>([]);
  const [totals, setTotals] = createSignal<Record<string, number>>({});
  const [next, setNext] = createSignal<string | null>(null);
  const [err, setErr] = createSignal("");
  const [busy, setBusy] = createSignal(true);
  const [extra, setExtra] = createSignal<Record<string, unknown>>({});
  let ask = 0;
  const load = async (cursor?: string) => {
    const p = params(); if (p === false) return;
    const mine = ++ask;
    setBusy(true); setErr("");
    const a = await evidence<T[]>(op(), { ...p, limit, ...(cursor ? { cursor } : {}) });
    if (mine !== ask) return;
    setBusy(false);
    if (a.error) { setErr(a.error); return; }
    setRows((r) => (cursor ? [...r, ...(a.data ?? [])] : a.data ?? []));
    setNext(a.next_cursor ?? null);
    setTotals(a.totals ?? {});
    setExtra(a as unknown as Record<string, unknown>);
  };
  createEffect(on([op, () => JSON.stringify(params())], () => { setRows([]); setNext(null); void load(); }));
  return { rows, totals, next, err, busy, extra, more: () => { const c = next(); if (c) void load(c); }, reload: () => void load() };
}

/** What a paged list shows under itself: loading, an error, nothing, or Load more. */
export function PagedFoot(p: { list: ReturnType<typeof usePaged<any>>; empty: string; loading: string }) {
  return <>
    <Show when={p.list.err()}><Err text={p.list.err()} /></Show>
    <Show when={!p.list.busy() && !p.list.err() && p.list.rows().length === 0}><p>{p.empty}</p></Show>
    <Show when={p.list.busy()} fallback={<Show when={p.list.next()}><div class="actions"><button type="button" onClick={p.list.more}>Load more</button></div></Show>}>
      <Busy text={p.list.rows().length ? "Loading more…" : p.loading} />
    </Show>
  </>;
}

/** Where you are: the crumbs, the last one the page itself. */
export function Crumbs(p: { trail: [string, string?][] }) {
  return <nav aria-label="Where you are"><ol class="crumbs"><For each={p.trail}>{([label, href]) =>
    <li aria-current={href ? undefined : "page"}>{href ? <A href={href}>{label}</A> : label}</li>}</For></ol></nav>;
}
