// Names to review: running binaries and installed programs whose NVD product the console wouldn't decide on its own
// (NVD has products by that name, but none or several whose vendor is the publisher). A signed-in person picks the
// candidate it is, or says it's none of them; each decision is confirmed here first, and recorded with who made it.
// The match jobs apply it within 30 minutes. Until then, nothing is matched for these names.
import { A, useSearchParams } from "@solidjs/router";
import { createEffect, createSignal, For, on, Show } from "solid-js";
import type { ReviewDecision } from "@msp/contract";
import { decide, evidence } from "../api";
import { Busy, Err, Muted, Panel, plural } from "../ui";
import { readable } from "../winproc";

type Candidate = { vendor: string; product: string; key: string; vendor_match: boolean; confidence: number };
type Name = { kind: "process" | "software"; name: string; company: string; candidates: Candidate[]; versions: string[]; devices: number; status: string; cpe: string | null;
  decided_by: string | null; decided_at: string | null };

const cpeOf = (c: Candidate) => `${c.vendor}:${c.product}`;
const STATUS: Record<string, string> = { pending: "Waiting for a decision", accepted: "Accepted", rejected: "Rejected" };

function Row(p: { n: Name; onDone: (said: string) => void }) {
  const id = () => `rv-${p.n.kind}-${p.n.name}-${p.n.company}`.replace(/\W+/g, "-");
  const [pick, setPick] = createSignal<string>(p.n.cpe ?? (p.n.candidates[0] ? cpeOf(p.n.candidates[0]) : ""));
  const [confirming, setConfirming] = createSignal<ReviewDecision | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [msg, setMsg] = createSignal<{ ok: boolean; text: string } | null>(null);
  const ask = (decision: ReviewDecision["decision"]) => {
    setMsg(null);
    setConfirming({ kind: p.n.kind, name: p.n.name, company: p.n.company, decision, ...(decision === "accept" ? { cpe: pick() } : {}) });
  };
  const send = async () => {
    const d = confirming(); if (!d) return;
    setBusy(true);
    const r = await decide(d);
    setBusy(false); setConfirming(null);
    if (r.error) { setMsg({ ok: false, text: r.error }); return; }
    p.onDone(r.data!.unchanged ? `“${p.n.name}”: that was already the decision; nothing changed.` : `“${p.n.name}”: recorded. The next match applies it, within 30 minutes.`);
  };
  const sentence = (d: ReviewDecision) => d.decision === "accept" ? `Match “${p.n.name}” to ${readable(d.cpe!)} on every device it's on?`
    : d.decision === "reject" ? `Never match “${p.n.name}” to any NVD product?` : `Put “${p.n.name}” back in the queue?`;
  return <li class="row">
    <fieldset class="grow" style={{ border: "0", padding: "0", margin: "0", "min-width": "0" }} aria-describedby={`${id()}-about`}>
      <legend><strong>{p.n.name}</strong><Show when={p.n.company}><Muted> · {p.n.company}</Muted></Show></legend>
      <div class="muted" id={`${id()}-about`} style={{ margin: "2px 0 6px" }}>{p.n.kind === "process" ? "Running" : "Installed"} on {plural(p.n.devices, "device")}
        {p.n.versions.length ? ` · ${p.n.versions.slice(0, 5).join(", ")}${p.n.versions.length > 5 ? ` and ${p.n.versions.length - 5} more` : ""}` : ""}
        {" · "}{STATUS[p.n.status] ?? p.n.status}{p.n.decided_by ? ` by ${p.n.decided_by}` : ""}{p.n.cpe ? `: ${readable(p.n.cpe)}` : ""}</div>
      <Show when={p.n.status === "pending"}>
        <For each={p.n.candidates}>{(c) => <label class="choice">
          <input type="radio" name={id()} value={cpeOf(c)} checked={pick() === cpeOf(c)} onChange={() => setPick(cpeOf(c))} />
          <span>{readable(cpeOf(c))}<Muted> · {c.vendor_match ? "its vendor matches the publisher" : "the name matches, the vendor doesn't"} · {Math.round(c.confidence * 100)}% sure</Muted></span>
        </label>}</For>
      </Show>
      <Show when={confirming()} fallback={<div class="actions">
        <Show when={p.n.status === "pending"} fallback={<button type="button" class="quiet" onClick={() => ask("reopen")} disabled={busy()}>Reopen</button>}>
          <button type="button" onClick={() => ask("accept")} disabled={!pick() || busy()}>Accept the chosen product</button>
          <button type="button" class="quiet" onClick={() => ask("reject")} disabled={busy()}>None of these</button>
        </Show>
      </div>}>{(d) => <div class="result" role="alertdialog" aria-labelledby={`${id()}-confirm`}>
        <p id={`${id()}-confirm`}>{sentence(d())}</p>
        <div class="actions">
          <button type="button" onClick={send} disabled={busy()}>{busy() ? "Saving…" : "Confirm"}</button>
          <button type="button" class="quiet" onClick={() => setConfirming(null)} disabled={busy()}>Cancel</button>
        </div>
      </div>}</Show>
      <Show when={msg()}>{(m) => <p class={`msg ${m().ok ? "ok" : "bad"}`} role={m().ok ? "status" : "alert"}>{m().text}</p>}</Show>
    </fieldset>
  </li>;
}

export default function ProcessReview() {
  const [search, setSearch] = useSearchParams<{ status?: string }>();
  const status = () => (search.status && STATUS[search.status] ? search.status : undefined);
  const [rows, setRows] = createSignal<Name[]>([]);
  const [totals, setTotals] = createSignal<Record<string, number> | null>(null);
  const [next, setNext] = createSignal<string | null>(null);
  const [err, setErr] = createSignal("");
  const [busy, setBusy] = createSignal(true);
  const [said, setSaid] = createSignal("");
  let ask = 0;
  const load = async (cursor?: string) => {
    const mine = ++ask;
    setBusy(true); setErr("");
    const a = await evidence<Name[]>("processes.review", { ...(status() ? { state: status() } : {}), limit: 100, ...(cursor ? { cursor } : {}) });
    if (mine !== ask) return;
    setBusy(false);
    if (a.error) { setErr(a.error); return; }
    setRows((r) => (cursor ? [...r, ...(a.data ?? [])] : a.data ?? []));
    setTotals(a.totals ?? null);
    setNext(a.next_cursor ?? null);
  };
  createEffect(on(status, () => { setRows([]); void load(); }));
  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li><A href="/processes">Running processes</A></li><li aria-current="page">Names to review</li></ol></nav>
    <Panel page title="Names to review" right={<Show when={totals()}><Muted>{`${plural(totals()!.pending ?? 0, "name")} waiting`}</Muted></Show>}>
      <p class="muted">NVD has products by these names, but the console isn't sure which, if any, each one is, so it matches none of them until someone decides. Decisions from the last 30 days are listed too.</p>
      <div class="toolbar">
        <label class="check" for="rvs">Show</label>
        <select id="rvs" value={status() ?? ""} onChange={(e) => setSearch({ status: e.currentTarget.value || undefined })}>
          <option value="">Waiting, and the last 30 days' decisions</option>
          <For each={Object.entries(STATUS)}>{([k, v]) => <option value={k}>{v}</option>}</For>
        </select>
      </div>
      <Show when={err()}><Err text={err()} /></Show>
      <p class="msg ok" role="status">{said()}</p>
      <Show when={!busy() && !err() && rows().length === 0}><p>Nothing to review: every name the console found is matched, or isn't one NVD lists.</p></Show>
      <ul class="rows"><For each={rows()}>{(n) => <Row n={n} onDone={(t) => { setSaid(t); void load(); }} />}</For></ul>
      <Show when={busy()} fallback={<Show when={next()}><div class="actions"><button type="button" onClick={() => load(next()!)}>Load more</button></div></Show>}>
        <Busy text="Loading the names to review…" />
      </Show>
    </Panel>
  </>;
}
