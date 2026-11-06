// Advisories ahead of NVD: a person's rule for a CVE NVD doesn't cover yet. Everyone sees the list and how many devices
// each names now; an admin adds, edits, supersedes (with a reason) or brings one back. A save applies at once.
import { A } from "@solidjs/router";
import { createResource, createSignal, For, Show } from "solid-js";
import { createStore } from "solid-js/store";
import { evidence, me, saveAdvisory } from "../api";
import { emptyForm, formOf, payload, rangeText, type Advisory, type Form } from "../advisories";
import { cveHref } from "../nav";
import { Busy, Err, Muted, Panel } from "../ui";
import { Count, KevTag, Table } from "./parts";

const FIELDS: { key: keyof Form; label: string; hint?: string; area?: boolean; required?: boolean }[] = [
  { key: "advisory_id", label: "Advisory id", hint: "The vendor's own id, like VENDOR-2026-001. Saving an id again changes that advisory.", required: true },
  { key: "cve_id", label: "CVE", hint: "CVE-2026-12345", required: true },
  { key: "title", label: "Title", required: true },
  { key: "product_key", label: "Product key", hint: "The product the Software tab lists it under, like notepadpp.", required: true },
  { key: "product_label", label: "Product name" },
  { key: "name_re", label: "Program name matches", hint: "A regular expression, case-insensitive: an installed program's name, or a running binary's." },
  { key: "company_re", label: "Publisher matches", hint: "Against an installed program's publisher, or a binary's company." },
  { key: "product_re", label: "Binary's product matches", hint: "Running binaries only: an advisory with this applies to what's running, not what's installed." },
  { key: "path_re", label: "Binary's path matches", hint: "Running binaries only." },
  { key: "ranges", label: "Affected versions", area: true, hint: "One a line: 8.5.0 - 8.6 (from 8.5.0, below 8.6), - 8.6, 8.5.0 -, or = 1.2.", required: true },
  { key: "fixed_in", label: "Fixed in", hint: "Versions, comma-separated." },
  { key: "severity", label: "Severity", hint: "critical, high, medium or low." },
  { key: "cvss", label: "CVSS" },
  { key: "url", label: "Advisory link", hint: "https only." },
  { key: "remedy", label: "What to do", area: true },
];

export default function Advisories() {
  const [who] = createResource(me);
  const admin = () => who()?.data?.admin === true;
  const [list, { refetch }] = createResource(() => evidence<Advisory[]>("advisories.list", {}));
  const [form, setForm] = createStore<Form>(emptyForm());
  const [editing, setEditing] = createSignal<"new" | string | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [msg, setMsg] = createSignal<{ ok: boolean; text: string } | null>(null);
  const [retire, setRetire] = createSignal<{ id: string; reason: string } | null>(null);

  const open = (a?: Advisory) => { setForm(a ? formOf(a) : emptyForm()); setEditing(a ? a.advisory_id : "new"); setMsg(null); };
  async function save(e: Event) {
    e.preventDefault();
    const p = payload(form);
    if (p.bad.length) { setMsg({ ok: false, text: p.bad.join(" ") }); return; }
    setBusy(true);
    const a = await saveAdvisory("save", p.advisory);
    setBusy(false);
    if (a.error) { setMsg({ ok: false, text: a.error }); return; }
    setMsg({ ok: true, text: `Saved ${a.data!.advisory_id}. It names ${a.data!.applied.advisory_rows} device${a.data!.applied.advisory_rows === 1 ? "" : "s"} now.` });
    setEditing(null); void refetch();
  }
  async function act(action: "supersede" | "reactivate", id: string, reason = "") {
    setBusy(true);
    const a = await saveAdvisory(action, { advisory_id: id }, reason);
    setBusy(false);
    setMsg(a.error ? { ok: false, text: a.error } : { ok: true, text: `${id} ${action === "supersede" ? "superseded" : "is active again"}.` });
    if (!a.error) { setRetire(null); void refetch(); }
  }

  return <>
    <h1 class="sr-only">Advisories</h1>
    <Panel title="Advisories ahead of NVD" right={<Show when={admin()}><button type="button" onClick={() => open()} disabled={busy()}>Add an advisory</button></Show>}>
      <p class="muted">A vendor's advisory for a CVE NVD doesn't cover yet: which software it's about and which versions. The console matches it against installed software at once, and again after every inventory.{admin() ? "" : " Only an admin can add or change one."}</p>
      <div aria-live="polite"><Show when={msg()}>{(m) => <p class={`msg ${m().ok ? "ok" : "bad"}`} role={m().ok ? "status" : "alert"}>{m().text}</p>}</Show></div>
      <Show when={editing()}>
        <form class="panel-body" onSubmit={save} novalidate aria-label={editing() === "new" ? "A new advisory" : `Editing ${editing()}`}>
          <h2>{editing() === "new" ? "A new advisory" : `Editing ${editing()}`}</h2>
          <For each={FIELDS}>{(f) => <div class="field">
            <label for={`adv-${f.key}`}>{f.label}{f.required ? "" : <span class="muted"> (optional)</span>}</label>
            {f.area
              ? <textarea id={`adv-${f.key}`} rows={3} value={form[f.key] as string} onInput={(e) => setForm(f.key, e.currentTarget.value)} aria-describedby={f.hint ? `adv-${f.key}-hint` : undefined} />
              : <input id={`adv-${f.key}`} type="text" value={form[f.key] as string} readOnly={f.key === "advisory_id" && editing() !== "new"} spellcheck={false}
                  onInput={(e) => setForm(f.key, e.currentTarget.value)} aria-describedby={f.hint ? `adv-${f.key}-hint` : undefined} />}
            <Show when={f.hint}><p class="hint" id={`adv-${f.key}-hint`}>{f.hint}</p></Show>
          </div>}</For>
          <label class="check"><input type="checkbox" checked={form.exploited} onChange={(e) => setForm("exploited", e.currentTarget.checked)} /> Exploited in the wild</label>
          <div class="actions"><button type="button" class="quiet" onClick={() => setEditing(null)} disabled={busy()}>Cancel</button><span class="spacer" />
            <button type="submit" disabled={busy()}>{busy() ? "Saving…" : "Save and apply"}</button></div>
        </form>
      </Show>
      <Show when={!list.loading} fallback={<Busy text="Loading the advisories…" />}>
        <Show when={!list()?.error} fallback={<Err text={list()!.error!} />}>
          <Show when={(list()?.data ?? []).length} fallback={<p>No advisories yet. Add one when a vendor publishes a CVE before NVD has it.</p>}>
            <Table<Advisory> caption="Advisories" rows={list()!.data!} cols={[
              { label: "CVE", cell: (a) => <span><A class="mono" href={cveHref(a.cve_id)}>{a.cve_id}</A> <KevTag on={a.exploited} /></span> },
              { label: "Advisory", cell: (a) => <span><strong>{a.title}</strong><div class="muted">{a.advisory_id}{a.url ? <> · <a href={a.url} target="_blank" rel="noopener noreferrer">the vendor's page ↗</a></> : null}</div></span> },
              { label: "Software and versions", cell: (a) => <span>{a.product_label ?? a.product_key}<div class="muted">{a.ranges.map(rangeText).join("; ")}{a.fixed_in.length ? ` · fixed in ${a.fixed_in.join(", ")}` : ""}</div></span> },
              { label: "Devices", num: true, cell: (a) => <Count n={a.devices} of="devices" f={{ advisory_id: a.advisory_id }} label={`Devices ${a.advisory_id} names`} /> },
              { label: "Status", cell: (a) => <span>{a.status}<div class="muted">{a.edited_by ?? a.added_by ?? ""}</div></span> },
              { label: "", cell: (a) => <Show when={admin()}><span class="chips">
                <button type="button" class="link" onClick={() => open(a)} disabled={busy()}>Edit<span class="sr-only"> {a.advisory_id}</span></button>
                <Show when={a.status === "active"} fallback={<button type="button" class="link" onClick={() => act("reactivate", a.advisory_id)} disabled={busy()}>Reactivate<span class="sr-only"> {a.advisory_id}</span></button>}>
                  <button type="button" class="link" onClick={() => setRetire({ id: a.advisory_id, reason: "" })} disabled={busy()}>Supersede<span class="sr-only"> {a.advisory_id}</span></button>
                </Show>
              </span></Show> },
            ]} />
          </Show>
        </Show>
      </Show>
      <Show when={retire()}>{(r) => <form onSubmit={(e) => { e.preventDefault(); void act("supersede", r().id, r().reason); }} aria-label={`Supersede ${r().id}`}>
        <div class="field"><label for="retire-why">Why supersede {r().id}?</label>
          <textarea id="retire-why" rows={2} value={r().reason} onInput={(e) => setRetire({ id: r().id, reason: e.currentTarget.value })} aria-describedby="retire-hint" />
          <p class="hint" id="retire-hint">It's a reviewed decision, kept in the advisory's notes with your name: NVD covers it now, say, with its ranges. Its devices stop counting it at once.</p></div>
        <div class="actions"><button type="button" class="quiet" onClick={() => setRetire(null)}>Cancel</button><span class="spacer" />
          <button type="submit" disabled={busy() || !r().reason.trim()}>Supersede it</button></div>
      </form>}</Show>
      <Muted>Every save is an audit line naming who made it.</Muted>
    </Panel>
  </>;
}
