// Settings → Connectors (admins): each connector's settings after setup, with the wizard's own rules (wizard.ts): what
// the environment sets is shown read-only, a secret is never shown and a blank one keeps the saved one, Test is live
// and read-only. Every section the wizard registers is here, whoever added it. Saving restarts the console with the
// change, as setup does. It ends with what isn't connected yet, and what each would add.
import { createEffect, createResource, createSignal, For, on, Show } from "solid-js";
import { createStore } from "solid-js/store";
import * as api from "../api";
import type { TestResult } from "../api";
import { SECTIONS, choicesOf, initialDraft, missing, notConnected, sectionValues, type Draft, type Section, type SectionId } from "../setup/wizard";
import { FieldInput, TestOutcome } from "../setup/fields";
import { Busy, Err, Muted, Panel } from "../ui";

export default function Settings() {
  const [state, { refetch }] = createResource(api.adminConnectors);
  const [draft, setDraft] = createStore<Draft>({ values: {}, mode: null, skipped: {} });
  const [results, setResults] = createStore<Record<string, TestResult | { error: string } | undefined>>({});
  const [busy, setBusy] = createSignal<string | null>(null);
  const [restarting, setRestarting] = createSignal<"no" | "waiting" | "late">("no");
  const [confirm, setConfirm] = createSignal<{ id: string; off: boolean } | null>(null);
  const s = () => state()?.data ?? null;
  // The sections the server says are connectors, as the wizard describes them.
  const sections = (): Section[] => SECTIONS.filter((x) => (s()?.sections ?? []).includes(x.id));
  createEffect(on(s, (x) => { if (x) setDraft(initialDraft(x)); }));

  async function test(id: SectionId) {
    setResults(id, undefined); setBusy(id);
    const a = await api.adminTest(id, sectionValues(s(), draft, id));
    setBusy(null);
    setResults(id, a.data ?? { error: a.error ?? "The test didn't answer." });
  }
  async function save(id: SectionId, off: boolean) {
    setConfirm(null); setBusy(id); setResults(id, undefined);
    const a = await api.adminSave(id, off ? {} : sectionValues(s(), draft, id), off);
    setBusy(null);
    if (a.error || !a.data) { setResults(id, { error: a.error ?? "The console didn't say it saved." }); return; }
    if (!a.data.restarting) { setResults(id, { error: "Nothing changed, so nothing was saved." }); return; }
    setRestarting("waiting");
    if (await api.waitForReady()) { setRestarting("no"); await refetch(); } else setRestarting("late");
  }

  return <>
    <h1 class="sr-only">Settings</h1>
    <Show when={!state.loading} fallback={<Busy text="Loading the connectors…" />}>
      <Show when={s()} fallback={<Err text={state()?.error ?? "The console didn't send its settings."} />}>
        <Panel title="Settings: connectors">
          <p class="muted">Each vendor the console reads from. Settings the environment sets are shown here and change only there. Saving checks the settings with start-up's own rules, then restarts the console with them.</p>
          <Show when={(s()!.plaintext_secrets ?? []).length}>
            <p class="msg bad" role="alert">These secrets are stored unencrypted in the config file: {s()!.plaintext_secrets.join(", ")}. Saving any connector encrypts them.</p>
          </Show>
          <Show when={restarting() !== "no"}>
            <Show when={restarting() === "waiting"} fallback={<p class="msg bad" role="alert">The console hasn't come back after a minute. Its log says why it didn't start.</p>}>
              <Busy text="Saved. The console is restarting with the change…" />
            </Show>
          </Show>
        </Panel>
        <For each={sections()}>{(sec) => <Panel title={sec.title}>
          <form onSubmit={(e) => { e.preventDefault(); setConfirm({ id: sec.id, off: false }); }} novalidate aria-label={`${sec.title} settings`}>
            <p class="muted">{sec.intro}</p>
            <For each={sec.fields}>{(f) => <FieldInput f={f} draft={draft} server={s()} prefix="set" onInput={(v) => { setDraft("values", f.key, v); if (!f.choices) setResults(sec.id, undefined); }}
              choices={choicesOf(f, (results[sec.id] as TestResult | undefined)?.detail)} />}</For>
            <div aria-live="polite"><Show when={results[sec.id]}>{(r) => <TestOutcome r={r()} />}</Show></div>
            <Show when={confirm()?.id === sec.id}>
              <div class="result bad" role="alertdialog" aria-label="Confirm">
                <p>{confirm()!.off ? `Turn ${sec.title} off? Its settings are cleared and the console restarts.` : `Save ${sec.title} and restart the console with it?`}</p>
                <div class="actions"><button type="button" class="quiet" onClick={() => setConfirm(null)}>Cancel</button><span class="spacer" />
                  <button type="button" onClick={() => save(sec.id, confirm()!.off)}>{confirm()!.off ? "Turn it off" : "Save and restart"}</button></div>
              </div>
            </Show>
            <div class="actions">
              <button type="button" class="quiet" onClick={() => setConfirm({ id: sec.id, off: true })} disabled={!!busy() || restarting() !== "no"}>Turn off</button>
              <span class="spacer" />
              <button type="button" class="quiet" onClick={() => test(sec.id)} disabled={!!busy()}>{busy() === sec.id ? "Testing…" : "Test connection"}</button>
              <button type="submit" disabled={!!busy() || restarting() !== "no" || missing(s(), draft, sec.id).length > 0}>Save</button>
            </div>
          </form>
        </Panel>}</For>
        <Panel title="What isn't connected yet">
          <NotConnected list={notConnected(s(), draft).filter((x) => sections().some((y) => y.id === x.id))} />
        </Panel>
      </Show>
    </Show>
  </>;
}

/** The optional connectors that are off, each with what turning it on adds. The review step shows the same list. */
export function NotConnected(p: { list: Section[] }) {
  return <Show when={p.list.length} fallback={<p>Every connector is connected.</p>}>
    <ul class="rows"><For each={p.list}>{(x) => <li class="row"><span class="grow"><strong>{x.title}</strong></span><Muted>{x.adds ?? x.intro}</Muted></li>}</For></ul>
  </Show>;
}
