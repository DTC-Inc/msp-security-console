// The first-run setup at /setup, while the console is unconfigured: the token from the log, the database, how people
// sign in, the vendors (each optional), review and save, then the restart. The rules about what is shown and sent are
// in wizard.ts; this is the screens. Every step is a form, so Enter goes on, and every field has its label.
import { createSignal, For, Match, onMount, Show, Switch, type JSX } from "solid-js";
import { createStore, produce } from "solid-js/store";
import * as api from "../api";
import type { SetupState, TestResult } from "../api";
import ThemeSwitch from "../ThemeSwitch";
import { NotConnected } from "../views/Settings";
import { FieldInput, TestOutcome } from "./fields";
import { Busy, Err } from "../ui";
import {
  AUTH_MODES, SECTIONS, visibleModes, STEPS, STEP_TITLES, fieldView, fieldsOf, initialDraft, missing, modeAllowed, modeLocked, newSessionKey,
  reviewValue, savePayload, section, sectionValues, keyState, notConnected, KEY_BACKUP_NOTE, masterKeyNote, STORES, DATABASE_TLS_NOTE, storeLocked, storeOf, choicesOf,
  type Draft, type Field, type SectionId, type Step, type Store,
} from "./wizard";

let firstStep = true;
/** A step's heading, which takes the focus when the step changes, so a screen reader hears where it is. */
function Heading(p: { children: JSX.Element }) {
  let h!: HTMLHeadingElement;
  onMount(() => { if (firstStep) firstStep = false; else h.focus(); });
  return <h2 ref={h} tabindex="-1">{p.children}</h2>;
}

export default function Setup() {
  const [step, setStep] = createSignal<Step>("token");
  const [server, setServer] = createSignal<SetupState | null>(null);
  const [draft, setDraft] = createStore<Draft>({ values: {}, mode: null, skipped: {} });
  const [results, setResults] = createStore<Partial<Record<SectionId, TestResult | { error: string }>>>({});
  const [msg, setMsg] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [checking, setChecking] = createSignal(true);
  const [configured, setConfigured] = createSignal(false);
  const [token, setToken] = createSignal("");
  const [saveErr, setSaveErr] = createSignal<{ error: string; section?: SectionId } | null>(null);
  const [restart, setRestart] = createSignal<"waiting" | "late">("waiting");
  const [keyPath, setKeyPath] = createSignal<string | null>(null);

  const go = (s: Step) => { setMsg(""); setStep(s); window.scrollTo({ top: 0 }); };
  const relock = (error?: string) => { setServer(null); setMsg(error ?? api.SETUP_LOCKED); setStep("token"); };

  async function loadState(): Promise<boolean> {
    const a = await api.setupState();
    if (a.locked) return false;
    if (a.configured) { setConfigured(true); setMsg(a.error!); return false; }
    if (a.error || !a.data) { setMsg(a.error ?? "The console didn't send its settings."); return false; }
    setServer(a.data);
    setDraft(initialDraft(a.data));
    return true;
  }
  // A reload inside the wizard: the setup cookie may still be good.
  onMount(async () => { if (await loadState()) setStep("database"); setChecking(false); });

  async function submitToken(e: Event) {
    e.preventDefault();
    if (!token().trim()) { setMsg("Enter the setup token from the console's log."); return; }
    setBusy(true); setMsg("");
    const a = await api.unlock(token());
    if (a.error) { setBusy(false); setMsg(a.error); return; }
    const ok = await loadState();
    setBusy(false);
    if (ok) { setToken(""); go("database"); }
  }

  const sectionSteps = SECTIONS.map((x) => x.id);
  const nextOf = (s: Step) => STEPS[STEPS.indexOf(s) + 1];
  const prevOf = (s: Step) => STEPS[STEPS.indexOf(s) - 1];

  // A changed setting makes the last Test stale, except a pick from that Test's own lists (Halo's ticket settings),
  // which would otherwise take the lists away after the first pick.
  function setValue(key: string, v: string, id: SectionId) {
    setDraft("values", key, v);
    if (!section(id).fields.some((f) => f.key === key && f.choices)) setResults(id, undefined);
  }

  function next(id: SectionId, e: Event) {
    e.preventDefault();
    const sk = section(id).optional && draft.skipped[id];
    const need = missing(server(), { ...draft, skipped: { ...draft.skipped, [id]: false } }, id);
    if (need.length && !sk) {
      setMsg(`${section(id).optional ? "To connect it, fill in" : "Fill in"} ${list(need)}${section(id).optional ? ", or choose Skip" : ""}.`);
      return;
    }
    setDraft("skipped", id, false);
    go(nextOf(id));
  }
  function skip(id: SectionId) { setDraft("skipped", id, true); setResults(id, undefined); go(nextOf(id)); }

  async function test(id: SectionId) {
    setResults(id, undefined);
    setBusy(true);
    const a = await api.testSection(id, sectionValues(server(), { ...draft, skipped: { ...draft.skipped, [id]: false } }, id));
    setBusy(false);
    if (a.locked) { relock(a.error); return; }
    setResults(id, a.data ?? { error: a.error ?? "The test didn't answer." });
  }

  async function doSave() {
    setBusy(true); setSaveErr(null);
    const a = await api.save(savePayload(server(), draft));
    setBusy(false);
    if (a.locked) { relock(a.error); return; }
    if (a.error || !a.data?.restarting) {
      const sid = sectionSteps.includes(a.section as SectionId) ? (a.section as SectionId) : undefined;
      setSaveErr({ error: a.error ?? "The console didn't say it saved.", section: sid });
      return;
    }
    setKeyPath(a.data.master_key_path ?? null);
    go("restart");
    await waitAndGo();
  }
  async function waitAndGo() {
    setRestart("waiting");
    if (await api.waitForReady()) api.goHome(); else setRestart("late");
  }

  const at = () => STEPS.indexOf(step());

  return <div class="wizard">
    <header>
      <div class="toolbar"><h1 style={{ flex: "1" }}>Set up the MSP Security Console</h1><ThemeSwitch /></div>
      <p>This page exists only until the console is configured. Everything here can be set by environment variables instead, and the environment always wins over what you save here.</p>
    </header>
    <nav aria-label="Setup steps"><ol class="steps">
      <For each={STEPS}>{(s, i) => <li classList={{ done: i() < at() }} aria-current={s === step() ? "step" : undefined}>{STEP_TITLES[s]}</li>}</For>
    </ol></nav>

    <section class="panel"><div class="panel-body step">
      <Switch>
        <Match when={checking()}><Busy text="Checking the setup…" /></Match>

        <Match when={configured()}>
          <Heading>Already set up</Heading>
          <p>{msg()}</p>
          <p><a href="/">Open the console</a></p>
        </Match>

        <Match when={step() === "token"}>
          <form onSubmit={submitToken} novalidate>
            <Heading>The setup token</Heading>
            <p>The console printed a one-time setup token to its log when it started. Enter it here to set it up.</p>
            <div class="field">
              <label for="token">Setup token</label>
              <input id="token" type="password" autocomplete="off" spellcheck={false} value={token()} onInput={(e) => setToken(e.currentTarget.value)}
                aria-describedby="token-hint" autofocus />
              <p class="hint" id="token-hint">To read it on one host, run <code>docker compose logs console</code> and copy the <code>setup_token</code> value. On Kubernetes, <code>kubectl logs</code> on the console's pod shows the same line. A restart prints a new token.</p>
            </div>
            <Show when={msg()}><Err text={msg()} /></Show>
            <div class="actions"><span class="spacer" /><button type="submit" disabled={busy()}>{busy() ? "Checking…" : "Continue"}</button></div>
          </form>
        </Match>

        <Match when={(sectionSteps as string[]).includes(step())}>
          {(() => {
            const id = step() as SectionId;
            const sec = section(id);
            return <form onSubmit={(e) => next(id, e)} novalidate>
              <Heading>{sec.title}{sec.optional ? <span class="muted"> (optional)</span> : null}</Heading>
              <p>{sec.intro}</p>
              <Show when={id === "database"}><StoreChoice server={server()} store={storeOf(server(), draft)} onChoose={(x) => { setDraft("store", x); setResults("database", undefined); setMsg(""); }} /></Show>
              <Show when={id === "auth"}><AuthChoice server={server()} mode={draft.mode} onChoose={(m) => { setDraft("mode", m); setResults("auth", undefined); setMsg(""); }} /></Show>
              <For each={fieldsOf(id, draft.mode, storeOf(server(), draft))}>{(f) =>
                <FieldInput f={f} server={server()} draft={draft} onInput={(v) => setValue(f.key, v, id)}
                  choices={choicesOf(f, (results[id] as TestResult | undefined)?.detail)}
                  extra={f.key === "SESSION_KEY" ? <button type="button" class="quiet" onClick={() => setValue("SESSION_KEY", newSessionKey(), id)}>Make one</button> : undefined} />}
              </For>
              <Show when={id === "database" && storeOf(server(), draft) === "postgres"}><p class="hint">{DATABASE_TLS_NOTE}</p></Show>
              <Show when={msg()}><Err text={msg()} /></Show>
              <div aria-live="polite"><Show when={results[id]}>{(r) => <TestOutcome r={r()} />}</Show></div>
              <div class="actions">
                <Show when={id !== "database"}><button type="button" class="quiet" onClick={() => go(prevOf(id))} disabled={busy()}>Back</button></Show>
                <span class="spacer" />
                <Show when={id !== "auth" || draft.mode}>
                  <button type="button" class="quiet" onClick={() => test(id)} disabled={busy()}>{busy() ? "Testing…" : "Test connection"}</button>
                </Show>
                <Show when={sec.optional}><button type="button" class="quiet" onClick={() => skip(id)} disabled={busy()}>Skip</button></Show>
                <button type="submit" disabled={busy()}>Next</button>
              </div>
            </form>;
          })()}
        </Match>

        <Match when={step() === "review"}>
          <div class="review">
            <Heading>Review and save</Heading>
            <p>The console checks these settings with the same rules it uses at start-up, saves them, and restarts with them.</p>
            <For each={SECTIONS}>{(sec) => <section aria-labelledby={`review-${sec.id}`}>
              <h3 id={`review-${sec.id}`}>{sec.title}<button type="button" class="link" onClick={() => go(sec.id)}>Change<span class="sr-only"> {sec.title}</span></button></h3>
              <Show when={!(sec.optional && draft.skipped[sec.id])} fallback={<p class="muted">Skipped. You can set it by environment later.</p>}>
                <dl>
                  <Show when={sec.id === "database"}><dt>Where the data is kept</dt><dd>{STORES.find((x) => x.id === storeOf(server(), draft))!.label}{storeLocked(server()) ? " (set by environment)" : ""}</dd></Show>
                  <Show when={sec.id === "auth"}><dt>How people sign in</dt><dd>{AUTH_MODES.find((m) => m.id === draft.mode)?.label ?? (modeLocked(server()) ? "Set by environment" : "Not chosen")}</dd></Show>
                  <For each={fieldsOf(sec.id, draft.mode, storeOf(server(), draft))}>{(f) => <><dt>{f.label}</dt><dd>{reviewValue(server(), draft, f)}</dd></>}</For>
                </dl>
              </Show>
            </section>}</For>
            <section aria-labelledby="review-not-connected">
              <h3 id="review-not-connected">What isn't connected yet</h3>
              <NotConnected list={notConnected(server(), draft)} />
              <p class="hint">Each can be connected later, by an admin in Settings or by environment.</p>
            </section>
            <p class="hint" style={{ "margin-top": "12px" }}>{KEY_BACKUP_NOTE}</p>
            <Show when={saveErr()}>{(e) => <div role="alert">
              <p class="msg bad">{e().error}</p>
              <Show when={e().section}><button type="button" class="quiet" onClick={() => go(e().section!)}>Go to {section(e().section!).title}</button></Show>
            </div>}</Show>
            <div class="actions">
              <button type="button" class="quiet" onClick={() => go(prevOf("review"))} disabled={busy()}>Back</button>
              <span class="spacer" />
              <button type="button" onClick={doSave} disabled={busy()}>{busy() ? "Checking and saving…" : "Check and save"}</button>
            </div>
          </div>
        </Match>

        <Match when={step() === "restart"}>
          <Heading>Restarting…</Heading>
          <Show when={masterKeyNote(keyPath())}>{(note) => <p class="msg">{note()}</p>}</Show>
          <Show when={restart() === "waiting"} fallback={<>
            <p class="msg bad" role="alert">The console hasn't come back after a minute. Check its log (<code>docker compose logs console</code>) for why it didn't start.</p>
            <div class="actions"><button type="button" onClick={waitAndGo}>Try again</button></div>
          </>}>
            <p>The settings checked out and are saved. The console is restarting with them; this page opens it when it's ready.</p>
            <Busy text="Waiting for the console…" />
          </Show>
        </Match>
      </Switch>
    </div></section>
  </div>;
}

function list(xs: string[]): string {
  const l = xs.map((x) => x.charAt(0).toLowerCase() + x.slice(1));
  return l.length < 2 ? l.join("") : `${l.slice(0, -1).join(", ")} and ${l[l.length - 1]}`;
}

/** The SQLite file or PostgreSQL. Fixed, and said so, when the environment sets either one's setting. */
function StoreChoice(p: { server: SetupState | null; store: Store; onChoose: (x: Store) => void }) {
  const locked = () => storeLocked(p.server);
  return <fieldset>
    <legend>Where the console keeps its data</legend>
    <For each={STORES}>{(x) => <div class="choice">
      <input type="radio" id={`store-${x.id}`} name="store" value={x.id} checked={p.store === x.id} disabled={!!locked() && locked() !== x.id} onChange={() => p.onChoose(x.id)}
        aria-describedby={`store-${x.id}-hint`} />
      <div><label for={`store-${x.id}`}><strong>{x.label}</strong></label><p class="hint" id={`store-${x.id}-hint`}>{x.hint}</p></div>
    </div>}</For>
    <Show when={locked()}><p class="note">Set by environment: <code>{locked() === "postgres" ? "DATABASE_URL" : "DATABASE_PATH"}</code></p></Show>
  </fieldset>;
}

function AuthChoice(p: { server: SetupState | null; mode: Draft["mode"]; onChoose: (m: NonNullable<Draft["mode"]>) => void }) {
  const fixed = () => modeLocked(p.server) && !visibleModes(p.server).some((m) => modeAllowed(p.server, m.id));
  return <Show when={!fixed()} fallback={<p class="note">Set by environment: <code>AUTH_MODE={keyState(p.server, "AUTH_MODE").value ?? "?"}</code></p>}>
    <fieldset>
      <legend>How people sign in</legend>
      <For each={visibleModes(p.server)}>{(m) => <div class="choice">
        <input type="radio" id={`mode-${m.id}`} name="auth-mode" value={m.id} checked={p.mode === m.id} disabled={!modeAllowed(p.server, m.id)} onChange={() => p.onChoose(m.id)}
          aria-describedby={`mode-${m.id}-hint`} />
        <div><label for={`mode-${m.id}`}><strong>{m.label}</strong></label><p class="hint" id={`mode-${m.id}-hint`}>{m.hint}</p></div>
      </div>}</For>
      <Show when={modeLocked(p.server)}><p class="note">Part of this is set by environment, so only the choices it allows are open.</p></Show>
    </fieldset>
  </Show>;
}

