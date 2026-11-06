// The inputs and the Test outcome shared by the setup wizard and Settings → Connectors, so both render every field kind
// (text, url, secret, number, a fixed choice, or a pick from the last Test's lists) the same way.
import { For, Show, type JSX } from "solid-js";
import type { SetupState, TestResult } from "../api";
import { detailLine, fieldView, type Draft, type Field } from "./wizard";

/** One setting's input, by its kind: a choice is a select of its options; a field with `choices` from the last Test is a
 * select of those; a secret is a password field; the rest are text. `prefix` keeps ids unique on a page. */
export function FieldInput(p: { f: Field; server: SetupState | null; draft: Draft; onInput: (v: string) => void; extra?: JSX.Element; choices?: { id: number; name: string }[]; prefix?: string }) {
  const id = `${p.prefix ?? "f"}-${p.f.key}`;
  const view = () => fieldView(p.server, p.draft, p.f);
  const hint = () => (view().locked ? undefined : p.f.hint);
  const described = () => [hint() ? `${id}-hint` : "", view().note ? `${id}-note` : ""].filter(Boolean).join(" ") || undefined;
  const type = () => (p.f.kind === "secret" ? "password" : p.f.kind === "number" ? "number" : p.f.kind === "url" ? "url" : "text");
  if (p.f.kind === "choice") return <div class="field">
    <label for={id}>{p.f.label}</label>
    <select id={id} name={p.f.key} value={view().value || p.f.options?.[0]?.value || ""} disabled={view().locked} aria-describedby={described()}
      onChange={(e) => p.onInput(e.currentTarget.value === p.f.options?.[0]?.value ? "" : e.currentTarget.value)}>
      <For each={p.f.options ?? []}>{(o) => <option value={o.value}>{o.label}</option>}</For>
    </select>
    <Show when={view().note}><span class="note" id={`${id}-note`}>{view().note}</span></Show>
    <Show when={hint()}><p class="hint" id={`${id}-hint`}>{hint()}</p></Show>
  </div>;
  return <div class="field">
    <label for={id}>{p.f.label}{p.f.required ? "" : <span class="muted"> (optional)</span>}</label>
    <div class="search">
      <Show when={!view().locked && (p.choices ?? []).length} fallback={
      <input id={id} name={p.f.key} type={type()} value={view().value} readOnly={view().locked}
        placeholder={view().locked ? undefined : p.f.placeholder} autocomplete={p.f.kind === "secret" ? "new-password" : "off"} spellcheck={false}
        aria-describedby={described()} onInput={(e) => p.onInput(e.currentTarget.value)} />}>
        <select id={id} name={p.f.key} aria-describedby={described()} onChange={(e) => p.onInput(e.currentTarget.value)}>
          <option value="" selected={!view().value}>Choose…</option>
          <For each={p.choices}>{(c) => <option value={String(c.id)} selected={view().value === String(c.id)}>{c.name} ({c.id})</option>}</For>
        </select>
      </Show>
      <Show when={!view().locked}>{p.extra}</Show>
    </div>
    <Show when={view().note}><span class="note" id={`${id}-note`}>{view().note}</span></Show>
    <Show when={hint()}><p class="hint" id={`${id}-hint`}>{hint()}</p></Show>
  </div>;
}

/** A Test's answer: connected or not, the vendor's status, and the plain values of its detail. */
export function TestOutcome(p: { r: TestResult | { error: string } }) {
  return <Show when={"ok" in p.r ? (p.r as TestResult) : null} fallback={<p class="msg bad" role="alert">{(p.r as { error: string }).error}</p>}>{(r) =>
    <div class={`result ${r().ok ? "ok" : "bad"}`}>
      <strong class={r().ok ? "ok" : "bad"}>{r().ok ? "Connected." : "Didn't connect."}</strong> {r().message}
      <Show when={r().status != null}><span class="muted"> (HTTP {r().status})</span></Show>
      <Show when={detailLine(r().detail)}>
        <div class="muted">{detailLine(r().detail)}</div>
      </Show>
    </div>}
  </Show>;
}
