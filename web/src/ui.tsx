// The few pieces every view uses, on the DTC tokens.
import { For, Show, type JSX } from "solid-js";
import { SRC, role } from "./theme";

/** A panel; `page` makes its title the page's heading (h1) rather than a section's (h2). */
export function Panel(p: { title?: string; right?: JSX.Element; children: JSX.Element; page?: boolean }) {
  const id = p.title ? `panel-${p.title.replace(/\W+/g, "-").toLowerCase()}` : undefined;
  return <section class="panel" aria-labelledby={id}>
    <Show when={p.title}><div class="panel-head">{p.page ? <h1 id={id}>{p.title}</h1> : <h2 id={id}>{p.title}</h2>}{p.right}</div></Show>
    <div class="panel-body">{p.children}</div>
  </section>;
}
export const Muted = (p: { children: JSX.Element }) => <span class="muted">{p.children}</span>;
export const Busy = (p: { text?: string }) => <p class="busy" role="status">{p.text ?? "Loading…"}</p>;
export const Err = (p: { text: string }) => <p class="msg bad" role="alert">{p.text}</p>;
export const Tag = (p: { text: string; fill: string }) => <span class="tag" style={{ background: role(p.fill) }}>{p.text}</span>;
export function SourceChips(p: { sources: string[] | undefined }) {
  return <span class="chips"><For each={p.sources ?? []}>{(s) => {
    const m = SRC[s] ?? { label: s, role: "fg-muted" };
    return <span class="chip" style={{ color: role(m.role) }}>{m.label}</span>;
  }}</For></span>;
}
export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
