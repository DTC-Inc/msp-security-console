// Find a client, a device, software or a CVE by name: the evidence API's search, then into its page.
import { A, useNavigate, useSearchParams } from "@solidjs/router";
import { createResource, createSignal, For, Match, Show, Switch, onMount } from "solid-js";
import { evidence } from "../api";
import { clientHref, cveHref, fromOldHash, homeHref } from "../nav";
import { deviceHref, productHref } from "../drill";
import { Busy, Err, Muted, Panel } from "../ui";

type Hit = { type: "client" | "cve" | "product" | "device"; id: string | number; label?: string; org_name?: string | null };

export default function Home() {
  const [params] = useSearchParams<{ q?: string }>();
  const navigate = useNavigate();
  const [q, setQ] = createSignal(params.q ?? "");
  onMount(() => { const old = fromOldHash(window.location.hash); if (old) navigate(old, { replace: true }); });
  const [hits] = createResource(() => params.q?.trim() || false, async (s) => evidence<Hit[]>("search", { q: s }));
  const submit = (e: Event) => { e.preventDefault(); const s = q().trim(); if (s) navigate(homeHref(s)); };
  return <>
    <h1 class="sr-only">Search</h1>
    <Panel title="Find a client, a device, software or a CVE">
      <form class="search" role="search" onSubmit={submit}>
        <label for="q" class="sr-only">A client's, device's or program's name, or a CVE id</label>
        <input id="q" type="search" value={q()} onInput={(e) => setQ(e.currentTarget.value)} placeholder="A client, device or program, or a CVE id" autofocus autocomplete="off" />
        <button type="submit" disabled={!q().trim()}>Search</button>
      </form>
    </Panel>
    <Show when={params.q?.trim()}>
      <Switch>
        <Match when={hits.loading}><Busy text="Searching…" /></Match>
        <Match when={hits()?.error}><Err text={hits()!.error!} /></Match>
        <Match when={hits()}>
          <Panel title="Results" right={<Muted>{`for “${params.q}”`}</Muted>}>
            <Show when={(hits()!.data ?? []).length} fallback={<p>Nothing matches “{params.q}”. Try part of a client's name, or a whole CVE id.</p>}>
              <ul class="rows"><For each={hits()!.data}>{(h) => <li class="row">
                <span class="grow">
                  <Switch fallback={<span>{h.label ?? String(h.id)}</span>}>
                    <Match when={h.type === "client"}><A href={clientHref(Number(h.id), h.label)}>{h.label}</A></Match>
                    <Match when={h.type === "cve"}><A class="mono" href={cveHref(String(h.id))}>{String(h.id)}</A></Match>
                    <Match when={h.type === "device"}><A href={deviceHref(Number(h.id))}>{h.label}</A></Match>
                    <Match when={h.type === "product"}><A href={productHref(String(h.id))}>{h.label}</A></Match>
                  </Switch>
                </span>
                <Muted>{h.type === "client" ? "client" : h.type === "cve" ? (h.label ?? "CVE") : h.type === "product" ? "software" : `device${h.org_name ? ` · ${h.org_name}` : ""}`}</Muted>
              </li>}</For></ul>
            </Show>
          </Panel>
        </Match>
      </Switch>
    </Show>
  </>;
}
