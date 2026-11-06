// Blackpoint's dark-web exposures (darkweb.list): an email address, where it was seen, when, and what kind of data was
// exposed. That's all the console keeps: never a password or a hash. Passwords first; each count filters the list.
import { A, useSearchParams } from "@solidjs/router";
import { createMemo, createResource, For, Match, Show, Switch } from "solid-js";
import { evidence } from "../api";
import { Busy, Err, Muted, Panel, Tag, plural } from "../ui";

type Exposure = { exposure_id: string; email: string | null; source: string | null; found_on: string | null; kind: "password" | "username" | "email";
                  tenant_id: string; tenant_name: string; org_id: number | null; client: string | null };
const KIND: Record<Exposure["kind"], string> = { password: "a password", username: "a username", email: "the address" };

export default function DarkWeb() {
  const [q, setQ] = useSearchParams<{ org?: string; show?: "passwords" }>();
  const org = () => { const n = Number(q.org); return Number.isInteger(n) && n > 0 ? n : undefined; };
  const [d] = createResource(() => ({ org: org() }), (x) => evidence<Exposure[]>("darkweb.list", { ...(x.org ? { org_id: x.org } : {}), limit: 500 }));
  const rows = createMemo(() => (d()?.data ?? []).filter((r) => q.show !== "passwords" || r.kind === "password"));
  const t = () => d()?.totals;
  return <>
    <nav aria-label="Where you are"><ol class="crumbs"><li><A href="/">Search</A></li><li><A href="/detections">Detections</A></li><li aria-current="page">Dark web</li></ol></nav>
    <Panel page title="Dark-web exposures">
      <p class="muted">From Blackpoint's dark-web scan, for tenants licensed for it. The console keeps the address, where it was seen, when and what kind of data, and never the exposed value itself.</p>
      <Show when={t()}><div class="toolbar" role="group" aria-label="Show">
        <button type="button" class={q.show ? "quiet" : ""} aria-pressed={!q.show} onClick={() => setQ({ show: undefined }, { replace: true })}>{plural(t()!.exposures, "exposure")} of {plural(t()!.emails, "address", "addresses")}</button>
        <button type="button" class={q.show ? "" : "quiet"} aria-pressed={!!q.show} onClick={() => setQ({ show: "passwords" }, { replace: true })}>{t()!.passwords} with a password</button>
      </div></Show>
      <Switch>
        <Match when={d.loading && !d.latest}><Busy text="Loading the exposures…" /></Match>
        <Match when={d()?.error}><Err text={d()!.error!} /></Match>
        <Match when={rows().length === 0}><p>No dark-web exposures{q.show ? " with a password" : ""}.</p></Match>
        <Match when={rows().length}>
          <ul class="rows"><For each={rows()}>{(r) => <li class="row">
            <span class="grow"><span class="mono">{r.email ?? "no address given"}</span><Show when={r.kind === "password"}><Tag text="password exposed" fill="bad" /></Show>
              <Muted>{r.source ?? "an unnamed source"} · {r.client ?? `${r.tenant_name} (not tied to a client)`}</Muted></span>
            <span class="muted">exposed {KIND[r.kind]}</span>
            <span class="num">{r.found_on ?? "—"}</span>
          </li>}</For></ul>
        </Match>
      </Switch>
    </Panel>
  </>;
}
