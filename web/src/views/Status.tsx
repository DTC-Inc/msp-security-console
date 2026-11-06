// The jobs behind the data (/api/status): when each last succeeded, its last error (a status, never a secret), and
// when it runs next; a line on the store: which kind, whether it holds vectors, and whose the backups are; and one on
// similar-CVE search: the embedder's model, or why it's off.
import { createResource, For, Match, Show, Switch } from "solid-js";
import { embedderLine, status, storeLine, type Job } from "../api";
import { Busy, Err, Muted, Panel } from "../ui";

const at = (s: string | null) => (s ? new Date(s) : null);
const abs = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const rel = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
export function when(s: string | null, now = Date.now()): string {
  const d = at(s); if (!d || Number.isNaN(d.getTime())) return "";
  const secs = Math.round((d.getTime() - now) / 1000), a = Math.abs(secs);
  const [n, unit]: [number, Intl.RelativeTimeFormatUnit] = a < 60 ? [secs, "second"] : a < 3600 ? [Math.round(secs / 60), "minute"] : a < 86400 ? [Math.round(secs / 3600), "hour"] : [Math.round(secs / 86400), "day"];
  return rel.format(n, unit);
}
const Time = (p: { s: string | null; none: string; due?: boolean }) => <Show when={at(p.s)} fallback={<Muted>{p.none}</Muted>}>
  <time datetime={p.s!} title={abs.format(at(p.s)!)}>{p.due && at(p.s)!.getTime() <= Date.now() ? "Due now" : when(p.s)}</time>
</Show>;
const detail = (d: Job["detail"]) => Object.entries(d ?? {}).filter(([, v]) => typeof v === "number" || typeof v === "string" || typeof v === "boolean")
  .map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`).join(" · ");

export default function Status() {
  const [s, { refetch }] = createResource(status);
  return <>
    <h1 class="sr-only">Status</h1>
    <Panel title="The jobs behind the data" right={<button type="button" class="quiet" onClick={() => refetch()} disabled={s.loading}>Refresh</button>}>
      <p class="muted">The console collects from your vendors on its own schedule. Each job's last success, last error and next run are here.</p>
      <Show when={s()?.data?.store}>{(x) => <p><strong>Store:</strong> {storeLine(x())}</p>}</Show>
      <Show when={s()?.data?.embedder}>{(x) => <p><strong>Similar-CVE search:</strong> {embedderLine(x())}</p>}</Show>
      <Switch>
        <Match when={s.loading && !s.latest}><Busy text="Loading the jobs…" /></Match>
        <Match when={s()?.error}><Err text={s()!.error!} /></Match>
        <Match when={(s()?.data?.jobs ?? []).length === 0}><p>No jobs have run yet. They appear here once the console's scheduler starts them.</p></Match>
        <Match when={s()?.data}>
          <table class="jobs">
            <thead><tr><th scope="col">Job</th><th scope="col">Last success</th><th scope="col">Last error</th><th scope="col">Next run</th></tr></thead>
            <tbody><For each={s()!.data!.jobs}>{(j) => <tr>
              <td><strong>{j.job}</strong>{j.running ? <Muted> · running now</Muted> : null}<Show when={detail(j.detail)}><div class="muted">{detail(j.detail)}</div></Show></td>
              <td data-label="Last success"><Time s={j.last_ok_at} none="Not yet" /></td>
              <td data-label="Last error">{j.last_error ? <span style={{ color: "var(--dtc-bad)" }}>{j.last_error}</span> : <Muted>None</Muted>}</td>
              <td data-label="Next run"><Time s={j.next_run_at} none="Not scheduled" due /></td>
            </tr>}</For></tbody>
          </table>
        </Match>
      </Switch>
    </Panel>
  </>;
}
