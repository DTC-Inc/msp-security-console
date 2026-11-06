// One CVE (cve.get), within a client when opened from one: NVD's score and words, or "not in NVD yet" and the
// advisories that name it, KEV, how many devices each source saw, the addresses it faces the internet on, and the CVEs
// whose descriptions read like this one's (cve.similar), or one sentence on why there's no such list.
import { A, useParams, useSearchParams } from "@solidjs/router";
import { createResource, For, Match, Show, Switch } from "solid-js";
import { evidence } from "../api";
import { clientHref, cveHref, isCveId, orgOf } from "../nav";
import { alike, similarView, type Similar } from "../similar";
import { SRC, cvssRole, role } from "../theme";
import { Busy, Err, Muted, Panel, Tag, plural } from "../ui";
import { Count } from "./parts";

type Advisory = { advisory_id: string; title: string; fixed_in?: string[]; devices?: number | null; remedy?: string | null };
type CveData = {
  cve_id: string;
  nvd: { cvss: number | null; severity: string | null; published: string | null; description: string | null } | null;
  kev: { name: string | null; ransomware: boolean; date_added: string | null; due_date: string | null } | null;
  advisories: Advisory[]; devices: number; devices_by_source: Record<string, number>; clients: number;
  internet_facing: { ip: string; client_name?: string | null; website?: boolean; sites?: string[]; edge?: boolean; sources?: string[]; ports?: string[] }[];
};

export default function Cve() {
  const params = useParams<{ id: string }>();
  const [search] = useSearchParams<{ org?: string; name?: string }>();
  const id = () => decodeURIComponent(params.id).toUpperCase();
  const org = () => orgOf(search.org);
  const clientName = () => search.name || `Client ${search.org}`;
  const [d] = createResource(() => (isCveId(id()) ? { id: id(), org: org() } : false),
    ({ id, org }) => evidence<CveData>("cve.get", { cve_id: id, ...(org ? { org_id: org } : {}) }));
  const seen = () => Object.entries(d()?.data?.devices_by_source ?? {}).filter(([, n]) => Number(n) > 0);
  const [near] = createResource(() => (isCveId(id()) ? { id: id(), org: org() } : false),
    ({ id, org }) => evidence<Similar[]>("cve.similar", { cve_id: id, limit: 8, ...(org ? { org_id: org } : {}) }));

  return <>
    <nav aria-label="Where you are"><ol class="crumbs">
      <li><A href="/">Search</A></li>
      <Show when={org()}><li><A href={clientHref(org()!, search.name)}>{clientName()}</A></li></Show>
      <li aria-current="page" class="mono">{id()}</li>
    </ol></nav>
    <Switch>
      <Match when={!isCveId(id())}><Err text={`${id()} isn't a CVE id. They look like CVE-2026-12345.`} /></Match>
      <Match when={d.loading}><Busy text={`Loading ${id()}…`} /></Match>
      <Match when={d()?.error}><Err text={d()!.error!} /></Match>
      <Match when={d()?.data}>{(c) => <>
        <Panel>
          <div class="cve-head">
            <h1>{id()}</h1>
            <Show when={c().nvd?.cvss != null}><span class="cve-score" style={{ color: role(cvssRole(c().nvd!.cvss)) }} title="CVSS score">{c().nvd!.cvss}</span></Show>
            <Show when={c().kev}><Tag text={c().kev!.ransomware ? "KEV · ransomware" : "actively exploited (KEV)"} fill={c().kev!.ransomware ? "x-ransomware-fill" : "x-kev-fill"} /></Show>
            <a href={`https://nvd.nist.gov/vuln/detail/${id()}`} target="_blank" rel="noopener noreferrer" class="muted">NVD ↗</a>
          </div>
          <p class="muted"><Count n={c().devices} of="devices" f={{ cve_id: id(), ...(org() ? { org_id: org()! } : {}) }} label={`${id()} › devices`}>{plural(c().devices, "device")}</Count>
            {org() ? ` at ${clientName()}` : <> · <Count n={c().clients} of="clients" f={{ cve_id: id() }} label={`${id()} › clients`}>{plural(c().clients, "client")}</Count></>}</p>
          <p>{c().nvd?.description ?? `Not in NVD's data yet${(c().advisories ?? []).length ? ": known from the advisories below." : "."}`}</p>
          <Show when={c().kev?.due_date}><p class="muted">CISA added it to KEV on {c().kev!.date_added}; its remediation date is {c().kev!.due_date}.</p></Show>
          <For each={c().advisories ?? []}>{(a) => <div class="msg">
            <p><strong style={{ color: role("x-src-advisory") }}>advisory </strong>{a.title}
              <Show when={(a.fixed_in ?? []).length}><Muted>{` · fixed in ${a.fixed_in!.join(", ")}`}</Muted></Show>
              <Show when={a.devices != null}><Muted> · <Count n={a.devices!} of="devices" f={{ advisory_id: a.advisory_id }} label={`Devices ${a.advisory_id} names`}>{plural(a.devices!, "device")}</Count></Muted></Show></p>
            <Show when={a.remedy}><p class="muted">{a.remedy}</p></Show>
          </div>}</For>
        </Panel>
        <Panel title="Devices by source">
          <Show when={seen().length} fallback={<p>No device carries it{org() ? " at this client" : ""}.</p>}>
            <ul class="rows"><For each={seen()}>{([s, n]) => <li class="row">
              <span class="grow" style={{ color: role(SRC[s]?.role ?? "fg") }}>{SRC[s]?.label ?? s}</span>
              <strong class="num"><Count n={Number(n)} of="devices" f={{ cve_id: id(), source: [s], ...(org() ? { org_id: org()! } : {}) }} label={`${id()} › devices ${SRC[s]?.label ?? s} saw it on`} /></strong>
            </li>}</For></ul>
          </Show>
        </Panel>
        <Show when={(c().internet_facing ?? []).length}>
          <Panel title="Internet-facing">
            <p class="muted">Shodan sees an address, not a device: the edge in front of these sites. Each address opens what's open on it.</p>
            <ul class="rows"><For each={c().internet_facing}>{(h) => <li class="row">
              <span class="grow"><A class="mono" href={`/exposure/${encodeURIComponent(h.ip)}`}>{h.ip}</A></span>
              <Muted>{[h.client_name, h.website ? (h.sites ?? []).join(", ") : null, (h.ports ?? []).length ? `ports ${(h.ports ?? []).join(", ")}` : null,
                h.edge ? "an edge entry point" : null].filter(Boolean).join(" · ")}</Muted>
            </li>}</For></ul>
          </Panel>
        </Show>
        <Panel title="Similar CVEs">
          <Show when={near()} fallback={<Busy text="Finding CVEs that read alike…" />}>{(a) => {
            const v = similarView(a());
            return "rows" in v ? <>
              <p class="muted">By the meaning of NVD's descriptions, compared inside this console.</p>
              <ul class="rows"><For each={v.rows}>{(s) => <li class="row">
                <A class="grow mono" href={cveHref(s.cve_id, org() ?? undefined, search.name)}>{s.cve_id}</A>
                <Show when={s.kev}><Tag text="KEV" fill="x-kev-fill" /></Show>
                <Show when={s.cvss != null}><span class="num" style={{ color: role(cvssRole(s.cvss)) }} title="CVSS score">{s.cvss}</span></Show>
                <Muted>{` · ${plural(s.devices, "device")} · ${alike(s.distance)}`}</Muted>
              </li>}</For></ul>
            </> : <p class="muted">{v.sentence}</p>;
          }}</Show>
        </Panel>
        <Show when={org()}><p><A href={clientHref(org()!, search.name)}>← {clientName()}'s CVEs</A></p></Show>
      </>}</Match>
    </Switch>
  </>;
}
