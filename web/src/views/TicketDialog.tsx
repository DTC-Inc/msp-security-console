// Raise a Halo ticket from a finding (a detection, an exposed address). The dialog shows the ticket exactly as the
// console will send it, and only "Send to Halo" sends it, with the digest of what was shown: if the finding changed in
// between, the console refuses and the dialog shows it again. Once a finding has a ticket, this is a link to it.
import { createSignal, Show } from "solid-js";
import { createTicket, detailsText, previewTicket, releaseTicket, ticketHref, type Features, type Preview } from "../actions";
import { Busy, Err } from "../ui";

export default function TicketButton(p: { finding: string; ticket: number | null | undefined; features: Features | undefined; onRaised?: (id: number) => void }) {
  let dlg!: HTMLDialogElement;
  const [preview, setPreview] = createSignal<Preview | null>(null);
  const [err, setErr] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [raised, setRaised] = createSignal<number | null>(null);
  const [confirmRelease, setConfirmRelease] = createSignal(false);
  const id = () => raised() ?? p.ticket ?? preview()?.existing?.halo_ticket_id ?? null;

  async function open() {
    setErr(""); setPreview(null); setBusy(true);
    dlg.showModal();
    const a = await previewTicket(p.finding);
    setBusy(false);
    if (a.error) { setErr(a.error); return; }
    setPreview(a.data!);
  }
  async function send() {
    const d = preview()?.digest; if (!d) return;
    setBusy(true); setErr("");
    const a = await createTicket(p.finding, d);
    setBusy(false);
    if (a.error) {
      setErr(a.error);
      // The finding changed: show what would be sent now.
      // The finding changed, or Halo's answer was lost and it may have the ticket: show what the console knows now.
      if (a.error.startsWith("the finding changed") || a.error.includes("Halo may have made a ticket")) { const again = await previewTicket(p.finding); if (again.data) setPreview(again.data); }
      return;
    }
    setRaised(a.data!.halo_ticket_id);
    p.onRaised?.(a.data!.halo_ticket_id);
  }

  // An admin's word that Halo has no ticket for it: the claim goes, and the dialog shows the ticket to raise again.
  async function release() {
    setBusy(true); setErr(""); setConfirmRelease(false);
    const a = await releaseTicket(p.finding);
    if (a.error) { setBusy(false); setErr(a.error); return; }
    const again = await previewTicket(p.finding);
    setBusy(false);
    if (again.error) { setErr(again.error); return; }
    setPreview(again.data!);
  }

  return <>
    <Show when={id()} fallback={<Show when={p.features?.tickets}><button type="button" onClick={open}>Raise a Halo ticket</button></Show>}>
      {(t) => <Show when={ticketHref(p.features, t())} fallback={<span>Halo ticket {t()}</span>}>
        {(href) => <a href={href()} target="_blank" rel="noopener noreferrer">Halo ticket {t()} ↗</a>}
      </Show>}
    </Show>
    <dialog ref={dlg} class="ticket" aria-labelledby="ticket-title" onClose={() => setErr("")}>
      <h2 id="ticket-title">Raise a Halo ticket</h2>
      <Show when={busy() && !preview()}><Busy text="Building the ticket…" /></Show>
      <Show when={raised()}><p class="msg ok" role="status">Halo ticket {raised()} was raised.</p></Show>
      <Show when={!raised() && preview()?.existing}>{(e) => <Show when={e().state === "unknown"} fallback={
        <p>{e().halo_ticket_id ? `This finding already has Halo ticket ${e().halo_ticket_id}.` : "A ticket for this finding is being raised now. Reload in a moment."}</p>}>
        <p class="msg bad" role="alert">{e().message ?? "A ticket may already exist in Halo. Search Halo for it before an admin releases this."} The console sent it once, and its answer was lost.</p>
        <Show when={p.features?.ticket_admin}>
          <Show when={confirmRelease()} fallback={<div class="actions tight"><button type="button" class="quiet" onClick={() => setConfirmRelease(true)} disabled={busy()}>Halo has no ticket: release</button></div>}>
            <div class="result bad" role="alertdialog" aria-label="Confirm the release">
              <p>Release it only after searching Halo for '{e().title}' and finding no ticket. The finding can then be raised again.</p>
              <div class="actions"><button type="button" class="quiet" onClick={() => setConfirmRelease(false)}>Cancel</button><span class="spacer" />
                <button type="button" onClick={release} disabled={busy()}>Release it</button></div>
            </div>
          </Show>
        </Show>
      </Show>}</Show>
      <Show when={!raised() && preview()?.payload}>{(t) => <>
        <p>This is exactly what the console will send to Halo, as you, for <strong>{preview()!.client}</strong>.</p>
        <dl class="ticket-fields">
          <dt>Summary</dt><dd>{t().summary}</dd>
          <dt>Halo client</dt><dd>{preview()!.client} (Halo id {t().client_id})</dd>
          <dt>Ticket type, status, priority</dt><dd>Halo ids {t().tickettype_id}, {t().status_id}, {t().priority_id} (from setup)</dd>
        </dl>
        <p class="label">Details</p>
        <pre class="ticket-text" tabindex="0">{detailsText(t().details_html)}</pre>
        <details><summary>The request, as sent</summary><pre class="ticket-text" tabindex="0">{JSON.stringify([t()], null, 2)}</pre></details>
      </>}</Show>
      <Show when={err()}><Err text={err()} /></Show>
      <div class="actions">
        <span class="spacer" />
        <button type="button" class="quiet" onClick={() => dlg.close()}>{raised() || preview()?.existing ? "Close" : "Cancel"}</button>
        <Show when={!raised() && preview()?.payload}><button type="button" onClick={send} disabled={busy()}>{busy() ? "Sending…" : "Send to Halo"}</button></Show>
      </div>
    </dialog>
  </>;
}
