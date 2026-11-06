// MSP Security Console: search, the clients and their devices, the software, coverage, the rows behind any count,
// one CVE, the advisories, the jobs behind the data and (admins) Settings; and, while the console is unconfigured, the
// setup wizard at /setup. Every view is a path.
import { A, Route, Router, type RouteSectionProps } from "@solidjs/router";
import { createResource, lazy, Show } from "solid-js";
import { me, signOut } from "./api";
import ThemeSwitch from "./ThemeSwitch";
import Home from "./views/Home";
import ClientCves from "./views/ClientCves";
import Cve from "./views/Cve";
import Status from "./views/Status";
import Clients from "./views/Clients";
import Client from "./views/Client";
import Device from "./views/Device";
import Software from "./views/Software";
import Product from "./views/Product";
import Coverage from "./views/Coverage";
import Rows from "./views/Rows";
import Advisories from "./views/Advisories";
import Settings from "./views/Settings";
import Detections, { DetectionPage } from "./views/Detections";
import BlackpointTenants from "./views/BlackpointTenants";
import DarkWeb from "./views/DarkWeb";
import Exposure, { AddressPage } from "./views/Exposure";
import Windows from "./views/Windows";
import Processes from "./views/Processes";
import ProcessReview from "./views/ProcessReview";
import { Err } from "./ui";

const Setup = lazy(() => import("./setup/Setup"));
/** NVD's terms ask every product that uses its API to say so, in these words. */
export const NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD.";

function Shell(p: RouteSectionProps) {
  const [who] = createResource(me);
  return <>
    <a class="skip" href="#main">Skip to the content</a>
    <header class="top"><div class="top-inner">
      <A href="/" class="brand">MSP Security Console</A>
      <nav aria-label="The console">
        <A href="/" end>Search</A>
        <A href="/clients">Clients</A>
        <A href="/software">Software</A>
        <A href="/coverage">Coverage</A>
        <A href="/advisories">Advisories</A>
        <A href="/detections">Detections</A>
        <A href="/exposure">Exposure</A>
        <A href="/windows">Windows</A>
        <A href="/processes">Processes</A>
        <A href="/status">Status</A>
        <Show when={who()?.data?.admin}><A href="/settings">Settings</A></Show>
      </nav>
      <div class="who">
        <Show when={who()?.data}>{(w) => <>
          <span class="email"><span class="sr-only">Signed in as </span>{w().email}</span>
          <Show when={w().logout}><button type="button" class="link" onClick={() => void signOut(w().logout!)}>Sign out</button></Show>
        </>}</Show>
        <Show when={who()?.error}><span class="muted" role="status">{who()!.error}</span></Show>
        <ThemeSwitch />
      </div>
    </div></header>
    <main id="main" tabindex="-1">{p.children}</main>
    <footer class="foot"><p>{NVD_NOTICE}</p></footer>
  </>;
}

const NotFound = () => <><h1 class="sr-only">Not found</h1><Err text="There's nothing at this address." /><p><A href="/">Go to the search</A></p></>;

export default function App() {
  return <Router>
    <Route path="/setup/*" component={Setup} />
    <Route path="/" component={Shell}>
      <Route path="/" component={Home} />
      <Route path="/clients" component={Clients} />
      <Route path="/clients/:org" component={Client} />
      <Route path="/clients/:org/cves" component={ClientCves} />
      <Route path="/devices/:id" component={Device} />
      <Route path="/software" component={Software} />
      <Route path="/software/:key" component={Product} />
      <Route path="/coverage" component={Coverage} />
      <Route path="/rows/:kind" component={Rows} />
      <Route path="/advisories" component={Advisories} />
      <Route path="/settings" component={Settings} />
      <Route path="/cves/:id" component={Cve} />
      <Route path="/windows" component={Windows} />
      <Route path="/processes" component={Processes} />
      <Route path="/processes/review" component={ProcessReview} />
      <Route path="/status" component={Status} />
      <Route path="/detections" component={Detections} />
      <Route path="/detections/:id" component={DetectionPage} />
      <Route path="/blackpoint/tenants" component={BlackpointTenants} />
      <Route path="/darkweb" component={DarkWeb} />
      <Route path="/exposure" component={Exposure} />
      <Route path="/exposure/:ip" component={AddressPage} />
      <Route path="*" component={NotFound} />
    </Route>
  </Router>;
}
