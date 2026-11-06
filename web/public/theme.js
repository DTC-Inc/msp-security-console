// Before the page paints: the viewer's chosen theme (Light, Dark, or System when nothing is stored). A file of its own
// because the console's CSP allows no inline script. Storage can be missing or blocked; then the system decides.
(function () {
  try {
    var t = window.localStorage.getItem("msp-console-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* no storage: follow the system */ }
})();
