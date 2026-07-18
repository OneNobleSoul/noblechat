// Registers the service worker and auto-reloads once when a new version takes
// control, so clients pick up a deploy without a manual refresh. Kept external
// so the page can ship a strict CSP (script-src 'self', no inline scripts).
if ("serviceWorker" in navigator) {
  var hadController = !!navigator.serviceWorker.controller;
  var refreshing = false;
  navigator.serviceWorker.addEventListener("controllerchange", function () {
    if (!hadController) { hadController = true; return; } // first install, not an update
    if (refreshing) return;
    refreshing = true;
    window.location.reload();
  });
  window.addEventListener("load", function () {
    navigator.serviceWorker.register("/sw.js").catch(function () {});
  });
}
