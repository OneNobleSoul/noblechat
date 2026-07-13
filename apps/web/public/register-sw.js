// Registers the service worker. Kept as an external file so the page can ship a
// strict Content-Security-Policy (script-src 'self', no inline scripts).
if ("serviceWorker" in navigator) {
  window.addEventListener("load", function () {
    navigator.serviceWorker.register("/sw.js").catch(function () {});
  });
}
