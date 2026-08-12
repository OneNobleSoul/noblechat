// NobleChat service worker.
// Network-first so a fresh build is always picked up (we've been bitten by
// stale bundles before); the cache is only a fallback for offline. The API
// and the /gateway WebSocket are never touched.
// The chat client lives at /app; "/" is the public landing page. Only the app
// shell is precached, since that is the part that has to survive going offline.
const CACHE = "noblechat-v6";
const APP_URLS = ["/app", "/app.html"];
const SHELL = APP_URLS;

self.addEventListener("install", (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL).catch(() => {})));
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  let url;
  try { url = new URL(req.url); } catch { return; }
  if (req.method !== "GET") return;
  if (url.origin !== self.location.origin) return; // fonts etc. straight to network
  if (url.pathname.startsWith("/api") || url.pathname === "/gateway") return;

  // Page navigations bypass the browser HTTP cache entirely (cache: "reload"),
  // so a client can never get stuck on a stale index.html from an old build.
  // The HTML is tiny and references hash-versioned assets, so this is cheap.
  const isApp = APP_URLS.includes(url.pathname);
  const isNav = req.mode === "navigate" || isApp || url.pathname === "/";
  e.respondWith((async () => {
    try {
      const res = await fetch(isNav ? new Request(req, { cache: "reload" }) : req);
      if (res && res.ok) {
        const clone = res.clone();
        caches.open(CACHE).then((c) => c.put(req, clone)).catch(() => {});
      }
      return res;
    } catch {
      const cached = await caches.match(req);
      if (cached) return cached;
      // Fall back to the document that was actually asked for: serving the
      // landing page to an offline app navigation would look like a logout.
      if (req.mode === "navigate") return (await caches.match(isApp ? "/app.html" : "/index.html")) || Response.error();
      return Response.error();
    }
  })());
});
