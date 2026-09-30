// RMM console service worker (installability + offline shell).
// Policy: the authed console (/) is NEVER cached (it varies by login);
// navigations are network-first with a login-page fallback. Only the
// public shell (login page, manifest, icons) is precached. API, WS and
// screen/file streams always pass through untouched.
var CACHE = "rmm-v1";
var CORE = [
  "/login.html",
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/maskable-512.png"
];

self.addEventListener("install", function (e) {
  e.waitUntil(
    caches.open(CACHE).then(function (c) { return c.addAll(CORE); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) {
        if (k !== CACHE) { return caches.delete(k); }
        return Promise.resolve(false);
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

function isPassthrough(url) {
  return url.pathname.indexOf("/api/") === 0 ||
    url.pathname === "/ws" ||
    url.pathname.indexOf("/screens/") === 0;
}

self.addEventListener("fetch", function (e) {
  var url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== self.location.origin) { return; }
  if (isPassthrough(url)) { return; }
  if (e.request.mode === "navigate") {
    e.respondWith(
      fetch(e.request).catch(function () {
        return caches.match("/login.html");
      })
    );
    return;
  }
  e.respondWith(
    caches.match(e.request).then(function (hit) {
      return hit || fetch(e.request);
    })
  );
});
