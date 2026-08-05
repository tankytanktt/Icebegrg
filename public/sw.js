// ICEBERG Showdown — Service Worker
const CACHE = 'showdown-v1';
const PRECACHE = [
  '/',
  '/style.css',
  '/manifest.json'
];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE).then(function(c) { return c.addAll(PRECACHE); })
  );
  self.skipWaiting();
});

self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(keys.filter(function(k) { return k !== CACHE; }).map(function(k) { return caches.delete(k); }));
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', function(e) {
  // Only cache GET requests; always go network-first for API calls
  if (e.request.method !== 'GET') return;
  if (e.request.url.includes('/api/')) return;

  e.respondWith(
    fetch(e.request)
      .then(function(res) {
        // Cache successful responses for static assets
        if (res && res.status === 200 && e.request.url.match(/\.(css|js|png|jpg|webp|svg|woff2?)$/)) {
          var clone = res.clone();
          caches.open(CACHE).then(function(c) { c.put(e.request, clone); });
        }
        return res;
      })
      .catch(function() {
        // Offline fallback: serve from cache
        return caches.match(e.request).then(function(cached) {
          return cached || caches.match('/');
        });
      })
  );
});
