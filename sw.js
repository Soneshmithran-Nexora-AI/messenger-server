/* Service worker: keeps the app shell available offline and shows message notifications. It never stores API responses. */
const CACHE = 'shell-v1';
self.addEventListener('install', (e) => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/icons/icon-192.png']).catch(() => {}))); });
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/')) return;
  if (r.mode === 'navigate') {
    /* page: always try the network first so updates arrive, fall back to the saved copy when offline */
    e.respondWith(fetch(r).then((res) => { const copy = res.clone(); caches.open(CACHE).then((c) => c.put('/', copy)); return res; }).catch(() => caches.match('/').then((m) => m || new Response('You are offline.', { status: 503, headers: { 'Content-Type': 'text/plain' } }))));
  }
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const data = e.notification.data || {};
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) { c.postMessage({ type: 'open', convId: data.convId || null, call: !!data.call }); if ('focus' in c) return c.focus(); }
    return self.clients.openWindow('/');
  }));
});
