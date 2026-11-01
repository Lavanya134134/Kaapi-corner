const C = 'kc2';
self.addEventListener('install', e => e.waitUntil(caches.open(C).then(c => c.addAll(['/', '/icon.svg']))));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || (u.pathname.startsWith('/api/') && !u.pathname.startsWith('/api/products'))) return;
  e.respondWith(fetch(e.request).then(r => { const k = r.clone(); caches.open(C).then(c => c.put(e.request, k)); return r; })
    .catch(() => caches.match(e.request)));
});
