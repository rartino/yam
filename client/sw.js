// Versioned cache via manifest.json
fetch('./manifest.json')
  .then(r => r.json())
  .then(manifest => {
    const APP_VERSION = manifest.version || 'dev';
    const CACHE_NAME = `messenger-cache-v${APP_VERSION}`;

    const urlsToCache = [
      './',
      './index.html',
      './manifest.json',
      './site.webmanifest',
      './sw.js',
      `./messenger.js?v=${APP_VERSION}`,
      './utils.js?v=${APP_VERSION}',
      './settings.js?v=${APP_VERSION}',
      './yam.css?v=${APP_VERSION}',
      './boot.js?v=${APP_VERSION}',
      './offline.html',
      './android-chrome-192x192.png',
      './android-chrome-512x512.png',
      './apple-touch-icon.png',
      './logo.svg',
      './vendor/qrcodejs/qrcode.js',
      './vendor/sodium/sodium.js'
    ];

    self.addEventListener('install', event => {
      event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache)));
      self.skipWaiting();
    });

    self.addEventListener('activate', event => {
      event.waitUntil(
        caches.keys().then(names => Promise.all(names.map(n => n !== CACHE_NAME && caches.delete(n))))
      );
      self.clients.claim();
    });

    // Stale-while-revalidate for static assets; offline fallback for navigations
    self.addEventListener('fetch', event => {
      const req = event.request;
      if (req.method !== 'GET') return; // don't touch mutating requests

      // HTML navigations → offline fallback
      if (req.mode === 'navigate') {
        event.respondWith(
          fetch(req).catch(() => caches.match('./offline.html'))
        );
        return;
      }

      event.respondWith(
        caches.match(req).then(cached => {
          const fetchPromise = fetch(req).then(networkRes => {
            const resClone = networkRes.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(req, resClone));
            return networkRes;
          }).catch(() => cached);
          return cached || fetchPromise;
        })
      );
    });
  })
  .catch(err => console.error('Failed to init SW via manifest:', err));

// === PUSH: show notifications when app isn't visible ===
self.addEventListener('push', event => {
  const data = (() => { try { return event.data ? event.data.json() : {}; } catch { return {}; } })();
  const room = data.room_id;
  const ts = data.ts || Date.now();
  const body = data.body || (data.nickname ? `${data.nickname} sent a message` : 'You have a new message');

  event.waitUntil((async () => {
    // If any client is visible, avoid a disruptive notification (app will render it itself).
    const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const hasVisible = clientList.some(c => 'visibilityState' in c && c.visibilityState === 'visible');
    if (hasVisible) {
      clientList.forEach(c => c.postMessage({ type: 'push-message', room_id: room, ts }));
      return;
    }
    return self.registration.showNotification('Secure Messenger', {
      body,
      tag: room || 'secmsg',
      data: { url: `/?room=${encodeURIComponent(room||'')}`, room_id: room, ts },
      icon: './android-chrome-192x192.png',
      badge: './android-chrome-192x192.png',
      timestamp: ts
    });
  })());
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = (event.notification && event.notification.data && event.notification.data.url) || '/';
  event.waitUntil((async () => {
    const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of allClients) {
      if ('focus' in client) {
        await client.focus();
        if (event.notification && event.notification.data && event.notification.data.room_id) {
          client.postMessage({ type: 'navigate-room', room_id: event.notification.data.room_id });
        }
        return;
      }
    }
    await self.clients.openWindow(targetUrl);
  })());
});
