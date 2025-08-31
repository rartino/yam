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
      './messenger.js',
      './offline.html',
      './android-chrome-192x192.png',
      './android-chrome-512x512.png',
      './vendor/sodium/sodium.js'
    ];

    self.addEventListener('install', event => {
      event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
      );
      self.skipWaiting();
    });

    self.addEventListener('activate', event => {
      event.waitUntil(
        caches.keys().then(names => Promise.all(
          names.map(n => n !== CACHE_NAME && caches.delete(n))
        ))
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
