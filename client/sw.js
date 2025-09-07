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
      './qr.js',
      './utils.js',
      './settings.js',		
      './yam.css',
      './boot.js',
      `./messenger.js?v=${APP_VERSION}`,
      './offline.html',
      './android-chrome-192x192.png',
      './android-chrome-512x512.png',
      './apple-touch-icon.png',	
      './logo.svg',
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

    self.addEventListener('fetch', event => {
      const req = event.request;
      if (req.method !== 'GET') return;

      if (req.mode === 'navigate') {
	event.respondWith(fetch(req).catch(() => caches.match('./offline.html')));
	return;
      }

      const url = new URL(req.url);
      const sameOrigin = url.origin === location.origin;

      event.respondWith((async () => {
	const cached = await caches.match(req);
	try {
	  const net = await fetch(req);
	  // Only cache small, same-origin, basic (non-opaque) responses
	  if (sameOrigin && net.ok && net.type === 'basic') {
	    const len = Number(net.headers.get('content-length') || '0');
	    if (len === 0 || len <= 3_000_000) {
	      const clone = net.clone();
	      const cache = await caches.open(CACHE_NAME);
	      cache.put(req, clone);
	    }
	  }
	  return cached || net;
	} catch {
	  return cached;
	}
      })());
    });
  })
  .catch(err => console.error('Failed to init SW via manifest:', err));
