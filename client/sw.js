// --- Version-aware caching that *bypasses* cached manifest and updates eagerly ---
const META_CACHE = 'messenger-meta';

async function fetchManifestFresh() {
  // Always bypass caches for the manifest to detect new versions
  const res = await fetch('./manifest.json', { cache: 'no-store' });
  return res.json();
}

async function getStoredVersion() {
  const cache = await caches.open(META_CACHE);
  const res = await cache.match('/__app_version__');
  return res ? (await res.text()) : null;
}

async function setStoredVersion(v) {
  const cache = await caches.open(META_CACHE);
  await cache.put('/__app_version__', new Response(v, { headers: { 'content-type': 'text/plain' } }));
}

function urlsToCacheFor(version) {
  return [
    './',
    './index.html',
    // DO NOT cache manifest or sw.js themselves (we fetch them network-first)
    //'./manifest.json',
    //'./sw.js',
    './site.webmanifest',
    `./messenger.js?v=${version}`,
    `./utils.js?v=${version}`,
    `./settings.js?v=${version}`,
    `./yam.css?v=${version}`,
    `./boot.js?v=${version}`,
    './offline.html',
    './android-chrome-192x192.png',
    './android-chrome-512x512.png',
    './apple-touch-icon.png',
    './logo.svg',
    './vendor/qrcodejs/qrcode.js',
    './vendor/sodium/sodium.js'
  ];
}

// Versioned cache name is computed dynamically in handlers using stored version
async function warmCache(version) {
  const CACHE_NAME = `messenger-cache-v${version}`;
  const cache = await caches.open(CACHE_NAME);
  await cache.addAll(urlsToCacheFor(version));
  // Remove all other versioned caches, keep META
  const names = await caches.keys();
  await Promise.all(
    names
      .filter(n => n !== CACHE_NAME && n !== META_CACHE)
      .map(n => caches.delete(n))
  );
  return CACHE_NAME;
}

async function checkAndUpdate() {
  try {
    const manifest = await fetchManifestFresh();               // no-store
    const newVersion = manifest.version || 'dev';
    const current = await getStoredVersion();
    if (current !== newVersion) {
      await warmCache(newVersion);
      await setStoredVersion(newVersion);
      await self.clients.claim();
      // tell pages an update is ready (they may choose to reload)
      const clis = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      clis.forEach(c => c.postMessage({ type: 'sw:update-ready', version: newVersion }));
    }
  } catch (e) {
    // network problems? stay quiet and keep current caches
  }
}

// Kick off initial check on install
self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const manifest = await fetchManifestFresh();               // no-store
    const version = manifest.version || 'dev';
    await warmCache(version);
    await setStoredVersion(version);
  })());
  self.skipWaiting();
});

// Claim and do a background version check when activating
self.addEventListener('activate', event => {
  event.waitUntil(checkAndUpdate());
  self.clients.claim();
});

// Network-first for navigations + background version check
self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  const sameOrigin = url.origin === location.origin;

  // Ensure manifest and sw.js are always fetched fresh
  if (sameOrigin && (url.pathname.endsWith('/manifest.json') || url.pathname.endsWith('/sw.js'))) {
    event.respondWith(fetch(new Request(url, { cache: 'no-store' })));
    return;
  }

  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match('./offline.html')));
    // In the background, check if a newer version exists and warm it
    event.waitUntil(checkAndUpdate());
    return;
  }

  event.respondWith((async () => {
    const cached = await caches.match(req);
    try {
      const net = await fetch(req);
      // Only cache small, same-origin, basic (non-opaque) responses
      if (sameOrigin && net.ok && net.type === 'basic') {
        const len = Number(net.headers.get('content-length') || '0');
        if (len === 0 || len <= 3_000_000) {
          const clone = net.clone();
          const version = (await getStoredVersion()) || 'dev';
          const cache = await caches.open(`messenger-cache-v${version}`);
          cache.put(req, clone);
        }
      }
      return cached || net;
    } catch {
      return cached;
    }
  })());
});

// Allow the page to force a refresh (clear old, warm new, then notify)
self.addEventListener('message', event => {
  const data = event.data || {};
  if (data.type === 'sw:force-refresh') {
    event.waitUntil((async () => {
      await checkAndUpdate();
      const clis = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      clis.forEach(c => c.postMessage({ type: 'sw:refresh-complete' }));
    })());
  }
});

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
