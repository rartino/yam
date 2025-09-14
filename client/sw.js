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
  const sameOrigin = url.origin === self.location.origin;
  // Do NOT intercept cross-origin requests (prevents accidental rewrites).
  // If you still want to serve a few third-party assets from cache when offline,
  // allow-list their hosts here.
  const XO_ALLOW = new Set([
    //'cdn.jsdelivr.net',   // libsodium, etc. (optional)
  ]);
  const allowXO = !sameOrigin && XO_ALLOW.has(url.hostname);
  if (!sameOrigin && !allowXO) return;

  // Ensure manifest and sw.js are always fetched fresh
  if (sameOrigin && (url.pathname.endsWith('/manifest.json') || url.pathname.endsWith('/sw.js'))) {
    event.respondWith(fetch(new Request(url, { cache: 'no-store' })));
    return;
  }

  if (req.mode === 'navigate' && sameOrigin) {
    event.respondWith(fetch(req).catch(() => caches.match('./offline.html')));
    // In the background, check if a newer version exists and warm it
    event.waitUntil(checkAndUpdate());
    return;
  }

  event.respondWith((async () => {
    const cached = await caches.match(req);
    try {
      const net = await fetch(req);
      // Only cache small, same-origin, basic (non-opaque) responses.
      // Cross-origin (allow-listed) assets are served from pre-cache when offline.
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
  const body = 'New messages in Yam';

  event.waitUntil((async () => {
    // If any client is visible, avoid a disruptive notification (app will render it itself).
    const clientList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const hasVisible = clientList.some(c => 'visibilityState' in c && c.visibilityState === 'visible');
    if (hasVisible) {
      clientList.forEach(c => c.postMessage({ type: 'push-message', room_id: room, ts }));
      return;
    }
    return self.registration.showNotification('Yam', {
      body,
      tag: room || 'Yam',
      data: { url: `/yam/?room=${encodeURIComponent(room||'')}`, room_id: room, ts },
      icon: '/yam/android-chrome-192x192.png',
      badge: '/yam/android-chrome-192x192.png',
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

// ======== PULL NOTIFICATIONS (Periodic Background Sync) ========
function pullTag(roomId){ return `pull:${roomId||'__'}`; }

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type !== 'show-pull' || !data.room_id) return;
  const tag = pullTag(data.room_id);
  event.waitUntil((async () => {
    const existing = await self.registration.getNotifications({ tag, includeTriggered: true });
    if (existing && existing.length) return;
    const ts = data.ts || Date.now();
    await self.registration.showNotification('Yam', {
      body: data.body || 'New message',
      tag,
      data: { url: `/?room=${encodeURIComponent(data.room_id)}`, room_id: data.room_id, ts },
      icon: './android-chrome-192x192.png',
      badge: './android-chrome-192x192.png',
      timestamp: ts
    });
  })());
});

self.addEventListener('periodicsync', (event) => {
  // Expect tags like "pull:<roomId>" — must match the page's registration.
  if (!event.tag || !event.tag.startsWith('pull:')) return;
  const roomId = event.tag.slice('pull:'.length);
  event.waitUntil((async () => {
    const tag = pullTag(roomId);
    // If a pull notification for this room is already up, don't re-trigger.
    const existing = await self.registration.getNotifications({ tag, includeTriggered: true });
    if (existing && existing.length) return;

    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length) {
      // Nudge any open page to fetch with WS 'history' and decide the first unseen.
      clients.forEach(c => c.postMessage({ type: 'pull-tick', room_id: roomId }));
      // Optional: lightweight engagement signal
      try { if (self.registration.setAppBadge) await self.registration.setAppBadge(); } catch(e){}
      return;
    }
    // No page is open. We cannot decrypt, so (optional) show a generic nudge.
    // If you want *no* notification in this case, delete the block below.
    await self.registration.showNotification('Secure Messenger', {
      body: 'Open to sync new messages',
      tag,
      data: { url: `/?room=${encodeURIComponent(roomId)}`, room_id: roomId, ts: Date.now() },
      icon: './android-chrome-192x192.png',
      badge: './android-chrome-192x192.png'
    });
  })());
});

// Optional: let pages know a pull notification was dismissed
self.addEventListener('notificationclose', (event) => {
  const rid = event.notification?.data?.room_id;
  if (!rid) return;
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    clients.forEach(c => c.postMessage({ type: 'pull-closed', room_id: rid }));
  })());
});
