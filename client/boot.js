fetch('./manifest.json')
  .then(r => r.json())
  .then(manifest => {
    window.APP_VERSION = manifest.version;
    const mv = document.getElementById('menuVersion');
    if (mv) mv.textContent = `v${window.APP_VERSION}`;

    const qr = document.createElement('script');
    qr.src = `./qr.js?v=${window.APP_VERSION}`;
    qr.onload = () => {
      const app = document.createElement('script');
      app.type = 'module';
      app.src = `./messenger.js?v=${window.APP_VERSION}`;
      document.body.appendChild(app);
    };
    document.body.appendChild(qr);
  })
  .catch(err => console.error('Failed to load manifest:', err));

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').then(() => console.log('Service Worker Registered'));
}
