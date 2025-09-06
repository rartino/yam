fetch('./manifest.json')
  .then(r => r.json())
  .then(manifest => {
    window.APP_VERSION = manifest.version;
    const mv = document.getElementById('menuVersion');
    if (mv) mv.textContent = `v${window.APP_VERSION}`;
    const script = document.createElement('script');
    script.type = 'module';
    script.src = `./messenger.js?v=${window.APP_VERSION}`;
    document.body.appendChild(script);
  })
  .catch(err => console.error('Failed to load manifest:', err));

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').then(() => console.log('Service Worker Registered'));
}
