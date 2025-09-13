//////////////////////////////
// UTILITIES
/////////////////////////////

export function b64uToBytes(b64uStr) {
  const pad = '='.repeat((4 - (b64uStr.length % 4)) % 4);
  const b64 = (b64uStr + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}
export function bytesToB64u(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64u(bytes) { return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING); }
export function fromB64u(str) { return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING); }
export async function blobToU8(blob) {
  const buf = await blob.arrayBuffer();
  return new Uint8Array(buf);
}
export async function blobToB64u(blob) {
  return b64u(await blobToU8(blob));
}
export async function sha256_b64u(blob) {
  const buf = await blob.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const bytes = new Uint8Array(digest);
  return b64u(bytes);
}
export async function sha256_b64u_string(s){
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return b64u(new Uint8Array(digest));
}
export async function sha256_b64u_bytes(u8) {
  const d = await crypto.subtle.digest('SHA-256', u8);
  return b64u(new Uint8Array(d));
}

export function utf8ToBytes(str){ return new TextEncoder().encode(str); }
export function bytesToUtf8(bytes){ return new TextDecoder().decode(bytes); }

export function normServer(url){
  if (!url) return '';
  let u = url.trim();
  if (u.endsWith('/')) u = u.slice(0,-1);
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}

export function dataUrlFromBlob(blob) {
  return new Promise((resolve) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.readAsDataURL(blob);
  });
}

export function nowMs() { return Date.now(); }
export function sevenDaysAgoMs() { return nowMs() - 7 * 24 * 60 * 60 * 1000; }
export function shortId(idB64u) { return idB64u.slice(0, 6) + '…' + idB64u.slice(-6); }
export function hostFromUrl(u){
  try { const x = new URL(normServer(u)); return x.host; } catch { return u; }
}
export function sanitizeColorHex(s) {
  const m = /^#?[0-9a-fA-F]{6}$/.exec(s || '');
  return m ? ('#' + m[0].replace('#','').toLowerCase()) : null;
}
export function pickTextColorOn(bgColor, { light = '#fff', dark = '#000', base = '#fff' } = {}) {
  let [r, g, b, a = 1] = cssColorToRgba(bgColor);
  if (a < 1) {
    // Composite semi-transparent bg over the base color (default white)
    const [br, bg, bb] = cssColorToRgba(base);
    const [R, G, B] = [r, g, b].map(v => srgbToLinear(v / 255));
    const [BR, BG, BB] = [br, bg, bb].map(v => srgbToLinear(v / 255));
    [r, g, b] = [R * a + BR * (1 - a), G * a + BG * (1 - a), B * a + BB * (1 - a)]
      .map(v => Math.round(linearToSrgb(v) * 255));
  }

  const Lbg = relLuminance(r, g, b);
  const contrastWhite = (1 + 0.05) / (Lbg + 0.05);
  const contrastBlack = (Lbg + 0.05) / (0 + 0.05);

  return contrastWhite >= contrastBlack ? light : dark;
}

// --- helpers ---

function cssColorToRgba(color) {
  // Let the browser parse ANY CSS color string.
  const el = document.createElement('div');
  el.style.color = color;
  el.style.display = 'none';
  document.body.appendChild(el);
  const cs = getComputedStyle(el).color; // "rgb(r,g,b)" or "rgba(r,g,b,a)"
  document.body.removeChild(el);
  const m = cs.match(/rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)(?:[,\s/]+([\d.]+))?\s*\)/i);
  if (!m) throw new Error('Unsupported color: ' + color);
  return [Number(m[1]), Number(m[2]), Number(m[3]), m[4] !== undefined ? Number(m[4]) : 1];
}

function relLuminance(r, g, b) {
  const [R, G, B] = [r, g, b].map(v => srgbToLinear(v / 255));
  // WCAG coefficients
  return 0.2126 * R + 0.7152 * G + 0.0722 * B;
}

function srgbToLinear(c) {
  return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

function linearToSrgb(c) {
  return c <= 0.0031308 ? 12.92 * c : 1.055 * Math.pow(c, 1 / 2.4) - 0.055;
}

export function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);
  return outputArray;
}

