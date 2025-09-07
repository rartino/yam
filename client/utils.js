//////////////////////////////
// UTILITIES
/////////////////////////////

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
