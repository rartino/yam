// ====== CONFIG ======
const MASTER_PASS_LS_KEY = 'secmsg_master_pass_v1';
const MASTER_PASS_SS_KEY = 'secmsg_master_pass_session_v1';
const KEYCHECK_LS_KEY = 'secmsg_kcv_v1';
const KEYCHECK_PLAINTEXT = new TextEncoder().encode('YAM-KCV-1');
const ROOMS_KEY = 'secmsg_rooms_v1';
const SECRET_DB = 'secmsg_secret_db';
const SECRET_STORE = 'roomsecrets';
const CURRENT_ROOM_KEY = 'secmsg_current_room_id';
const SETTINGS_KEY = 'secmsg_settings_v1';
const MSG_DB = 'secmsg_msgs_db';
const MSG_STORE = 'msgs';
const PROFILE_DB = 'secmsg_profile_db';
const PROFILE_STORE = 'kv';
const PBKDF2_ITERS_CURRENT = 250_000;
const KDF_ALGO = { name: 'PBKDF2', hash: 'SHA-256' };
const RTC_CONFIG = {
  iceServers: [
    { urls: ['stun:stun.l.google.com:19302'] },
    // { urls: 'turn:your.turn.server:3478', username: 'user', credential: 'pass' }
  ],
  iceCandidatePoolSize: 2,
};
const CHUNK_SIZE = 64 * 1024; // 64KB chunks for file send

// Paging
const PAGE_SIZE = 60;              // messages per page
const MAX_DOM_MESSAGES = 250;      // hard cap in DOM
const TOP_LOAD_PX = 150;           // when scrollTop < this → load older
const BOTTOM_NEAR_PX = 400;        // near-bottom for autoscroll

// ====== DEBUG ======
const DEBUG_SIG = true;     // WebSocket signaling logs
const DEBUG_RTC = true;     // WebRTC flow logs
function dbg(tag, ...args){
  const ts = new Date().toISOString().split('T')[1].replace('Z','');
  console.log(`[${ts}] ${tag}`, ...args);
}

// ====== UI REFS ======

const statuses = {
    connected: '↔', // ✅
    disconnected: '↮', // ❌
    connecting: '↻', // ☑️
    passive: '·', // ✔️
};

const ui = {
  status: document.getElementById('status'),
  messages: document.getElementById('messages'),
  msgInput: document.getElementById('messageInput'),
  btnSend: document.getElementById('btnSend'),
  btnAttach: document.getElementById('btnAttach'),
  fileInput: document.getElementById('fileInput'),
  identityInfo: document.getElementById('identityInfo'),
  btnSettings: document.getElementById('btnSettings'),
  btnRoomMenu: document.getElementById('btnRoomMenu'),
  roomMenu: document.getElementById('roomMenu'),
  currentRoomName: document.getElementById('currentRoomName'),
  settingsMenu: document.getElementById('settingsMenu'),
  menuProfile: document.getElementById('menuProfile'),
  menuRoomOpts: document.getElementById('menuRoomOpts'),
  menuInvite: document.getElementById('menuInvite'),
};

// Gear -> configure room
const cfg = {
  dlg: document.getElementById('settingsModal'),
  name: document.getElementById('cfgRoomName'),
  btnSave: document.getElementById('btnSaveRoomCfg'),
  btnRemove: document.getElementById('btnRemoveRoom'),
  btnClose: document.getElementById('btnCloseSettings'),
};

const prof = {
  dlg: document.getElementById('profileModal'),
  btnClose: document.getElementById('btnCloseProfile'),
  name: document.getElementById('profName'),
  pubKey: document.getElementById('profPubKey'),
  btnCopy: document.getElementById('btnCopyPubKey'),
  btnRegen: document.getElementById('btnRegenIdentity'),
  btnSave: document.getElementById('btnSaveProfile'),
  avatarPreview: document.getElementById('avatarPreview'),
  avatarInput: document.getElementById('avatarInput'),
  btnAvatarUpload: document.getElementById('btnAvatarUpload'),
  btnAvatarClear: document.getElementById('btnAvatarClear'),
  requirePass: document.getElementById('profRequirePass'),
};

// Invite (sender)
const inv = {
  dlg: document.getElementById('inviteModal'),
  codeInput: document.getElementById('inviteCodeInput'),
  btnScan: document.getElementById('btnScanInviteQr'),
  btnPaste: document.getElementById('btnPasteInviteCode'),
  btnSend: document.getElementById('btnSendInvite'),
  btnClose: document.getElementById('btnCloseInvite'),
  scanArea: document.getElementById('scanArea'),
  scanVideo: document.getElementById('inviteScanVideo'),
  btnStopScan: document.getElementById('btnStopScan'),
};

// Join (receiver)
const join = {
  dlg: document.getElementById('joinModal'),
  server: document.getElementById('joinServer'),
  codeTA: document.getElementById('joinCode'),
  qrCanvas: document.getElementById('joinQrCanvas'),
  qrHint: document.getElementById('joinQrHint'),
  btnCopyCode: document.getElementById('btnCopyJoinCode'),
  btnRefresh: document.getElementById('btnRefreshJoinCode'),
  btnClose: document.getElementById('btnCloseJoin'),
};

// Unlock dialog refs
const unlock = {
  dlg: document.getElementById('unlockModal'),
  form: document.getElementById('unlockForm'),
  input: document.getElementById('unlockPass'),
  btn: document.getElementById('btnUnlock'),
  err: document.getElementById('unlockError'),
};

// ====== STATE ======
let SETTINGS = { username: '', requirePass: false, roomSkB64: '' };
let MASTER_PASS = null;
let MASTER_BASE_KEY = null; // PBKDF2 base CryptoKey (non-extractable)

let secretDbP = null;

let edPk = null;   // room public key (Uint8Array) — set per active room when switching
let edSk = null;   // room private key (Uint8Array)
let curvePk = null;
let curveSk = null;

let myIdPk = null; // device identity public key (Uint8Array)
let myIdSk = null; // device identity private key (Uint8Array)
let myPeerId = null; // base64url of myIdPk

let rooms = [];            // [{id, name, server, roomSkB64, roomId, createdAt}]
let currentRoomId = null;  // string id = roomId (ed25519 pk b64u)

// Per-server connections { url, ws, reconnectAttempt, reconnectTimer, heartbeatTimer, subscribed:Set, authed:Set }
const servers = new Map();

let profileDbPromise = null;

// WebRTC maps
// request_id -> { serverUrl, roomId, pc, dc, hash, remotePeerId?, iceBuf?, incomingIceBuf?, haveAnswer? }
const pendingRequests = new Map();
// request_id -> { serverUrl, roomId, pc, hash }
const serveRequests   = new Map();
// request_id -> ICE buffered before responder PC exists
const preServeIce     = new Map();

// ====== UTIL ======
function roomKey(serverUrl, roomId){ return `${normServer(serverUrl)}|${roomId}`; }
function b64u(bytes) { return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING); }
function fromB64u(str) { return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING); }
function nowMs() { return Date.now(); }
function sevenDaysAgoMs() { return nowMs() - 7 * 24 * 60 * 60 * 1000; }
function setStatus(text) { ui.status.textContent = text; }
function shortId(idB64u) { return idB64u.slice(0, 6) + '…' + idB64u.slice(-6); }
function randomB64u(n = 32) {
  const a = new Uint8Array(n); crypto.getRandomValues(a);
  return b64u(a); // you already have b64u(..) in your codebase
}
function hostFromUrl(u){
  try { const x = new URL(normServer(u)); return x.host; } catch { return u; }
}
async function sha256_b64u_bytes(u8) {
  const d = await crypto.subtle.digest('SHA-256', u8);
  return b64u(new Uint8Array(d));
}

const _subtle = crypto.subtle;
const subtleImportKey = _subtle.importKey.bind(_subtle);
const subtleDeriveKey = _subtle.deriveKey.bind(_subtle);
const subtleEncrypt   = _subtle.encrypt.bind(_subtle);
const subtleDecrypt   = _subtle.decrypt.bind(_subtle);

const te = new TextEncoder();

async function setKeyCheckMarker() {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveAesKey(salt, ['encrypt']);
  const ct   = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, KEYCHECK_PLAINTEXT));
  const payload = { salt: b64u(salt), iv: b64u(iv), ct: b64u(ct) };
  localStorage.setItem(KEYCHECK_LS_KEY, JSON.stringify(payload));
}

async function verifyKeyCheck() {
  const raw = localStorage.getItem(KEYCHECK_LS_KEY);
  if (!raw) {
    // First run under this scheme: create marker now for future checks
    await setKeyCheckMarker();
    return true;
  }
  try {
    const sealed = JSON.parse(raw);
    const salt = fromB64u(sealed.salt);
    const iv   = fromB64u(sealed.iv);
    const ct   = fromB64u(sealed.ct);
    const key  = await deriveAesKey(salt, ['decrypt']);
    const pt   = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
    if (pt.length !== KEYCHECK_PLAINTEXT.length) return false;
    for (let i = 0; i < pt.length; i++) if (pt[i] !== KEYCHECK_PLAINTEXT[i]) return false;
    return true;
  } catch {
    return false;
  }
}

function getStartupPassString() {
  if (SETTINGS.requirePass) {
    const pass = sessionStorage.getItem(MASTER_PASS_SS_KEY);
    if (!pass) throw new Error('locked');  // UI will handle unlocking
    return pass;
  } else {
    let pass = localStorage.getItem(MASTER_PASS_LS_KEY);
    if (!pass) {
      pass = randomB64u(32);
      localStorage.setItem(MASTER_PASS_LS_KEY, pass);
    }
    return pass;
  }
}

async function ensureMasterBaseKey() {
  if (MASTER_BASE_KEY) return MASTER_BASE_KEY;
  const pass = getStartupPassString();
  MASTER_BASE_KEY = await crypto.subtle.importKey(
    'raw',
    te.encode(pass),
    { name: 'PBKDF2' },
    /* extractable */ false,
    ['deriveKey']
  );
  return MASTER_BASE_KEY;
}

function getOrCreateMasterPass() {
  let pass = localStorage.getItem(MASTER_PASS_LS_KEY);
  if (!pass) {
    pass = randomB64u(32);
    localStorage.setItem(MASTER_PASS_LS_KEY, pass);
  }
  return pass;
}

// Re-key all sealed room secrets to a NEW password.
// persist = true  -> store pass in localStorage (OFF mode; auto-unlock)
// persist = false -> store pass in sessionStorage only (ON mode; prompt each run)
async function rotateMasterPassTo(newPass, { persist }) {
  // 1) Collect plaintext secrets with CURRENT base key
  const secrets = [];
  for (const r of rooms) {
    const sealed = await secretGet(r.id);
    if (!sealed) continue;
    const skB64 = await openSecret(sealed); // uses current MASTER_BASE_KEY
    secrets.push({ id: r.id, skB64 });
  }

  // 2) Swap storage & derive new base key
  if (persist) {
    localStorage.setItem(MASTER_PASS_LS_KEY, newPass);
    sessionStorage.removeItem(MASTER_PASS_SS_KEY);
  } else {
    sessionStorage.setItem(MASTER_PASS_SS_KEY, newPass);
    localStorage.removeItem(MASTER_PASS_LS_KEY);
  }
  MASTER_BASE_KEY = await crypto.subtle.importKey(
    'raw', te.encode(newPass), { name:'PBKDF2' }, false, ['deriveKey']
  );

  // 3) Re-seal with the new base key
  for (const s of secrets) {
    const sealed2 = await sealSecret(s.skB64); // uses NEW MASTER_BASE_KEY under the hood
    await secretPut(s.id, sealed2);
  }

  await setKeyCheckMarker();    
}

// Derive a per-room AES-GCM key (non-extractable) from the base key + salt
async function deriveAesKey(saltU8, usages = ['encrypt','decrypt'], iterations = PBKDF2_ITERS_CURRENT) {
  return subtleDeriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltU8, iterations },
    await ensureMasterBaseKey(),
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

// Seals a base64url string (roomSkB64) -> {salt, iv, ct} (all base64url)
async function sealSecret(roomSkB64) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveAesKey(salt, ['encrypt'], PBKDF2_ITERS_CURRENT);
  const pt   = fromB64u(roomSkB64);
  const ct   = new Uint8Array(await subtleEncrypt({ name: 'AES-GCM', iv }, key, pt));
  return {
    kdf: { a: 'PBKDF2-SHA256', i: PBKDF2_ITERS_CURRENT },   // <— stored for migration
    salt: b64u(salt), iv: b64u(iv), ct: b64u(ct)
  };
}

async function openSecret(sealed) {
  const salt = fromB64u(sealed.salt);
  const iv   = fromB64u(sealed.iv);
  const ct   = fromB64u(sealed.ct);
  const iters = (sealed.kdf && sealed.kdf.i) ? Number(sealed.kdf.i) : PBKDF2_ITERS_CURRENT;
  const key  = await deriveAesKey(salt, ['decrypt'], iters);
  const pt   = new Uint8Array(await subtleDecrypt({ name: 'AES-GCM', iv }, key, ct));
  return b64u(pt);
}

function openSecretDB() {
  if (secretDbP) return secretDbP;
  secretDbP = new Promise((resolve, reject) => {
    const req = indexedDB.open(SECRET_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(SECRET_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return secretDbP;
}
async function secretPut(roomId, value) {
  const db = await openSecretDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(SECRET_STORE, 'readwrite');
    tx.objectStore(SECRET_STORE).put(value, roomId);
    tx.oncomplete = () => res(true);
    tx.onerror = () => rej(tx.error);
  });
}
async function secretGet(roomId) {
  const db = await openSecretDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(SECRET_STORE, 'readonly');
    const req = tx.objectStore(SECRET_STORE).get(roomId);
    req.onsuccess = () => res(req.result || null);
    req.onerror = () => rej(req.error);
  });
}

// yam-v1:<host[:port]>:<pk_b64u>
function encodeInviteCode(host, pkB64u){
  return `yam-v1:${host}:${pkB64u}`;
}

async function parseInviteCode(raw) {
  const s = (raw || '').trim();
  const prefix = 'yam-v1:';
  if (!s.toLowerCase().startsWith(prefix)) throw new Error('Code must start with yam-v1:');
  const rest = s.slice(prefix.length);
  const i = rest.indexOf(':');
  if (i < 0) throw new Error('Missing server or key.');
  const serverPart = rest.slice(0, i).trim();
  const keyPart    = rest.slice(i + 1).trim();
  if (!serverPart) throw new Error('Missing server.');
  if (!keyPart) throw new Error('Missing invite public key.');
  const server = normServer(serverPart);

  await ensureSodium();
  let pub;
  try { pub = fromB64u(keyPart); } catch { throw new Error('Bad base64url key.'); }
  if (!(pub instanceof Uint8Array) || pub.length !== 32) throw new Error('Invite public key must be 32 bytes.');
  const pubHashB64 = await sha256_b64u_bytes(pub);
  return { server, pubB64: keyPart, pub, pubHashB64 };
}

// Camera QR scanning (BarcodeDetector API). Graceful fallback to manual paste.
let _scanStream = null, _scanRAF = 0, _detector = null;
async function startInviteScan() {
  if (!('BarcodeDetector' in window)) {
    alert('QR scanning not supported in this browser. Paste the code instead.');
    return;
  }
  try {
    _detector = new BarcodeDetector({ formats: ['qr_code'] });
  } catch {
    alert('QR scanning unavailable on this device. Paste the code instead.');
    return;
  }
  inv.scanArea.classList.remove('hidden');
  try {
    _scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch {
    alert('Camera permission denied. Paste the code instead.');
    stopInviteScan();
    return;
  }
  inv.scanVideo.srcObject = _scanStream;
  await inv.scanVideo.play();

  const loop = async () => {
    if (!_scanStream) return;
    try {
      const results = await _detector.detect(inv.scanVideo);
      if (results && results.length) {
        const val = (results[0].rawValue || '').trim();
        if (val) {
          inv.codeInput.value = val;
          stopInviteScan();
          // optional: auto-send after successful scan:
          // deliverInvite();
          return;
        }
      }
    } catch {}
    _scanRAF = requestAnimationFrame(loop);
  };
  _scanRAF = requestAnimationFrame(loop);
}

function stopInviteScan() {
  if (_scanRAF) cancelAnimationFrame(_scanRAF);
  _scanRAF = 0;
  if (inv.scanVideo) {
    try { inv.scanVideo.pause(); } catch {}
    inv.scanVideo.srcObject = null;
  }
  if (_scanStream) {
    try { _scanStream.getTracks().forEach(t => t.stop()); } catch {}
    _scanStream = null;
  }
  inv.scanArea.classList.add('hidden');
}

// Send the encrypted room secret to the invitee’s waiting connection
async function deliverInvite() {
  const code = (inv.codeInput.value || '').trim();
  if (!code) { alert('Paste or scan the invite code first.'); return; }

  // Need an active room (the one you’re inviting to)
  const room = getCurrentRoom?.();
  if (!room) { alert('Open a room to invite someone to.'); return; }

  let parsed;
  try {
    parsed = await parseInviteCode(code);
  } catch (e) {
    alert(e.message || 'Invalid invite code.');
    return;
  }

  // Enforce relay match to avoid accidental cross-server delivery
  const expected = normServer(room.server);
  if (parsed.server !== expected) {
    alert(`Server mismatch.\nCode is for: ${parsed.server}\nCurrent room uses: ${expected}`);
    return;
  }

  // Ensure we have the room secret locally
  let sealedSecret;
  try {
    const sealed = await secretGet(room.id);               // sealed under your master password
    const roomSkB64 = await openSecret(sealed);            // base64url string (Ed25519 private key)
    await ensureSodium();
    const payload = JSON.stringify({
      ver: 1,
      kind: 'room-invite',
      room: {
        id: room.id,
        name: room.name || 'Room',
        server: expected,
        roomSkB64,
        createdAt: room.createdAt || nowMs()
      }
    });
    // Encrypt to invitee’s X25519 public key (sealed box)
    sealedSecret = b64u(sodium.crypto_box_seal(utf8ToBytes(payload), parsed.pub));
  } catch (e) {
    console.error(e);
    alert('Could not access or encrypt the room key on this device.');
    return;
  }

  // Use the existing WS connection for this relay (no new socket)
  const sc = servers.get(expected) || ensureServerConnection(expected);
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN) {
    alert('Not connected to the relay yet. Try again in a moment.');
    return;
  }

  try {
    sc.ws.send(JSON.stringify({
      type: 'invite-send',
      hash: parsed.pubHashB64,
      ciphertext: sealedSecret
    }));
    inv.btnSend.disabled = true;
    const old = inv.btnSend.textContent;
    inv.btnSend.textContent = 'Sent';
    setTimeout(() => { inv.btnSend.disabled = false; inv.btnSend.textContent = old; inv.dlg.close(); }, 900);
  } catch (e) {
    console.error(e);
    alert('Failed to send invite to the relay.');
  }
}

async function clearRoomData(serverUrl, roomId){
  const db = await openMsgDB();
  const key = roomKey(serverUrl, roomId);
  // delete all msgs for room + marker
  return new Promise((res, rej) => {
    const tx = db.transaction(MSG_STORE, 'readwrite');
    const store = tx.objectStore(MSG_STORE);
    const idx = store.index('byRoomTsId');
    const lower = [key, 0, ''];
    const upper = [key, Number.MAX_SAFE_INTEGER, '\uffff'];
    const req = idx.openCursor(IDBKeyRange.bound(lower, upper));
    req.onsuccess = e => {
      const cur = e.target.result;
      if (!cur) return;
      store.delete(cur.primaryKey);
      cur.continue();
    };
    tx.oncomplete = () => res(true);
    tx.onerror = () => rej(tx.error);
  });
}

function openProfileDB() {
  if (profileDbPromise) return profileDbPromise;
  profileDbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(PROFILE_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(PROFILE_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return profileDbPromise;
}
async function profileGet(key) {
  const db = await openProfileDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(PROFILE_STORE, 'readonly');
    const store = tx.objectStore(PROFILE_STORE);
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
async function profilePut(key, value) {
  const db = await openProfileDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(PROFILE_STORE, 'readwrite');
    const store = tx.objectStore(PROFILE_STORE);
    const req = store.put(value, key);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}
async function profileDel(key) {
  const db = await openProfileDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(PROFILE_STORE, 'readwrite');
    const store = tx.objectStore(PROFILE_STORE);
    const req = store.delete(key);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}

async function ensureSodium() { await sodium.ready; }
function normServer(url){
  if (!url) return '';
  let u = url.trim();
  if (u.endsWith('/')) u = u.slice(0,-1);
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}
function scrollToEnd() {
  const el = ui.messages; if (!el) return;
  const doScroll = () => { el.scrollTop = el.scrollHeight; };
  doScroll(); requestAnimationFrame(doScroll); setTimeout(doScroll, 0);
}
function clearMessagesUI() { ui.messages.innerHTML = ''; }

function utf8ToBytes(str){ return new TextEncoder().encode(str); }
function bytesToUtf8(bytes){ return new TextDecoder().decode(bytes); }
function packSignal(obj){ return b64u(utf8ToBytes(JSON.stringify(obj))); }
function unpackSignal(code){
  try { return JSON.parse(bytesToUtf8(fromB64u(code.trim()))); }
  catch { return null; }
}

// Wait until ICE gathering completes (no trickle)
//function waitIceComplete(pc){
//  if (pc.iceGatheringState === 'complete') return Promise.resolve();
//  return new Promise(res => {
//    const check = () => {
//      if (pc.iceGatheringState === 'complete') {
//        pc.removeEventListener('icegatheringstatechange', check);
//        res();
//      }
//    };
//    pc.addEventListener('icegatheringstatechange', check);
//    // fallback: also re-check after a short delay
//    setTimeout(check, 100);
//  });
//}

// Collect ICE candidates for a short window, not until "complete"
function gatherIceCandidates(pc, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const candidates = [];
    const onCand = (e) => { if (e.candidate) candidates.push(iceToJSON(e.candidate)); };
    pc.addEventListener('icecandidate', onCand);

    const finish = () => {
      pc.removeEventListener('icecandidate', onCand);
      resolve({ sdp: pc.localDescription?.sdp || '', candidates });
    };

    if (pc.iceGatheringState === 'complete') return finish();

    const onState = () => {
      if (pc.iceGatheringState === 'complete') {
        pc.removeEventListener('icegatheringstatechange', onState);
        finish();
      }
    };
    pc.addEventListener('icegatheringstatechange', onState);

    setTimeout(() => {
      pc.removeEventListener('icegatheringstatechange', onState);
      finish();
    }, timeoutMs);
  });
}

// Wait until all queued bytes have left the datachannel, or timeout
async function waitForDrain(dc, { settleMs = 200, timeoutMs = 5000 } = {}) {
  if (!dc || dc.readyState !== 'open') return;
  return new Promise((resolve) => {
    let done = false;
    const start = performance.now();
    function maybeDone() {
      if (done) return;
      if (dc.readyState !== 'open') { done = true; return resolve(); }
      if (dc.bufferedAmount === 0) {
        setTimeout(() => { done = true; resolve(); }, settleMs);
      } else if (performance.now() - start > timeoutMs) {
        done = true; resolve();
      } else {
        setTimeout(maybeDone, 50);
      }
    }
    try {
      dc.bufferedAmountLowThreshold = Math.max(16384, CHUNK_SIZE >> 2);
      const onLow = () => maybeDone();
      dc.addEventListener('bufferedamountlow', onLow, { once: true });
    } catch {}
    maybeDone();
  });
}

function derivePubFromSk(sk) {
  if (sodium.crypto_sign_ed25519_sk_to_pk) return sodium.crypto_sign_ed25519_sk_to_pk(sk);
  return sk.slice(32, 64);
}

async function setCryptoForRoom(room) {
  edSk = await getRoomPrivateKeyBytes(room.id);
  if (!(edSk instanceof Uint8Array) || edSk.length !== 64) {
    console.error('Room secret must be 64 bytes; got', edSk && edSk.length);
    throw new Error('invalid-room-secret');
  }
  edPk = derivePubFromSk(edSk);
  curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);
}

function iceToJSON(c) {
  if (!c) return null;
  const j = typeof c.toJSON === 'function'
    ? c.toJSON()
    : { candidate: c.candidate, sdpMid: c.sdpMid, sdpMLineIndex: c.sdpMLineIndex, usernameFragment: c.usernameFragment };
  if (DEBUG_RTC) dbg('RTC/ICE->JSON', { hasCandidate: !!j.candidate, mid: j.sdpMid, mline: j.sdpMLineIndex });
  return j;
}

async function getRoomPrivateKeyBytes(roomId) {
  const sealed = await secretGet(roomId);
  if (!sealed) throw new Error('Room secret missing locally');
  const skB64 = await openSecret(sealed);
  return fromB64u(skB64);
}

// ====== IndexedDB (files by hash) ======
const DB_NAME = 'secmsg_files_db';
const STORE = 'files';
let dbPromise = null;
function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}
async function idbGet(hash) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const store = tx.objectStore(STORE);
    const req = store.get(hash);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
async function idbPut(hash, blob) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    const req = store.put(blob, hash);
    req.onsuccess = () => resolve(true);
    req.onerror = () => reject(req.error);
  });
}
async function sha256_b64u(blob) {
  const buf = await blob.arrayBuffer();
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const bytes = new Uint8Array(digest);
  return b64u(bytes);
}

// ====== IndexedDB (messages by room) ======

let msgDbPromise = null;
function openMsgDB(){
  if (msgDbPromise) return msgDbPromise;
  msgDbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(MSG_DB, 2);
    req.onupgradeneeded = () => {
      const db = req.result;
      let s;
      if (!db.objectStoreNames.contains(MSG_STORE)) {
        s = db.createObjectStore(MSG_STORE, { keyPath: 'id' });
      } else {
        s = req.transaction.objectStore(MSG_STORE);
      }
      if (!s.indexNames.contains('byRoomTsId')) s.createIndex('byRoomTsId', ['roomKey','ts', 'id'], { unique:false });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return msgDbPromise;
}

async function msgPut(rec){
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(MSG_STORE, 'readwrite');
    tx.objectStore(MSG_STORE).put(rec);
    tx.oncomplete = () => res(true);
    tx.onerror = () => rej(tx.error);
  });
}
async function msgBulkPut(recs){
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(MSG_STORE, 'readwrite');
    const store = tx.objectStore(MSG_STORE);
    for (const r of recs) store.put(r);
    tx.oncomplete = () => res(true);
    tx.onerror = () => rej(tx.error);
  });
}

async function msgDeleteRoom(serverUrl, roomId){
  const list = await msgListByRoom(serverUrl, roomId);
  if (!list.length) return;
  const db = await openMsgDB();
  await new Promise((res, rej) => {
    const tx = db.transaction(MSG_STORE, 'readwrite');
    const store = tx.objectStore(MSG_STORE);
    for (const r of list) store.delete(r.id);
    tx.oncomplete = () => res(true);
    tx.onerror = () => rej(tx.error);
  });
}
async function sha256_b64u_string(s){
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return b64u(new Uint8Array(digest));
}

async function msgPageByRoom(serverUrl, roomId, { beforeTs = Number.MAX_SAFE_INTEGER, limit = PAGE_SIZE } = {}) {
  const key = roomKey(serverUrl, roomId);
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const out = [];
    const tx  = db.transaction(MSG_STORE, 'readonly');
    const idx = tx.objectStore(MSG_STORE).index('byRoomTsId');
    const lower = [key, 0, ''];
    const upper = [key, Math.max(0, beforeTs - 1), '\uffff'];
    const range = IDBKeyRange.bound(lower, upper);
    const req = idx.openCursor(range, 'prev'); // newest first
    req.onsuccess = e => {
      const cur = e.target.result;
      if (!cur || out.length >= limit) return res(out.reverse()); // return ascending
      out.push(cur.value);
      cur.continue();
    };
    req.onerror = () => rej(req.error);
  });
}

async function msgGetLastTs(serverUrl, roomId){
  const key = roomKey(serverUrl, roomId);
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const tx  = db.transaction(MSG_STORE, 'readonly');
    const idx = tx.objectStore(MSG_STORE).index('byRoomTsId');
    const lower = [key, 0, ''];
    const upper = [key, Number.MAX_SAFE_INTEGER, '\uffff'];
    const range = IDBKeyRange.bound(lower, upper);
    const req = idx.openCursor(range, 'prev'); // newest first
    req.onsuccess = e => {
      const cur = e.target.result;
      if (!cur) return res(0);
      res(cur.value.ts || 0);
    };
    req.onerror = () => rej(req.error);
  });
}

async function msgListByRoom(serverUrl, roomId){
  const key = roomKey(serverUrl, roomId);
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const out = [];
    const tx  = db.transaction(MSG_STORE, 'readonly');
    const idx = tx.objectStore(MSG_STORE).index('byRoomTsId');
    const lower = [key, 0, ''];
    const upper = [key, Number.MAX_SAFE_INTEGER, '\uffff'];
    const range = IDBKeyRange.bound(lower, upper);
    const req = idx.openCursor(range, 'next'); // ascending
    req.onsuccess = e => {
      const cur = e.target.result;
      if (!cur) return res(out);
      out.push(cur.value);
      cur.continue();
    };
    req.onerror = () => rej(req.error);
  });
}

// ====== Rooms store ======
function loadSettings() {
  try { SETTINGS = { ...SETTINGS, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; }
  catch {}
}
function saveSettings() { localStorage.setItem(SETTINGS_KEY, JSON.stringify(SETTINGS)); }

function loadRooms(){
  try { rooms = JSON.parse(localStorage.getItem(ROOMS_KEY) || '[]'); } catch { rooms = []; }
  currentRoomId = localStorage.getItem(CURRENT_ROOM_KEY) || null;
  if (!currentRoomId && rooms.length) currentRoomId = rooms[0].id;
}
function saveRooms(){
  localStorage.setItem(ROOMS_KEY, JSON.stringify(rooms));
  if (currentRoomId) localStorage.setItem(CURRENT_ROOM_KEY, currentRoomId);
}
function getCurrentRoom(){
  return rooms.find(r => r.id === currentRoomId) || null;
}
function setCurrentRoom(roomId){
  currentRoomId = roomId;
  saveRooms();
  const r = getCurrentRoom();
  ui.currentRoomName.textContent = r ? r.name : 'No room';
}
function getRoomsByServer() {
  const by = new Map();
  for (const r of rooms) {
    const url = normServer(r.server);
    if (!by.has(url)) by.set(url, []);
    by.get(url).push(r);
  }
  return by;
}

// ====== Identity ======
function persistIdentity() {
  // Always set myPeerId and UI, and keep storage in sync
  myPeerId = b64u(myIdPk);
  localStorage.setItem('secmsg_id_pk', myPeerId);
  localStorage.setItem('secmsg_id_sk', b64u(myIdSk));
}

async function ensureIdentity() {
  await ensureSodium();
  try {
    const pk = localStorage.getItem('secmsg_id_pk');
    const sk = localStorage.getItem('secmsg_id_sk');
    if (pk && sk) {
      // Rehydrate from storage
      myIdPk = fromB64u(pk);
      myIdSk = fromB64u(sk);
    } else {
      // First run (or storage empty) → create a new pair
      const pair = sodium.crypto_sign_keypair();
      myIdPk = pair.publicKey;
      myIdSk = pair.privateKey;
    }
  } catch {
    // Storage corrupted or decode failed → recover with a fresh pair
    const pair = sodium.crypto_sign_keypair();
    myIdPk = pair.publicKey;
    myIdSk = pair.privateKey;
  }
  // IMPORTANT: always call persistIdentity so myPeerId is set
  persistIdentity();
}

function announceIdentityToServers() {
  for (const [, sc] of servers) {
    if (!sc.ws || sc.ws.readyState !== WebSocket.OPEN) continue;
    for (const roomId of sc.authed || []) {
      try { sc.ws.send(JSON.stringify({ type:'announce', room_id: roomId, peer_id: myPeerId })); } catch {}
    }
  }
}

// ====== Rendering ======
function renderTextMessage({ text, ts, nickname, senderId, verified }, { prepend=false } = {}) {
  const row = document.createElement('div');
  const isMe = senderId && myPeerId && senderId === myPeerId;
  row.className = 'row ' + (isMe ? 'me' : 'other');

  const wrap = document.createElement('div'); wrap.className = 'wrap';
  const label = document.createElement('div'); label.className = 'name-label';
  const who = nickname || (senderId ? shortId(senderId) : 'room');
  const when = new Date(ts || nowMs()).toLocaleString();
  label.textContent = `${who} • ${when}${verified === false ? ' • ⚠︎ unverified' : ''}`;

  const bubble = document.createElement('div'); bubble.className = 'bubble';
  bubble.textContent = text;

  wrap.appendChild(label); wrap.appendChild(bubble); row.appendChild(wrap);
  if (prepend) ui.messages.insertBefore(row, ui.messages.firstChild);
  else ui.messages.appendChild(row);
  return row;
}

function fileBubbleSkeleton({ meta, ts, nickname, senderId, verified }, { prepend=false } = {}) {
  const row = document.createElement('div');
  const isMe = senderId && myPeerId && senderId === myPeerId;
  row.className = 'row ' + (isMe ? 'me' : 'other');

  const wrap = document.createElement('div'); wrap.className = 'wrap';
  const label = document.createElement('div'); label.className = 'name-label';
  const who = nickname || (senderId ? shortId(senderId) : 'room');
  const when = new Date(ts || nowMs()).toLocaleString();
  label.textContent = `${who} • ${when}${verified === false ? ' • ⚠︎ unverified' : ''}`;

  const bubble = document.createElement('div'); bubble.className = 'bubble';
  bubble.dataset.hash = meta.hash;
  if (meta.mime && meta.mime.startsWith('image/')) bubble.textContent = 'Image pending…';
  else {
    const p = document.createElement('div');
    p.textContent = `${meta.name || 'file'} (${meta.size || '?'} bytes)`;
    bubble.appendChild(p);
  }

  wrap.appendChild(label); wrap.appendChild(bubble); row.appendChild(wrap);
  if (prepend) ui.messages.insertBefore(row, ui.messages.firstChild);
  else ui.messages.appendChild(row);
  return bubble;
}

async function renderFileIfAvailable(bubbleEl, meta) {
  if (!bubbleEl) return false; // not active room
  const blob = await idbGet(meta.hash);
  if (!blob) return false;

  bubbleEl.innerHTML = '';
  const url = URL.createObjectURL(blob);

  if (meta.mime && meta.mime.startsWith('image/')) {
    const img = document.createElement('img');
    img.onload = () => URL.revokeObjectURL(url);
    img.src = url;
    img.alt = meta.name || 'image';
    bubbleEl.appendChild(img);
  } else {
    const link = document.createElement('a');
    link.href = url;
    link.textContent = `${meta.name || 'file'} (${meta.size || blob.size} bytes)`;
    link.className = 'file-link';
    link.target = '_blank';
    link.rel = 'noopener';
    link.download = meta.name || 'file';
    link.addEventListener('click', () => setTimeout(() => URL.revokeObjectURL(url), 0), { once: true });
    bubbleEl.appendChild(link);
  }

  return true;
}

function showPendingBubble(bubbleEl, meta) {
  if (!bubbleEl) return;
  bubbleEl.innerHTML = '';
  const wrap = document.createElement('div'); wrap.className = 'pending';
  const label = document.createElement('span');
  label.textContent = meta.mime && meta.mime.startsWith('image/') ? 'Image pending…' : 'File pending…';
  const btn = document.createElement('button');
  btn.className = 'retry-btn'; btn.type = 'button'; btn.title = 'Retry';
  btn.innerHTML = `
    <svg class="retry-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 5v2.5l3.5-3.5L12 0.5V3a9 9 0 1 0 9 9h-2a7 7 0 1 1-7-7z"/>
    </svg>`;
  const hash = meta.hash;
  btn.addEventListener('click', async () => {
    const ok = await renderFileIfAvailable(bubbleEl, meta);
    if (!ok) requestFile(meta.room_id || currentRoomId, hash);
  });
  wrap.appendChild(label); wrap.appendChild(btn);
  bubbleEl.appendChild(wrap);
}

// ====== Encrypt/Decrypt ======
function encryptStringForRoom(str) {
  const cipher = sodium.crypto_box_seal(sodium.from_string(str), curvePk);
  return b64u(cipher);
}
function decryptToString(cipherB64u) {
  const cipher = fromB64u(cipherB64u);
  try {
    const plain = sodium.crypto_box_seal_open(cipher, curvePk, curveSk);
    return sodium.to_string(plain);
  } catch {
    return '[unable to decrypt]';
  }
}
function signCiphertextB64(ciphertextB64) {
  const sig = sodium.crypto_sign_detached(fromB64u(ciphertextB64), myIdSk);
  return b64u(sig);
}

// ====== Send/Receive ======
async function sendTextMessage(room, text) {
  const ciphertextB64 = encryptStringForRoom(text);
  const payload = {
    type: 'send',
    room_id: room.id,
    ciphertext: ciphertextB64,
    ts_client: nowMs(),
    nickname: SETTINGS.username || undefined,
    sender_id: myPeerId,
    sig: signCiphertextB64(ciphertextB64),
  };
  const sc = servers.get(normServer(room.server));
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN || !sc.authed?.has(room.id)) {
    alert('Not connected');
    return;
  }
  if (DEBUG_SIG) dbg('SIG/TX', 'send:text', { room: room.name, len: text.length });
  sc.ws.send(JSON.stringify(payload));
}

async function sendFileMetadata(room, meta) {
  const metaJson = JSON.stringify({ kind: 'file', ...meta });
  const ciphertextB64 = encryptStringForRoom(metaJson);
  const payload = {
    type: 'send',
    room_id: room.id,
    ciphertext: ciphertextB64,
    ts_client: nowMs(),
    nickname: SETTINGS.username || undefined,
    sender_id: myPeerId,
    sig: signCiphertextB64(ciphertextB64),
  };
  const sc = servers.get(normServer(room.server));
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN || !sc.authed?.has(room.id)) {
    alert('Not connected');
    return;
  }
  if (DEBUG_SIG) dbg('SIG/TX', 'send:file-meta', { room: room.name, hash: meta.hash, name: meta.name, mime: meta.mime, size: meta.size });
  sc.ws.send(JSON.stringify(payload));
}

async function handleIncoming(serverUrl, m, fromHistory = false) {
  // Decrypt
  const pt = decryptToString(m.ciphertext);

  // Figure out which room this belongs to
  const roomId = m.room_id || currentRoomId;
  const rKey   = roomKey(serverUrl, roomId);

  // Stable message id: roomKey + sha256(ciphertext)
  const idHash = await sha256_b64u_string(m.ciphertext);
  const id     = `${rKey}|${idHash}`;

  // Optional signature verification (over the ciphertext)
  let verified = undefined;
  if (m.sender_id && m.sig) {
    try {
      const senderPk   = fromB64u(m.sender_id);
      const sigBytes   = fromB64u(m.sig);
      const cipherBytes= fromB64u(m.ciphertext);
      verified = sodium.crypto_sign_verify_detached(sigBytes, cipherBytes, senderPk);
    } catch { verified = false; }
  }

  const tsVal = m.ts || nowMs();

  // Try to interpret payload as a file-metadata message
  let isFile = false, meta = null;
  try {
    const obj = JSON.parse(pt);
    if (obj && obj.kind === 'file' && obj.hash) {
      isFile = true;
      // carry room for convenience in requestFile()
      meta = { ...obj, room_id: roomId };
    }
  } catch { /* not JSON → plain text */ }

  // Persist first (IDB dedupe is by primary key 'id')
  if (isFile) {
    await msgPut({
      id,
      roomKey: rKey,
      roomId,
      serverUrl,
      ts: tsVal,
      nickname: m.nickname,
      senderId: m.sender_id,
      verified,
      kind: 'file',
      meta
    });
  } else {
    await msgPut({
      id,
      roomKey: rKey,
      roomId,
      serverUrl,
      ts: tsVal,
      nickname: m.nickname,
      senderId: m.sender_id,
      verified,
      kind: 'text',
      text: pt
    });
  }

  // Only render if this message is for the *currently visible* room and not from history
  const isActive = (VL && VL.serverUrl === serverUrl && VL.roomId === roomId);
  if (!isActive || fromHistory) return;

  // Runtime replay guard: if we've already rendered this id in the live view, skip
  if (VL.seenIds && VL.seenIds.has(id)) return;
  if (VL.seenIds) VL.seenIds.add(id);

  // Render
  if (isFile) {
    const bubble = fileBubbleSkeleton(
      { meta, ts: tsVal, nickname: m.nickname, senderId: m.sender_id, verified }
    );
    renderFileIfAvailable(bubble, meta).then(ok => {
      if (!ok) {
        showPendingBubble(bubble, meta);
        requestFile(roomId, meta.hash);
      } else {
        scrollToEnd();
      }
    });
  } else {
    appendLiveRecord({
      kind: 'text',
      ts: tsVal,
      nickname: m.nickname,
      senderId: m.sender_id,
      verified,
      text: pt
    });
  }
}

// ====== WebRTC Signaling (via server) ======
function randomIdB64(n=16) {
  const a = new Uint8Array(n); crypto.getRandomValues(a); return b64u(a);
}

async function requestFile(room_id, hash) {
  const room = rooms.find(r => r.id === room_id);
  if (!room) return;
  const sc = servers.get(normServer(room.server));
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN) return;

  if (DEBUG_RTC) dbg('RTC/REQ', 'start', { room: room.name, hash });

  const pc = new RTCPeerConnection(RTC_CONFIG);
  pc.oniceconnectionstatechange = () => dbg('RTC/REQ iceState', pc.iceConnectionState);
  pc.onconnectionstatechange = () => dbg('RTC/REQ pcState', pc.connectionState);

  const dc = pc.createDataChannel('file');
  const reqId = randomIdB64(16);
  const state = { serverUrl: normServer(room.server), roomId: room_id, pc, dc, hash, remotePeerId: null, iceBuf: [], incomingIceBuf: [], haveAnswer: false };
  pendingRequests.set(reqId, state);

  dc.binaryType = 'arraybuffer';
  dc.onopen = () => { if (DEBUG_RTC) dbg('RTC/REQ', 'dc open', { reqId }); };
  dc.onclose = () => { if (DEBUG_RTC) dbg('RTC/REQ', 'dc close', { reqId }); };
  dc.onerror = (e) => { if (DEBUG_RTC) dbg('RTC/REQ', 'dc error', { reqId, e }); };

  let header = null, chunks = [], received = 0, expected = 0;
  dc.onmessage = async (evt) => {
    if (!header) {
      header = JSON.parse(new TextDecoder().decode(evt.data));
      expected = header.size|0;
      if (DEBUG_RTC) dbg('RTC/REQ', 'header', { reqId, hash, expected, mime: header.mime, name: header.name });
      return;
    }
    chunks.push(evt.data);
    received += evt.data.byteLength || (evt.data.size||0);
    if (DEBUG_RTC && received % (512*1024) < CHUNK_SIZE) dbg('RTC/REQ', 'chunk', { reqId, received, expected });
    if (expected && received >= expected) {
      if (DEBUG_RTC) dbg('RTC/REQ', 'complete', { reqId, received });
      const blob = new Blob(chunks, { type: header.mime || 'application/octet-stream' });
      await idbPut(hash, blob);
      const bubble = ui.messages.querySelector(`.bubble[data-hash="${hash}"]`);
      if (bubble) await renderFileIfAvailable(bubble, header);
      try { dc.close(); } catch {}
      try { pc.close(); } catch {}
      pendingRequests.delete(reqId);
      scrollToEnd();
    }
  };

  pc.onicecandidate = (e) => {
    const cand = iceToJSON(e.candidate);
    if (!cand) { if (DEBUG_RTC) dbg('RTC/REQ', 'ice end', { reqId }); return; }
    if (state.remotePeerId) {
      if (DEBUG_SIG) dbg('SIG/TX', 'ice (req->resp)', { reqId, mid: cand.sdpMid, mline: cand.sdpMLineIndex });
      sc.ws.send(JSON.stringify({ type: 'webrtc-ice', room_id, request_id: reqId, candidate: cand, to: state.remotePeerId, from: myPeerId }));
    } else {
      state.iceBuf.push(cand);
      if (DEBUG_RTC) dbg('RTC/REQ', 'ice buffered', { reqId, count: state.iceBuf.length });
    }
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  if (DEBUG_RTC) dbg('RTC/REQ', 'offer created', { reqId, sdpLen: (offer.sdp||'').length });

  if (DEBUG_SIG) dbg('SIG/TX', 'webrtc-request', { reqId, hash, sdpLen: (offer.sdp||'').length });
  sc.ws.send(JSON.stringify({ type: 'webrtc-request', room_id, request_id: reqId, checksum: hash, offer, from: myPeerId }));
}

async function serveFileIfWeHaveIt(serverUrl, msg) {
  const { request_id, checksum, from, offer, room_id } = msg;
  const blob = await idbGet(checksum);
  if (!blob) { if (DEBUG_RTC) dbg('RTC/RESP', 'no-file', { request_id, checksum }); return; }

  if (DEBUG_RTC) dbg('RTC/RESP', 'serve', { request_id, checksum, size: blob.size, mime: blob.type, from });

  const pc = new RTCPeerConnection(RTC_CONFIG);
  pc.oniceconnectionstatechange = () => dbg('RTC/RESP iceState', pc.iceConnectionState);
  pc.onconnectionstatechange = () => dbg('RTC/RESP pcState', pc.connectionState);

  serveRequests.set(request_id, { serverUrl, roomId: room_id, pc, hash: checksum });

  pc.ondatachannel = (evt) => {
    const dc = evt.channel;
    dc.binaryType = 'arraybuffer';
    dc.onopen = async () => {

      if (DEBUG_RTC) dbg('RTC/RESP', 'dc open', { request_id });
      dc.bufferedAmountLowThreshold = Math.max(16384, CHUNK_SIZE >> 2);

      const header = { kind: 'file', name: blob.name || 'file', mime: blob.type || 'application/octet-stream', size: blob.size, hash: checksum };
      dc.send(new TextEncoder().encode(JSON.stringify(header)));

      const total = blob.size | 0;
      for (let offset = 0; offset < total; offset += CHUNK_SIZE) {
        const slice = blob.slice(offset, Math.min(offset + CHUNK_SIZE, total));
        const buf = new Uint8Array(await slice.arrayBuffer());
        dc.send(buf);
        if (DEBUG_RTC && (offset % (512 * 1024)) === 0) dbg('RTC/RESP', 'sent', { request_id, offset, total });
        while (dc.bufferedAmount > 8 * CHUNK_SIZE && dc.readyState === 'open') {
          await new Promise(r => setTimeout(r, 10));
        }
      }
      await waitForDrain(dc, { settleMs: 300, timeoutMs: 8000 });
      if (DEBUG_RTC) dbg('RTC/RESP', 'complete', { request_id, total });

      try { dc.close(); } catch {}
      try { pc.close(); } catch {}
      serveRequests.delete(request_id);
    };

    dc.onclose = () => { if (DEBUG_RTC) dbg('RTC/RESP', 'dc close', { request_id }); };
    dc.onerror = (e) => { if (DEBUG_RTC) dbg('RTC/RESP', 'dc error', { request_id, e }); };
  };

  pc.onicecandidate = (e) => {
    const cand = iceToJSON(e.candidate);
    if (!cand) { if (DEBUG_RTC) dbg('RTC/RESP', 'ice end', { request_id }); return; }
    if (DEBUG_SIG) dbg('SIG/TX', 'ice (resp->req)', { request_id, mid: cand.sdpMid, mline: cand.sdpMLineIndex });
    const sc = servers.get(serverUrl);
    if (sc && sc.ws && sc.ws.readyState === WebSocket.OPEN) {
      sc.ws.send(JSON.stringify({ type: 'webrtc-ice', room_id, request_id, candidate: cand, to: from, from: myPeerId }));
    }
  };

  await pc.setRemoteDescription(offer);
  if (DEBUG_RTC) dbg('RTC/RESP', 'offer applied', { request_id });

  const buffered = preServeIce.get(request_id);
  if (buffered && buffered.length) {
    if (DEBUG_RTC) dbg('RTC/RESP', 'flush buffered ICE', { request_id, count: buffered.length });
    for (const cand of buffered) {
      try { await pc.addIceCandidate(new RTCIceCandidate(cand)); } catch (e) { if (DEBUG_RTC) dbg('RTC/RESP', 'flush addIce error', e); }
    }
    preServeIce.delete(request_id);
  }

  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  await new Promise(r => setTimeout(r, 50));
  if (DEBUG_RTC) dbg('RTC/RESP', 'answer created', { request_id, sdpLen: (answer.sdp||'').length });

  const sc = servers.get(serverUrl);
  if (sc && sc.ws && sc.ws.readyState === WebSocket.OPEN) {
    sc.ws.send(JSON.stringify({ type: 'webrtc-response', room_id, request_id, answer, to: from, from: myPeerId, checksum }));
    if (DEBUG_SIG) dbg('SIG/TX', 'webrtc-response', { request_id, to: from, sdpLen: (answer.sdp||'').length });
  }
}

async function handleWebRtcResponse(serverUrl, msg) {
  const { request_id, answer, from } = msg;
  const st = pendingRequests.get(request_id);
  if (!st) return;

  if (st.serverUrl !== serverUrl) return; // safety

  if (DEBUG_SIG) dbg('SIG/RX', 'webrtc-response', { request_id, from, sdpLen: (answer.sdp||'').length });

  if (st.remotePeerId && st.remotePeerId !== from) {
    if (DEBUG_RTC) dbg('RTC/REQ', 'ignore secondary answer', { request_id, from, chosen: st.remotePeerId });
    return;
  }

  await st.pc.setRemoteDescription(answer);
  if (!st.remotePeerId) {
    st.remotePeerId = from;
    st.haveAnswer = true;
    const sc = servers.get(serverUrl);
    if (sc && sc.ws && sc.ws.readyState === WebSocket.OPEN) {
      sc.ws.send(JSON.stringify({
	type: 'webrtc-taken',
	room_id: st.roomId,
	request_id,
	chosen: from,
      }));
    }
  }
  if (DEBUG_RTC) dbg('RTC/REQ', 'answer applied', { request_id });
    
  // Flush buffered OUTGOING ICE
  const sc = servers.get(serverUrl);
  for (const cand of st.iceBuf) {
    sc.ws.send(JSON.stringify({ type:'webrtc-ice', room_id: st.roomId, request_id, candidate: cand, to: from, from: myPeerId }));
  }
  st.iceBuf = [];

  // Flush buffered INCOMING ICE
  if (st.incomingIceBuf.length) {
    if (DEBUG_RTC) dbg('RTC/REQ', 'flush buffered incoming ICE', { request_id, count: st.incomingIceBuf.length });
    for (const cInit of st.incomingIceBuf) {
      try { await st.pc.addIceCandidate(new RTCIceCandidate(cInit)); }
      catch (e) { if (DEBUG_RTC) dbg('RTC/REQ', 'flush addIce error', e); }
    }
    st.incomingIceBuf = [];
  }
}

async function handleWebRtcIce(serverUrl, msg) {
  const { request_id, candidate, from } = msg;
  if (!candidate) return;
  const iceInit = candidate;

  if (pendingRequests.has(request_id)) {
    const st = pendingRequests.get(request_id);
    if (st.serverUrl !== serverUrl) return;

    if (st.remotePeerId && from && from !== st.remotePeerId) {
      if (DEBUG_SIG) dbg('SIG/RX', 'ice from non-selected responder ignored', { request_id, from, chosen: st.remotePeerId });
      return;
    }

    if (!st.haveAnswer) {
      st.incomingIceBuf.push(iceInit);
      if (DEBUG_SIG) dbg('SIG/RX', 'ice buffered (no remoteDescription yet)', { request_id, count: st.incomingIceBuf.length });
      return;
    }

    if (DEBUG_SIG) dbg('SIG/RX', 'ice to requester', { request_id, from, mid: iceInit.sdpMid, mline: iceInit.sdpMLineIndex });
    try { await st.pc.addIceCandidate(new RTCIceCandidate(iceInit)); }
    catch (e) { if (DEBUG_RTC) dbg('RTC/REQ', 'addIce error', e); }

  } else if (serveRequests.has(request_id)) {
    const st = serveRequests.get(request_id);
    if (st.serverUrl !== serverUrl) return;
    if (DEBUG_SIG) dbg('SIG/RX', 'ice to responder', { request_id, from, mid: iceInit.sdpMid, mline: iceInit.sdpMLineIndex });
    try { await st.pc.addIceCandidate(new RTCIceCandidate(iceInit)); }
    catch (e) { if (DEBUG_RTC) dbg('RTC/RESP', 'addIce error', e); }

  } else {
    const arr = preServeIce.get(request_id) || [];
    arr.push(iceInit);
    preServeIce.set(request_id, arr);
    if (DEBUG_SIG) dbg('SIG/RX', 'ice buffered (no serve)', { request_id, count: arr.length });
  }
}

function openInviteDialog(){
  inv.codeInput.value = '';
  inv.scanArea.classList.add('hidden');
  inv.dlg.showModal();
}

// ====== Server connection mgmt ======
function ensureServerConnection(serverUrl) {
  serverUrl = normServer(serverUrl);
  if (servers.has(serverUrl)) {
    const sc = servers.get(serverUrl);
    if (sc.ws && (sc.ws.readyState === WebSocket.OPEN || sc.ws.readyState === WebSocket.CONNECTING)) {
      return sc;
    }
  }
  const sc = {
    url: serverUrl,
    ws: null,
    reconnectAttempt: 0,
    reconnectTimer: null,
    heartbeatTimer: null,
    subscribed: new Set(), // rooms we asked to subscribe
    authed: new Set(),     // rooms that are 'ready'
  };
  servers.set(serverUrl, sc);

  connect(sc);
  return sc;
}

function connect(sc) {
  if (sc.ws) { try { sc.ws.onclose = null; sc.ws.close(); } catch {} }
  sc.ws = new WebSocket(sc.url.replace(/^http/i, 'ws') + '/ws');

  sc.ws.onopen = () => {
    if (DEBUG_SIG) dbg('SIG/WS', 'open', sc.url);
    sc.reconnectAttempt = 0;
    // subscribe to all rooms on this server
    const roomsOnServer = rooms.filter(r => normServer(r.server) === sc.url);
    for (const r of roomsOnServer) {
      sc.subscribed.add(r.id);
      sc.ws.send(JSON.stringify({ type: 'subscribe', room_id: r.id }));
    }
    // heartbeat
    if (sc.heartbeatTimer) clearInterval(sc.heartbeatTimer);
    sc.heartbeatTimer = setInterval(() => {
      try { sc.ws.send(JSON.stringify({ type: 'ping', ts: nowMs() })); } catch {}
    }, 25000);
  };

  sc.ws.onerror = (e) => { if (DEBUG_SIG) dbg('SIG/WS', 'error', sc.url, e); };
  sc.ws.onclose = (e) => {
    if (DEBUG_SIG) dbg('SIG/WS', 'close', sc.url, { code:e.code, reason:e.reason });
    if (sc.heartbeatTimer) { clearInterval(sc.heartbeatTimer); sc.heartbeatTimer = null; }
    sc.authed.clear();
    const r = getCurrentRoom();
    if (r && normServer(r.server) === sc.url) setStatus(statuses.disconnected);
    scheduleReconnect(sc);
  };

  sc.ws.onmessage = async (evt) => {
    const m = JSON.parse(evt.data);
    if (DEBUG_SIG) dbg('SIG/RX', m.type, Object.assign({}, m, {
      ciphertext: m.ciphertext ? `<${m.ciphertext.length} chars>`: undefined,
      offer: m.offer ? { type:m.offer.type, sdpLen: (m.offer.sdp||'').length } : undefined,
      answer: m.answer ? { type:m.answer.type, sdpLen: (m.answer.sdp||'').length } : undefined,
      candidate: m.candidate ? { has: true } : undefined
    }));

    if (m.type === 'challenge') {
      // m.room_id comes from the server; sign using THAT room's secret
      const room = rooms.find(r => r.id === m.room_id && normServer(r.server) === sc.url);
      if (!room) { if (DEBUG_SIG) dbg('SIG/RX', 'challenge for unknown room', m.room_id); return; }

      await ensureSodium();
      const nonce = fromB64u(m.nonce);
      const edSkBytes = await getRoomPrivateKeyBytes(room.id);
      const sig = sodium.crypto_sign_detached(nonce, edSkBytes);

      sc.ws.send(JSON.stringify({ type: 'auth', room_id: room.id, signature: b64u(sig) }));

    } else if (m.type === 'ready') {

      const room = rooms.find(r => r.id === m.room_id && normServer(r.server) === sc.url);
      if (!room) return;

      sc.authed.add(room.id);
      sc.ws.send(JSON.stringify({ type: 'announce', room_id: room.id, peer_id: myPeerId }));

      const lastTs = await msgGetLastTs(sc.url, room.id);
      const since = lastTs > 0 ? (lastTs + 1) : sevenDaysAgoMs();

      sc.ws.send(JSON.stringify({ type: 'history', room_id: room.id, since }));

      if (room.id === currentRoomId) {
        await ensureSodium();
        setCryptoForRoom(room);
        await initVirtualRoomView(sc.url, room.id);
        setStatus(statuses.connected);
      }

    } else if (m.type === 'history') {
      for (const item of (m.messages || [])) {
        await handleIncoming(sc.url, item, true);
      }
      if (m.room_id === currentRoomId) {
        if (!ui.messages.firstChild || !VL?.oldestKey) {
          await initVirtualRoomView(sc.url, m.room_id);
          setStatus(statuses.connected);
        } else if (ui.status && ui.status.textContent !== 'Connected') {
          setStatus(statuses.connected);
        }
      }

    } else if (m.type === 'message') {
      handleIncoming(sc.url, m);

    } else if (m.type === 'webrtc-request') {
      // only respond if we have the file locally
      serveFileIfWeHaveIt(sc.url, m);

    } else if (m.type === 'webrtc-response') {
      await handleWebRtcResponse(sc.url, m);

    } else if (m.type === 'webrtc-ice') {
      await handleWebRtcIce(sc.url, m);

    } else if (m.type === 'webrtc-taken') {
      const { request_id, chosen } = m;
      // Responder side
      const s = serveRequests.get(request_id);
      if (s && chosen !== myPeerId) {
	try { s.pc.close(); } catch {}
	serveRequests.delete(request_id);
	if (DEBUG_RTC) dbg('RTC/RESP', 'taken -> closing', { request_id, chosen });
      }
      // (Requester side) if for some reason we’re not the chosen peer, cancel our pending attempt
      const p = pendingRequests.get(request_id);
      if (p && p.remotePeerId && p.remotePeerId !== chosen) {
	try { p.pc.close(); } catch {}
	pendingRequests.delete(request_id);
	if (DEBUG_RTC) dbg('RTC/REQ', 'taken (not me) -> closing', { request_id, chosen });
      }	

    } else if (m.type === 'pong') {
      // noop

    } else if (m.type === 'error') {
      // optionally display when active room matches
      if (m.room_id === currentRoomId) {
        renderTextMessage({ text: `Server error: ${m.error}`, ts: nowMs(), nickname: 'server', senderId: null });
      }
    }
  };
}

function scheduleReconnect(sc) {
  const base = Math.min(30000, 1000 * Math.pow(2, sc.reconnectAttempt));
  const jitter = Math.floor(Math.random() * 500);
  const delay = base + jitter;
  sc.reconnectAttempt++;
  if (DEBUG_SIG) dbg('SIG/WS', 'reconnect in', delay, 'ms', sc.url);
  if (sc.reconnectTimer) clearTimeout(sc.reconnectTimer);
  sc.reconnectTimer = setTimeout(() => connect(sc), delay);
}

// Ensure all servers have connections and subscribed rooms
function ensureAllServerConnections() {
  const by = getRoomsByServer();
  for (const url of by.keys()) ensureServerConnection(url);
}

// Register room (optional HTTP no-op)
async function registerRoomIfNeeded(room) {
  try {
    await fetch(`${normServer(room.server)}/rooms`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ room_id: room.id, ed25519_public_key_b64u: room.id })
    });
  } catch {}
}

// ====== UI: room menu & dialogs ======
function renderRoomMenu(){
  const menu = ui.roomMenu;
  menu.innerHTML = '';
  rooms.forEach(room => {
    const div = document.createElement('div');
    div.className = 'room-item';
    div.innerHTML = `
      <div>
        <div>${room.name}</div>
        <div class="sub">${room.server}</div>
      </div>
      ${room.id === currentRoomId ? '<div class="sub">✓</div>' : ''}
    `;
    div.addEventListener('click', () => {
      menu.hidden = true;
      if (room.id !== currentRoomId) openRoom(room.id);
    });
    menu.appendChild(div);
  });
  const create = document.createElement('div');
  create.className = 'room-create';
  create.textContent = 'Create room…';
  create.addEventListener('click', () => {
    menu.hidden = true;
    openCreateRoomDialog();
  });
  menu.appendChild(create);
  const joinItem = document.createElement('div');
  joinItem.className = 'room-create';
  joinItem.textContent = 'Join room…';
  joinItem.addEventListener('click', () => {
    ui.roomMenu.hidden = true;
    openJoinDialog();
  });
  menu.appendChild(joinItem);
}

function openCreateRoomDialog(){
  cr.name.value = '';
  cr.server.value = rooms[0]?.server || 'https://rartino.pythonanywhere.com';
  cr.dlg.showModal();
}

const cr = {
  dlg: document.getElementById('createRoomModal'),
  name: document.getElementById('newRoomName'),
  server: document.getElementById('newServerUrl'),
  btnCreate: document.getElementById('btnCreateRoom'),
  btnClose: document.getElementById('btnCloseCreateRoom'),
};

cr.btnClose.addEventListener('click', () => cr.dlg.close());
cr.btnCreate.addEventListener('click', async () => {
  const name = (cr.name.value || '').trim() || 'New room';
  const server = normServer(cr.server.value || '');
  if (!server) { alert('Server URL is required'); return; }

  await ensureSodium();
  const { privateKey } = sodium.crypto_sign_keypair();
  const rid = b64u(derivePubFromSk(privateKey));
  const room = { id: rid, name, server, roomId: rid, createdAt: nowMs() };
  rooms.push(room); saveRooms();
  await secretPut(rid, await sealSecret(b64u(privateKey)));
  saveRooms();
  cr.dlg.close();

  ensureServerConnection(server);

  await openRoom(room.id);
});

cfg.btnClose.addEventListener('click', () => cfg.dlg.close());
cfg.btnSave.addEventListener('click', () => {
  const r = getCurrentRoom(); if (!r) return;
  r.name = (cfg.name.value || '').trim() || r.name;
  saveRooms();
  setCurrentRoom(r.id);
  renderRoomMenu();
  cfg.dlg.close();
});

cfg.btnRemove.addEventListener('click', async () => {
  const r = getCurrentRoom(); if (!r) return;
  if (!confirm(`Remove room “${r.name}”?`)) return;

  await clearRoomData(r.server, r.id);

  rooms = rooms.filter(x => x.id !== r.id);
  saveRooms();
  cfg.dlg.close();

  // Pick next room or reset UI
  if (rooms.length) {
    await openRoom(rooms[0].id);
  } else {
    // No rooms left; disconnect and prompt create
    clearMessagesUI();
    setStatus(statuses.passive);
    document.getElementById('currentRoomName').textContent = 'No room';
    openCreateRoomDialog();
  }
});

// Room dropdown interactions
ui.btnRoomMenu.addEventListener('click', () => {
  renderRoomMenu();
  ui.roomMenu.hidden = !ui.roomMenu.hidden;
  ui.btnRoomMenu.setAttribute('aria-expanded', String(!ui.roomMenu.hidden));
});
document.addEventListener('click', (e) => {
  if (!ui.roomMenu.contains(e.target) && !ui.btnRoomMenu.contains(e.target)) {
    ui.roomMenu.hidden = true;
    ui.btnRoomMenu.setAttribute('aria-expanded', 'false');
  }
});

// Open a room in the UI (does not open new WS; uses pool)
async function openRoom(roomId){
  setCurrentRoom(roomId);
  const room = getCurrentRoom();
  if (!room) return;
  await ensureSodium();
  setCryptoForRoom(room);
  setStatus(statuses.connecting);

  const sc = ensureServerConnection(room.server); // your existing helper

  if (sc.ws && sc.ws.readyState === WebSocket.OPEN) {
    if (!sc.subscribed.has(room.id)) {
      sc.subscribed.add(room.id);
      sc.ws.send(JSON.stringify({ type: 'subscribe', room_id: room.id }));
      setStatus(statuses.connecting);
    } else if (sc.authed.has(room.id)) {
      await initVirtualRoomView(sc.url, room.id);
      setStatus(statuses.connected);
    } else {
      setStatus(statuses.connecting);
    }
  } else {
    setStatus(statuses.connecting);
  }
}

let _joinWait = { ws:null, curvePk:null, curveSk:null, hash:null, host:null };

async function drawInviteQr(text){
  // If you already have a QR lib, call it here; otherwise draw a simple fallback box
  const c = join.qrCanvas;
  if (!c) return;
  if (typeof window.drawQRCode === 'function') {
    window.drawQRCode(c, text);  // hook for your preferred QR lib
    return;
  }
  // Fallback placeholder (no QR lib): show nothing, keep hint
  c.width = c.height = 0;
}

async function openJoinDialog(){
  await ensureSodium();

  // Prefill server
  join.server.value = rooms[0]?.server || 'https://rartino.pythonanywhere.com';

  // Generate fresh Curve25519 pair and code
  const kp = sodium.crypto_box_keypair();
  _joinWait.curvePk = kp.publicKey;
  _joinWait.curveSk = kp.privateKey;
  _joinWait.host    = hostFromUrl(join.server.value);
  _joinWait.hash    = await sha256_b64u_bytes(_joinWait.curvePk);

  const code = encodeInviteCode(_joinWait.host, b64u(_joinWait.curvePk));
  join.codeTA.value = code;
  await drawInviteQr(code);

  // Open waiting WS to this server, register invite-open
  if (_joinWait.ws) { try { _joinWait.ws.close(); } catch{} }
  const wsUrl = normServer(join.server.value).replace(/^http/i,'ws') + '/ws';
  const w = new WebSocket(wsUrl);
  _joinWait.ws = w;

  w.onopen = () => {
    if (DEBUG_SIG) dbg('SIG/TX','invite-open',{hash:_joinWait.hash.slice(0,12)+'…'});
    w.send(JSON.stringify({ type:'invite-open', hash: _joinWait.hash }));
  };
  w.onmessage = async (evt) => {
    const m = JSON.parse(evt.data);
    if (m.type === 'invite-deliver') {
      try {
        const sealed = fromB64u(m.ciphertext);
        const plain  = sodium.crypto_box_seal_open(sealed, _joinWait.curvePk, _joinWait.curveSk);
        const obj    = JSON.parse(bytesToUtf8(plain));

        if (!obj || obj.k !== 'room-invite' || !obj.room || !obj.room.sk || !obj.room.id) {
          alert('Bad invite payload'); return;
        }
        const skBytes = fromB64u(obj.room.sk);
        const pkBytes = derivePubFromSk(skBytes);
        if (b64u(pkBytes) !== obj.room.id) { alert('Invite id mismatch'); return; }

        // Upsert room & secret
        const serverUrl = 'https://' + _joinWait.host;
        const rid = obj.room.id;
        if (!rooms.find(x => x.id === rid)) {
          rooms.push({ id: rid, name: obj.room.name || 'Room', server: serverUrl, roomId: rid, createdAt: nowMs() });
          saveRooms();
        }
        await secretPut(rid, await sealSecret(b64u(skBytes)));

        ensureServerConnection(serverUrl);
        await registerRoomIfNeeded({ id: rid, server: serverUrl });
        await openRoom(rid);

        try { _joinWait.ws.close(); } catch {}
        join.dlg.close();
      } catch (e) {
        console.error(e);
        alert('Failed to decrypt invite.');
      }
    } else if (m.type === 'error') {
      alert(`Server error: ${m.error}`);
    }
  };

  join.dlg.showModal();
}

async function generateJoinAnswer(){
  try { await navigator.clipboard.writeText(join.offerTA.value); }
  catch {}
}

join.btnClose?.addEventListener('click', () => { try { _joinWait.ws?.close(); } catch{} join.dlg.close(); });
join.btnCopyCode?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(join.codeTA.value); join.btnCopyCode.textContent='Copied'; setTimeout(()=>join.btnCopyCode.textContent='Copy',900); } catch {}
});
join.btnRefresh?.addEventListener('click', openJoinDialog);

// ---- Virtual list state for current room ----
const VL = {
  serverUrl: null,
  roomId: null,
  oldestTs: Number.MAX_SAFE_INTEGER,
  newestTs: 0,
  hasMoreOlder: true,
  loadingOlder: false,
};
let scrollHandler = null;

function nearBottom() {
  const el = ui.messages;
  return (el.scrollHeight - el.clientHeight - el.scrollTop) < BOTTOM_NEAR_PX;
}

function pruneTopIfNeeded() {
  const el = ui.messages;
  while (el.children.length > MAX_DOM_MESSAGES) el.removeChild(el.firstChild);
}
function pruneBottomIfNeeded() {
  const el = ui.messages;
  while (el.children.length > MAX_DOM_MESSAGES) el.removeChild(el.lastChild);
}

function buildRowFromRecord(rec) {
  const row = document.createElement('div');
  const isMe = rec.senderId && myPeerId && rec.senderId === myPeerId;
  row.className = 'row ' + (isMe ? 'me' : 'other');

  if (rec.id) row.dataset.msgId = rec.id;

  const wrap  = document.createElement('div'); wrap.className = 'wrap';
  const label = document.createElement('div'); label.className = 'name-label';
  const who = rec.nickname || (rec.senderId ? shortId(rec.senderId) : 'room');
  const when = new Date(rec.ts || nowMs()).toLocaleString();
  label.textContent = `${who} • ${when}${rec.verified === false ? ' • ⚠︎ unverified' : ''}`;

  const bubble = document.createElement('div'); bubble.className = 'bubble';

  let fileMeta = null;
  if (rec.kind === 'text') {
    bubble.textContent = rec.text;
  } else {
    fileMeta = rec.meta;
    bubble.dataset.hash = fileMeta.hash;
    if (fileMeta.mime && fileMeta.mime.startsWith('image/')) {
      bubble.textContent = 'Image pending…';
    } else {
      const p = document.createElement('div');
      p.textContent = `${fileMeta.name || 'file'} (${fileMeta.size || '?'} bytes)`;
      bubble.appendChild(p);
    }
  }

  wrap.appendChild(label); wrap.appendChild(bubble); row.appendChild(wrap);
  return { node: row, bubble: (rec.kind === 'file') ? bubble : null, meta: fileMeta };
}

function renderRecord(rec, { prepend=false } = {}) {
  if (rec.kind === 'text') {
    renderTextMessage({ text: rec.text, ts: rec.ts, nickname: rec.nickname, senderId: rec.senderId, verified: rec.verified }, { prepend });
  } else if (rec.kind === 'file') {
    const bubble = fileBubbleSkeleton({ meta: rec.meta, ts: rec.ts, nickname: rec.nickname, senderId: rec.senderId, verified: rec.verified }, { prepend });
    renderFileIfAvailable(bubble, rec.meta).then(ok => {
      if (!ok) { showPendingBubble(bubble, rec.meta); requestFile(VL.roomId, rec.meta.hash); }
    });
  }
}

async function loadOlderPage() {
  if (VL.loadingOlder || !VL.hasMoreOlder) return;
  VL.loadingOlder = true;

  // capture current view generation; abort later if it changed
  const gen = VL.viewGen;

  const el = ui.messages;
  const prevH = el.scrollHeight;

  const page = await msgPageByRoom(VL.serverUrl, VL.roomId, {
    beforeTs: VL.oldestTs,
    limit: PAGE_SIZE
  });

  // user switched rooms while we were fetching → no-op
  if (gen !== VL.viewGen) { VL.loadingOlder = false; return; }

  if (!page.length) {
    VL.hasMoreOlder = false;
    VL.loadingOlder = false;
    return;
  }

  VL.oldestTs  = Math.min(VL.oldestTs, page[0].ts);
  VL.oldestKey = { ts: page[0].ts, id: page[0].id };
  VL.hasMoreOlder = (page.length === PAGE_SIZE);

  const frag = document.createDocumentFragment();
  const pendingFiles = [];

  for (const rec of page) {
    // extra safety: skip any cross-room stragglers
    if ((rec.roomId && rec.roomId !== VL.roomId) ||
        (rec.serverUrl && rec.serverUrl !== VL.serverUrl)) continue;
    if (VL.seenIds.has(rec.id)) continue;
    VL.seenIds.add(rec.id);

    const built = buildRowFromRecord(rec);
    frag.appendChild(built.node);
    if (built.bubble) pendingFiles.push(built);
  }

  // re-check before touching the DOM
  if (gen !== VL.viewGen) { VL.loadingOlder = false; return; }

  el.insertBefore(frag, el.firstChild);

  const newH = el.scrollHeight;
  el.scrollTop += (newH - prevH);

  for (const { bubble, meta } of pendingFiles) {
    renderFileIfAvailable(bubble, meta).then(ok => {
      if (!ok) { showPendingBubble(bubble, meta); requestFile(VL.roomId, meta.hash); }
    });
  }

  pruneBottomIfNeeded();
  VL.loadingOlder = false;
}

let _vlLastLoad = 0;
function attachVirtualScroll() {
  if (scrollHandler) ui.messages.removeEventListener('scroll', scrollHandler);
  scrollHandler = () => {
    const now = performance.now();
    if (ui.messages.scrollTop < TOP_LOAD_PX && now - _vlLastLoad > 150) {
      _vlLastLoad = now;
      loadOlderPage();
    }
  };
  ui.messages.addEventListener('scroll', scrollHandler);
}

async function initVirtualRoomView(serverUrl, roomId) {
  // bump gen and capture it locally
  VL.viewGen = (VL.viewGen || 0) + 1;
  const gen = VL.viewGen;

  VL.serverUrl = serverUrl;
  VL.roomId = roomId;
  VL.oldestTs = Number.MAX_SAFE_INTEGER;
  VL.newestTs = 0;
  VL.hasMoreOlder = true;
  VL.loadingOlder = false;

  // strict boundary + DOM dedupe
  VL.oldestKey = null;       // { ts, id }
  VL.seenIds   = new Set();

  clearMessagesUI();

  const first = await msgPageByRoom(serverUrl, roomId, {
    beforeTs: Number.MAX_SAFE_INTEGER,
    limit: PAGE_SIZE
  });

  // If the user switched rooms while we were fetching, abort
  if (gen !== VL.viewGen) return;

  if (first.length) {
    VL.oldestTs  = first[0].ts;
    VL.newestTs  = first[first.length - 1].ts;
    VL.oldestKey = { ts: first[0].ts, id: first[0].id };
    VL.hasMoreOlder = (first.length === PAGE_SIZE);

    const frag = document.createDocumentFragment();
    const pendingFiles = [];

    for (const rec of first) {
      // extra safety: skip any cross-room stragglers
      if ((rec.roomId && rec.roomId !== VL.roomId) ||
          (rec.serverUrl && rec.serverUrl !== VL.serverUrl)) continue;
      if (VL.seenIds.has(rec.id)) continue;
      VL.seenIds.add(rec.id);

      const built = buildRowFromRecord(rec);
      frag.appendChild(built.node);
      if (built.bubble) pendingFiles.push(built);
    }

    // re-check token just before DOM write
    if (gen !== VL.viewGen) return;
    ui.messages.appendChild(frag);

    for (const { bubble, meta } of pendingFiles) {
      renderFileIfAvailable(bubble, meta).then(ok => {
        if (!ok) { showPendingBubble(bubble, meta); requestFile(roomId, meta.hash); }
      });
    }
  } else {
    VL.hasMoreOlder = false;
  }

  attachVirtualScroll();
  requestAnimationFrame(scrollToEnd);
}

// Append a new live record at bottom (keep window size, autoscroll if near bottom)
function appendLiveRecord(rec) {
  const autoscroll = nearBottom();
  const built = buildRowFromRecord(rec);
  ui.messages.appendChild(built.node);
  if (built.bubble) {
    renderFileIfAvailable(built.bubble, built.meta).then(ok => {
      if (!ok) { showPendingBubble(built.bubble, built.meta); requestFile(VL.roomId, built.meta.hash); }
    });
  }
  pruneTopIfNeeded();
  if (autoscroll) requestAnimationFrame(scrollToEnd);
}

function toggleSettingsMenu(show) {
  const willShow = (typeof show === 'boolean') ? show : ui.settingsMenu.hidden;
  ui.settingsMenu.hidden = !willShow;
}

function dataUrlFromBlob(blob) {
  return new Promise((resolve) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.readAsDataURL(blob);
  });
}

async function refreshAvatarPreview() {
  const blob = await profileGet('avatar');
  prof.avatarPreview.innerHTML = '';
  if (blob) {
    const url = URL.createObjectURL(blob);
    const img = document.createElement('img');
    img.onload = () => URL.revokeObjectURL(url);
    img.src = url;
    prof.avatarPreview.appendChild(img);
  } else {
    prof.avatarPreview.textContent = 'No avatar';
  }
}

async function openProfile() {
  await ensureIdentity();
  prof.name.value = (SETTINGS.username || '').trim();
  prof.pubKey.value = myPeerId || (myIdPk ? b64u(myIdPk) : '');
  prof.requirePass.checked = !!SETTINGS.requirePass;   // <-- add this
  await refreshAvatarPreview();
  prof.dlg.showModal();
}

function closeProfile() { prof.dlg.close(); }

async function saveProfile() {
  SETTINGS.username = (prof.name.value || '').trim();

  const prev = !!SETTINGS.requirePass;
  const next = !!prof.requirePass.checked;

  try {
    if (!prev && next) {
      // Turning ON: ask the user to set a password and ROTATE to it (not persisted)
      let pass = '';
      for (let tries = 0; tries < 3 && (!pass || pass.length < 6); tries++) {
        pass = prompt('Set a startup password (min 6 chars)');
        if (pass === null) break;
        pass = (pass || '').trim();
      }
      if (!pass || pass.length < 6) { alert('Password not set; leaving setting OFF.'); prof.requirePass.checked = false; return; }

      await rotateMasterPassTo(pass, { persist: false }); // session-only
      SETTINGS.requirePass = true;
      saveSettings();
      alert('Startup password enabled.');
    } else if (prev && !next) {
      // Turning OFF: persist the current pass so we can auto-unlock next run (no rotation needed)
      const sessionPass = sessionStorage.getItem(MASTER_PASS_SS_KEY);
      if (sessionPass) localStorage.setItem(MASTER_PASS_LS_KEY, sessionPass);
      SETTINGS.requirePass = false;
      saveSettings();
      alert('Startup password disabled (auto-unlock enabled).');
    } else {
      // No change to the toggle; just save the other fields
      saveSettings();
    }
  } finally {
    closeProfile();
  }
}

async function handleAvatarPicked(file) {
  if (!file) return;
  // Optional: resize/compress here if you want. For now store as-is.
  await profilePut('avatar', file);
  await refreshAvatarPreview();
}

async function clearAvatar() {
  await profileDel('avatar');
  await refreshAvatarPreview();
}

async function regenerateIdentity() {
  await ensureSodium();
  const pair = sodium.crypto_sign_keypair();
  myIdPk = pair.publicKey;
  myIdSk = pair.privateKey;
  persistIdentity();                 // sets myPeerId too
  prof.pubKey.value = myPeerId;
  announceIdentityToServers();       // optional: re-announce to authed rooms
}

async function continueBootAfterUnlock() {
  // Everything you normally do after settings are loaded + (optionally) identity ensured
  await ensureIdentity();
  loadRooms();
  if (rooms.length) {
    ensureAllServerConnections?.();   // if using multi-room version
    await openRoom?.(currentRoomId);  // if present in your codebase
  } else {
    setStatus(statuses.passive); // idle state
    const el = document.getElementById('currentRoomName');
    if (el) el.textContent = 'No room';
  }
}

// Show lock dialog and resolve only when correct password is provided
function showLockDialog() {
  unlock.err.textContent = '';
  unlock.input.value = '';
  unlock.dlg.showModal();

  // Don't allow ESC to close while locked
  const preventCancel = (e) => e.preventDefault();
  unlock.dlg.addEventListener('cancel', preventCancel);

  const onSubmit = async (e) => {
    e.preventDefault(); // <-- critical; stops the form from closing the dialog

    const pass = (unlock.input.value || '').trim();
    if (!pass) {
      unlock.err.textContent = 'Enter a password';
      unlock.input.focus();
      return;
    }

    try {
      // Try this password
      sessionStorage.setItem(MASTER_PASS_SS_KEY, pass);
      MASTER_BASE_KEY = null;                // force re-derive with this pass
      await ensureMasterBaseKey();           // derives PBKDF2 base key
      const ok = await verifyKeyCheck();     // decrypt key-check marker
      if (!ok) throw new Error('bad-pass');

      // Success → proceed
      unlock.err.textContent = '';
      unlock.dlg.removeEventListener('cancel', preventCancel);
      unlock.dlg.close();
      await continueBootAfterUnlock();
    } catch {
      // Wrong password → keep dialog open
      sessionStorage.removeItem(MASTER_PASS_SS_KEY);
      MASTER_BASE_KEY = null;
      unlock.err.textContent = 'Incorrect password. Try again.';
      unlock.input.select();
      unlock.input.focus();
    }
  };

  // Set (or replace) the handler — no `{ once:true }`
  unlock.form.onsubmit = onSubmit;

  // Focus the input every time we open
  setTimeout(() => unlock.input?.focus(), 0);
}

// ====== Events ======
ui.btnSend.addEventListener('click', async () => {
  const text = ui.msgInput.value.trim();
  if (!text) return;
  const room = getCurrentRoom(); if (!room) return;
  await sendTextMessage(room, text);
  ui.msgInput.value = '';
});
ui.msgInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); ui.btnSend.click(); } });
ui.msgInput.addEventListener('focus', scrollToEnd);
ui.msgInput.addEventListener('input', scrollToEnd);
window.addEventListener('resize', scrollToEnd);
document.addEventListener('visibilitychange', () => { if (!document.hidden) scrollToEnd(); });

// Attach → file picker
ui.btnAttach?.addEventListener('click', () => ui.fileInput.click());
ui.fileInput?.addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const room = getCurrentRoom(); if (!room) return;

  const sc = servers.get(normServer(room.server));
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN || !sc.authed.has(room.id)) {
    alert('Not connected'); return;
  }

  const hash = await sha256_b64u(file);
  await idbPut(hash, file);

  const meta = { hash, name: file.name, mime: file.type || 'application/octet-stream', size: file.size|0 };
  await sendFileMetadata(room, meta);
  ui.fileInput.value = '';
});

//// Invitation dialog
inv.btnClose?.addEventListener('click', () => { stopInviteScan(); inv.dlg.close(); });

// Actions
inv.btnScan?.addEventListener('click', startInviteScan);
inv.btnStopScan?.addEventListener('click', stopInviteScan);
inv.btnPaste?.addEventListener('click', async () => {
  try {
    const txt = await navigator.clipboard.readText();
    if (txt) inv.codeInput.value = txt.trim();
  } catch {}
});
inv.btnSend?.addEventListener('click', deliverInvite);

// Settings dropdown
ui.btnSettings.addEventListener('click', (e) => {
  e.stopPropagation();
  toggleSettingsMenu(true);
});
document.addEventListener('click', (e) => {
  if (!ui.settingsMenu.contains(e.target) && !ui.btnSettings.contains(e.target)) {
    toggleSettingsMenu(false);
  }
});
ui.menuProfile.addEventListener('click', () => { toggleSettingsMenu(false); openProfile(); });

ui.menuRoomOpts.addEventListener('click', () => {
  toggleSettingsMenu(false);
  const r = getCurrentRoom();
  if (!r) { openCreateRoomDialog(); return; }
  cfg.name.value = r.name || '';
  cfg.dlg.showModal();
});

ui.menuInvite.addEventListener('click', () => {
  toggleSettingsMenu(false);
  const r = getCurrentRoom();
  if (!r) { openCreateRoomDialog(); return; }
  openInviteDialog();
});

// Profile dialog
prof.btnClose.addEventListener('click', closeProfile);
prof.btnSave.addEventListener('click', saveProfile);
prof.btnCopy.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText((prof.pubKey.value || '').trim()); prof.btnCopy.textContent='Copied'; setTimeout(()=>prof.btnCopy.textContent='Copy', 900); } catch {}
});
prof.btnRegen.addEventListener('click', regenerateIdentity);

prof.btnAvatarUpload.addEventListener('click', () => prof.avatarInput.click());
prof.avatarInput.addEventListener('change', (e) => handleAvatarPicked(e.target.files && e.target.files[0]));
    prof.btnAvatarClear.addEventListener('click', clearAvatar);

unlock.dlg.addEventListener('close', () => {
  if (SETTINGS.requirePass && !sessionStorage.getItem(MASTER_PASS_SS_KEY)) {
    // Re-open on next tick if still locked
    setTimeout(() => unlock.dlg.showModal(), 0);
  }
});

// ====== Boot ======
ensureSodium();
loadSettings();

if (SETTINGS.requirePass) {
  // Block boot here until unlocked
  showLockDialog();
} else {
  // Auto-unlock mode; derive base key immediately and create marker if missing
  try {
    await ensureMasterBaseKey();
    await verifyKeyCheck(); // creates marker on first run
  } catch {} // non-fatal in auto mode

  await continueBootAfterUnlock();
}
