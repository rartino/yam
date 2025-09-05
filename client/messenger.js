// ====== CONFIG ======
const ROOMS_KEY = 'secmsg_rooms_v1';
const CURRENT_ROOM_KEY = 'secmsg_current_room_id';
const SETTINGS_KEY = 'secmsg_settings_v1';
const HIST_FLAGS_KEY = 'secmsg_hist_fetched_v1';
const RTC_CONFIG = {
  iceServers: [
    { urls: ['stun:stun.l.google.com:19302'] },
    // { urls: 'turn:your.turn.server:3478', username: 'user', credential: 'pass' }
  ],
  iceCandidatePoolSize: 2,
};
const CHUNK_SIZE = 64 * 1024; // 64KB chunks for file send

// ====== DEBUG ======
const DEBUG_SIG = true;     // WebSocket signaling logs
const DEBUG_RTC = true;     // WebRTC flow logs
function dbg(tag, ...args){
  const ts = new Date().toISOString().split('T')[1].replace('Z','');
  console.log(`[${ts}] ${tag}`, ...args);
}

// ====== UI REFS ======
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
};

// Gear -> configure room
const cfg = {
  dlg: document.getElementById('settingsModal'),
  name: document.getElementById('cfgRoomName'),
  btnSave: document.getElementById('btnSaveRoomCfg'),
  btnRemove: document.getElementById('btnRemoveRoom'),
  btnClose: document.getElementById('btnCloseSettings'),
  btnInvite: document.getElementById('btnInvite'),
};

// Invite (sender)
const inv = {
  dlg: document.getElementById('inviteModal'),
  offerTA: document.getElementById('inviteOffer'),
  answerTA: document.getElementById('inviteAnswer'),
  btnCopyOffer: document.getElementById('btnCopyInviteOffer'),
  btnRefreshOffer: document.getElementById('btnRefreshInviteOffer'),
  btnFinish: document.getElementById('btnFinishInvite'),
  btnClose: document.getElementById('btnCloseInvite'),
};

// Join (receiver)
const join = {
  dlg: document.getElementById('joinModal'),
  offerTA: document.getElementById('joinOffer'),
  answerTA: document.getElementById('joinAnswer'),
  btnGen: document.getElementById('btnMakeJoinAnswer'),
  btnCopy: document.getElementById('btnCopyJoinAnswer'),
  btnClose: document.getElementById('btnCloseJoin'),
};

// ====== STATE ======
let SETTINGS = { username: '', roomSkB64: '' };

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

// WebRTC maps
// request_id -> { serverUrl, roomId, pc, dc, hash, remotePeerId?, iceBuf?, incomingIceBuf?, haveAnswer? }
const pendingRequests = new Map();
// request_id -> { serverUrl, roomId, pc, hash }
const serveRequests   = new Map();
// request_id -> ICE buffered before responder PC exists
const preServeIce     = new Map();

// ====== UTIL ======
function roomKey(serverUrl, roomId){ return `${normServer(serverUrl)}|${roomId}`; }
function _loadHistFlags(){ try{ return JSON.parse(localStorage.getItem(HIST_FLAGS_KEY)||'{}'); }catch{ return {}; } }
function _saveHistFlags(obj){ localStorage.setItem(HIST_FLAGS_KEY, JSON.stringify(obj)); }
function hasHistoryFetched(serverUrl, roomId){ const f=_loadHistFlags(); return !!f[roomKey(serverUrl, roomId)]; }
function markHistoryFetched(serverUrl, roomId){ const f=_loadHistFlags(); f[roomKey(serverUrl, roomId)] = true; _saveHistFlags(f); }
function clearHistoryFlag(serverUrl, roomId){ const f=_loadHistFlags(); delete f[roomKey(serverUrl, roomId)]; _saveHistFlags(f); }
function b64u(bytes) { return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING); }
function fromB64u(str) { return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING); }
function nowMs() { return Date.now(); }
function sevenDaysAgoMs() { return nowMs() - 7 * 24 * 60 * 60 * 1000; }
function setStatus(text) { ui.status.textContent = text; }
function shortId(idB64u) { return idB64u.slice(0, 6) + '…' + idB64u.slice(-6); }
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

function setCryptoForRoom(room) {
  edSk = fromB64u(room.roomSkB64);
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
const MSG_DB = 'secmsg_msgs_db';
const MSG_STORE = 'msgs';

let msgDbPromise = null;
function openMsgDB(){
  if (msgDbPromise) return msgDbPromise;
  msgDbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(MSG_DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      const s = db.createObjectStore(MSG_STORE, { keyPath: 'id' });
      s.createIndex('byRoom', 'roomKey', { unique: false });
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
async function msgListByRoom(serverUrl, roomId){
  const key = roomKey(serverUrl, roomId);
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const out = [];
    const tx = db.transaction(MSG_STORE, 'readonly');
    const idx = tx.objectStore(MSG_STORE).index('byRoom');
    const req = idx.openCursor(IDBKeyRange.only(key));
    req.onsuccess = (e) => {
      const cur = e.target.result;
      if (!cur) { out.sort((a,b)=> (a.ts||0)-(b.ts||0)); return res(out); }
      out.push(cur.value); cur.continue();
    };
    req.onerror = () => rej(req.error);
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

// ====== Rooms store ======
function loadSettings() {
  try { SETTINGS = { ...SETTINGS, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; }
  catch {}
}
function saveSettings() { localStorage.setItem(SETTINGS_KEY, JSON.stringify(SETTINGS)); }

function loadRooms(){
  try { rooms = JSON.parse(localStorage.getItem(ROOMS_KEY) || '[]'); } catch { rooms = []; }
  currentRoomId = localStorage.getItem(CURRENT_ROOM_KEY) || null;

  // Migration: lift legacy single-room setting into rooms (if any)
  if (!rooms.length && SETTINGS.roomSkB64) {
    const migratedServer = 'https://rartino.pythonanywhere.com';
    const tmpSk = SETTINGS.roomSkB64;
    try {
      const sk = fromB64u(tmpSk);
      const pk = derivePubFromSk(sk);
      const rid = b64u(pk);
      rooms.push({ id: rid, name: 'Room 1', server: migratedServer, roomSkB64: tmpSk, roomId: rid, createdAt: nowMs() });
      currentRoomId = rid;
      localStorage.removeItem(SETTINGS_KEY);
    } catch {}
  }

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
  localStorage.setItem('secmsg_id_pk', b64u(myIdPk));
  localStorage.setItem('secmsg_id_sk', b64u(myIdSk));
  myPeerId = b64u(myIdPk);
  ui.identityInfo.textContent = `Your device ID: ${shortId(myPeerId)} (stored locally)`;
}
function rotateIdentityWithName(newName) {
  const pair = sodium.crypto_sign_keypair();
  myIdPk = pair.publicKey; myIdSk = pair.privateKey;
  SETTINGS.username = newName.trim(); saveSettings(); persistIdentity();
}
async function ensureIdentity() {
  await ensureSodium();
  const pk = localStorage.getItem('secmsg_id_pk');
  const sk = localStorage.getItem('secmsg_id_sk');
  if (pk && sk) { myIdPk = fromB64u(pk); myIdSk = fromB64u(sk); persistIdentity(); }
  else { rotateIdentityWithName(SETTINGS.username || 'Me'); }
}

// ====== Rendering ======
function renderTextMessage({ room_id, text, ts, nickname, senderId, verified }) {
  if (room_id !== currentRoomId) return; // only show active room
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
  ui.messages.appendChild(row); scrollToEnd();
}

function fileBubbleSkeleton({ room_id, meta, ts, nickname, senderId, verified }) {
  if (room_id !== currentRoomId) return null; // only draw for active room
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

  if (meta.mime && meta.mime.startsWith('image/')) {
    bubble.textContent = 'Image pending…';
  } else {
    const p = document.createElement('div');
    p.textContent = `${meta.name || 'file'} (${meta.size || '?'} bytes)`;
    bubble.appendChild(p);
  }

  wrap.appendChild(label); wrap.appendChild(bubble); row.appendChild(wrap);
  ui.messages.appendChild(row);
  return bubble;
}

async function renderFileIfAvailable(bubbleEl, meta) {
  if (!bubbleEl) return false; // not active room
  const blob = await idbGet(meta.hash);
  if (!blob) return false;

  bubbleEl.innerHTML = '';
  if (meta.mime && meta.mime.startsWith('image/')) {
    const url = URL.createObjectURL(blob);
    const img = document.createElement('img');
    img.src = url; img.alt = meta.name || 'image';
    bubbleEl.appendChild(img);
  } else {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.textContent = `${meta.name || 'file'} (${meta.size || blob.size} bytes)`;
    link.className = 'file-link'; link.target = '_blank'; link.rel = 'noopener';
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
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN) { alert('Not connected'); return; }
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
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN) { alert('Not connected'); return; }
  if (DEBUG_SIG) dbg('SIG/TX', 'send:file-meta', { room: room.name, hash: meta.hash, name: meta.name, mime: meta.mime, size: meta.size });
  sc.ws.send(JSON.stringify(payload));
}

async function handleIncoming(serverUrl, m, fromHistory=false) {
  const pt = decryptToString(m.ciphertext);
  const roomId = m.room_id || currentRoomId; // server includes this for history/live
  const rKey = roomKey(serverUrl, roomId);
  const id = `${rKey}|${await sha256_b64u_string(m.ciphertext)}`;    
    
  let verified = undefined;
  if (m.sender_id && m.sig) {
    try {
      const senderPk = fromB64u(m.sender_id);
      const sig = fromB64u(m.sig);
      const ciphertext = fromB64u(m.ciphertext);
      verified = sodium.crypto_sign_verify_detached(sig, ciphertext, senderPk);
    } catch { verified = false; }
  }

  try {
    const obj = JSON.parse(pt);
    if (obj && obj.kind === 'file' && obj.hash) {
      // persist
      await msgPut({
        id, roomKey: rKey, roomId, serverUrl,
        ts: m.ts || nowMs(), nickname: m.nickname, senderId: m.sender_id,
        verified, kind: 'file', meta: obj
      });

      // render to UI only if this is the visible room
      if (roomId === currentRoomId) {
        const bubble = fileBubbleSkeleton({ meta: obj, ts: m.ts, nickname: m.nickname, senderId: m.sender_id, verified });
        renderFileIfAvailable(bubble, obj).then(hasIt => { if (!hasIt) { showPendingBubble(bubble, obj); requestFile(obj.hash); } else { scrollToEnd(); } });
      }
      return;
    }
  } catch (_) { /* not JSON */ }

  // plain text
  await msgPut({
    id, roomKey: rKey, roomId, serverUrl,
    ts: m.ts || nowMs(), nickname: m.nickname, senderId: m.sender_id,
    verified, kind: 'text', text: pt
  });
  if (roomId === currentRoomId) {
    renderTextMessage({ text: pt, ts: m.ts, nickname: m.nickname, senderId: m.sender_id, verified });
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
  st.remotePeerId = from;
  st.haveAnswer = true;
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

let invitePC = null, inviteDC = null;

async function openInviteDialog(){
  const room = getCurrentRoom();
  if (!room) { alert('No active room'); return; }
  await ensureSodium();

  if (invitePC) { try { invitePC.close(); } catch{} invitePC = null; }
  const pc = new RTCPeerConnection(RTC_CONFIG);
  invitePC = pc;

  pc.oniceconnectionstatechange = () => dbg('RTC/INV iceState', pc.iceConnectionState);
  pc.onconnectionstatechange = () => dbg('RTC/INV pcState', pc.connectionState);

  const dc = pc.createDataChannel('invite');
  inviteDC = dc;
  inviteDC.onopen = () => dbg('RTC/INV', 'dc open');
  inviteDC.onmessage = (evt) => {
    // (Optional) early ACKs before finishInviteDialog attaches handler
    try {
      const txt = typeof evt.data === 'string' ? evt.data : new TextDecoder().decode(evt.data);
      const o = JSON.parse(txt);
      if (o && o.kind === 'invite-ack') dbg('RTC/INV', 'early ack');
    } catch {}
  };

  // Build offer (no trickle; short gather window)
  const offer = await pc.createOffer({ offerToReceiveAudio:false, offerToReceiveVideo:false });
  await pc.setLocalDescription(offer);

  const { sdp, candidates } = await gatherIceCandidates(pc, 1200);
  inv.offerTA.value = packSignal({ type:'offer', sdp, candidates });
  inv.answerTA.value = '';

  inv.dlg.showModal();
}

async function finishInviteDialog(){
  const room = getCurrentRoom();
  if (!room) return;
  const code = (inv.answerTA.value || '').trim();
  if (!code) { alert('Paste response code first'); return; }
  const msg = unpackSignal(code);
    if (!msg || msg.type !== 'answer' || !msg.sdp) { alert('Invalid response code'); return; }

  try {
     await invitePC.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
     dbg('RTC/INV', 'answer applied');

     const ansCands = Array.isArray(msg.candidates) ? msg.candidates : [];
     for (const c of ansCands) {
       try { await invitePC.addIceCandidate(new RTCIceCandidate(c)); } catch (e) { dbg('RTC/INV addIce answer', e); }
     }

    const sendRoom = async () => {
      dbg('RTC/INV', 'dc open -> send room');
      const room = getCurrentRoom();
      const payload = {
	ver:1, kind:'room-invite',
	room: {
	  id: room.id,
	  name: room.name,
	  server: normServer(room.server),
	  roomSkB64: room.roomSkB64,
	  createdAt: nowMs()
	}
      };
      inviteDC.send(JSON.stringify(payload));
    };

    // NEW: listen for ACK and then close
    let acked = false;
    inviteDC.onmessage = (evt) => {
      // In case the joiner sends ACK earlier than we attach in finish
      try {
	const txt = (typeof evt.data === 'string') ? evt.data : new TextDecoder().decode(evt.data);
	const o = JSON.parse(txt);
	if (o && o.kind === 'invite-ack') dbg('RTC/INV', 'early ack');
      } catch {}
    };

    // Send now if already open, otherwise on open
    if (inviteDC.readyState === 'open') {
      await sendRoom();
    } else {
      inviteDC.onopen = sendRoom;
    }

    // Fallback close if no ACK within 5s
    setTimeout(() => {
      if (!acked) {
	dbg('RTC/INV', 'no ack timeout; closing');
	try{ inviteDC.close(); }catch{} try{ invitePC.close(); }catch{}
	inv.dlg.close();
      }
    }, 5000);

  } catch (e) {
    console.error(e);
    alert('Failed to apply response');
  }

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
      const edSkBytes = fromB64u(room.roomSkB64);
      const sig = sodium.crypto_sign_detached(nonce, edSkBytes);

      sc.ws.send(JSON.stringify({ type: 'auth', room_id: room.id, signature: b64u(sig) }));

    } else if (m.type === 'ready') {

      const room = rooms.find(r => r.id === m.room_id && normServer(r.server) === sc.url);
      if (!room) return;

      sc.authed.add(room.id);
      sc.ws.send(JSON.stringify({ type: 'announce', room_id: room.id, peer_id: myPeerId }));

      if (room.id === currentRoomId) {
	await ensureSodium();
	setCryptoForRoom(room);
	clearMessagesUI();
	sc.ws.send(JSON.stringify({ type: 'history', room_id: room.id, since: sevenDaysAgoMs() }));
	setStatus('Connected');
	requestAnimationFrame(() => requestAnimationFrame(scrollToEnd));
      }	

    } else if (m.type === 'history') {
      markHistoryFetched(sc.url, m.room_id);
      if (m.room_id === currentRoomId) {
	for (const item of (m.messages||[])) await handleIncoming(sc.url, item, true);
	scrollToEnd(); requestAnimationFrame(scrollToEnd);
      } else {
	// still persist them via handleIncoming so cache is warm even if room not visible
	for (const item of (m.messages||[])) await handleIncoming(sc.url, item, true);
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

    } else if (m.type === 'pong') {
      // noop

    } else if (m.type === 'error') {
      // optionally display when active room matches
      if (m.room_id === currentRoomId) {
        renderTextMessage({ room_id: m.room_id, text: `Server error: ${m.error}`, ts: nowMs(), nickname: 'server', senderId: null });
      }
    }
  };
}

function scheduleReconnect(sc) {
  const delay = Math.min(30000, 1000 * Math.pow(2, sc.reconnectAttempt));
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
  const room = { id: rid, name, server, roomSkB64: b64u(privateKey), roomId: rid, createdAt: nowMs() };

  rooms.push(room); saveRooms();
  cr.dlg.close();

  ensureServerConnection(server);

  await openRoom(room.id);
});

ui.btnSettings.addEventListener('click', () => {
  const r = getCurrentRoom();
  if (!r) { openCreateRoomDialog(); return; }
  cfg.name.value = r.name || '';
  cfg.dlg.showModal();
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

  // Clear local history for the room
  await msgDeleteRoom(r.server, r.id);
  clearHistoryFlag(r.server, r.id);

  // Remove from list and persist
  rooms = rooms.filter(x => x.id !== r.id);
  saveRooms();
  cfg.dlg.close();

  // Pick next room or reset UI
  if (rooms.length) {
    await openRoom(rooms[0].id);
  } else {
    // No rooms left; disconnect and prompt create
    if (ws) { try { ws.close(); } catch {} ws = null; }
    clearMessagesUI();
    setStatus('No room');
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
  setStatus('Connecting…');

  const sc = ensureServerConnection(room.server); // your existing helper

  if (sc.ws && sc.ws.readyState === WebSocket.OPEN) {
    if (!sc.subscribed.has(room.id)) {
      sc.subscribed.add(room.id);
      sc.ws.send(JSON.stringify({ type: 'subscribe', room_id: room.id }));
      setStatus('Connecting…');
    } else if (sc.authed.has(room.id)) {
      // Decide: cached vs first fetch
      if (hasHistoryFetched(sc.url, room.id)) {
	await ensureSodium();
	setCryptoForRoom(room);
	clearMessagesUI();
	const cached = await msgListByRoom(sc.url, room.id);
	for (const rec of cached) {
	  if (rec.kind === 'text') {
	    renderTextMessage({ text: rec.text, ts: rec.ts, nickname: rec.nickname, senderId: rec.senderId, verified: rec.verified });
	  } else if (rec.kind === 'file') {
	    const bubble = fileBubbleSkeleton({ meta: rec.meta, ts: rec.ts, nickname: rec.nickname, senderId: rec.senderId, verified: rec.verified });
	    // try show if we have it, else pending+auto request
	    // (renderFileIfAvailable returns false if not in IDB yet)
	    // don't await to keep UI snappy
	    renderFileIfAvailable(bubble, rec.meta).then(ok => { if (!ok) { showPendingBubble(bubble, rec.meta); requestFile(rec.meta.hash); } });
	  }
	}
	setStatus('Connected');
	requestAnimationFrame(() => requestAnimationFrame(scrollToEnd));
      } else {
	// First time ever for this room → fetch once
	await ensureSodium();
	setCryptoForRoom(room);
	clearMessagesUI();
	sc.ws.send(JSON.stringify({ type: 'history', room_id: room.id, since: sevenDaysAgoMs() }));
	setStatus('Connected'); // will render when history arrives
      }
    } else {
      setStatus('Connecting…');
    }
  } else {
    setStatus('Connecting…');
  }
}

let joinPC = null, joinDC = null;

function openJoinDialog(){
  join.offerTA.value = '';
  join.answerTA.value = '';
  join.dlg.showModal();
}

async function generateJoinAnswer(){
  const code = (join.offerTA.value || '').trim();
  const msg = unpackSignal(code);
  if (!msg || msg.type !== 'offer' || !msg.sdp) { alert('Invalid invitation code'); return; }

  if (joinPC) { try { joinPC.close(); } catch{} joinPC = null; }
  const pc = new RTCPeerConnection(RTC_CONFIG);
  joinPC = pc;

  pc.oniceconnectionstatechange = () => dbg('RTC/JOIN iceState', pc.iceConnectionState);
  pc.onconnectionstatechange = () => dbg('RTC/JOIN pcState', pc.connectionState);

  pc.ondatachannel = (evt) => {
    const dc = evt.channel;
    joinDC = dc;
    dc.onopen = () => dbg('RTC/JOIN', 'dc open');
    dc.onmessage = async (evt) => {
      try {
	// Handle both string and binary frames
	const text = (typeof evt.data === 'string')
	  ? evt.data
	  : new TextDecoder().decode(evt.data);
	const obj = JSON.parse(text);

	if (obj && obj.kind === 'room-invite' && obj.room) {
	  const r = obj.room;

	  // Validate: derived id must match provided id
	  await ensureSodium();
	  const sk = fromB64u(r.roomSkB64);
	  const pk = derivePubFromSk(sk);
	  const derived = b64u(pk);
	  if (derived !== r.id) { alert('Invalid room code received'); return; }

	  // Add room if not present
	  if (!rooms.find(x => x.id === r.id)) {
	    rooms.push({
	      id: r.id,
	      name: r.name || 'New room',
	      server: normServer(r.server),
	      roomSkB64: r.roomSkB64,
	      roomId: r.id,
	      createdAt: r.createdAt || nowMs()
	    });
	    saveRooms();
	    ensureServerConnection(r.server);
	    await registerRoomIfNeeded(r);
	    await openRoom(r.id);
	  }

	  // NEW: acknowledge so inviter knows it landed
	  try { dc.send(JSON.stringify({ kind: 'invite-ack' })); } catch {}

	  join.dlg.close();
	  setTimeout(() => { try { dc.close(); } catch{} try { pc.close(); } catch{} }, 300);
	}
      } catch (e) {
	dbg('RTC/JOIN', 'message parse error', e);
      }
    };
  };

  // msg contains { type:'offer', sdp, candidates? }
  await pc.setRemoteDescription({ type:'offer', sdp: msg.sdp });

  // Apply inviter's candidates (if present)
  const offerCands = Array.isArray(msg.candidates) ? msg.candidates : [];
  for (const c of offerCands) {
    try { await pc.addIceCandidate(new RTCIceCandidate(c)); } catch (e) { dbg('RTC/JOIN addIce offer', e); }
  }

  // Create/Set local answer as usual
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);

  const { sdp, candidates } = await gatherIceCandidates(pc, 1500);
  const answerCode = packSignal({ type: 'answer', sdp, candidates });
  join.answerTA.value = answerCode;
}

join.btnClose?.addEventListener('click', () => join.dlg.close());
join.btnGen?.addEventListener('click', generateJoinAnswer);
join.btnCopy?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(join.answerTA.value); join.btnCopy.textContent='Copied'; setTimeout(()=>join.btnCopy.textContent='Copy',1000);} catch {}
});

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

btnInvite?.addEventListener('click', openInviteDialog);
inv.btnClose?.addEventListener('click', () => inv.dlg.close());
inv.btnCopyOffer?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(inv.offerTA.value); inv.btnCopyOffer.textContent='Copied'; setTimeout(()=>inv.btnCopyOffer.textContent='Copy',1000);} catch {}
});
inv.btnRefreshOffer?.addEventListener('click', openInviteDialog);
inv.btnFinish?.addEventListener('click', finishInviteDialog);

// ====== Boot ======
loadSettings();
await ensureIdentity();
loadRooms();
if (rooms.length) {
  // connect to all servers & subscribe to all rooms
  ensureAllServerConnections();
  // open current room in the UI
  await openRoom(currentRoomId);
} else {
  setStatus('No room');
  ui.currentRoomName.textContent = 'No room';
}
