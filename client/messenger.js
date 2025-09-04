// ====== CONFIG ======
const ROOMS_KEY = 'secmsg_rooms_v1';
const CURRENT_ROOM_KEY = 'secmsg_current_room_id';
const SETTINGS_KEY = 'secmsg_settings_v1';
const RTC_CONFIG = {
  iceServers: [
    { urls: ['stun:stun.l.google.com:19302'] },
    // { urls: 'turn:your.turn.server:3478', username: 'user', credential: 'pass' }
  ]
};
const CHUNK_SIZE = 64 * 1024; // 64KB chunks for file send

// ====== DEBUG ======
const DEBUG_SIG = true;     // WebSocket signaling logs
const DEBUG_RTC = true;     // WebRTC flow logs

function dbg(tag, ...args){
  const ts = new Date().toISOString().split('T')[1].replace('Z','');
  console.log(`[${ts}] ${tag}`, ...args);
}

//
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
  btnRoomMenu   = document.getElementById('btnRoomMenu');
  roomMenu      = document.getElementById('roomMenu');
  currentRoomName = document.getElementById('currentRoomName');
};

const cr = {
  dlg: document.getElementById('createRoomModal'),
  name: document.getElementById('newRoomName'),
  server: document.getElementById('newServerUrl'),
  btnCreate: document.getElementById('btnCreateRoom'),
  btnClose: document.getElementById('btnCloseCreateRoom'),
};

const cfg = {
  dlg: document.getElementById('settingsModal'),
  name: document.getElementById('cfgRoomName'),
  btnSave: document.getElementById('btnSaveRoomCfg'),
  btnRemove: document.getElementById('btnRemoveRoom'),
  btnClose: document.getElementById('btnCloseSettings'),
};

//
// ====== STATE ======
let SETTINGS = { username: '', roomSkB64: '' };
let RELAY_HTTP_BASE = null;
let RELAY_WS_URL = null;

let ws = null;
let authed = false;
let reconnectTimer = null;
let reconnectAttempt = 0;
let heartbeatTimer = null;

let edPk = null;   // room public key (Uint8Array)
let edSk = null;   // room private key (Uint8Array)
let curvePk = null;
let curveSk = null;
let currentRoomId = null;

let myIdPk = null; // device identity public key (Uint8Array)
let myIdSk = null; // device identity private key (Uint8Array)
let myPeerId = null; // base64url of myIdPk

let rooms = [];            // [{id, name, server, roomSkB64, roomId, createdAt}]
let currentRoomId = null;  // string id = roomId (ed25519 pk b64u)

// WebRTC maps
const pendingRequests = new Map(); // request_id -> { pc, dc, hash, remotePeerId?, iceBuf? }
const serveRequests   = new Map(); // request_id -> { pc, dc, hash } (we are sender)
const preServeIce     = new Map(); // request_id -> RTCIceCandidateInit[]


// ====== UTIL ======
function b64u(bytes) { return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING); }
function fromB64u(str) { return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING); }
function nowMs() { return Date.now(); }
function sevenDaysAgoMs() { return nowMs() - 7 * 24 * 60 * 60 * 1000; }
function setStatus(text) { ui.status.textContent = text; }
function shortId(idB64u) { return idB64u.slice(0, 6) + '…' + idB64u.slice(-6); }
async function ensureSodium() { await sodium.ready; }

function derivePubFromSk(sk) {
  if (sodium.crypto_sign_ed25519_sk_to_pk) return sodium.crypto_sign_ed25519_sk_to_pk(sk);
  return sk.slice(32, 64);
}

function scrollToEnd() {
  const el = ui.messages;
  if (!el) return;
  const doScroll = () => { el.scrollTop = el.scrollHeight; };
  doScroll(); requestAnimationFrame(doScroll); setTimeout(doScroll, 0);
}

function clearMessagesUI() { ui.messages.innerHTML = ''; }

function loadRooms(){
  try { rooms = JSON.parse(localStorage.getItem(ROOMS_KEY) || '[]'); } catch { rooms = []; }
  currentRoomId = localStorage.getItem(CURRENT_ROOM_KEY) || null;

  // Migration: if legacy single-room settings exist, lift them into rooms
  if (!rooms.length && getCurrentRoom().roomSkB64) {
    const migratedServer = RELAY_HTTP_BASE || 'https://rartino.pythonanywhere.com';
    const tmpSk = getCurrentRoom().roomSkB64;
    try {
      const sk = fromB64u(tmpSk);
      const pk = derivePubFromSk(sk);
      const rid = b64u(pk);
      rooms.push({ id: rid, name: 'Room 1', server: migratedServer, roomSkB64: tmpSk, roomId: rid, createdAt: nowMs() });
      currentRoomId = rid;
      localStorage.removeItem(SETTINGS_KEY); // old structure not needed for room code
    } catch {}
  }

  // If no current room but we have rooms, pick first
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
  document.getElementById('currentRoomName').textContent = r ? r.name : 'No room';
  setRelayFromServer(r ? r.server : '');
}

function renderRoomMenu(){
  const menu = document.getElementById('roomMenu');
  const r = getCurrentRoom();
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
}

async function openRoom(roomId){
  setCurrentRoom(roomId);
  const r = getCurrentRoom();
  if (!r) return;
  // set keys for this room
  await ensureSodium();
  edSk = fromB64u(r.roomSkB64);
  edPk = derivePubFromSk(edSk);
  curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);
  currentRoomId = r.id; // equals b64u(edPk)
  await registerRoomIfNeeded(r.server);
  await connectToCurrentRoom();
}

function normServer(url){
  if (!url) return '';
  let u = url.trim();
  if (u.endsWith('/')) u = u.slice(0,-1);
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}

function setRelayFromServer(serverUrl){
  RELAY_HTTP_BASE = normServer(serverUrl);
  RELAY_WS_URL = RELAY_HTTP_BASE.replace(/^http/i, 'ws') + '/ws';
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
        // give the network a short settle period to ship the last packets
        setTimeout(() => { done = true; resolve(); }, settleMs);
      } else if (performance.now() - start > timeoutMs) {
        done = true; resolve();
      } else {
        // wait for next low-watermark or poll again
        // (some browsers don’t always fire 'bufferedamountlow')
        setTimeout(maybeDone, 50);
      }
    }

    // Use low-watermark event when available
    try {
      dc.bufferedAmountLowThreshold = Math.max(16384, CHUNK_SIZE >> 2);
      const onLow = () => maybeDone();
      dc.addEventListener('bufferedamountlow', onLow, { once: true });
    } catch {}
    maybeDone();
  });
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

function iceToJSON(c) {
  if (!c) return null;
  const j = typeof c.toJSON === 'function'
    ? c.toJSON()
    : { candidate: c.candidate, sdpMid: c.sdpMid, sdpMLineIndex: c.sdpMLineIndex, usernameFragment: c.usernameFragment };
  if (DEBUG_RTC) dbg('RTC/ICE->JSON', { hasCandidate: !!j.candidate, mid: j.sdpMid, mline: j.sdpMLineIndex });
  return j;
}

// ====== Identity & Settings ======
function loadSettings() {
  try { SETTINGS = { ...SETTINGS, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; }
  catch {}
}

function saveSettings() {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(SETTINGS));
}

function persistIdentity() {
  localStorage.setItem('secmsg_id_pk', b64u(myIdPk));
  localStorage.setItem('secmsg_id_sk', b64u(myIdSk));
  myPeerId = b64u(myIdPk);
  document.getElementById('identityInfo').textContent = `Your device ID: ${shortId(myPeerId)} (stored locally)`;
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

function setRoomFromSecret(skB64) {
  edSk = fromB64u(skB64);
  edPk = derivePubFromSk(edSk);
  curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);
  currentRoomId = b64u(edPk);
}

async function registerRoomIfNeeded(serverUrl) {
  try {
    await fetch(`${normServer(serverUrl)}/rooms`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ room_id: currentRoomId, ed25519_public_key_b64u: currentRoomId })
    });
  } catch {}
}

function openCreateRoomDialog(){
  cr.name.value = '';
  cr.server.value = RELAY_HTTP_BASE || 'https://rartino.pythonanywhere.com';
  cr.dlg.showModal();
}
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
  await openRoom(room.id);
});

// ====== Rendering ======
function renderTextMessage({ text, ts, nickname, senderId, verified }) {
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

function fileBubbleSkeleton({ meta, ts, nickname, senderId, verified }) {
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

  // Placeholder content
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

// ====== Send/Receive ======
function signCiphertextB64(ciphertextB64) {
  const sig = sodium.crypto_sign_detached(fromB64u(ciphertextB64), myIdSk);
  return b64u(sig);
}

async function sendTextMessage(text) {
  const ciphertextB64 = encryptStringForRoom(text);
  const payload = {
    type: 'send',
    ciphertext: ciphertextB64,
    ts_client: nowMs(),
    nickname: SETTINGS.username || undefined,
    sender_id: myPeerId,
    sig: signCiphertextB64(ciphertextB64),
  };
  if (DEBUG_SIG) dbg('SIG/TX', 'send:text', { len: text.length });
  ws.send(JSON.stringify(payload));
}

async function sendFileMetadata(meta) {
  const metaJson = JSON.stringify({ kind: 'file', ...meta });
  const ciphertextB64 = encryptStringForRoom(metaJson);
  const payload = {
    type: 'send',
    ciphertext: ciphertextB64,
    ts_client: nowMs(),
    nickname: SETTINGS.username || undefined,
    sender_id: myPeerId,
    sig: signCiphertextB64(ciphertextB64),
  };
  if (DEBUG_SIG) dbg('SIG/TX', 'send:file-meta', { hash: meta.hash, name: meta.name, mime: meta.mime, size: meta.size }); 
  ws.send(JSON.stringify(payload));
}

function handleIncoming(m) {
  const pt = decryptToString(m.ciphertext);
  let verified = undefined;
  if (m.sender_id && m.sig) {
    try {
      const senderPk = fromB64u(m.sender_id);
      const sig = fromB64u(m.sig);
      const ciphertext = fromB64u(m.ciphertext);
      verified = sodium.crypto_sign_verify_detached(sig, ciphertext, senderPk);
    } catch { verified = false; }
  }

  // Try parse JSON
  try {
    const obj = JSON.parse(pt);
      if (obj && obj.kind === 'file' && obj.hash) {
	const bubble = fileBubbleSkeleton({ meta: obj, ts: m.ts, nickname: m.nickname, senderId: m.sender_id, verified });
	renderFileIfAvailable(bubble, obj).then((hasIt) => {
	  if (!hasIt) {
	    // show pending + allow manual retry, and also auto-request
	    showPendingBubble(bubble, obj);
	    requestFile(obj.hash);
	  } else {
	    scrollToEnd();
	  }
	});
      return;
    }
  } catch (_) { /* not JSON */ }
    
  // Plain text
  renderTextMessage({ text: pt, ts: m.ts, nickname: m.nickname, senderId: m.sender_id, verified });
}

// ====== WebRTC Signaling (via server) ======
function randomIdB64(n=16) {
  const a = new Uint8Array(n); crypto.getRandomValues(a); return b64u(a);
}

async function requestFile(hash) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  if (DEBUG_RTC) dbg('RTC/REQ', 'start', { hash });

  const pc = new RTCPeerConnection(RTC_CONFIG);
  pc.oniceconnectionstatechange = () => dbg('RTC/REQ iceState', pc.iceConnectionState);
  pc.onconnectionstatechange = () => dbg('RTC/REQ pcState', pc.connectionState);
    
  const dc = pc.createDataChannel('file');
  const reqId = randomIdB64(16);

  const state = { pc, dc, hash, remotePeerId: null, iceBuf: [], incomingIceBuf: [], haveAnswer: false };
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
      ws.send(JSON.stringify({ type: 'webrtc-ice', request_id: reqId, candidate: cand, to: state.remotePeerId, from: myPeerId }));
    } else {
      state.iceBuf.push(cand);
      if (DEBUG_RTC) dbg('RTC/REQ', 'ice buffered', { reqId, count: state.iceBuf.length });
    }
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  if (DEBUG_RTC) dbg('RTC/REQ', 'offer created', { reqId, sdpLen: (offer.sdp||'').length });

  if (DEBUG_SIG) dbg('SIG/TX', 'webrtc-request', { reqId, hash, sdpLen: (offer.sdp||'').length });
  ws.send(JSON.stringify({ type: 'webrtc-request', request_id: reqId, checksum: hash, offer, from: myPeerId }));
}

async function serveFileIfWeHaveIt(msg) {
  const { request_id, checksum, from, offer } = msg;
  const blob = await idbGet(checksum);
  if (!blob) { if (DEBUG_RTC) dbg('RTC/RESP', 'no-file', { request_id, checksum }); return; }

  if (DEBUG_RTC) dbg('RTC/RESP', 'serve', { request_id, checksum, size: blob.size, mime: blob.type, from });

  const pc = new RTCPeerConnection(RTC_CONFIG);
  pc.oniceconnectionstatechange = () => dbg('RTC/RESP iceState', pc.iceConnectionState);
  pc.onconnectionstatechange = () => dbg('RTC/RESP pcState', pc.connectionState);

  // Register EARLY so incoming ICE has somewhere to land
  serveRequests.set(request_id, { pc, hash: checksum, iceBuf: [] });

  pc.ondatachannel = (evt) => {
    const dc = evt.channel;
    dc.binaryType = 'arraybuffer';

    dc.onopen = async () => {
      if (DEBUG_RTC) dbg('RTC/RESP', 'dc open', { request_id });

      // Header first
      const header = { kind: 'file', name: blob.name || 'file', mime: blob.type || 'application/octet-stream', size: blob.size, hash: checksum };
      dc.send(new TextEncoder().encode(JSON.stringify(header)));

      // Send file by slices (compat > streams)
      const total = blob.size | 0;
      for (let offset = 0; offset < total; offset += CHUNK_SIZE) {
	const slice = blob.slice(offset, Math.min(offset + CHUNK_SIZE, total));
	const buf = new Uint8Array(await slice.arrayBuffer());
	dc.send(buf);

	if (DEBUG_RTC && (offset % (512 * 1024)) === 0) dbg('RTC/RESP', 'sent', { request_id, offset, total });

	// Backpressure: keep the send queue bounded
	while (dc.bufferedAmount > 8 * CHUNK_SIZE && dc.readyState === 'open') {
	  await new Promise(r => setTimeout(r, 10));
	}
      }

      // *** NEW: wait for the channel buffer to drain before closing ***
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
    ws.send(JSON.stringify({ type: 'webrtc-ice', request_id, candidate: cand, to: from, from: myPeerId }));
  };

  // Apply remote offer
  await pc.setRemoteDescription(offer);
  if (DEBUG_RTC) dbg('RTC/RESP', 'offer applied', { request_id });

  // Flush any ICE that arrived before we were ready
  const buffered = preServeIce.get(request_id);
  if (buffered && buffered.length) {
    if (DEBUG_RTC) dbg('RTC/RESP', 'flush buffered ICE', { request_id, count: buffered.length });
    for (const cand of buffered) {
      try { await pc.addIceCandidate(new RTCIceCandidate(cand)); } catch (e) { if (DEBUG_RTC) dbg('RTC/RESP', 'flush addIce error', e); }
    }
    preServeIce.delete(request_id);
  }

  // Create/send answer
  const answer = await pc.createAnswer();
  await pc.setLocalDescription(answer);
  await new Promise(r => setTimeout(r, 50));
  if (DEBUG_RTC) dbg('RTC/RESP', 'answer created', { request_id, sdpLen: (answer.sdp||'').length });

  ws.send(JSON.stringify({ type: 'webrtc-response', request_id, answer, to: from, from: myPeerId, checksum }));
  if (DEBUG_SIG) dbg('SIG/TX', 'webrtc-response', { request_id, to: from, sdpLen: (answer.sdp||'').length });
}

async function handleWebRtcResponse(msg) {
  const { request_id, answer, from } = msg;
  const st = pendingRequests.get(request_id);
  if (!st) return;

  if (DEBUG_SIG) dbg('SIG/RX', 'webrtc-response', { request_id, from, sdpLen: (answer.sdp||'').length });

  // If we already picked a responder, ignore other replies
  if (st.remotePeerId && st.remotePeerId !== from) {
    if (DEBUG_RTC) dbg('RTC/REQ', 'ignore secondary answer', { request_id, from, chosen: st.remotePeerId });
    return;
  }

  await st.pc.setRemoteDescription(answer);
  st.remotePeerId = from;
  st.haveAnswer = true;
  if (DEBUG_RTC) dbg('RTC/REQ', 'answer applied', { request_id });

  // Flush any buffered OUTGOING ICE we generated before we knew who to send to
  for (const cand of st.iceBuf) {
    ws.send(JSON.stringify({ type:'webrtc-ice', request_id, candidate: cand, to: from, from: myPeerId }));
  }
  st.iceBuf = [];

  // **** NEW: Flush any buffered INCOMING ICE that arrived before answer ****
  if (st.incomingIceBuf.length) {
    if (DEBUG_RTC) dbg('RTC/REQ', 'flush buffered incoming ICE', { request_id, count: st.incomingIceBuf.length });
    for (const cInit of st.incomingIceBuf) {
      try { await st.pc.addIceCandidate(new RTCIceCandidate(cInit)); }
      catch (e) { if (DEBUG_RTC) dbg('RTC/REQ', 'flush addIce error', e); }
    }
    st.incomingIceBuf = [];
  }
}

async function handleWebRtcIce(msg) {
  const { request_id, candidate, from } = msg;
  if (!candidate) return;
  const iceInit = candidate;

  if (pendingRequests.has(request_id)) {
    // We are the requester
    const st = pendingRequests.get(request_id);

    // If we've already chosen a responder and this ICE is from someone else, ignore it
    if (st.remotePeerId && from && from !== st.remotePeerId) {
      if (DEBUG_SIG) dbg('SIG/RX', 'ice from non-selected responder ignored', { request_id, from, chosen: st.remotePeerId });
      return;
    }

    // If we don't have an answer yet, we can't add ICE—buffer it
    if (!st.haveAnswer) {
      st.incomingIceBuf.push(iceInit);
      if (DEBUG_SIG) dbg('SIG/RX', 'ice buffered (no remoteDescription yet)', { request_id, count: st.incomingIceBuf.length });
      return;
    }

    if (DEBUG_SIG) dbg('SIG/RX', 'ice to requester', { request_id, from, mid: iceInit.sdpMid, mline: iceInit.sdpMLineIndex });
    try { await st.pc.addIceCandidate(new RTCIceCandidate(iceInit)); }
    catch (e) { if (DEBUG_RTC) dbg('RTC/REQ', 'addIce error', e); }

  } else if (serveRequests.has(request_id)) {
    // We are the responder; PC exists—add immediately
    if (DEBUG_SIG) dbg('SIG/RX', 'ice to responder', { request_id, from, mid: iceInit.sdpMid, mline: iceInit.sdpMLineIndex });
    try { await serveRequests.get(request_id).pc.addIceCandidate(new RTCIceCandidate(iceInit)); }
    catch (e) { if (DEBUG_RTC) dbg('RTC/RESP', 'addIce error', e); }

  } else {
    // Not requester or responder yet -> buffer for responder setup (race)
    const arr = preServeIce.get(request_id) || [];
    arr.push(iceInit);
    preServeIce.set(request_id, arr);
    if (DEBUG_SIG) dbg('SIG/RX', 'ice buffered (no serve)', { request_id, count: arr.length });
  }
}

// ====== Connection lifecycle ======
async function connectToCurrentRoom() {
  const room = getCurrentRoom();
  if (!room) return;

  // cancel timers
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }

  // close previous socket
  if (ws) { try { ws.onclose = null; ws.close(); } catch(_){} ws = null; }

  setRelayFromServer(room.server);
  const url = `${RELAY_WS_URL}?room=${encodeURIComponent(currentRoomId)}`;
  ws = new WebSocket(url);

  ws.onopen  = () => { if (DEBUG_SIG) dbg('SIG/WS', 'open'); setStatus('Connecting…'); };
  ws.onerror = (e) => { setStatus('WebSocket error'); if (DEBUG_SIG) dbg('SIG/WS', 'error', e); };
  ws.onclose = (e) => {
    authed = false; setStatus('Disconnected');
    if (DEBUG_SIG) dbg('SIG/WS', 'close', { code:e.code, reason:e.reason });
    scheduleReconnect();
  };

  ws.onmessage = async (evt) => {
    const m = JSON.parse(evt.data);
    if (DEBUG_SIG) dbg('SIG/RX', m.type, Object.assign({}, m, {
      ciphertext: m.ciphertext ? `<${m.ciphertext.length} chars>`: undefined,
      offer: m.offer ? { type:m.offer.type, sdpLen: (m.offer.sdp||'').length } : undefined,
      answer: m.answer ? { type:m.answer.type, sdpLen: (m.answer.sdp||'').length } : undefined,
      candidate: m.candidate ? { has: true } : undefined
    }));

    if (m.type === 'challenge') {
      const nonce = fromB64u(m.nonce);
      const sig = sodium.crypto_sign_detached(nonce, edSk);
      ws.send(JSON.stringify({ type: 'auth', room_id: currentRoomId, signature: b64u(sig) }));

    } else if (m.type === 'ready') {
      authed = true; setStatus('Connected'); reconnectAttempt = 0;
      ws.send(JSON.stringify({ type: 'announce', peer_id: myPeerId }));
      clearMessagesUI();
      ws.send(JSON.stringify({ type: 'history', since: sevenDaysAgoMs() }));
      requestAnimationFrame(() => requestAnimationFrame(scrollToEnd));
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => { try { ws.send(JSON.stringify({ type: 'ping', ts: nowMs() })); } catch {} }, 25000);

    } else if (m.type === 'history') {
      if (DEBUG_SIG) dbg('SIG/RX', 'history', { count: (m.messages||[]).length });
      for (const item of m.messages) handleIncoming(item, /*fromHistory=*/true);
      scrollToEnd(); requestAnimationFrame(scrollToEnd);

    } else if (m.type === 'message') {
      handleIncoming(m);

    } else if (m.type === 'webrtc-request') {
      serveFileIfWeHaveIt(m);

    } else if (m.type === 'webrtc-response') {
      await handleWebRtcResponse(m);

    } else if (m.type === 'webrtc-ice') {
      await handleWebRtcIce(m);

    } else if (m.type === 'pong') {
      // no-op
    } else if (m.type === 'error') {
      renderTextMessage({ text: `Server error: ${m.error}`, ts: nowMs(), nickname: 'server', senderId: null });
    }
  };
}

function scheduleReconnect() {
  const r = getCurrentRoom();
  if (!r) return;
  const delay = Math.min(30000, 1000 * Math.pow(2, reconnectAttempt));
  reconnectAttempt++;
  setStatus(`Disconnected — reconnecting in ${Math.round(delay/1000)}s`);
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(() => connectToCurrentRoom(), delay);
}

function showPendingBubble(bubbleEl, meta) {
  bubbleEl.innerHTML = '';
  const wrap = document.createElement('div'); wrap.className = 'pending';

  const label = document.createElement('span');
  label.textContent = meta.mime && meta.mime.startsWith('image/') ? 'Image pending…' : 'File pending…';

  const btn = document.createElement('button');
  btn.className = 'retry-btn'; btn.type = 'button'; btn.title = 'Retry';
  btn.innerHTML = `
    <svg class="retry-icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 5v2.5l3.5-3.5L12 0.5V3a9 9 0 1 0 9 9h-2a7 7 0 1 1-7-7z"/>
    </svg>
  `;

  btn.addEventListener('click', async () => {
    // Try local again first (maybe IDB finished opening)
    const ok = await renderFileIfAvailable(bubbleEl, meta);
    if (!ok) {
      if (DEBUG_SIG) dbg('PENDING', 'retry request', { hash: meta.hash });
      requestFile(meta.hash);
    }
  });

  wrap.appendChild(label);
  wrap.appendChild(btn);
  bubbleEl.appendChild(wrap);
}

// ====== Events ======
ui.btnSend.addEventListener('click', async () => {
  const text = ui.msgInput.value.trim();
  if (!text) return;
  if (!ws || ws.readyState !== WebSocket.OPEN || !authed) { alert('Not connected'); return; }
  await sendTextMessage(text);
  ui.msgInput.value = '';
});

ui.msgInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); ui.btnSend.click(); } });
ui.msgInput.addEventListener('focus', scrollToEnd);
ui.msgInput.addEventListener('input', scrollToEnd);
window.addEventListener('resize', scrollToEnd);
document.addEventListener('visibilitychange', () => { if (!document.hidden) scrollToEnd(); });

// Attach button → open file picker
ui.btnAttach.addEventListener('click', () => ui.fileInput.click());
ui.fileInput.addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  if (!ws || ws.readyState !== WebSocket.OPEN || !authed) { alert('Not connected'); return; }

  const hash = await sha256_b64u(file);
  // Store locally first so we can serve others and render on echo/history
  await idbPut(hash, file);

  const meta = { hash, name: file.name, mime: file.type || 'application/octet-stream', size: file.size|0 };
  await sendFileMetadata(meta);
    
  // clear file input
  ui.fileInput.value = '';
});

// Settings dialog
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

cfg.btnRemove.addEventListener('click', () => {
  const r = getCurrentRoom(); if (!r) return;
  if (!confirm(`Remove room “${r.name}”?`)) return;
  rooms = rooms.filter(x => x.id !== r.id);
  saveRooms();
  cfg.dlg.close();
  if (rooms.length) {
    openRoom(rooms[0].id);
  } else {
    // No rooms left; disconnect and prompt create
    if (ws) { try { ws.close(); } catch{} ws = null; }
    clearMessagesUI();
    setStatus('No room');
    document.getElementById('currentRoomName').textContent = 'No room';
    openCreateRoomDialog();
  }
});

// Room dialog
ui.btnRoomMenu.addEventListener('click', () => {
  const open = ui.roomMenu.hasAttribute('hidden');
  renderRoomMenu();
  ui.roomMenu.hidden = !open;
  ui.btnRoomMenu.setAttribute('aria-expanded', String(open));
});
document.addEventListener('click', (e) => {
  if (!ui.roomMenu.contains(e.target) && !ui.btnRoomMenu.contains(e.target)) {
    ui.roomMenu.hidden = true;
    ui.btnRoomMenu.setAttribute('aria-expanded', 'false');
  }
});

// ====== Boot ======
loadSettings();           // keeps username + device identity behavior
await ensureIdentity();
loadRooms();

// If we have at least one room, activate it; else prompt to create
if (rooms.length) {
  setCurrentRoom(currentRoomId);
  await openRoom(currentRoomId);
} else {
  setStatus('No room');
  document.getElementById('currentRoomName').textContent = 'No room';
  openCreateRoomDialog();
}
