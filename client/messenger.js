// ====== CONFIG ======
const RELAY_HTTP_BASE = 'https://rartino.pythonanywhere.com';
const RELAY_WS_URL    = RELAY_HTTP_BASE.replace(/^http/, 'ws') + '/ws';
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
};

const dlg = document.getElementById('settingsModal');
const f = {
  name: document.getElementById('setName'),
  room: document.getElementById('setRoomCode'),
  gen: document.getElementById('btnGenRoom'),
  connect: document.getElementById('btnConnectSettings'),
  close: document.getElementById('btnCloseSettings'),
  copy: document.getElementById('btnCopyRoom'),
};

//
// ====== STATE ======
let SETTINGS = { username: '', roomSkB64: '' };

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

async function registerRoomIfNeeded() {
  try {
    await fetch(`${RELAY_HTTP_BASE}/rooms`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ room_id: currentRoomId, ed25519_public_key_b64u: currentRoomId })
    });
  } catch {}
}

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
  const dc = pc.createDataChannel('file');
  const reqId = randomIdB64(16);

  const state = { pc, dc, hash, remotePeerId: null, iceBuf: [] };
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
  await st.pc.setRemoteDescription(answer);
  if (DEBUG_RTC) dbg('RTC/REQ', 'answer applied', { request_id });
  st.remotePeerId = from;

  // Flush any buffered ICE
  for (const cand of st.iceBuf) {
    ws.send(JSON.stringify({ type:'webrtc-ice', request_id, candidate: cand, to: from, from: myPeerId }));
  }
  st.iceBuf = [];
}

async function handleWebRtcIce(msg) {
  const { request_id, candidate, from } = msg;
  if (!candidate) return;
  const iceInit = candidate;                       // already JSON
  const ice = new RTCIceCandidate(iceInit);

  if (pendingRequests.has(request_id)) {
    // We are the requester
    if (DEBUG_SIG) dbg('SIG/RX', 'ice to requester', { request_id, from, mid: iceInit.sdpMid, mline: iceInit.sdpMLineIndex });
    try { await pendingRequests.get(request_id).pc.addIceCandidate(ice); }
    catch (e) { if (DEBUG_RTC) dbg('RTC/REQ', 'addIce error', e); }

  } else if (serveRequests.has(request_id)) {
    // We are the responder and already set up
    if (DEBUG_SIG) dbg('SIG/RX', 'ice to responder', { request_id, from, mid: iceInit.sdpMid, mline: iceInit.sdpMLineIndex });
    try { await serveRequests.get(request_id).pc.addIceCandidate(ice); }
    catch (e) { if (DEBUG_RTC) dbg('RTC/RESP', 'addIce error', e); }

  } else {
    // Not ready yet -> buffer it only if we might become responder for this request
    if (!serveRequests.has(request_id)) {
      const arr = preServeIce.get(request_id) || [];
      arr.push(iceInit);
      preServeIce.set(request_id, arr);
      if (DEBUG_SIG) dbg('SIG/RX', 'ice buffered (no serve)', { request_id, count: arr.length });
    }
  }
}

// ====== Connection lifecycle ======
async function connectFromSettings() {
  if (!SETTINGS.roomSkB64) return;

  await ensureSodium();
  setRoomFromSecret(SETTINGS.roomSkB64);

  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
  if (ws) { try { ws.onclose = null; ws.close(); } catch(_){} ws = null; }

  ws = new WebSocket(`${RELAY_WS_URL}?room=${encodeURIComponent(currentRoomId)}`);
  if (DEBUG_SIG) dbg('SIG/WS', 'opening', { room: currentRoomId });

  ws.onopen  = () => { if (DEBUG_SIG) dbg('SIG/WS', 'open'); setStatus('Connecting…'); };
  ws.onerror = (e) => { setStatus('WebSocket error'); if (DEBUG_SIG) dbg('SIG/WS', 'error', e); };
  ws.onclose = (e) => { authed = false; setStatus('Disconnected'); if (DEBUG_SIG) dbg('SIG/WS', 'close', { code:e.code, reason:e.reason }); scheduleReconnect(); };

  ws.onmessage = async (evt) => {
    const m = JSON.parse(evt.data);
    if (DEBUG_SIG) dbg('SIG/RX', m.type, Object.assign({}, m, { ciphertext: m.ciphertext ? `<${m.ciphertext.length} chars>`: undefined, offer: m.offer ? { type:m.offer.type, sdpLen: (m.offer.sdp||'').length } : undefined, answer: m.answer ? { type:m.answer.type, sdpLen: (m.answer.sdp||'').length } : undefined, candidate: m.candidate ? { has: true } : undefined }));

    if (m.type === 'challenge') {
      const nonce = fromB64u(m.nonce);
      const sig = sodium.crypto_sign_detached(nonce, edSk);
      ws.send(JSON.stringify({ type: 'auth', room_id: currentRoomId, signature: b64u(sig) }));

    } else if (m.type === 'ready') {
      authed = true; setStatus('Connected'); reconnectAttempt = 0;
      // Announce our device id for signaling
      if (DEBUG_SIG) dbg('SIG/TX', 'announce', { peer_id: myPeerId });
      ws.send(JSON.stringify({ type: 'announce', peer_id: myPeerId }));

      clearMessagesUI();
      if (DEBUG_SIG) dbg('SIG/TX', 'history', { since: sevenDaysAgoMs() });
      ws.send(JSON.stringify({ type: 'history', since: sevenDaysAgoMs() }));
      requestAnimationFrame(() => requestAnimationFrame(scrollToEnd));

      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        try { ws.send(JSON.stringify({ type: 'ping', ts: nowMs() })); } catch {}
      }, 25000);


    } else if (m.type === 'history') {
      if (DEBUG_SIG) dbg('SIG/RX', 'history', { count: (m.messages||[]).length });
      for (const item of m.messages) handleIncoming(item);
      scrollToEnd(); requestAnimationFrame(scrollToEnd);

    } else if (m.type === 'message') {
      handleIncoming(m);

    } else if (m.type === 'webrtc-request') {
      // Someone is asking for a file by checksum
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
  if (!SETTINGS.roomSkB64) return;
  const delay = Math.min(30000, 1000 * Math.pow(2, reconnectAttempt));
  reconnectAttempt++;
  setStatus(`Disconnected — reconnecting in ${Math.round(delay/1000)}s`);
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(() => connectFromSettings(), delay);
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
  f.name.value = SETTINGS.username || '';
  f.room.value = SETTINGS.roomSkB64 || '';
  dlg.showModal();
});
f.gen.addEventListener('click', async () => {
  await ensureSodium();
  const { privateKey } = sodium.crypto_sign_keypair();
  f.room.value = b64u(privateKey);
});
f.close.addEventListener('click', () => dlg.close());
f.copy.addEventListener('click', async () => {
  const val = (f.room.value || '').trim();
  if (!val) { alert('No room code to copy'); return; }
  try { await navigator.clipboard.writeText(val); f.copy.textContent = 'Copied'; }
  catch { try { f.room.select(); document.execCommand('copy'); f.copy.textContent = 'Copied'; } catch {} }
  setTimeout(() => { f.copy.textContent = 'Copy'; }, 1500);
});
f.connect.addEventListener('click', async () => {
  const newName = (f.name.value || '').trim() || 'Me';
  const newRoomSk = (f.room.value || '').trim();
  if (!newRoomSk) { alert('Room code is required.'); return; }
  if ((SETTINGS.username || '') !== newName) { await ensureSodium(); rotateIdentityWithName(newName); }
  const roomChanged = SETTINGS.roomSkB64 !== newRoomSk;
  SETTINGS.username = newName; SETTINGS.roomSkB64 = newRoomSk; saveSettings();
  dlg.close();
  await ensureSodium(); setRoomFromSecret(SETTINGS.roomSkB64);
  if (roomChanged) await registerRoomIfNeeded();
  connectFromSettings();
});

// ====== Boot ======
loadSettings();
await ensureIdentity();
setStatus('Ready');

if (SETTINGS.roomSkB64) {
  await registerRoomIfNeeded();
  connectFromSettings();
} else {
  dlg.showModal();
}
