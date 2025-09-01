const RELAY_HTTP_BASE = 'https://rartino.pythonanywhere.com';
const RELAY_WS_URL    = RELAY_HTTP_BASE.replace(/^http/, 'ws') + '/ws';
const SETTINGS_KEY = 'secmsg_settings_v1';
let SETTINGS = { username: '', roomSkB64: '' };

const ui = {
  status: document.getElementById('status'),
  secretKey: document.getElementById('secretKey'),
  nickname: document.getElementById('nickname'),
  btnJoin: document.getElementById('btnJoin'),
  btnCreate: document.getElementById('btnCreate'),
  messages: document.getElementById('messages'),
  msgInput: document.getElementById('messageInput'),
  btnSend: document.getElementById('btnSend'),
};

ui.btnSettings = document.getElementById('btnSettings');

const dlg = document.getElementById('settingsModal');
const f = {
  name: document.getElementById('setName'),
  room: document.getElementById('setRoomCode'),
  gen: document.getElementById('btnGenRoom'),
  connect: document.getElementById('btnConnectSettings'),
  close: document.getElementById('btnCloseSettings'),
  copy: document.getElementById('btnCopyRoom'),  
};

let ws = null;
let edPk = null; // Uint8Array room public key
let edSk = null; // Uint8Array room private key (secret)
let curvePk = null; // for sealed boxes
let curveSk = null;
let currentRoomId = null;
let authed = false;
let reconnectTimer = null;
let reconnectAttempt = 0;
let heartbeatTimer = null;

// Per-device identity for "me" bubbles
let myIdPk = null; // Uint8Array
let myIdSk = null; // Uint8Array

function b64u(bytes) { return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING); }
function fromB64u(str) { return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING); }
function nowMs() { return Date.now(); }
function sevenDaysAgoMs() { return nowMs() - 7 * 24 * 60 * 60 * 1000; }
function setStatus(text) { ui.status.textContent = text; }

function loadSettings() {
  try { SETTINGS = { ...SETTINGS, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; }
  catch {}
}

function saveSettings() {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(SETTINGS));
}

function clearMessagesUI() {
  ui.messages.innerHTML = '';
}

function scrollToEnd() {
  const el = ui.messages;
  if (!el) return;
  const doScroll = () => { el.scrollTop = el.scrollHeight; };
  // try immediately, then after layout, then after paint
  doScroll();
  requestAnimationFrame(doScroll);
  setTimeout(doScroll, 0);
}

function renderMessage({ text, ts, nickname, senderId, verified }) {
  const row = document.createElement('div');
  const isMe = senderId && myIdPk && senderId === b64u(myIdPk);
  row.className = 'row ' + (isMe ? 'me' : 'other');

  const who = nickname || (senderId ? shortId(senderId) : 'room');
  const when = new Date(ts || nowMs()).toLocaleString();

  const wrap = document.createElement('div');
  wrap.className = 'wrap';

  const label = document.createElement('div');
  label.className = 'name-label';
  label.textContent = `${who} • ${when}${verified === false ? ' • ⚠︎ unverified' : ''}`;

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text;

  wrap.appendChild(label);
  wrap.appendChild(bubble);
  row.appendChild(wrap);

  ui.messages.appendChild(row);

  scrollToEnd();
}

function shortId(idB64u) { return idB64u.slice(0, 6) + '…' + idB64u.slice(-6); }

async function ensureSodium() { await sodium.ready; }

function derivePubFromSk(sk) {
  // Prefer API if available, else slice (libsodium sk = 64 bytes, last 32 is pk)
  if (sodium.crypto_sign_ed25519_sk_to_pk) {
    return sodium.crypto_sign_ed25519_sk_to_pk(sk);
  }
  return sk.slice(32, 64);
}

function persistIdentity() {
  localStorage.setItem('secmsg_id_pk', b64u(myIdPk));
  localStorage.setItem('secmsg_id_sk', b64u(myIdSk));
}

function rotateIdentityWithName(newName) {
  const pair = sodium.crypto_sign_keypair();
  myIdPk = pair.publicKey; myIdSk = pair.privateKey;
  SETTINGS.username = newName.trim();
  saveSettings();
  localStorage.setItem('secmsg_id_pk', b64u(myIdPk));
  localStorage.setItem('secmsg_id_sk', b64u(myIdSk));
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

async function connectFromSettings() {
  if (!SETTINGS.roomSkB64) return;

  await ensureSodium();
  setRoomFromSecret(SETTINGS.roomSkB64);

  // Cancel any pending reconnects/heartbeats
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }

  // Close old socket (if any)
  if (ws) { try { ws.onclose = null; ws.close(); } catch(_){} ws = null; }

  // Start fresh
  const url = `${RELAY_WS_URL}?room=${encodeURIComponent(currentRoomId)}`;
  ws = new WebSocket(url);

  ws.onopen  = () => setStatus('Connecting…');
  ws.onerror = () => setStatus('WebSocket error');

  ws.onclose = () => {
    authed = false;
    setStatus('Disconnected');
    scheduleReconnect();
  };

  ws.onmessage = (evt) => {
    const m = JSON.parse(evt.data);

    if (m.type === 'challenge') {
      const nonce = fromB64u(m.nonce);
      const sig = sodium.crypto_sign_detached(nonce, edSk);
      ws.send(JSON.stringify({ type: 'auth', room_id: currentRoomId, signature: b64u(sig) }));

    } else if (m.type === 'ready') {
      authed = true;
      setStatus('Connected');
      reconnectAttempt = 0;

      // Clear UI to prevent duplicates on (re)connect
      clearMessagesUI();

      // Request last 7 days
      ws.send(JSON.stringify({ type: 'history', since: sevenDaysAgoMs() }));
      requestAnimationFrame(() => requestAnimationFrame(scrollToEnd));

      // Heartbeat every 25s to keep proxies from idling us out
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        try { ws.send(JSON.stringify({ type: 'ping', ts: nowMs() })); } catch {}
      }, 25000);

    } else if (m.type === 'history') {
       for (const item of m.messages) handleIncoming(item);
       scrollToEnd();
       requestAnimationFrame(scrollToEnd);

    } else if (m.type === 'message') {
      handleIncoming(m);

    } else if (m.type === 'pong') {
      // no-op

    } else if (m.type === 'error') {
      renderMessage({ text: `Server error: ${m.error}`, ts: nowMs(), nickname: 'server' });
    }
  };
}

function scheduleReconnect() {
  if (!SETTINGS.roomSkB64) return;
  const delay = Math.min(30000, 1000 * Math.pow(2, reconnectAttempt)); // 1s,2s,4s,... max 30s
  reconnectAttempt++;
  setStatus(`Disconnected — reconnecting in ${Math.round(delay/1000)}s`);
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(() => {
    connectFromSettings();
  }, delay);
}

async function ensureIdentity() {
  await ensureSodium();
  const pk = localStorage.getItem('secmsg_id_pk');
  const sk = localStorage.getItem('secmsg_id_sk');
  if (pk && sk) {
    myIdPk = fromB64u(pk); myIdSk = fromB64u(sk);
  } else {
    rotateIdentityWithName(SETTINGS.username || 'Me');
  }
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
  renderMessage({ text: pt, ts: m.ts, nickname: m.nickname, senderId: m.sender_id, verified });
}

async function sendMessage() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !authed) { alert('Not connected'); return; }
  const text = ui.msgInput.value.trim();
  if (!text) return;
  await ensureSodium();
  const cipher = sodium.crypto_box_seal(sodium.from_string(text), curvePk);
  const ciphertextB64 = b64u(cipher);
  const sig = sodium.crypto_sign_detached(fromB64u(ciphertextB64), myIdSk);

  const payload = {
    type: 'send',
    ciphertext: ciphertextB64,
    ts_client: nowMs(),
    nickname: SETTINGS.username || undefined,
    sender_id: b64u(myIdPk),
    sig: b64u(sig)
  };

  ws.send(JSON.stringify(payload));
  ui.msgInput.value = '';
}

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

f.connect.addEventListener('click', async () => {
  const newName = (f.name.value || '').trim() || 'Me';
  const newRoomSk = (f.room.value || '').trim();
  if (!newRoomSk) { alert('Room code is required.'); return; }

  // Enforce: changing name rotates device identity
  if ((SETTINGS.username || '') !== newName) {
    await ensureSodium();
    rotateIdentityWithName(newName);
  }

  const roomChanged = SETTINGS.roomSkB64 !== newRoomSk;
  SETTINGS.username = newName;
  SETTINGS.roomSkB64 = newRoomSk;
  saveSettings();

  dlg.close();

  await ensureSodium();
  setRoomFromSecret(SETTINGS.roomSkB64);
  if (roomChanged) await registerRoomIfNeeded();

  connectFromSettings();
});

f.copy.addEventListener('click', async () => {
  const val = (f.room.value || '').trim();
  if (!val) { alert('No room code to copy'); return; }
  try {
    await navigator.clipboard.writeText(val);
    f.copy.textContent = 'Copied';
  } catch {
    // Fallback for older browsers
    try { f.room.select(); document.execCommand('copy'); f.copy.textContent = 'Copied'; } catch {}
  }
  setTimeout(() => { f.copy.textContent = 'Copy'; }, 1500);
});

ui.btnSend.addEventListener('click', sendMessage);
ui.msgInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendMessage(); });
ui.msgInput.addEventListener('focus', scrollToEnd);
ui.msgInput.addEventListener('input', scrollToEnd);

window.addEventListener('resize', scrollToEnd);
document.addEventListener('visibilitychange', () => { if (!document.hidden) scrollToEnd(); });

loadSettings();
await ensureIdentity();
setStatus('Ready');

if (SETTINGS.roomSkB64) {
  await registerRoomIfNeeded();
  connectFromSettings();
} else {
  dlg.showModal();
}
