/* global sodium */
// === Relay config (update to your domain) ===
const RELAY_HTTP_BASE = 'https://rartino.pythonanywhere.com';
const RELAY_WS_URL    = RELAY_HTTP_BASE.replace(/^http/, 'ws') + '/ws';

const ui = {
  status: document.getElementById('status'),
  secretKey: document.getElementById('secretKey'),
  nickname: document.getElementById('nickname'),
  btnJoin: document.getElementById('btnJoin'),
  btnCreate: document.getElementById('btnCreate'),
  messages: document.getElementById('messages'),
  msgInput: document.getElementById('messageInput'),
  btnSend: document.getElementById('btnSend'),
  identityInfo: document.getElementById('identityInfo'),
};

let ws = null;
let edPk = null; // Uint8Array room public key
let edSk = null; // Uint8Array room private key (secret)
let curvePk = null; // for sealed boxes
let curveSk = null;
let currentRoomId = null;
let authed = false;

// Per-device identity for "me" bubbles
let myIdPk = null; // Uint8Array
let myIdSk = null; // Uint8Array

function b64u(bytes) { return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING); }
function fromB64u(str) { return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING); }
function nowMs() { return Date.now(); }
function sevenDaysAgoMs() { return nowMs() - 7 * 24 * 60 * 60 * 1000; }
function setStatus(text) { ui.status.textContent = text; }

function renderMessage({ text, ts, nickname, senderId, verified }) {
  const row = document.createElement('div');
  const isMe = senderId && myIdPk && senderId === b64u(myIdPk);
  row.className = 'row ' + (isMe ? 'me' : 'other');

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text;

  const meta = document.createElement('div');
  meta.className = 'meta';
  const when = new Date(ts || nowMs()).toLocaleString();
  const who = nickname || (senderId ? shortId(senderId) : 'room');
  meta.textContent = `${who} • ${when}${verified === false ? ' • ⚠︎ unverified' : ''}`;

  bubble.appendChild(document.createElement('br'));
  bubble.appendChild(meta);
  row.appendChild(bubble);
  ui.messages.appendChild(row);
  ui.messages.scrollTop = ui.messages.scrollHeight;
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
  ui.identityInfo.textContent = `Your device ID: ${shortId(b64u(myIdPk))} (stored locally)`;
}

async function ensureIdentity() {
  await ensureSodium();
  const pk = localStorage.getItem('secmsg_id_pk');
  const sk = localStorage.getItem('secmsg_id_sk');
  if (pk && sk) {
    myIdPk = fromB64u(pk); myIdSk = fromB64u(sk);
  } else {
    const pair = sodium.crypto_sign_keypair();
    myIdPk = pair.publicKey; myIdSk = pair.privateKey;
    persistIdentity();
  }
  ui.identityInfo.textContent = `Your device ID: ${shortId(b64u(myIdPk))} (stored locally)`;
}

async function createRoom() {
  await ensureSodium();
  const { publicKey, privateKey } = sodium.crypto_sign_keypair();
  edPk = publicKey; edSk = privateKey;
  curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);
  currentRoomId = b64u(edPk);

  // Show the single secret to user
  ui.secretKey.value = b64u(edSk);

  // Register room (server stores only the public key)
  try {
    await fetch(`${RELAY_HTTP_BASE}/rooms`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ room_id: currentRoomId, ed25519_public_key_b64u: currentRoomId })
    });
  } catch (e) {
    // non-fatal
  }
}

async function joinWithSecret() {
  await ensureSodium();
  const skStr = ui.secretKey.value.trim();
  if (!skStr) { alert('Paste the secret room key'); return; }
  edSk = fromB64u(skStr);
  edPk = derivePubFromSk(edSk);
  curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);
  currentRoomId = b64u(edPk);

  // Connect WS
  const wsUrl = `${RELAY_WS_URL}?room=${encodeURIComponent(currentRoomId)}`;
  if (ws) { try { ws.close(); } catch(_){} }
  ws = new WebSocket(wsUrl);

  ws.onopen = () => setStatus('Connecting…');
  ws.onerror = () => setStatus('WebSocket error');
  ws.onclose = () => { setStatus('Disconnected'); authed = false; };

  ws.onmessage = async (evt) => {
    const m = JSON.parse(evt.data);
    if (m.type === 'challenge') {
      const nonce = fromB64u(m.nonce);
      const sig = sodium.crypto_sign_detached(nonce, edSk);
      ws.send(JSON.stringify({ type: 'auth', room_id: currentRoomId, signature: b64u(sig) }));
    } else if (m.type === 'ready') {
      authed = true; setStatus('Connected');
      ws.send(JSON.stringify({ type: 'history', since: sevenDaysAgoMs() }));
    } else if (m.type === 'history') {
      for (const item of m.messages) handleIncoming(item);
    } else if (m.type === 'message') {
      handleIncoming(m);
    } else if (m.type === 'error') {
      renderMessage({ text: `Server error: ${m.error}`, ts: nowMs(), nickname: 'server' });
    }
  };
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
    nickname: ui.nickname.value.trim() || undefined,
    sender_id: b64u(myIdPk),
    sig: b64u(sig)
  };
  ws.send(JSON.stringify(payload));
  ui.msgInput.value = '';
}

ui.btnCreate.addEventListener('click', createRoom);
ui.btnJoin.addEventListener('click', joinWithSecret);
ui.btnSend.addEventListener('click', sendMessage);
ui.msgInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendMessage(); });

await ensureIdentity();
setStatus('Ready');
