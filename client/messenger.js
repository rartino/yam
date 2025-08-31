/* global sodium */

const RELAY_HTTP_BASE = 'https://rartino.pythonanywhere.com';
const RELAY_WS_URL    = RELAY_HTTP_BASE.replace(/^http/, 'ws') + '/ws';

const ui = {
  status: document.getElementById('status'),
  keys: document.getElementById('keys'),
  roomId: document.getElementById('roomId'),
  privateKey: document.getElementById('privateKey'),
  nickname: document.getElementById('nickname'),
  btnJoin: document.getElementById('btnJoin'),
  btnCreate: document.getElementById('btnCreate'),
  messages: document.getElementById('messages'),
  msgInput: document.getElementById('messageInput'),
  btnSend: document.getElementById('btnSend')
};

let ws = null;
let edPk = null; // Uint8Array (room public key)
let edSk = null; // Uint8Array (room private key)
let curvePk = null; // Uint8Array
let curveSk = null; // Uint8Array
let currentRoomId = null;
let authed = false;

function b64u(bytes) { return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING); }
function fromB64u(str) { return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING); }
function nowMs() { return Date.now(); }
function sevenDaysAgoMs() { return nowMs() - 7 * 24 * 60 * 60 * 1000; }

function setStatus(text) { ui.status.textContent = text; }
function addMsg(text, ts, who = 'cipher') {
  const div = document.createElement('div');
  div.className = 'msg';
  const d = new Date(ts || nowMs());
  div.innerHTML = `<div>${text}</div><small>${who} • ${d.toLocaleString()}</small>`;
  ui.messages.appendChild(div);
  ui.messages.scrollTop = ui.messages.scrollHeight;
}

async function ensureSodium() {
  if (!sodium || !sodium.ready) throw new Error('libsodium missing');
  await sodium.ready;
}

async function createRoom() {
  await ensureSodium();
  const { publicKey, privateKey } = sodium.crypto_sign_keypair();
  edPk = publicKey; edSk = privateKey;
  curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);

  const roomId = b64u(edPk);
  currentRoomId = roomId;

  // Show/export keys locally
  ui.roomId.value = roomId;
  ui.privateKey.value = b64u(edSk);
  ui.keys.innerHTML = `
    <div><strong>Room created.</strong> Share <em>Room ID</em> with participants, and send the <em>Private key</em> to trusted clients out-of-band.</div>
    <div class="keybox">Room ID (pub): ${roomId}</div>
    <div class="keybox">Private key (keep secret!): ${b64u(edSk)}</div>
  `;

  // Register room on the relay (stores only public key)
  const res = await fetch(`${RELAY_HTTP_BASE}/rooms`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ room_id: roomId, ed25519_public_key_b64u: roomId })
  });
  if (!res.ok) addMsg('Warning: room registration failed (server unreachable or exists). You can still try joining if server already knows this room.', nowMs(), 'client');
}

async function joinRoom() {
  await ensureSodium();
  const roomId = ui.roomId.value.trim();
  const skStr = ui.privateKey.value.trim();
  if (!roomId || !skStr) { alert('Provide Room ID and Private key (base64url)'); return; }

  edPk = fromB64u(roomId);
  edSk = fromB64u(skStr);
  curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);
  currentRoomId = roomId;

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${RELAY_WS_URL}?room=${encodeURIComponent(roomId)}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => { setStatus('Connecting…'); };
  ws.onerror = () => { setStatus('WebSocket error.'); };
  ws.onclose = () => { setStatus('Disconnected'); authed = false; };

  ws.onmessage = async (evt) => {
    const m = JSON.parse(evt.data);
    if (m.type === 'challenge') {
      // Sign the challenge with Ed25519 private key
      const nonce = fromB64u(m.nonce);
      const sig = sodium.crypto_sign_detached(nonce, edSk);
      ws.send(JSON.stringify({ type: 'auth', room_id: roomId, signature: b64u(sig) }));
    } else if (m.type === 'ready') {
      authed = true;
      setStatus('Connected');
      // Request last 7 days
      ws.send(JSON.stringify({ type: 'history', since: sevenDaysAgoMs() }));
    } else if (m.type === 'history') {
      for (const item of m.messages) {
        const pt = decryptToString(item.ciphertext);
        addMsg(pt, item.ts, item.nickname || 'room');
      }
    } else if (m.type === 'message') {
      const pt = decryptToString(m.ciphertext);
      addMsg(pt, m.ts, m.nickname || 'room');
    } else if (m.type === 'error') {
      addMsg(`Server error: ${m.error}`, nowMs(), 'server');
    }
  };
}

function decryptToString(cipherB64u) {
  const cipher = fromB64u(cipherB64u);
  try {
    const plain = sodium.crypto_box_seal_open(cipher, curvePk, curveSk);
    return sodium.to_string(plain);
  } catch (e) {
    return '[unable to decrypt]';
  }
}

async function sendMessage() {
  if (!ws || ws.readyState !== WebSocket.OPEN || !authed) { alert('Not connected'); return; }
  const text = ui.msgInput.value.trim();
  if (!text) return;
  await ensureSodium();
  const cipher = sodium.crypto_box_seal(sodium.from_string(text), curvePk);
  const payload = {
    type: 'send',
    ciphertext: b64u(cipher),
    ts_client: nowMs(),
    nickname: ui.nickname.value.trim() || undefined
  };
  ws.send(JSON.stringify(payload));
  ui.msgInput.value = '';
}

ui.btnCreate.addEventListener('click', createRoom);
ui.btnJoin.addEventListener('click', joinRoom);
ui.btnSend.addEventListener('click', sendMessage);
ui.msgInput.addEventListener('keydown', e => { if (e.key === 'Enter') sendMessage(); });

setStatus('Ready');
