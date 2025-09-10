import {b64u, fromB64u, blobToU8, blobToB64u, sha256_b64u, sha256_b64u_string, sha256_b64u_bytes, utf8ToBytes, bytesToUtf8, normServer, dataUrlFromBlob, nowMs, sevenDaysAgoMs, hostFromUrl, shortId, sanitizeColorHex, pickTextColorOn} from './utils.js';
import {loadSettings, saveSettings} from './settings.js';

async function ensureSodium() { await sodium.ready; }

//////////////////////////////
// UI
/////////////////////////////

function setStatus(text) { ui.status.textContent = text; }

const statuses = {
    connected: '↔', // ✅
    disconnected: '↮', // ❌
    connecting: '↻', // ☑️
    passive: '·', // ✔️
};

const cr = {
  dlg: document.getElementById('createRoomModal'),
  name: document.getElementById('newRoomName'),
  server: document.getElementById('newServerUrl'),
  btnCreate: document.getElementById('btnCreateRoom'),
  btnClose: document.getElementById('btnCloseCreateRoom'),
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
  profileColor: document.getElementById('profileColor'),
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
  qrCode: document.getElementById('joinQrCode'),
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

// Wiring

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
  ROOM_KEYS.delete(r.id);
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

join.btnClose?.addEventListener('click', () => { try { _joinWait.ws?.close(); } catch{} join.dlg.close(); });
join.btnCopyCode?.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(join.codeTA.value); join.btnCopyCode.textContent='Copied'; setTimeout(()=>join.btnCopyCode.textContent='Copy',900); } catch {}
});
join.btnRefresh?.addEventListener('click', openJoinDialog);

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

function toggleSettingsMenu(show) {
  const willShow = (typeof show === 'boolean') ? show : ui.settingsMenu.hidden;
  ui.settingsMenu.hidden = !willShow;
}

/////////////////////////////
// MASTER PASSWORD
/////////////////////////////

const MASTER_PASS_LS_KEY = 'secmsg_master_pass_v1';
const MASTER_PASS_SS_KEY = 'secmsg_master_pass_session_v1';
let MASTER_PASS = null;
let MASTER_BASE_KEY = null; // PBKDF2 base CryptoKey (non-extractable)

function randomB64u(n = 32) {
  const a = new Uint8Array(n); crypto.getRandomValues(a);
  return b64u(a);
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

/////////////////////////////
// KEYCHECK
/////////////////////////////

const KEYCHECK_LS_KEY = 'secmsg_kcv_v1';
const KEYCHECK_PLAINTEXT = new TextEncoder().encode('YAM-KCV-1');

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

////////////////////////
// MESSAGES
////////////////////////

let msgDbPromise = null;

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

function openMsgDB(){
  if (msgDbPromise) return msgDbPromise;
  msgDbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(MSG_DB, 3);
    req.onupgradeneeded = () => {
      const db = req.result;
      let s;
      if (!db.objectStoreNames.contains(MSG_STORE)) {
        s = db.createObjectStore(MSG_STORE, { keyPath: 'id' });
      } else {
        s = req.transaction.objectStore(MSG_STORE);
      }
      if (!s.indexNames.contains('byRoomTsId')) s.createIndex('byRoomTsId', ['roomKey','ts','id'], { unique:false });
      if (!s.indexNames.contains('byRoomSeq'))  s.createIndex('byRoomSeq',  ['roomKey','seq'], { unique:false });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return msgDbPromise;
}

async function msgGetLastSeq(serverUrl, roomId){
  const key = roomKey(serverUrl, roomId);
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const tx  = db.transaction(MSG_STORE, 'readonly');
    const idx = tx.objectStore(MSG_STORE).index('byRoomSeq');
    // openCursor with prev across roomKey to get highest seq; but we don't know max bound -> use IDBKeyRange.bound
    const lower = [key, 0];
    const upper = [key, Number.MAX_SAFE_INTEGER];
    const range = IDBKeyRange.bound(lower, upper);
    const req = idx.openCursor(range, 'prev');
    req.onsuccess = e => {
      const cur = e.target.result;
      if (!cur) return res(-1); // none seen yet
      res(cur.value.seq ?? -1);
    };
    req.onerror = () => rej(req.error);
  });
}



////////////////////////
// ROOMS
///////////////////////

const ROOMS_KEY = 'secmsg_rooms_v1';
const ROOM_KEYS = new Map(); // (roomId -> { edSk, edPk, curvePk, curveSk })

let rooms = [];            // [{id, name, server, roomSkB64, roomId, createdAt}]
let currentRoomId = null;  // string id = roomId (ed25519 pk b64u)

async function getRoomKeys(roomId) {
  await ensureSodium();
  let k = ROOM_KEYS.get(roomId);
  if (k) return k;

  const edSk = await getRoomPrivateKeyBytes(roomId); // 64 bytes
  if (!(edSk instanceof Uint8Array) || edSk.length !== 64) {
    throw new Error('invalid-room-secret');
  }
  const edPk    = derivePubFromSk(edSk); // 32 bytes
  const curvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
  const curveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);

  k = { edSk, edPk, curvePk, curveSk };
  ROOM_KEYS.set(roomId, k);
  return k;
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

async function getRoomPrivateKeyBytes(roomId) {
  const sealed = await secretGet(roomId);
  if (!sealed) throw new Error('Room secret missing locally');
  const skB64 = await openSecret(sealed);
  return fromB64u(skB64);
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

function roomKey(serverUrl, roomId){ return `${normServer(serverUrl)}|${roomId}`; }

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

////////////////////////
// IDENTITY / PROFILE
///////////////////////

let profileDbPromise = null;
// Cached profiles: key = roomKey(serverUrl, roomId) + '|' + senderId  -> { name, avatarHash }
const profileCache = new Map();
// Throttle duplicate in-flight requests
const profileReqInflight = new Set();
const profileRetryState = new Map(); // key -> { tries, timer }

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

function profileRetryKey(serverUrl, roomId, senderId) {
  return `${serverUrl}|${roomId}|${senderId}`;
}

function scheduleProfileRetry(serverUrl, roomId, senderId) {
  const key = profileRetryKey(serverUrl, roomId, senderId);
  const st = profileRetryState.get(key) || { tries: 0, timer: null };
  if (st.tries >= 5) return; // cap retries

  st.tries += 1;
  const delay = [400, 1000, 2000, 4000, 8000][st.tries - 1]; // backoff
  clearTimeout(st.timer);
  st.timer = setTimeout(() => {
    profileReqInflight.delete(profileKeyLocal(serverUrl, roomId, senderId)); // allow another request
    requestProfileIfMissing(serverUrl, roomId, senderId);
  }, delay);

  profileRetryState.set(key, st);
}

function clearProfileRetry(serverUrl, roomId, senderId) {
  const key = profileRetryKey(serverUrl, roomId, senderId);
  const st = profileRetryState.get(key);
  if (st) { clearTimeout(st.timer); profileRetryState.delete(key); }
}

function profileKeyLocal(serverUrl, roomId, senderId) {
  return `${roomKey(serverUrl, roomId)}|${senderId}`;
}
async function profileMetaGet(serverUrl, roomId, senderId) {
  const k = 'prof|' + profileKeyLocal(serverUrl, roomId, senderId);
  const v = await profileGet(k);
  if (v) profileCache.set(profileKeyLocal(serverUrl, roomId, senderId), v);
  return v || null;
}
async function profileMetaPut(serverUrl, roomId, senderId, meta) {
  const k = 'prof|' + profileKeyLocal(serverUrl, roomId, senderId);
  await profilePut(k, meta);
  profileCache.set(profileKeyLocal(serverUrl, roomId, senderId), meta);
}

async function buildMyProfilePayload() {
  const name = (SETTINGS.username || '').trim();
  const color = (sanitizeColorHex(SETTINGS.profilecolor) || '').trim();
  const avatar = await profileGet('avatar');  // the 192×192 PNG
  let ah = null, ab = null;
  if (avatar) {
    const hash = await sha256_b64u(avatar);
    await idbPut(hash, avatar);
    ah = hash;
    ab = await blobToB64u(avatar);
  }
  return { v: 1, name, color, ah, ab, ts: nowMs() };
}

async function sendMyProfile(serverUrl, roomId) {
  try {
    await ensureSodium();
    const profObj = await buildMyProfilePayload();
    const ctB64 = await encryptStringForRoom(roomId, JSON.stringify(profObj));
    const sc = servers.get(normServer(serverUrl));
    if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN || !sc.authed?.has(roomId)) return;
    sc.ws.send(JSON.stringify({
      type: 'profile-change',
      room_id: roomId,
      sender_id: myPeerId,
      ciphertext: ctB64
    }));
  } catch (e) {
    console.error('sendMyProfile failed', e);
  }
}

async function applyProfileCipher(serverUrl, roomId, senderId, ctB64) {
  await ensureSodium();
  let obj;
  try {
    const pt = await decryptToStringForRoom(roomId, ctB64);
    obj = JSON.parse(pt);
  } catch {
    return; // ignore malformed
  }
  const name = (obj.name || '').trim();
  const color = (sanitizeColorHex(obj.color) || '').trim();
  let avatarHash = obj.ah || null;

  // If bytes are included, store them and trust their hash
  if (obj.ab) {
    try {
      const bytes = fromB64u(obj.ab);
      const blob = new Blob([bytes], { type: 'image/png' });
      const h = await sha256_b64u(blob);
      avatarHash = avatarHash || h;
      await idbPut(avatarHash, blob);
    } catch {}
  }

  await profileMetaPut(serverUrl, roomId, senderId, { name, color, avatarHash });
  updateMessagesForSender(serverUrl, roomId, senderId);
}

function requestProfileIfMissing(serverUrl, roomId, senderId) {
  const key = profileKeyLocal(serverUrl, roomId, senderId);
  if (profileCache.has(key)) return;

  const sc = servers.get(normServer(serverUrl));
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN || !sc.authed?.has(roomId)) return;

  // Let retries through if a backoff timer scheduled us
  if (profileReqInflight.has(key)) return;

  profileReqInflight.add(key);
  sc.ws.send(JSON.stringify({ type: 'profile-retrieve', room_id: roomId, sender_id: senderId }));
  // Auto-clear the inflight guard after a short window so retries can fire
  setTimeout(() => profileReqInflight.delete(key), 1500);
}

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
  prof.profileColor.value = (sanitizeColorHex(SETTINGS.profilecolor) || '').trim();
  prof.pubKey.value = myPeerId || (myIdPk ? b64u(myIdPk) : '');
  prof.requirePass.checked = !!SETTINGS.requirePass;   // <-- add this
  await refreshAvatarPreview();
  prof.dlg.showModal();
}

function closeProfile() { prof.dlg.close(); }

async function saveProfile() {
  SETTINGS.username = (prof.name.value || '').trim();
  SETTINGS.profilecolor = (sanitizeColorHex(prof.profileColor.value) || '').trim();
    
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
    for (const [, sc] of servers) {
      for (const rid of sc.authed || []) {
        try { await sendMyProfile(sc.url, rid); } catch {}
      }
    }
  } finally {
    closeProfile();
  }
}

async function handleAvatarPicked(file) {
  if (!file) return;
  const resized = await normalizeAvatarSize(file);
  console.warn('[handleAvatarPicked] image size:', resized);
  await profilePut('avatar', resized);                     // keep latest avatar blob for self-preview
  const hash = await sha256_b64u(resized);
  await idbPut(hash, resized);                             // reuse the files DB as an avatar cache
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

async function transcodeBlob(blob, {type, quality}) {
  const bmp = await createImageBitmap(blob);
  const canvas = (typeof OffscreenCanvas !== 'undefined')
    ? new OffscreenCanvas(PROFILE_AVATAR_W, PROFILE_AVATAR_H)
    : Object.assign(document.createElement('canvas'), {width: PROFILE_AVATAR_W, height: PROFILE_AVATAR_H});
  const ctx = canvas.getContext('2d');
  ctx.imageSmoothingEnabled = true;
  if ('imageSmoothingQuality' in ctx) ctx.imageSmoothingQuality = 'high';
  ctx.clearRect(0, 0, PROFILE_AVATAR_W, PROFILE_AVATAR_H);
  // Fit-crop center to square
  const s = Math.min(bmp.width, bmp.height);
  const sx = ((bmp.width  - s) / 2) | 0;
  const sy = ((bmp.height - s) / 2) | 0;
  ctx.drawImage(bmp, sx, sy, s, s, 0, 0, PROFILE_AVATAR_W, PROFILE_AVATAR_H);

  if (canvas.convertToBlob) return await canvas.convertToBlob({type, quality});
  return await new Promise(res => canvas.toBlob(res, type, quality));
}

async function normalizeAvatarSize(inputBlob) {
  const tryOrders = [
    {type: 'image/webp', qualities: [0.82, 0.72, 0.62, 0.52, 0.4]},
    {type: 'image/jpeg', qualities: [0.82, 0.72, 0.62, 0.52, 0.4]},
    // As a last resort, a tiny PNG (often larger than JPEG/WEBP)
    {type: 'image/png',   qualities: [1]}
  ];
  for (const {type, qualities} of tryOrders) {
    for (const q of qualities) {
      const out = await transcodeBlob(inputBlob, {type, quality: q});
      if (out.size <= PROFILE_AVATAR_TARGET_BYTES) return out;
      if (out.size <= PROFILE_AVATAR_HARD_BYTES && q === qualities[qualities.length - 1]) return out;
    }
  }
  // If we get here, pick the smallest tried.
  let best = await transcodeBlob(inputBlob, {type:'image/webp', quality:0.35});
  if (best.size > PROFILE_AVATAR_HARD_BYTES) {
    // Give JPEG a shot at very low quality
    const alt = await transcodeBlob(inputBlob, {type:'image/jpeg', quality:0.35});
    if (alt.size < best.size) best = alt;
  }
  return best;
}

////////////////////////
// FILES
///////////////////////

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

////////////////////////
// RENDER
///////////////////////

function canonDeleteBytes(roomId, seq) {
  return new TextEncoder().encode(`delete|${roomId}|seq:${seq}`);
}

async function msgGetBySeq(serverUrl, roomId, seq) {
  const key = roomKey(serverUrl, roomId);
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(MSG_STORE, 'readonly');
    const idx = tx.objectStore(MSG_STORE).index('byRoomSeq');
    const req = idx.openCursor(IDBKeyRange.only([key, seq]));
    req.onsuccess = (e) => res(e.target.result ? e.target.result.value : null);
    req.onerror = () => rej(req.error);
  });
}

async function msgDeleteById(id) {
  const db = await openMsgDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(MSG_STORE, 'readwrite');
    tx.objectStore(MSG_STORE).delete(id);
    tx.oncomplete = () => res(true);
    tx.onerror = () => rej(tx.error);
  });
}

function removeDomRowBySeq(seq) {
  const n = ui.messages.querySelector(`.row[data-seq="${String(seq)}"]`);
  if (n && n.parentNode) n.parentNode.removeChild(n);
}

async function requestDeleteMessage(rec) {
  // Only allow deleting your own messages that have a sequence number
  if (!rec || !isSelf(rec.senderId) || typeof rec.seq !== 'number') return;

  const serverUrl = rec.serverUrl || VL?.serverUrl;
  const roomId    = rec.roomId    || VL?.roomId;
  const sc = servers.get(normServer(serverUrl));
  if (!sc || !sc.ws || sc.ws.readyState !== WebSocket.OPEN || !sc.authed?.has(roomId)) {
    alert('Not connected');
    return;
  }

  try {
    // Build TWO sealed payloads:
    //  A) tombstone to overwrite the original row (same seq on server)
    //  B) control "delete" record (new seq) to log/broadcast the action
    const targetSeq = rec.seq;

    const tombstoneJson = JSON.stringify({ kind: 'deleted', target_seq: targetSeq });
    const controlJson   = JSON.stringify({ kind: 'delete',  target_seq: targetSeq });

    // Encrypt to room public key (sealed box); returns base64url
    const tombCtB64 = await encryptStringForRoom(roomId, tombstoneJson);
    const ctrlCtB64 = await encryptStringForRoom(roomId, controlJson);

    // Sign each ciphertext with our device identity (detached)
    const tombSigB64 = signCiphertextB64(tombCtB64);
    const ctrlSigB64 = signCiphertextB64(ctrlCtB64);

    const payload = {
      type: 'delete',
      room_id: roomId,
      ref_seq: targetSeq,                     // server must see this outside the ciphertext
      tombstone_ciphertext: tombCtB64,        // sealed {"kind":"deleted","target_seq":...}
      tombstone_sig: tombSigB64,              // detached sig over tombstone_ciphertext
      delete_ciphertext: ctrlCtB64,           // sealed {"kind":"delete","target_seq":...}
      delete_sig: ctrlSigB64,                 // detached sig over delete_ciphertext
      sender_id: myPeerId,                    // our device pk (b64url)
      ts_client: nowMs()
    };

    if (DEBUG_SIG) dbg('SIG/TX', 'delete', { room: roomId, ref_seq: targetSeq });
    sc.ws.send(JSON.stringify(payload));
  } catch (e) {
    console.error('requestDeleteMessage failed', e);
    alert('Delete failed to prepare or send.');
  }
}

function flashBtn(btn, glyph='✓', ms=900) {
  if (!btn) return;
  const old = btn.textContent;
  btn.textContent = glyph;
  btn.disabled = true;
  setTimeout(() => { btn.textContent = old; btn.disabled = false; }, ms);
}

async function copyTextToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text || '');
    return true;
  } catch {
    // Fallback (works in many older browsers)
    try {
      const ta = document.createElement('textarea');
      ta.value = text || '';
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

async function copyBlobToClipboard(blob) {
  if (!navigator.clipboard || !('write' in navigator.clipboard) || !window.ClipboardItem) return false;
  try {
    const item = new ClipboardItem({ [blob.type || 'application/octet-stream']: blob });
    await navigator.clipboard.write([item]);
    return true;
  } catch {
    return false;
  }
}

function fileLabel(meta = {}) {
  const name = meta.name || 'file';
  const size = (meta.size != null) ? `${meta.size} bytes` : '?';
  return `[file] ${name} (${size})`;
}

async function copyMessageToClipboard(rec, btn) {

  console.log('copyMessageToClipboard', rec);
    
  if (rec.kind === 'text') {
    const ok = await copyTextToClipboard(rec.text || '');
    flashBtn(btn, ok ? '✓' : '⚠︎');
    return;
  }

  if (rec.kind === 'file') {
    const hash = rec.meta?.hash;
    let ok = false;

    // Try copying the actual blob (best effort; images work in most modern browsers)
    if (hash) {
      try {
        const blob = await idbGet(hash);
        if (blob) ok = await copyBlobToClipboard(blob);
      } catch { /* ignore */ }
    }

    // Fallback to text label if blob copy isn't possible
    if (!ok) ok = await copyTextToClipboard(fileLabel(rec.meta));
    flashBtn(btn, ok ? '✓' : '⚠︎');
    return;
  }

  if (rec.kind === 'gap') {
    const count = rec.count ?? Math.max(0, (rec.toSeq ?? rec.fromSeq) - (rec.fromSeq ?? 0));
    const ok = await copyTextToClipboard(`[${count} messages missing]`);
    flashBtn(btn, ok ? '✓' : '⚠︎');
  }
}

function toQuoteBlock(str) {
  const body = (str || '').replace(/\r?\n/g, '\n> ');
  return `> ${body}\n\n`;
}

function getMessageTextForQuote(rec) {
  if (rec.kind === 'text') return rec.text || '';
  if (rec.kind === 'file') {
    const m = rec.meta || {};
    const label = m.name || 'file';
    const size  = (m.size != null) ? `${m.size} bytes` : '?';
    return `[file] ${label} (${size})`;
  }
  if (rec.kind === 'gap') {
    const count = rec.count ?? Math.max(0, (rec.toSeq ?? rec.fromSeq) - (rec.fromSeq ?? 0));
    return `[${count} messages missing]`;
  }
  return '';
}

function isSelf(senderId) {
  return !!(senderId && myPeerId && senderId === myPeerId);
}

function setAvatar(avatarEl, blob) {
  avatarEl.innerHTML = '';
  if (!blob) { avatarEl.textContent = ''; return; }
  const url = URL.createObjectURL(blob);
  const img = document.createElement('img');
  img.onload = () => URL.revokeObjectURL(url);
  img.src = url;
  avatarEl.appendChild(img);
}

/**
 * One-path profile styler:
 *  - Applies immediate hints (self SETTINGS or cached peer meta)
 *  - Kicks off async fetch (local DB / server) to complete avatar/color/name
 * Safe to call repeatedly.
 */
function styleBubbleProfile(avatarEl, nameEl, bubbleEl, { serverUrl, roomId, senderId, fallbackName }) {
  // 1) Immediate hints
  if (isSelf(senderId)) {
    // self: SETTINGS are instant
    const name = (SETTINGS?.username || '').trim();
    if (name) nameEl.textContent = name;

    const col = sanitizeColorHex(SETTINGS?.profilecolor);
    if (col) { bubbleEl.style.backgroundColor = col; bubbleEl.style.color = pickTextColorOn(col); }

    // avatar from local store (async)
    profileGet('avatar').then(blob => { if (blob) setAvatar(avatarEl, blob); }).catch(() => {});
    return;
  }

  // peers: try memory cache
  const key = profileKeyLocal(serverUrl, roomId, senderId);
  const cached = profileCache.get(key);
  if (cached) {
    if (cached.name)  nameEl.textContent = cached.name;
    if (cached.color) {
      const c = sanitizeColorHex(cached.color);
      if (c) { bubbleEl.style.backgroundColor = c; bubbleEl.style.color = pickTextColorOn(c); }
    }
    if (cached.avatarHash) {
      idbGet(cached.avatarHash).then(blob => { if (blob) setAvatar(avatarEl, blob); });
    }
  } else {
    nameEl.textContent = fallbackName;
  }

  // 2) Async completion path
  requestProfileIfMissing(serverUrl, roomId, senderId);
  profileMetaGet(serverUrl, roomId, senderId).then(meta => {
    if (!meta) return;
    if (meta.name) nameEl.textContent = meta.name;
    if (meta.color) {
      const c = sanitizeColorHex(meta.color);
      if (c) { bubbleEl.style.backgroundColor = c; bubbleEl.style.color = pickTextColorOn(c); }
    }
    if (meta.avatarHash) {
      idbGet(meta.avatarHash).then(blob => { if (blob) setAvatar(avatarEl, blob); });
    }
  }).catch(() => {});
}

async function updateMessagesForSender(serverUrl, roomId, senderId) {
  const children = Array.from(ui.messages.children);
  for (const row of children) {
    if (row.dataset.senderId !== senderId) continue;
    const wrap     = row.querySelector('.wrap');
    const avatarEl = wrap?.querySelector('.msg-avatar');
    const nameEl   = wrap?.querySelector('.name-label');
    const bubbleEl = wrap?.querySelector('.bubble');
    if (avatarEl && nameEl && bubbleEl) {
      const ctx = { serverUrl, roomId, senderId, fallbackName: shortId(senderId) };
      styleBubbleProfile(avatarEl, nameEl, bubbleEl, ctx);
    }
  }
}

function makeActionButton(char, label, onClick) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'action-btn';
  btn.textContent = char;
  btn.title = label;
  btn.setAttribute('aria-label', label);
  btn.addEventListener('click', (e) => {
    e.stopPropagation(); // don't clear selection
    try { onClick && onClick(); } catch {}
  });
  return btn;
}

function makeActionsBar(rec) {
  const bar = document.createElement('div');
  bar.className = 'bubble-actions';

  const onReply = () => {
    const text = getMessageTextForQuote(rec);
    const quoted = toQuoteBlock(text);

    ui.msgInput.value = quoted + ui.msgInput.value;

    // Focus and place caret at end so user can continue typing
    try {
      ui.msgInput.focus();
      const end = ui.msgInput.value.length;
      ui.msgInput.setSelectionRange(end, end);
    } catch {}

    // Optionally scroll composer into view
    try { ui.msgInput.scrollIntoView({ block: 'nearest' }); } catch {}
  };

  // Delete only for my messages
  let delBtn = null;
  if (isSelf(rec.senderId)) {
    const onDelete = () => requestDeleteMessage(rec);
    delBtn = makeActionButton('🗑', 'Delete', onDelete);
  }
    
  const onReact  = () => console.log('react clicked', rec);

  const replyBtn = makeActionButton('↩', 'Reply',  onReply);

  let copyBtn; // declare first so the handler can capture it
  const onCopy = () => { copyMessageToClipboard(rec, copyBtn); };
  copyBtn = makeActionButton('🗐', 'Copy', onCopy);

  const reactBtn = makeActionButton('✹', 'React',  onReact);

  bar.appendChild(replyBtn);
  bar.appendChild(copyBtn);
  if(delBtn) bar.appendChild(delBtn);
  bar.appendChild(reactBtn);

  bar.addEventListener('click', (e) => e.stopPropagation());
  return bar;
}
    
function bubbleContentOf(bubbleEl) {
  return bubbleEl.querySelector('.bubble-content') || bubbleEl;
}

// --- Selection state ---
let _selected = null; // { row, bubble, timeEl }

function fmtFullTs(ts) {
  try {
    return new Date(Number(ts) || Date.now()).toLocaleString(undefined, {
      year:'numeric', month:'long', day:'2-digit',
      hour:'2-digit', minute:'2-digit', second:'2-digit',
      hour12:false
    });
  } catch { return new Date().toLocaleString(); }
}

function clearSelection() {
  if (!_selected) return;
  _selected.bubble.classList.remove('--selected');
  _selected.row.classList.remove('--lift');
  if (_selected.timeEl) _selected.timeEl.textContent = '';
  _selected = null;
}

function selectBubble(row, bubble, timeEl) {
  if (_selected && _selected.bubble === bubble) { clearSelection(); return; }
  clearSelection();
  _selected = { row, bubble, timeEl };
  row.classList.add('--lift');
  bubble.classList.add('--selected');
  const ts = row.dataset.ts || Date.now();
  timeEl.textContent = fmtFullTs(ts);
}

// click outside / Esc clears
document.addEventListener('click', (e) => {
  if (!_selected) return;
  if (!_selected.bubble.contains(e.target)) clearSelection();
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') clearSelection(); });

// ========== UNIFIED RENDERING PIPELINE ==========

// Normalized record shape expected by renderer:
// {
//   id: string,                    // stable id (roomKey|sha256(ciphertext)) or any unique
//   roomId: string,
//   serverUrl: string,
//   kind: 'text'|'file'|'gap',
//   ts: number,                    // ms
//   seq?: number|null,             // integer if present
//   senderId?: string|null,        // base64url of device pk
//   nickname?: string|null,
//   verified?: boolean|undefined,
//   // for text:
///  text?: string,
//   // for file:
///  meta?: { hash, name, mime, size }
//   // for gap:
///  fromSeq?: number, toSeq?: number, count?: number
// }

function renderBubble(rec) {
  if (!VL || VL.serverUrl !== rec.serverUrl || VL.roomId !== rec.roomId) return null;
  if (rec.kind === 'deleted') { return null; }
    
  const row = document.createElement('div');
  const mine = isSelf(rec.senderId);
  row.className = 'row ' + (mine ? 'me' : 'other');
  if (rec.id) row.dataset.msgId = rec.id;
  if (rec.senderId) row.dataset.senderId = rec.senderId;
  row.dataset.ts = String(rec.ts || nowMs());

  const wrap   = document.createElement('div'); wrap.className = 'wrap';
  const avatar = document.createElement('div'); avatar.className = 'msg-avatar';
  const nameEl = document.createElement('div'); nameEl.className = 'name-label';
  const bubble = document.createElement('div'); bubble.className = 'bubble _pre';

  const whoFallback = rec.senderId ? shortId(rec.senderId) : (rec.nickname || 'room');
  nameEl.textContent = `${whoFallback}${rec.verified === false ? ' ⚠︎ unverified' : ''}`;

  // Content container
  const content = document.createElement('div');
  content.className = 'bubble-content';
  bubble.appendChild(content);

  // Body content goes into `content`
  if (rec.kind === 'gap') {
    const count = rec.count ?? Math.max(0, (rec.toSeq ?? rec.fromSeq) - (rec.fromSeq ?? 0));
    content.textContent = `${count} messages missing`;
  } else if (rec.kind === 'text') {
    content.textContent = rec.text || '';
  } else if (rec.kind === 'file') {
    bubble.dataset.hash = rec.meta.hash;
    if (rec.meta.mime && rec.meta.mime.startsWith('image/')) {
      content.textContent = 'Image pending…';
    } else {
      const p = document.createElement('div');
      p.textContent = `${rec.meta.name || 'file'} (${rec.meta.size ?? '?' } bytes)`;
      content.appendChild(p);
    }
    renderFileIfAvailable(bubble, rec.meta).then(ok => {
      if (!ok) { showPendingBubble(bubble, rec.meta); requestFile(rec.roomId, rec.meta.hash); }
    });
  }

  // Timestamp label (stays after content)
  const timeEl = document.createElement('div');
  timeEl.className = 'time-label';
  bubble.appendChild(timeEl);

  // Actions bar (stays after content)
  const actionsBar = makeActionsBar(rec);
  bubble.appendChild(actionsBar);

  // Unified profile styling
  const ctx = { serverUrl: rec.serverUrl, roomId: rec.roomId, senderId: rec.senderId, fallbackName: whoFallback };
  styleBubbleProfile(avatar, nameEl, bubble, ctx);

  requestAnimationFrame(() => bubble.classList.remove('_pre'));
  setTimeout(() => { if (bubble.classList.contains('_pre')) bubble.classList.remove('_pre'); }, 140);

  bubble.addEventListener('click', (ev) => {
    ev.stopPropagation();
    selectBubble(row, bubble, timeEl);
  });

  wrap.appendChild(avatar);
  wrap.appendChild(nameEl);
  wrap.appendChild(bubble);
  row.appendChild(wrap);
  return row;
}

/**
 * Renders a contiguous segment of records, with optional gap detection.
 * @param {Array} records - normalized records (see shape above). Should be for one room/server.
 * @param {Object} opts
 *  - placement: 'append' | 'prepend' | 'replace'  (default 'append')
 *  - computeGaps: boolean (default true) — detect seq gaps within the segment and vs lastSeqSeen
 *  - persistGaps: boolean (default true) — also persist a gap record via putGapRecord(...)
 *  - dedupe: boolean (default true)    — skip items already seen in VL.seenIds
 */
function renderSegment(records, { placement = 'append', computeGaps = true, persistGaps = true, dedupe = true } = {}) {
  if (!records || !records.length) return;

  // All records should share same context; take from first
  const serverUrl = records[0].serverUrl;
  const roomId    = records[0].roomId;
  if (!VL || VL.serverUrl !== serverUrl || VL.roomId !== roomId) return; // render only for active view

  // Sort ascending by (seq if present) else ts
  records = [...records].sort((a, b) => {
    const sa = (typeof a.seq === 'number'), sb = (typeof b.seq === 'number');
    if (sa && sb) return a.seq - b.seq || a.ts - b.ts;
    if (sa && !sb) return -1;
    if (!sa && sb) return  1;
    return a.ts - b.ts;
  });

  const el = ui.messages;
  const frag = document.createDocumentFragment();

  // Dedupe and compute local gaps
  let prevSeq = null;
  let prevSeenSeq = null;
  const rk = roomKey(serverUrl, roomId);

  if (computeGaps) {
    // For live append, reconcile with last seen (kept across batches)
    prevSeenSeq = lastSeqSeen.has(rk) ? lastSeqSeen.get(rk) : null;
  }

  // Maintain scroll position on prepend/load-older
  const trackingPrepend = (placement === 'prepend');
  const prevHeight = trackingPrepend ? el.scrollHeight : 0;

  for (const rec of records) {
    // make sure shape is sane
    if (!rec || rec.roomId !== roomId || rec.serverUrl !== serverUrl) continue;

    // segment-level dedupe
    if (dedupe && VL.seenIds && rec.id && VL.seenIds.has(rec.id) && rec.kind !== 'gap') continue;

    // GAP DETECTION
    if (computeGaps) {
      const s = (typeof rec.seq === 'number') ? rec.seq : null;

      // gap vs *segment* previous
      if (prevSeq !== null && s !== null && s > prevSeq + 1) {
        const gapCount = s - prevSeq - 1;
        const gapRec = {
          id: `${rk}|gap|${prevSeq + 1}-${s}`, // stable
          roomId, serverUrl, kind: 'gap',
          ts: rec.ts, fromSeq: prevSeq, toSeq: s, count: gapCount
        };
        const gapNode = renderBubble(gapRec);
        if (gapNode) frag.appendChild(gapNode);
        if (persistGaps) { try { putGapRecord({ serverUrl, roomId, ts: rec.ts, fromSeq: prevSeq, toSeq: s }); } catch {} }
      }

      // gap vs *global last seen* (live)
      if (prevSeenSeq !== null && s !== null && s > prevSeenSeq + 1) {
        const gapCount = s - prevSeenSeq - 1;
        const gapRec = {
          id: `${rk}|gap-live|${prevSeenSeq + 1}-${s}`,
          roomId, serverUrl, kind: 'gap',
          ts: rec.ts, fromSeq: prevSeenSeq, toSeq: s, count: gapCount
        };
        const gapNode = renderBubble(gapRec);
        if (gapNode) frag.appendChild(gapNode);
        if (persistGaps) { try { putGapRecord({ serverUrl, roomId, ts: rec.ts, fromSeq: prevSeenSeq, toSeq: s }); } catch {} }
      }

      if (s !== null) {
        prevSeq = s;
        lastSeqSeen.set(rk, s);
      }
    }

    // Bubble
    const node = renderBubble(rec);
    if (!node) continue;
    frag.appendChild(node);

    // Housekeeping (VL tracking)
    if (VL.seenIds && rec.id && rec.kind !== 'gap') VL.seenIds.add(rec.id);
    if (rec.ts) {
      VL.oldestTs = Math.min(VL.oldestTs, rec.ts|0);
      VL.newestTs = Math.max(VL.newestTs, rec.ts|0);
    }
  }

  // Write to DOM
  if (placement === 'replace') {
    el.innerHTML = '';
    el.appendChild(frag);
    attachVirtualScroll(); // re-attach scroll listener if needed
    requestAnimationFrame(scrollToEnd);
  } else if (placement === 'prepend') {
    el.insertBefore(frag, el.firstChild);
    // keep scroll anchored
    const newHeight = el.scrollHeight;
    el.scrollTop += (newHeight - prevHeight);
    pruneBottomIfNeeded();
  } else {
    const autoscroll = nearBottom();
    el.appendChild(frag);
    pruneTopIfNeeded();
    if (autoscroll) requestAnimationFrame(scrollToEnd);
  }
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

async function putGapRecord({ serverUrl, roomId, ts, fromSeq, toSeq }) {
  const rKey = roomKey(serverUrl, roomId);
  const id = `${rKey}|gap|${fromSeq + 1}-${toSeq}`; // stable id
  const rec = {
    id,
    roomKey: rKey,
    roomId, serverUrl,
    ts: ts || nowMs(),
    kind: 'gap',
    fromSeq, toSeq,
    seq: fromSeq + 0.5 // lets 'byRoomSeq' place it between from and to (not relied upon, but handy)
  };
  try { await msgPut(rec); } catch {}
  return rec;
}

function scrollToEnd() {
  const el = ui.messages; if (!el) return;
  const doScroll = () => { el.scrollTop = el.scrollHeight; };
  doScroll(); requestAnimationFrame(doScroll); setTimeout(doScroll, 0);
}
function clearMessagesUI() { ui.messages.innerHTML = ''; }

async function renderFileIfAvailable(bubbleEl, meta) {
  const content = bubbleContentOf(bubbleEl);
  const blob = await idbGet(meta.hash);
  if (!blob) return false;

  content.innerHTML = '';
  const url = URL.createObjectURL(blob);

  if (meta.mime && meta.mime.startsWith('image/')) {
    const img = document.createElement('img');
    img.onload = () => URL.revokeObjectURL(url);
    img.src = url;
    img.alt = meta.name || 'image';
    content.appendChild(img);
  } else {
    const link = document.createElement('a');
    link.href = url;
    link.textContent = `${meta.name || 'file'} (${meta.size || blob.size} bytes)`;
    link.className = 'file-link';
    link.target = '_blank';
    link.rel = 'noopener';
    link.download = meta.name || 'file';
    link.addEventListener('click', () => setTimeout(() => URL.revokeObjectURL(url), 0), { once: true });
    content.appendChild(link);
  }

  return true;
}

function showPendingBubble(bubbleEl, meta) {
  const content = bubbleContentOf(bubbleEl);
  content.innerHTML = '';

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
  content.appendChild(wrap);
}

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
    
  renderSegment(page, { placement: 'prepend', computeGaps: true, persistGaps: false });
    
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
      renderSegment(first, { placement: 'replace', computeGaps: true, persistGaps: false });
    } else {
      VL.hasMoreOlder = false;
    }
    attachVirtualScroll();
    requestAnimationFrame(scrollToEnd);
}

////////////////////////
// ENCRYPTION
///////////////////////

async function encryptStringForRoom(roomId, str) {
  const { curvePk } = await getRoomKeys(roomId);
  const cipher = sodium.crypto_box_seal(sodium.from_string(str), curvePk);
  return b64u(cipher);
}
async function decryptToStringForRoom(roomId, ciphertextB64) {
  await ensureSodium();
  const { curvePk, curveSk } = await getRoomKeys(roomId);
  try {
    const pt = sodium.crypto_box_seal_open(fromB64u(ciphertextB64), curvePk, curveSk);
    return bytesToUtf8(pt);
  } catch {
    return '[unable to decrypt]';
  }
}
function signCiphertextB64(ciphertextB64) {
  const sig = sodium.crypto_sign_detached(fromB64u(ciphertextB64), myIdSk);
  return b64u(sig);
}

////////////////////////
// CRYPTO
///////////////////////

const _subtle = crypto.subtle;
const subtleImportKey = _subtle.importKey.bind(_subtle);
const subtleDeriveKey = _subtle.deriveKey.bind(_subtle);
const subtleEncrypt   = _subtle.encrypt.bind(_subtle);
const subtleDecrypt   = _subtle.decrypt.bind(_subtle);

let myIdPk = null; // device identity public key (Uint8Array)
let myIdSk = null; // device identity private key (Uint8Array)
let myPeerId = null; // base64url of myIdPk

function derivePubFromSk(sk) {
  if (sodium.crypto_sign_ed25519_sk_to_pk) return sodium.crypto_sign_ed25519_sk_to_pk(sk);
  return sk.slice(32, 64);
}

async function setCryptoForRoom(room) {
  await getRoomKeys(room.id);
}

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

let secretDbP = null;

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

////////////////////////
// SEND/RECEIVE
///////////////////////

const te = new TextEncoder();
// Per-server connections { url, ws, reconnectAttempt, reconnectTimer, heartbeatTimer, subscribed:Set, authed:Set }
const servers = new Map();
const lastSeqSeen = new Map(); // key: roomKey(serverUrl, roomId) -> integer

async function sendTextMessage(room, text) {
  const ciphertextB64 = await encryptStringForRoom(room.id, text);
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
  const ciphertextB64 = await encryptStringForRoom(room.id, metaJson);
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

async function upsertTombstone(serverUrl, roomId, seq, extra = {}) {
  const rec = await msgGetBySeq(serverUrl, roomId, seq);
  const rKey = roomKey(serverUrl, roomId);
  const tombId = rec?.id || `${rKey}|tomb|${seq}`;

  // (Optional) verify the sig against original author if you have it here
  // When called from `kind:"delete"` flow you may have m.sig/m.signer_id; if rec exists,
  // verify over canonDeleteBytes(roomId, seq) with rec.senderId’s key.

  const tomb = {
    id: tombId,
    roomKey: rKey,
    roomId, serverUrl,
    ts: rec?.ts ?? (extra.ts || nowMs()),
    seq,
    senderId: rec?.senderId ?? extra.signer_id ?? null,
    nickname: rec?.nickname ?? undefined,
    verified: rec?.verified ?? undefined,
    kind: 'deleted'
  };
  await msgPut(tomb);

  // Remove any rendered node
  removeDomRowBySeq(seq);
  if (_selected?.row?.dataset?.seq === String(seq)) clearSelection();
}

// helper to fetch previous once per room if needed
async function getPrevSeq(serverUrl, roomId) {
  const rk = roomKey(serverUrl, roomId);
  if (lastSeqSeen.has(rk)) return lastSeqSeen.get(rk);
  const prev = await msgGetLastSeq(serverUrl, roomId); // -1 if none
  lastSeqSeen.set(rk, prev);
  return prev;
}

async function handleIncoming(serverUrl, m, fromHistory = false) {
  const roomId = m.room_id;
  if (!roomId) return;

  const pt = await decryptToStringForRoom(roomId, m.ciphertext);
  const rKey = roomKey(serverUrl, roomId);

  // Stable id by ciphertext
  const idHash = await sha256_b64u_string(m.ciphertext);
  const id     = `${rKey}|${idHash}`;

  // Signature check over ciphertext
  let verified;
  if (m.sender_id && m.sig) {
    try {
      const senderPk    = fromB64u(m.sender_id);
      const sigBytes    = fromB64u(m.sig);
      const cipherBytes = fromB64u(m.ciphertext);
      verified = sodium.crypto_sign_verify_detached(sigBytes, cipherBytes, senderPk);
    } catch { verified = false; }
  } else {
    verified = undefined; // no signature provided
  }

  // Only drop if verification explicitly FAILS
  if (verified === false) {
    if (DEBUG_SIG) dbg('handleIncoming: signature failed; dropping');
    return;
  }

  const tsVal  = m.ts ?? nowMs();
  const seqVal = (typeof m.seq === 'number') ? m.seq : null;

  // ---- Gap detection centralized here ----
  if (seqVal !== null) {
    const prev = await getPrevSeq(serverUrl, roomId);
    if (prev >= -1 && seqVal > prev + 1) {
      await putGapRecord({ serverUrl, roomId, ts: tsVal, fromSeq: prev, toSeq: seqVal });
      const isActive = VL && VL.serverUrl === serverUrl && VL.roomId === roomId && !fromHistory;
      if (isActive) renderGapBubble(seqVal - prev - 1);
    }
    lastSeqSeen.set(rKey, seqVal);
  }

  // Try to parse control/file messages
  try {
    const obj = JSON.parse(pt);

    // FILE META
    if (obj && obj.kind === 'file' && obj.hash) {
      const meta = { ...obj, room_id: roomId };
      await msgPut({
        id, roomKey: rKey, roomId, serverUrl,
        ts: tsVal, seq: seqVal, nickname: m.nickname,
        senderId: m.sender_id, verified, kind: 'file', meta
      });
      const isActive = VL && VL.serverUrl === serverUrl && VL.roomId === roomId && !fromHistory;
      if (isActive) {
        const rec = { id, roomId, serverUrl, kind:'file', ts: tsVal, seq: seqVal, nickname:m.nickname, senderId:m.sender_id, verified, meta };
        renderSegment([rec], { placement:'append', computeGaps:true, persistGaps:true });
      }
      return;
    }

    // IN-BAND DELETE EVENT (control record that points to a target seq)
    if (obj && obj.kind === 'delete') {
      const targetSeq = Number(obj.target_seq);
      if (Number.isFinite(targetSeq)) {
        await upsertTombstone(serverUrl, roomId, targetSeq, { ts: m.ts, signer_id: m.signer_id, sig: m.sig });
      }
      // also store the delete control itself so it occupies its seq slot
      await msgPut({
        id: `${rKey}|ctrl|del|${m.seq}`,
        roomKey: rKey, roomId, serverUrl,
        ts: tsVal, seq: m.seq,
        kind: 'delete', targetSeq
      });
      return;
    }

    // IN-BAND TOMBSTONE ROW
    if (obj && obj.kind === 'deleted') {
      const targetSeq = Number.isFinite(obj.target_seq) ? Number(obj.target_seq) : Number(m.seq);
      await upsertTombstone(serverUrl, roomId, targetSeq, { ts: m.ts, signer_id: m.signer_id, sig: m.sig });
      // also store the tombstone row so its seq is occupied
      await msgPut({
        id: `${rKey}|tomb|row|${m.seq}`,
        roomKey: rKey, roomId, serverUrl,
        ts: tsVal, seq: m.seq,
        kind: 'deleted-row', targetSeq
      });
      return;
    }

  } catch { /* plaintext text message */ }

  // TEXT
  await msgPut({
    id, roomKey: rKey, roomId, serverUrl,
    ts: tsVal, seq: seqVal,
    nickname: m.nickname, senderId: m.sender_id,
    verified, kind: 'text', text: pt
  });

  const isActive = VL && VL.serverUrl === serverUrl && VL.roomId === roomId && !fromHistory;
  if (isActive) {
    const rec = { id, roomId, serverUrl, kind:'text', ts: tsVal, seq: seqVal, nickname:m.nickname, senderId:m.sender_id, verified, text: pt };
    renderSegment([rec], { placement:'append', computeGaps:true, persistGaps:true });
  }
}

/////////////////////
// WebRTC proxying
/////////////////////

// request_id -> { serverUrl, roomId, pc, hash }
const pendingRequests = new Map();
// request_id -> ICE buffered before responder PC exists
const serveRequests   = new Map();
const preServeIce     = new Map();

function iceToJSON(c) {
  if (!c) return null;
  const j = typeof c.toJSON === 'function'
    ? c.toJSON()
    : { candidate: c.candidate, sdpMid: c.sdpMid, sdpMLineIndex: c.sdpMLineIndex, usernameFragment: c.usernameFragment };
  if (DEBUG_RTC) dbg('RTC/ICE->JSON', { hasCandidate: !!j.candidate, mid: j.sdpMid, mline: j.sdpMLineIndex });
  return j;
}

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
      if (DEBUG_SIG) dbg('SIG/TX', 'send profile', { room: room.name, id: room.id, url: sc.url });
      sendMyProfile(sc.url, room.id);

      const lastTs = await msgGetLastTs(sc.url, room.id);
      const since = lastTs > 0 ? (lastTs + 1) : sevenDaysAgoMs();

      sc.ws.send(JSON.stringify({ type: 'history', room_id: room.id, since }));

      if (room.id === currentRoomId) {
        await ensureSodium();
        setCryptoForRoom(room);
        await initVirtualRoomView(sc.url, room.id);
        setStatus(statuses.connected);
      }

    } else if (m.type === 'profile-notify') {
      await applyProfileCipher(sc.url, m.room_id, m.sender_id, m.ciphertext);
      clearProfileRetry(sc.url, m.room_id, m.sender_id);	

    } else if (m.type === 'profile-retrieve') {
      await applyProfileCipher(sc.url, m.room_id, m.sender_id, m.ciphertext);
      clearProfileRetry(sc.url, m.room_id, m.sender_id);
	
    } else if (m.type === 'profile-none') {
      // no profile available; you could cache a sentinel if you like
      scheduleProfileRetry(sc.url, m.room_id, m.sender_id);

    } else if (m.type === 'history') {
      const serverUrl = sc.url;
      const rid = m.room_id;

      for (const item of (m.messages || [])) {
	// No DOM writes here; fromHistory=true
	await handleIncoming(serverUrl, item, true);
      }

      // If this is the active room, draw (from IDB) using your normal init
      if (rid === currentRoomId) {
	await initVirtualRoomView(serverUrl, rid);
	setStatus(statuses.connected);
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
      //if (m.room_id === currentRoomId) {
        console.log({ text: `Server error: ${m.error}`, ts: nowMs(), nickname: 'server', senderId: null });
      //}
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

////////////////////////////
// INVITATIONS
////////////////////////////

function openInviteDialog(){
  inv.codeInput.value = '';
  inv.scanArea.classList.add('hidden');
  inv.dlg.showModal();
}

let _joinWait = { ws:null, curvePk:null, curveSk:null, hash:null, host:null };

//async function drawInviteQr(text){
  // If you already have a QR lib, call it here; otherwise draw a simple fallback box
  //const c = join.qrCanvas;
  //if (!c) return;
  //new QRCode(join.qrCanvas, text);
  //if (typeof window.drawQRCode === 'function') {
  //  window.drawQRCode(c, text);  // hook for your preferred QR lib
  //  return;
  //}
  // Fallback placeholder (no QR lib): show nothing, keep hint
  //c.width = c.height = 0;
//}

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
  join.qrCode.innerHTML = "";  
  new QRCode(join.qrCode, { text: code, width: 192, height: 192, colorDark: "#000000", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.M } );
  //await drawInviteQr(code);

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

	// 🔧 Align with sender: 'kind' (not 'k'), 'room.roomSkB64' (not 'room.sk')
	if (!obj || obj.kind !== 'room-invite' || !obj.room || !obj.room.roomSkB64 || !obj.room.id) {
	  alert('Bad invite payload'); return;
	}

	const skBytes = fromB64u(obj.room.roomSkB64);
	const pkBytes = derivePubFromSk(skBytes);
	if (b64u(pkBytes) !== obj.room.id) { alert('Invite id mismatch'); return; }

	// Prefer the explicit server in payload; fall back to the host we’re connected to
	const serverUrl = obj.room.server || ('https://' + _joinWait.host);
	const rid = obj.room.id;

	// Upsert room (if not present)
	if (!rooms.find(x => x.id === rid)) {
	  rooms.push({
	    id: rid,
	    name: obj.room.name || 'Room',
	    server: serverUrl,
	    roomId: rid,
	    createdAt: obj.room.createdAt || nowMs()
	  });
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

const SECRET_DB = 'secmsg_secret_db';
const SECRET_STORE = 'roomsecrets';
const CURRENT_ROOM_KEY = 'secmsg_current_room_id';
const MSG_DB = 'secmsg_msgs_db';
const MSG_STORE = 'msgs';
const PROFILE_DB = 'secmsg_profile_db';
const PROFILE_STORE = 'kv';
const PBKDF2_ITERS_CURRENT = 250_000;
const KDF_ALGO = { name: 'PBKDF2', hash: 'SHA-256' };
const PROFILE_AVATAR_TARGET_BYTES = 12 * 1024;   // try to keep avatar ≤ 12 KiB
const PROFILE_AVATAR_HARD_BYTES   = 16 * 1024;   // refuse above this after retries
const PROFILE_AVATAR_W = 192;
const PROFILE_AVATAR_H = 192;

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

////////////////////////////////
////////// BOOT
///////////////////////////////

ensureSodium();
let SETTINGS = loadSettings();

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
