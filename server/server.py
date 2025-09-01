import json
import os
import sqlite3
import time
from urllib.parse import parse_qs

from flask import Flask, request, jsonify
from flask_sock import Sock
from flask_cors import CORS
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from nacl import utils

def LOG(*args):
    ts = time.strftime('%H:%M:%S')
    print(f"[WSR {ts}]", *args, flush=True)

APP = Flask(__name__, static_folder=None)
app = APP
SOCK = Sock(APP)
CORS(
    APP,
    resources={r"/rooms": {"origins": ["https://rickard.armiento.se"]}, r"/health": {"origins": "*"}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)
DB_PATH = os.path.join(os.path.dirname(__file__), 'messages.db')

def db():
  conn = sqlite3.connect(DB_PATH, check_same_thread=False)
  conn.execute('PRAGMA journal_mode=WAL;')
  conn.row_factory = sqlite3.Row
  return conn

CONN = db()
CONN.execute("""
CREATE TABLE IF NOT EXISTS rooms (
  room_id TEXT PRIMARY KEY,
  ed25519_public_key BLOB NOT NULL,
  created_at INTEGER NOT NULL
)""")
CONN.execute("""
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  nickname TEXT,
  sender_id BLOB,
  sig BLOB,
  ciphertext BLOB NOT NULL
)""")
# best-effort migrations
try: CONN.execute('ALTER TABLE messages ADD COLUMN sender_id BLOB')
except Exception: pass
try: CONN.execute('ALTER TABLE messages ADD COLUMN sig BLOB')
except Exception: pass
CONN.commit()

# in-room connection registries
ROOM_CONNECTIONS = {}          # room_id -> set(ws)
ROOM_PEERS = {}                # room_id -> { peer_id(str b64): ws }

@APP.get('/health')
def health():
  return {"ok": True, "time": now_ms()}

@APP.post('/rooms')
def create_room():
  data = request.get_json(force=True)
  room_id = data.get('room_id')
  pub_b64u = data.get('ed25519_public_key_b64u')
  if not room_id or not pub_b64u:
    return jsonify({"error": "room_id and ed25519_public_key_b64u required"}), 400
  try:
    edpk = base64url_decode(pub_b64u)
  except Exception:
    return jsonify({"error": "invalid public key encoding"}), 400
  with CONN:
    CONN.execute(
      "INSERT OR IGNORE INTO rooms(room_id, ed25519_public_key, created_at) VALUES (?, ?, ?)",
      (room_id, edpk, now_ms())
    )
  return jsonify({"ok": True, "room_id": room_id})

@APP.get('/')
def root():
  return '<h3>Secure Messenger Relay</h3><p>Use the PWA client to connect.</p>'

@SOCK.route('/ws')
def ws_handler(ws):
  query = ws.environ.get('QUERY_STRING', '')
  room_id = (parse_qs(query).get('room') or [None])[0]
  LOG("WS connect", "room=", room_id)
  if not room_id:
    ws.send(json.dumps({"type": "error", "error": "room parameter required"}))
    ws.close(); return

  cur = CONN.execute("SELECT ed25519_public_key FROM rooms WHERE room_id=?", (room_id,))
  row = cur.fetchone()
  if not row:
    ws.send(json.dumps({"type": "error", "error": "unknown room"}))
    ws.close(); return

  verify_key = VerifyKey(row['ed25519_public_key'])

  # Auth handshake
  challenge = utils.random(32)
  ws.send(json.dumps({"type": "challenge", "nonce": base64url_encode(challenge)}))
  raw = ws.receive()
  if not raw: return
  try:
    msg = json.loads(raw)
  except Exception:
    ws.send(json.dumps({"type": "error", "error": "invalid JSON"}))
    ws.close(); return

  if msg.get('type') != 'auth' or not msg.get('signature'):
    ws.send(json.dumps({"type": "error", "error": "expected auth"}))
    ws.close(); return

  try:
    signature = base64url_decode(msg['signature'])
    verify_key.verify(challenge, signature)
  except BadSignatureError:
    ws.send(json.dumps({"type": "error", "error": "bad signature"}))
    ws.close(); return
  except Exception:
    ws.send(json.dumps({"type": "error", "error": "verification error"}))
    ws.close(); return

  LOG("Auth OK", "room=", room_id)
    
  # Register connection
  ROOM_CONNECTIONS.setdefault(room_id, set()).add(ws)
  ROOM_PEERS.setdefault(room_id, {})

  ws.send(json.dumps({"type": "ready"}))
  LOG("Joined", "room=", room_id, "conns=", len(ROOM_CONNECTIONS.get(room_id, set())))

  peer_id = None  # b64 string after announce

  try:
    while True:
      raw = ws.receive()
      if raw is None: break
      try:
        m = json.loads(raw)
      except Exception:
        ws.send(json.dumps({"type": "error", "error": "invalid JSON"}))
        continue
      
      t = m.get('type')
      LOG("RX", t)

      if t == 'announce':
        # Client announces its device id (base64url of Ed25519 pubkey)
        pid = m.get('peer_id')
        if isinstance(pid, str) and pid:
            ROOM_PEERS[room_id][pid] = ws
            LOG("announce", "room=", room_id, "peer=", pid, "peers=", len(ROOM_PEERS[room_id]))
            peer_id = pid

      elif t == 'history':
        since = int(m.get('since') or (now_ms() - 7*24*60*60*1000))
        cur = CONN.execute(
          "SELECT ts, nickname, sender_id, sig, ciphertext FROM messages WHERE room_id=? AND ts>=? ORDER BY ts ASC",
          (room_id, since)
        )
        items = [{
          'ts': row['ts'],
          'nickname': row['nickname'],
          'sender_id': base64url_encode(row['sender_id']) if row['sender_id'] is not None else None,
          'sig': base64url_encode(row['sig']) if row['sig'] is not None else None,
          'ciphertext': base64url_encode(row['ciphertext'])
        } for row in cur.fetchall()]
        
        LOG("history", "room=", room_id, "since=", since, "count=", len(items))
        ws.send(json.dumps({"type": "history", "messages": items}))

      elif t == 'send':
        ciph_b64u = m.get('ciphertext')
        nickname = m.get('nickname')
        sender_id_b64u = m.get('sender_id')
        sig_b64u = m.get('sig')
        if not ciph_b64u:
          ws.send(json.dumps({"type": "error", "error": "missing ciphertext"})); continue
        try:
          ciphertext = base64url_decode(ciph_b64u)
          sender_id = base64url_decode(sender_id_b64u) if sender_id_b64u else None
          sig = base64url_decode(sig_b64u) if sig_b64u else None
        except Exception:
          ws.send(json.dumps({"type": "error", "error": "bad encoding"})); continue

        ts = now_ms()
        with CONN:
          CONN.execute(
            "INSERT INTO messages(room_id, ts, nickname, sender_id, sig, ciphertext) VALUES (?, ?, ?, ?, ?, ?)",
            (room_id, ts, nickname, sender_id, sig, ciphertext)
          )

        sent = broadcast(room_id, {
            'type': 'message',
            'ts': ts, 'nickname': nickname,
            'sender_id': sender_id_b64u, 'sig': sig_b64u, 'ciphertext': ciph_b64u
        })
        LOG("send", "room=", room_id, "bytes=", len(ciphertext), "fanout=", sent)

      elif t == 'ping':
        ws.send(json.dumps({"type": "pong", "ts": now_ms()}))

      # --- WebRTC signaling (volatile; not stored) ---
      elif t == 'webrtc-request':
          payload = {
              'type': 'webrtc-request',
              'request_id': m.get('request_id'),
              'checksum': m.get('checksum'),
              'offer': m.get('offer'),
              'from': m.get('from')
          }
          fanout = broadcast(room_id, payload, exclude=ws)
          LOG("rtc/request", "room=", room_id, "req=", m.get('request_id'), "hash=", m.get('checksum'), "from=", m.get('from'), "fanout=", fanout)

      elif t == 'webrtc-response':
          target = m.get('to')
          payload = {
              'type': 'webrtc-response',
              'request_id': m.get('request_id'),
              'answer': m.get('answer'),
              'from': m.get('from'),
              'checksum': m.get('checksum')
          }
          ok = unicast(room_id, target, payload)
          LOG("rtc/response", "room=", room_id, "req=", m.get('request_id'), "to=", target, "ok=", ok)

      elif t == 'webrtc-ice':
          target = m.get('to')
          payload = {
              'type': 'webrtc-ice',
              'request_id': m.get('request_id'),
              'candidate': m.get('candidate'),
              'from': m.get('from')
          }
          ok = unicast(room_id, target, payload)
          LOG("rtc/ice", "room=", room_id, "req=", m.get('request_id'), "to=", target, "ok=", ok)

      else:
        ws.send(json.dumps({"type": "error", "error": f"unknown type: {t}"}))

  finally:
      try:
          ROOM_CONNECTIONS.get(room_id, set()).discard(ws)
          if peer_id and ROOM_PEERS.get(room_id):
              if ROOM_PEERS[room_id].get(peer_id) is ws:
                  ROOM_PEERS[room_id].pop(peer_id, None)
          LOG("Left", "room=", room_id, "conns=", len(ROOM_CONNECTIONS.get(room_id, set())), "peers=", len(ROOM_PEERS.get(room_id, {})))
      except Exception:
          pass

# helpers
def broadcast(room_id, payload, exclude=None):
    dead, sent = [], 0
    for sock in list(ROOM_CONNECTIONS.get(room_id, set())):
        if exclude is not None and sock is exclude:
            continue
        try:
            sock.send(json.dumps(payload))
            sent += 1
        except Exception:
            dead.append(sock)
    for d in dead:
        try: ROOM_CONNECTIONS.get(room_id, set()).discard(d)
        except Exception: pass
    return sent

def unicast(room_id, peer_id_b64, payload):
    ws = ROOM_PEERS.get(room_id, {}).get(peer_id_b64)
    if not ws:
        LOG("unicast-miss", "room=", room_id, "peer=", peer_id_b64)
        return False
    try:
        ws.send(json.dumps(payload))
        return True
    except Exception:
        try: ROOM_CONNECTIONS.get(room_id, set()).discard(ws)
        except Exception: pass
        LOG("unicast-error", "room=", room_id, "peer=", peer_id_b64)
        return False

def base64url_encode(b: bytes) -> str:
  import base64
  if b is None: return None
  return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def base64url_decode(s: str) -> bytes:
  import base64
  if s is None: return None
  pad = '=' * (-len(s) % 4)
  return base64.urlsafe_b64decode(s + pad)

def now_ms():
  return int(time.time() * 1000)

if __name__ == '__main__':
  try:
    import eventlet
    eventlet.monkey_patch()
  except Exception:
    pass
  port = int(os.environ.get('PORT', '5000'))
  APP.run(host='0.0.0.0', port=port, debug=True)
