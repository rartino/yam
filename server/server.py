import os
import json
import time
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sock import Sock

DB_PATH = os.environ.get("WS_DB_PATH", "messages.db")
ALLOWED_ORIGINS = set(
    [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "https://rickard.armiento.se").split(",") if o.strip()]
)

app = Flask(__name__)
APP = app
CORS(
    app,
    resources={
        r"/ws": {"origins": ALLOWED_ORIGINS},
        r"/health": {"origins": ALLOWED_ORIGINS},
        r"/rooms": {"origins": ALLOWED_ORIGINS},
    },
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)
sock = Sock(app)

# ---------- Logging ----------
def LOG(*args):
    ts = time.strftime('%H:%M:%S')
    print(f"[WSR {ts}]", *args, flush=True)

# ---------- DB ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id TEXT NOT NULL,
      ts INTEGER NOT NULL,
      nickname TEXT,
      sender_id TEXT,
      sig TEXT,
      ciphertext TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_room_cipher ON messages(room_id, ciphertext)
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- “Create room” endpoint (no-op but useful) ----------
@app.route("/rooms", methods=["POST"])
def rooms_post():
    data = request.get_json(silent=True) or {}
    rid = data.get("room_id")
    if not rid:
        return jsonify({"ok": False, "error": "room_id required"}), 400
    # no-op: we trust room_id to be an Ed25519 pk b64url
    return jsonify({"ok": True})

# ---------- In-memory WS state (multi-room per socket) ----------
# For each socket -> set of subscribed room_ids
SUBSCRIPTIONS = {}               # ws -> set(room_id)
# Pending auth challenge per ws and room: (ws, room_id) -> nonce bytes (b64url)
PENDING_CHALLENGES = {}

# Room membership: room_id -> set(ws) (only authed sockets)
ROOM_CONNECTIONS = {}

# Room peers for signaling: room_id -> {peer_id_b64u: ws}
ROOM_PEERS = {}

# Simple sliding-window rate limit (per IP + room + kind)
_RATE = {}  # key -> (reset_epoch_ms, count)

# ---------- Helpers ----------
def broadcast(room_id, payload, exclude=None):
    """Fanout to all authed subscribers of room_id"""
    sent = 0
    dead = []
    for sock in list(ROOM_CONNECTIONS.get(room_id, set())):
        if exclude is not None and sock is exclude:
            continue
        try:
            sock.send(json.dumps(payload))
            sent += 1
        except Exception:
            dead.append(sock)
    for d in dead:
        # cleanup dead sockets
        for rid in list(SUBSCRIPTIONS.get(d, set())):
            ROOM_CONNECTIONS.get(rid, set()).discard(d)
            # also clear peer maps if pointing to this ws
            peers = ROOM_PEERS.get(rid, {})
            for k, v in list(peers.items()):
                if v is d:
                    peers.pop(k, None)
        SUBSCRIPTIONS.pop(d, None)
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
        # Clean up this ws as dead
        try:
            ROOM_CONNECTIONS.get(room_id, set()).discard(ws)
        except Exception:
            pass
        LOG("unicast-error", "room=", room_id, "peer=", peer_id_b64)
        return False

def _ws_origin(ws) -> str:
    return (ws.environ.get("HTTP_ORIGIN") or "").strip()

def _peer_ip(ws) -> str:
    xf = (ws.environ.get("HTTP_X_FORWARDED_FOR") or "").split(",")[0].strip()
    return xf or (ws.environ.get("REMOTE_ADDR") or "0.0.0.0")

def _too_many(kind: str, ip: str, room_id: str | None, limit: int, window_sec: int = 30) -> bool:
    now = now_ms()
    key = (kind, ip, room_id or "-")
    reset, cnt = _RATE.get(key, (0, 0))
    if now > reset:
        _RATE[key] = (now + window_sec * 1000, 1)
        return False
    cnt += 1
    _RATE[key] = (reset, cnt)
    return cnt > limit

def _is_authed(ws, room_id: str) -> bool:
    return ws in ROOM_CONNECTIONS.get(room_id, set())

def _ensure_peer_maps_for(room_id: str):
    ROOM_CONNECTIONS.setdefault(room_id, set())
    ROOM_PEERS.setdefault(room_id, {})

# ---------- WebSocket (no room in URL; subscribe per room) ----------
@sock.route('/ws')
def ws_handler(ws):
    # Origin gate (defense-in-depth; keep your proxy checking too)
    origin = _ws_origin(ws)
    if ALLOWED_ORIGINS and origin not in ALLOWED_ORIGINS:
        LOG("WS reject origin", origin)
        try:
            ws.close()
        except Exception:
            pass
        return

    ip = _peer_ip(ws)
    SUBSCRIPTIONS[ws] = set()
    LOG("WS open", "ip=", ip, "origin=", origin)

    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break

            try:
                m = json.loads(raw)
            except Exception:
                ws.send(json.dumps({'type': 'error', 'error': 'invalid JSON'}))
                continue

            t = m.get('type')

            # ---------- Ping/Pong ----------
            if t == 'ping':
                ws.send(json.dumps({'type': 'pong', 'ts': now_ms()}))
                continue

            # ---------- Subscribe (per room) -> send auth challenge ----------
            if t == 'subscribe':
                room_id = m.get('room_id')
                if not isinstance(room_id, str) or not room_id:
                    ws.send(json.dumps({'type': 'error', 'error': 'room_id required'}))
                    continue

                if _too_many('subscribe', ip, room_id, limit=20):
                    ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'rate_limited'}))
                    continue

                SUBSCRIPTIONS[ws].add(room_id)
                _ensure_peer_maps_for(room_id)

                # Challenge = 32 random bytes; verify with Ed25519 pubkey = room_id (b64url)
                nonce = os.urandom(32)
                PENDING_CHALLENGES[(ws, room_id)] = nonce
                LOG("challenge", "room=", room_id)
                ws.send(json.dumps({'type': 'challenge', 'room_id': room_id, 'nonce': _b64u(nonce)}))
                continue

            # ---------- Auth (per room) ----------
            if t == 'auth':
                room_id = m.get('room_id')
                sig_b64 = m.get('signature')
                if not room_id or not sig_b64:
                    ws.send(json.dumps({'type': 'error', 'error': 'room_id & signature required'}))
                    continue

                if _too_many('auth', ip, room_id, limit=30):
                    ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'rate_limited'}))
                    continue

                nonce = PENDING_CHALLENGES.pop((ws, room_id), None)
                if nonce is None:
                    ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'no_challenge'}))
                    continue

                try:
                    import nacl.signing, nacl.encoding, nacl.exceptions
                    pk_bytes = _from_b64u(room_id)
                    verify_key = nacl.signing.VerifyKey(pk_bytes, encoder=nacl.encoding.RawEncoder)
                    verify_key.verify(nonce, _from_b64u(sig_b64))
                except Exception as e:
                    LOG("auth fail", "room=", room_id, "err=", repr(e))
                    ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'auth_failed'}))
                    continue

                _ensure_peer_maps_for(room_id)
                ROOM_CONNECTIONS[room_id].add(ws)
                LOG("auth ok", "room=", room_id, "conns=", len(ROOM_CONNECTIONS[room_id]))
                ws.send(json.dumps({'type': 'ready', 'room_id': room_id}))
                continue

            # ---------- Everything below requires room_id + authorization ----------
            room_id = m.get('room_id')
            if t not in ('history', 'send', 'announce', 'webrtc-request', 'webrtc-response', 'webrtc-ice'):
                ws.send(json.dumps({'type': 'error', 'error': f'unknown type: {t}'}))
                continue
            if not isinstance(room_id, str) or not room_id:
                ws.send(json.dumps({'type': 'error', 'error': 'room_id required'}))
                continue
            if not _is_authed(ws, room_id):
                ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'not_authorized'}))
                continue

            # ---------- Announce peer id (used for signaling routing) ----------
            if t == 'announce':
                pid = m.get('peer_id')
                if isinstance(pid, str) and pid:
                    ROOM_PEERS.setdefault(room_id, {})[pid] = ws
                    LOG("announce", "room=", room_id, "peer=", pid[:6] + "…")
                continue

            # ---------- History ----------
            if t == 'history':
                try:
                    since = int(m.get('since', 0))
                except Exception:
                    since = 0
                conn = get_db()
                cur = conn.cursor()
                cur.execute(
                    "SELECT ts,nickname,sender_id,sig,ciphertext FROM messages "
                    "WHERE room_id=? AND ts>=? ORDER BY ts ASC",
                    (room_id, since)
                )
                rows = cur.fetchall()
                conn.close()
                items = [{
                    'type': 'message',
                    'room_id': room_id,
                    'ts': r['ts'],
                    'nickname': r['nickname'],
                    'sender_id': r['sender_id'],
                    'sig': r['sig'],
                    'ciphertext': r['ciphertext'],
                } for r in rows]
                LOG("history", "room=", room_id, "count=", len(items))
                ws.send(json.dumps({'type': 'history', 'room_id': room_id, 'messages': items}))
                continue

            # ---------- Send (store + broadcast, with de-dupe) ----------
            if t == 'send':
                if _too_many('send', ip, room_id, limit=300):  # ~10 msg/sec in 30s window
                    ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'rate_limited'}))
                    continue

                ciphertext = m.get('ciphertext')
                if not isinstance(ciphertext, str) or not ciphertext:
                    ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'missing_ciphertext'}))
                    continue

                ts_client = m.get('ts_client')
                try:
                    ts = int(ts_client) if ts_client is not None else now_ms()
                except Exception:
                    ts = now_ms()

                nickname = m.get('nickname')
                sender_id = m.get('sender_id')
                sig = m.get('sig')

                # De-dupe: skip if this ciphertext already exists for this room
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM messages WHERE room_id=? AND ciphertext=? LIMIT 1",
                            (room_id, ciphertext))
                exists = cur.fetchone() is not None
                if not exists:
                    cur.execute(
                        "INSERT OR IGNORE INTO messages (room_id, ts, nickname, sender_id, sig, ciphertext) "
                        "VALUES (?,?,?,?,?,?)",
                        (room_id, ts, nickname, sender_id, sig, ciphertext)
                    )
                    conn.commit()
                conn.close()

                payload = {
                    'type': 'message',
                    'room_id': room_id,
                    'ts': ts,
                    'nickname': nickname,
                    'sender_id': sender_id,
                    'sig': sig,
                    'ciphertext': ciphertext
                }
                fanout = broadcast(room_id, payload)
                LOG("send", "room=", room_id, "bytes=", len(ciphertext), "fanout=", fanout)
                continue

            # ---------- WebRTC signaling ----------
            is_signal_rate_limited = _too_many('signal', ip, room_id, limit=800)  # plenty of headroom
            if is_signal_rate_limited:
                ws.send(json.dumps({'type': 'error', 'room_id': room_id, 'error': 'rate_limited'}))
                continue

            if t == 'webrtc-request':
                payload = {
                    'type': 'webrtc-request',
                    'room_id': room_id,
                    'request_id': m.get('request_id'),
                    'checksum': m.get('checksum'),
                    'offer': m.get('offer'),
                    'from': m.get('from')
                }
                fanout = broadcast(room_id, payload, exclude=ws)
                LOG("rtc/request", "room=", room_id, "req=", m.get('request_id'), "hash=", m.get('checksum'), "fanout=", fanout)
                continue

            if t == 'webrtc-response':
                target = m.get('to')
                payload = {
                    'type': 'webrtc-response',
                    'room_id': room_id,
                    'request_id': m.get('request_id'),
                    'answer': m.get('answer'),
                    'from': m.get('from'),
                    'checksum': m.get('checksum')
                }
                ok = unicast(room_id, target, payload)
                LOG("rtc/response", "room=", room_id, "req=", m.get('request_id'), "to=", target, "ok=", ok)
                continue

            if t == 'webrtc-ice':
                target = m.get('to')
                payload = {
                    'type': 'webrtc-ice',
                    'room_id': room_id,
                    'request_id': m.get('request_id'),
                    'candidate': m.get('candidate'),
                    'from': m.get('from')
                }
                ok = unicast(room_id, target, payload)
                LOG("rtc/ice", "room=", room_id, "req=", m.get('request_id'), "to=", target, "ok=", ok)
                continue

    except Exception as e:
        LOG("WS error", str(e))
    finally:
        # Full cleanup of this socket from all structures
        for rid in list(SUBSCRIPTIONS.get(ws, set())):
            try:
                ROOM_CONNECTIONS.get(rid, set()).discard(ws)
                peers = ROOM_PEERS.get(rid, {})
                for k, v in list(peers.items()):
                    if v is ws:
                        peers.pop(k, None)
            except Exception:
                pass
        SUBSCRIPTIONS.pop(ws, None)
        # remove pending challenges for this ws
        for key in [k for k in PENDING_CHALLENGES.keys() if k[0] is ws]:
            PENDING_CHALLENGES.pop(key, None)
        LOG("WS close", "ip=", ip)
        try:
            ws.close()
        except Exception:
            pass

# ---------- utils ----------
def _b64u(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode('utf-8').rstrip('=')

def _from_b64u(s: str) -> bytes:
    import base64
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode('utf-8'))

if __name__ == "__main__":
    # For local testing; on PythonAnywhere you’ll use WSGI
    app.run(host="0.0.0.0", port=5000, debug=True)
