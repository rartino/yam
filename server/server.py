import os
import json
import time
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sock import Sock
from simple_websocket import Server

DB_PATH = os.environ.get("WS_DB_PATH", "messages.db")

app = Flask(__name__)
APP = app
CORS(
    app,
    resources={
        r"/ws": {"origins": ["https://rickard.armiento.se"]},
        r"/health": {"origins": ["https://rickard.armiento.se"]},
        r"/rooms": {"origins": ["https://rickard.armiento.se"]},
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

# ---------- WebSocket (no room in URL; subscribe per room) ----------
@sock.route('/ws')
def ws_handler(ws: Server):
    # Per-connection bookkeeping
    SUBSCRIPTIONS[ws] = set()
    LOG("WS open")

    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break
            try:
                m = json.loads(raw)
            except Exception:
                continue

            t = m.get('type')
            if not t:
                continue

            # ---------- Ping/Pong ----------
            if t == 'ping':
                ws.send(json.dumps({'type': 'pong', 'ts': int(time.time() * 1000)}))
                continue

            # ---------- Subscribe to a room (starts challenge) ----------
            if t == 'subscribe':
                room_id = m.get('room_id')
                if not room_id:
                    continue
                # mark desired subscription; auth not granted yet
                SUBSCRIPTIONS[ws].add(room_id)
                # challenge
                nonce = os.urandom(32)
                PENDING_CHALLENGES[(ws, room_id)] = nonce
                LOG("challenge", "room=", room_id)
                ws.send(json.dumps({
                    'type': 'challenge',
                    'room_id': room_id,
                    'nonce': _b64u(nonce)
                }))
                continue

            # ---------- Auth for a room (response to challenge) ----------
            if t == 'auth':
                room_id = m.get('room_id')
                signature_b64 = m.get('signature')
                if not room_id or not signature_b64:
                    continue
                nonce = PENDING_CHALLENGES.pop((ws, room_id), None)
                if nonce is None:
                    ws.send(json.dumps({'type': 'error', 'error': 'no challenge', 'room_id': room_id}))
                    continue
                try:
                    import nacl.signing, nacl.encoding, nacl.exceptions
                    # Decode unpadded base64url -> raw 32-byte public key
                    pk_bytes = _from_b64u(room_id)
                    verify_key = nacl.signing.VerifyKey(pk_bytes, encoder=nacl.encoding.RawEncoder)

                    sig = _from_b64u(signature_b64)
                    verify_key.verify(nonce, sig)  # message=nonce, signature=sig

                    ROOM_CONNECTIONS.setdefault(room_id, set()).add(ws)
                    ROOM_PEERS.setdefault(room_id, {})
                    LOG("auth ok", "room=", room_id, "conns=", len(ROOM_CONNECTIONS[room_id]))
                    ws.send(json.dumps({'type': 'ready', 'room_id': room_id}))
                except Exception as e:
                    LOG("auth fail", "room=", room_id, "err=", repr(e))
                    ws.send(json.dumps({'type': 'error', 'error': 'auth failed', 'room_id': room_id}))
                continue

            # ---------- Announce peer (per room) ----------
            if t == 'announce':
                room_id = m.get('room_id')
                pid = m.get('peer_id')
                if room_id and isinstance(pid, str) and pid:
                    ROOM_PEERS.setdefault(room_id, {})[pid] = ws
                    LOG("announce", "room=", room_id, "peer=", pid[:6] + "…")
                continue

            # ---------- History ----------
            if t == 'history':
                room_id = m.get('room_id')
                since = int(m.get('since', 0))
                if not room_id:
                    continue
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT ts,nickname,sender_id,sig,ciphertext FROM messages WHERE room_id=? AND ts>=? ORDER BY ts ASC",
                            (room_id, since))
                rows = cur.fetchall()
                items = [{
                    'type':'message', 'room_id': room_id,
                    'ts': r['ts'], 'nickname': r['nickname'],
                    'sender_id': r['sender_id'], 'sig': r['sig'],
                    'ciphertext': r['ciphertext']
                } for r in rows]
                conn.close()
                LOG("history", "room=", room_id, "count=", len(items))
                ws.send(json.dumps({'type': 'history', 'room_id': room_id, 'messages': items}))
                continue

            # ---------- Send message (store + broadcast) ----------
            if t == 'send':
                room_id = m.get('room_id')
                ciphertext = m.get('ciphertext')
                ts = int(m.get('ts_client', time.time()*1000))
                nickname = m.get('nickname')
                sender_id = m.get('sender_id')
                sig = m.get('sig')
                if not room_id or not ciphertext:
                    continue
                # store
                conn = get_db()
                cur = conn.cursor()
                cur.execute("INSERT INTO messages (room_id, ts, nickname, sender_id, sig, ciphertext) VALUES (?,?,?,?,?,?)",
                            (room_id, ts, nickname, sender_id, sig, ciphertext))
                conn.commit()
                conn.close()
                # broadcast (echo to sender as well)
                payload = {
                    'type':'message', 'room_id': room_id,
                    'ts': ts, 'nickname': nickname,
                    'sender_id': sender_id, 'sig': sig,
                    'ciphertext': ciphertext
                }
                fanout = broadcast(room_id, payload)
                LOG("send", "room=", room_id, "bytes=", len(ciphertext), "fanout=", fanout)
                continue

            # ---------- WebRTC signaling (must include room_id) ----------
            if t == 'webrtc-request':
                room_id = m.get('room_id')
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
                room_id = m.get('room_id')
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
                room_id = m.get('room_id')
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
        # cleanup this socket from all rooms
        for rid in list(SUBSCRIPTIONS.get(ws, set())):
            ROOM_CONNECTIONS.get(rid, set()).discard(ws)
            peers = ROOM_PEERS.get(rid, {})
            for k, v in list(peers.items()):
                if v is ws:
                    peers.pop(k, None)
        SUBSCRIPTIONS.pop(ws, None)
        # remove challenges
        for k in list(PENDING_CHALLENGES.keys()):
            if k[0] is ws:
                PENDING_CHALLENGES.pop(k, None)
        LOG("WS close")
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
