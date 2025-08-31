import json
import os
import sqlite3
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from flask import Flask, request, jsonify, send_from_directory
from flask_sock import Sock
from flask_cors import CORS
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from nacl import utils

APP = Flask(__name__, static_folder=None)
app = APP
SOCK = Sock(APP)
CORS(APP, resources={r"/rooms": {"origins": ["https://rickard.armiento.se/wsmessenger"]}})
DB_PATH = os.path.join(os.path.dirname(__file__), 'messages.db')

# --- Database helpers ---

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.row_factory = sqlite3.Row
    return conn

CONN = db()

CONN.execute(
    """
    CREATE TABLE IF NOT EXISTS rooms (
        room_id TEXT PRIMARY KEY,
        ed25519_public_key BLOB NOT NULL,
        created_at INTEGER NOT NULL
    )
    """
)
CONN.execute(
    """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        nickname TEXT,
        ciphertext BLOB NOT NULL
    )
    """
)
CONN.commit()

# In-memory connection registry: room_id -> set(websocket)
ROOM_CONNECTIONS = {}

# --- HTTP endpoints ---

@APP.get('/health')
def health():
    return {"ok": True, "time": int(time.time() * 1000)}

@APP.post('/rooms')
def create_room():
    data = request.get_json(force=True)
    room_id = data.get('room_id')
    pub_b64u = data.get('ed25519_public_key_b64u')
    if not room_id or not pub_b64u:
        return jsonify({"error": "room_id and ed25519_public_key_b64u required"}), 400
    try:
        # They are the same here: room_id = base64url(pubkey)
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
    # Helpful message if someone opens server root directly
    return '<h3>Secure Messenger Relay</h3><p>Use the PWA client to connect.</p>'

# --- WebSocket relay ---

@SOCK.route('/ws')
def ws_handler(ws):
    # Parse room id from query
    environ = ws.environ
    query = environ.get('QUERY_STRING', '')
    qs = parse_qs(query)
    room_id = (qs.get('room') or [None])[0]
    if not room_id:
        ws.send(json.dumps({"type": "error", "error": "room parameter required"}))
        ws.close()
        return

    # Lookup stored public key
    APP.run(host='0.0.0.0', port=port, debug=True)
