# wsmessenger
Simple client-server messaging PWA app

## How to run

1. **Server**

```bash
cd server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Server listens on `http://localhost:5000` and exposes `ws://localhost:5000/ws`.

2. **Client**

* Serve the `client/` folder over HTTP(S) (any static server). Example with Python:

```bash
cd client
python -m http.server 8000
```

Open `http://localhost:8000` in your browser. (For production, put behind HTTPS so PWA install + service worker works everywhere.)

3. **Flow**

* Click **Create Room** → copy **Room ID** (public key, base64url) and **Private key** (keep secret!)
* Server receives only the **public key** via `POST /rooms`.
* On another client, paste Room ID + Private key → **Join**. The client signs the server’s challenge to authenticate.
* Messages are **sealed** to the room’s public key. The server stores only ciphertext in SQLite and can’t decrypt. On join, the client requests the last **7 days**.
