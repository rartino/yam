# YAM: yet another messenger [WIP]

A PWA app for a very no-nonsense messaging app with the expected featureset to be useful (users, rooms, stickers), with a simple workflow to invite new users.

## How to run

1. **Server**

```bash
cd server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Server listens on `http://localhost:8080` and exposes `ws://localhost:8080/ws`.

2. **Client**

* Serve the `client/` folder over HTTP(S) (any static server). Example with Python:

```bash
cd client
python -m http.server 8000
```

Open `http://localhost:8000` in your browser. (For production, put behind HTTPS so PWA install + service worker works everywhere.)

3. **Flow**

* Visit the client static web pages in your browser.
* Create a new room in the popup dialog.
* Open the cog icon top right, and send the room URL to people you want to invite (note that the URL is security sensitive: use a trusted channel).
