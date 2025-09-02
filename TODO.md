* Turn server into supporting STUN/TURN: https://stackoverflow.com/questions/22233980/implementing-our-own-stun-turn-server-for-webrtc-application
* Room management

  - Clients keeps track of a room list in internel storage. Rooms are identified by a name and a "Room URL" wich is a server https URL plus "?room=${encodeURIComponent(currentRoomId)}".
  - The currently open room name is shown at center top, which is also a dropdown menu to show the list of all known rooms, and chosing one opens that room. At the bottom are the options "Add room..." and "Create room...".
  - "Add room..." opens an "Add room" dialog that only asks for a Room URL and a "Room name", and shows a "Connect" button.
    The "Connect" button adds the room to the room list with the chosen name, and opens the room.
  - "Create..." opens a "Create new room" dialog which asks for a server URL, a "Room name", and shows a "Create room" button.
    Upon clicking "Create room" a new unique room code is created (now shown) and the room is opened in the client (the server doesn't really need "creation" of a room, the client just connects to the empty room).
  - The server is extended so that if someone opens a room URL in the browser, it forwards the user to an app URL (configured in server.py) plus a http GET parameter with the room URL and an optional parameter with a room name, e.g., "?room=...&name=Example".
    The app handles this by opening up the "Add room..." dialog with the provided room URL pre-filled in "Room URL" and name (if provided) in "Name", the user only has to click "Connect".
    This way it gets very easy to invite someone to a room: just send them that room URL.
  - Cog menu top right remains and shows a "Configure room" dialog where one can change "Room name" and also a red "Remove room" button to remove it from the list of rooms.
    It also displays the full room URL, including the name argument that matches what the user currently has set as Room name.

* Update messages in the background: https://learn.microsoft.com/en-us/microsoft-edge/progressive-web-apps/how-to/background-syncs
 
* Push notifications: https://learn.microsoft.com/en-us/microsoft-edge/progressive-web-apps/how-to/push
  https://www.reddit.com/r/PWA/comments/1jmluey/how_are_push_notifications_created_and_handled_in/

* Stickers library. Just a folder "stickers" that contains a set of folders for different categories, these folders conain image files + tiny preview images.
  There has to be a stickers index at top level stickers/index.json.
  Set up a bash script to create preview images from all images that do not already have them, and also (re)creates the index.json.

* User profiles:

  - Add a three bars menu to the left of the logo + "Yam" name, to open a "Profile" dialog where the user can set their username and a bubble color.
  - When opening a session by connecting to the server, the client transmits their name + profile info (color) to the server.
    The server checks if the client ID is new, or the profile info has changed, and in that case updates its internal storage AND sends out a message about "profile update" for this client ID to all connected clients.
  - Each client keeps track of the profile info of all other client IDs it has seen this session (i.e., starting empty each reconnect).
  - Upon receiving a message (live or from history) with a client ID it hasn't seen this session, it requests that client's profile data from the server. It adapts all speech bubble color to what it receives.
  - If a "profile update" message comes from the server (for a client ID that isn't its own), it runs the same code to update the client's profile.

* Allow configuration of an avatar photo in the "Profile" dialog.

  - The profile data contains the same kind of metadata packages as when images are transmitted in the chat.
  - A client that misses the avatar image in its internal storage requests it the same way as for other images (i.e., an RTC request)

* Download further history from other clients

  - Use the webrtc channel feature to request history from other clients.
  - At the top of history, there is a button "Request history from others", clicking this sends out a request for an RTC handshake to download history from others.

* Direct messaging

  - Set up some handling around rooms and client IDs so that it is obvious how to set up a 1-to-1 DM room between two users.
    When receiving such a message, the client sets up a DM room in the room list.

* Better security around invite URLs.

  - Alter the handling of Room URLs so that an invite to a room instead refences the DM room plus the public key of the invite room.
    When the Room URL is visited in the browser, the server handles an RTC handshake between the inviter and the invitee, and the proper secret key is transmitted of that channel.

* Rethink security

  - Should perhaps all client know all other clients public keys and encrypt the messages for all of them; to avoid the major sensitivity of room keys.

Other links:

- https://learn.microsoft.com/en-us/microsoft-edge/progressive-web-apps/
