* Turn server into supporting STUN/TURN: https://stackoverflow.com/questions/22233980/implementing-our-own-stun-turn-server-for-webrtc-application
* Relay the WebRTC handshake via the server to cut down on the length of the invitation code.

  - Upon clicking 'Invite', the inviter's client contacts the server and deposits an "invite" which is a short invitation secret (say, 16 bytes) plus the WebRTC offer.
    The server stores this information along with the inviters ID.
  - The inviter creates an invitation code which is a base64 encoded gziped json of the server URL and the invitation secret, and the user sends this to the invitee over another channel.
  - When the invitee pastes this code into the invitation text field and clicks "Accept", the client contacts the server, and requests 'invitation-request' the invite matching the invitation secret.
  - The client automatically (in the background) generates the WebRTC response code and sends to the server as an 'initation-response'.
  - The server relays the response back to the inviting client.
  - The inviter finishes the WebRTC handshake and the process continues as before.
  
* Update messages in the background: https://learn.microsoft.com/en-us/microsoft-edge/progressive-web-apps/how-to/background-syncs
 
* Push notifications: https://learn.microsoft.com/en-us/microsoft-edge/progressive-web-apps/how-to/push
  https://www.reddit.com/r/PWA/comments/1jmluey/how_are_push_notifications_created_and_handled_in/

* Reactions: single unicode characters attached below the bubbles. Clicking on an existing reaction increments the reaction count. Long-clicking a message allows setting a new reaction.

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

* Somehow handle (too?) large files
