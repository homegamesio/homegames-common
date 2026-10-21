# Homegames end-to-end flows

Checked against source on October 20, 2026.

## Create, edit and save in Studio

1. `/studio.html` loads the editor without an account. New game reads a static template ZIP; importing a game validates its source, media and inventory without executing it.
2. A template copy receives a new game UUID and local installation ID. An ordinary import preserves its game UUID and receives a new local installation ID.
3. Edits stay in memory until **Save** or Cmd/Ctrl+S. Save writes the project and a History snapshot in one IndexedDB transaction. Unfinished source can be saved.
4. History can display a snapshot without discarding the working copy. **Restore** brings it into the editor; Save records the restored version.
5. Generation and workspace checks reject conflicting writes from other tabs. Full Studio backup includes saved projects/history, media, preview data and unsaved working edits; single-game exports do not include the whole workspace.

Sources: `homegamesio/studio-portable.js`, `studio-project-store.js`, `studio-workspace.js`.

## Preview, invite and export

1. Play validates the project and starts a LocalSession in an opaque-origin iframe. The trusted parent owns storage and connects progress, exports and player controls through explicit MessagePorts.
2. The host runs the simulation. Open the **Homegames menu** for a multiplayer invitation link or QR code. Guests receive filtered scenes and media and send input to the host.
3. Joining does not automatically install the project. Joined players can request a game copy when the host provides project export; a play invitation is not a source-access restriction.
4. **Share with friends** in the player menu sends an independent copy through a separate private RTC room. Studio's export controls also offer editable copy sharing.
5. ZIP exports contain source/media and a generated inventory. Playable HTML embeds the project and runtime. Each new HTML export has a fresh installation ID. Game-generated user exports can accompany player downloads; ordinary progress and Studio history are separate.
6. Download save / Load save transfers compatible progress JSON. `saveGame` acknowledges a committed storage write, not merely a request to save.

Closing the host or stopping the preview ends its session. Automatic RTC also closes peers when signaling disconnects. Manual offer/answer pairing can bypass Homegames signaling when the network allows it; the manual UI has optional STUN but no TURN configuration or live microphone/camera streams.

Sources: Common `portable-html.js`, `portable-saves.js`, `project-transfer.js`; Client `src/local-session.js`, `src/rtc-session.js`, `src/rtc-manual.js`.

## Receive an independent copy

1. A copy invitation opens `/game-app.html?game=<uuid>&revision=<hash>#copy=…`. The recipient chooses **Receive game**.
2. The sender transfers the ZIP in acknowledged 64 KiB chunks. Signaling carries connection details, not the game archive. Configured TURN may relay the encrypted peer traffic.
3. The receiver checks SHA-256, inventory and game identity without executing source. It stores the verified ZIP and a reference to a shared, cached player runtime. Older stored HTML copies remain readable for migration.
4. Play starts an opaque iframe. Download builds a self-contained HTML file; ZIP download provides the editable project. A completed copy remains usable after the sender closes.
5. The app's local manifest identifies its UUID/revision. On iOS, receive or import inside the installed app: Safari and Home Screen app storage are separate. The initial app URL retains the copy invitation.

Keep file and progress backups against browser storage loss. A raw HTML file in iOS Files is not itself an installed web app.

Sources: Client `src/rtc-copy.js`, `src/rtc-copy-protocol.js`; website `game-app.js`, `game-app-storage.js`, `game-app-sw.js`.

## Play a catalog game

1. The website build selects game folders/ZIPs and generates static catalog pages, metadata and versioned packs.
2. Play opens `/game-app.html?game=<uuid>&revision=<hash>&builtin=<slug>`, validates the pinned ZIP and caches it with the player runtime.
3. **Ready offline** confirms local storage. Subsequent launches use the saved copy. A fresh Home Screen installation downloads the selected pack on its first online launch.
4. Progress uses `builtin-<gameId>` and the game's save schema. A source revision does not automatically reset it. Installed games retain their selected revision.
5. The Homegames menu creates private invitations. There is no public room feed or catalog database in this flow. **Edit this game** creates a separate Studio project with a new game UUID.

Sources: `homegamesio/scripts/build-game-library.js`, `scripts/render-game-pages.js`, `game-app.js`.

## Home server

The launcher starts Core, which serves the dashboard and browser client. The local library finds built-in/installed games; localhost Import ZIP validates and installs portable archives. Browser Play runs the game in a tab and uses the household room registry. The separate Node/WebSocket action starts a Docker session, or a child process if the host has explicitly allowed running without Docker. Clients connect to its allocated port.

With `START_PATH`, Core defaults to browser-hosted direct play; `START_MODE: "server"` selects Node execution. Optional homegames.link discovery redirects visitors on the LAN; it is not a tunnel into that network.

Sources: `homegames-core/game_server.js`, `src/library/`, `src/util/browser-game-server.js`; Common `game-session-manager.js`.

## Certificates and legacy services

The connection API validates a CSR for the caller's assigned network domain, stores the job in MongoDB and processes it with its own certificate runner. The client polls `/cert-status`. RTC signaling and certificate requests require no Homegames account or game registration.

The current API does not register account, publishing, remote asset or docs-assistant routes. Retained source and historical data remain separate; they are not automatically migrated or erased. See [legacy-hosted-publishing.md](legacy-hosted-publishing.md) for the former workflow.
