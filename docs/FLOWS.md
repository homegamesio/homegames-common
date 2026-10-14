> Website flow update, October 12: build-selected folders/ZIPs supply the static HTML collection and game packs. Website Play uses isolated portable execution and private RTC invitations. Legacy catalog/public-room source is not registered by the active API; see the [website README](../../homegamesio/README.md).

# Homegames — End-to-end flows

These traces follow current code, reviewed October 11, 2026. The active entry point no longer exposes account-backed paths.

## 1. Create, edit and save a browser project

1. `/studio.html` loads the editor and portable integration. No login is requested.
2. **New game** fetches `/studio-templates.json` and the selected static ZIP. **Import ZIP** reads a supplied archive. Common validates source/manifest/media/inventory as data.
3. Studio writes the project to `homegames-studio-projects` IndexedDB under a fresh installation ID. Editing source or adding media auto-saves drafts, including unfinished code.
4. A generation check catches concurrent-tab writes. Failed or quota-blocked writes stay visibly unsaved; the user can keep a copy or reload the saved version.
5. **Versions → Save snapshot** stores a named copy of source/media. Open snapshot is read-only; Restore snapshot backs up the draft and restores the selected files/name atomically. Progress is separate.

Source: `homegamesio/studio-portable.js`, `studio-project-store.js`, common `portable-project.js`.

## 2. Play, share and export a project

1. Play validates the selected files and embeds the project/runtime in an opaque-origin iframe.
2. The parent attaches an installation/schema-scoped progress channel. The iframe loads the game and runs one LocalSession.
3. **Share** creates a private RTC invitation; guests render their filtered view and send input to this same game. The game source is not transferred as an editable project.
4. **Manual connection** exchanges offer/answer text without Homegames signaling. Each peer needs a loaded/downloaded player. STUN is optional; some networks need TURN, which the manual UI does not configure.
5. **Export ZIP** packages the selected source/media with an integrity inventory. **Download HTML** bundles a runnable copy and gives that export a fresh installation ID. Neither includes snapshot history or existing game progress.
6. **Download save / Load save** moves compatible JSON progress independently. `saveGame` resolves after the parent's IndexedDB transaction commits.

Stopping/restarting the preview or closing its host ends that game. The catalog needs a network load; Studio caches its editor/player/templates/examples/guide for offline use. A downloaded HTML supports offline local play. Manual mode supports scene/media-file/input transport, not live camera/microphone streams.

Source: common `portable-html.js`, `portable-saves.js`, client `src/rtc-manual.js` and `src/local-session.js`.

### Send an independent copy and keep it offline

1. Studio or a newly exported playable HTML offers **Share a copy**, creating a private signaling room separate from live multiplayer.
2. The invitation opens `/game-app.html?game=<uuid>&revision=<hash>#copy=…`. RTC sends an offer until the recipient accepts. The portable ZIP then travels in acknowledged 64 KiB chunks; the API carries SDP/ICE, never game files. TURN may relay encrypted transport.
3. The receiver validates the hash, inventory, UUID and revision without executing source, then builds a standalone HTML with the static site's trusted runtime. **Download game HTML** saves the file; **Download project ZIP** permits explicit import into Studio. Local persistence failure leaves the completed HTML downloadable.
4. **Play** starts an opaque iframe with installation-scoped saves. Saved app URLs launch directly on subsequent visits; the player shell and complete game HTML are kept locally for offline use. A downloaded HTML also plays directly in a desktop browser and can share onward after its original sender closes.
5. For iOS/iPadOS, use Safari's Add to Home Screen on the game's receiving page, open that game icon, then receive or import inside the app. Safari storage does not populate app storage. The locally generated manifest retains the private invitation fragment for first launch. No game registration/upload is required: the host serves the same generic page for every game.
6. Keep HTML/progress backups against browser storage clearing or eviction. A raw downloaded HTML in iOS Files is not itself an installable PWA. Physical Add to Home Screen verification remains a release check.

Source: client `src/rtc-copy.js`, `src/rtc-copy-protocol.js`; common `portable-html.js`; website `game-app.js`, `game-app-storage.js`, `game-app-sw.js`, `scripts/build-game-app.js`. Receipts/imports get fresh local save identities; progress migration is explicit. Existing old HTML exports retain their embedded runtime until re-exported.

## 3. Play an existing catalog game

1. `client.js` fetches game metadata, published versions and a local-play manifest from the API.
2. An eligible Play action opens `/play.html?localGame=…&ref=…`. The player loads source/assets and starts a browser LocalSession; it does not call the old Node session-create path.
3. Website games use private RTC rooms. Share reuses the room; invitations carry a capability.
4. Homepage/catalog/game discovery reads `GET /rooms`. Only live public catalog rooms are listed; stale catalog host leases expire after 90 seconds without updates.
5. Guests join the browser host. A newer published version does not change a running host or a previously downloaded HTML.

Catalog downloads still use the API's catalog HTML builder and retained catalog save identity. They are distinct from Studio portable exports. Games requiring `contentGenerator` cannot use browser play/download.

Source: `homegamesio/client.js`, `play.html`, `api/handlers.js`, common `rtc-signaling.js`, `local-play.js`.

## 4. Home server play

1. The launcher starts Core; Core serves the dashboard and browser client on `HOME_PORT`.
2. The dashboard loads built-in/installed games and can download catalog games. Browser Play hosts a LocalSession in the tab and advertises household rooms through the home's room registry.
3. The separate Node/WebSocket hosting action asks the shared session manager for a child port. Docker is preferred; an explicit fork opt-in permits a child process if Docker is unavailable.
4. WebSocket clients connect directly to that child. Input and recipient filtering use the shared runtime.
5. Optional homegames.link discovery redirects LAN visitors to the local server. Certificates are acquired through API/worker services; discovery is not an internet tunnel.

With `START_PATH`, Core defaults to serving a browser-hosted direct-start game instead of the dashboard; `START_MODE: "server"` selects the Node path.

Source: `homegames-core/game_server.js`, `src/dashboard/`, `src/util/browser-game-server.js`, `src/util/household-rooms.js`, common `game-session-manager.js`.

## 5. User exports and game copies

The game calls `createExport(name, bytes)`. The session persists raw bytes and makes them available through `userExports` on the next launch. Node stores these in the game's `user-exports/` directory; browser hosts persist them locally. Download/share packages these files alongside unchanged source and default assets. See [the contract](ARCHITECTURE.md#game-defined-user-exports).

## 6. Certificates and retired services

The API validates the caller's CSR for its assigned network domain and queues a certificate job. The worker performs issuance; the client polls `/cert-status`. RTC signaling is enabled unless explicitly disabled. Neither connection flow requires a Homegames account or central game registration.

Account, publishing, remote asset and docs-AI handlers are retained source, not active routes. Existing hosted records are not erased or imported automatically.
