# Homegames — Architecture

Implementation paths checked on October 20, 2026. See [SYSTEM.md](SYSTEM.md) for the product map and [INFRA.md](INFRA.md) for deployment dependencies.

## Studio and portable games

`homegamesio/studio.html` loads the existing editor plus `studio-portable.js` and `studio-project-store.js`. `/studio-local.html` redirects to this integrated editor. New game fetches a static template catalog and content-hashed ZIP; Import ZIP validates a portable project. Every template copy gets a fresh game UUID, and every import gets a fresh local installation ID.

The project store owns IndexedDB drafts and snapshots. Explicit Save writes the project and a History snapshot together. Drafts may contain syntax errors; play/export validate separately. Writes compare generations inside a transaction, so stale tabs cannot silently overwrite another tab's edits. Studio loads a selected snapshot into the editor; Save records that restored version. Full workspace backup includes history, media, preview data and unsaved working edits.

Studio's account, profile, publishing, remote asset and hosted AI branches have been removed. The active API entry point does not register those routes. Old `?game=` links do not migrate hosted projects; retained legacy source and database records are not a migration service.

Common's portable modules split responsibilities:

- `portable-project.js`: validates paths, manifest/runtime agreement, relative JS/JSON imports, statically resolved metadata and authored media; ZIP import also verifies the generated inventory. Reading/importing does not execute source.
- `portable-project-node.js`: filesystem/CLI adapter.
- `portable-runtime.js`: project-scoped source/media loader, requiring explicit trust. It is not itself an execution boundary.
- `portable-html.js`: Studio and exported HTML run the game in an opaque-origin iframe (`allow-scripts allow-pointer-lock`) with a restrictive content policy. The parent retains project storage.
- `portable-saves.js`: the parent exposes only installation-bound game-progress operations through a MessagePort, stores acknowledged writes in IndexedDB, and supports JSON save backups.

The iframe separates game code from editor DOM/storage; it does not limit CPU/memory. ZIP integrity checks establish consistency, not author identity or code safety.

`homegames-client/src/rtc-copy.js` sends independent game copies through a separate private room. The acknowledged archive protocol in `rtc-copy-protocol.js` validates SHA-256 and the portable inventory before persistence. The API carries connection signals, not game files.

The generic `homegamesio/game-app.html` receiver stores a verified ZIP plus a reference to a cached runtime shared across games. It builds an isolated player for execution and standalone HTML on download. Older cached HTML copies remain readable and can migrate without changing their installation/save identity. The scoped service worker caches the player shell; game packs, runtime versions and per-game manifests are retained separately from shell updates.

Each receipt/import gets a fresh local installation UUID. Catalog links use the same receiver with a UUID, revision and `builtin` slug, preserving the `builtin-<gameId>` progress identity. A fresh Home Screen app downloads the pinned catalog ZIP on its first online launch. Peer invitations retain their fragment for receipt inside a new app; Safari and installed iOS apps have separate storage. No game registration or upload is needed. Studio remains the authoring editor.

## Browser runtime and multiplayer

`homegames-client/src/local-session.js` instantiates one game, owns player lifecycle and uses the shared dispatcher/runtime. Rendering, input, media and LocalSession are bundled into `dist/homegames-client.js`. The browser Squish map is static for webpack and supports 150 (Squish 1.5.0) and 151 (1.5.1). New projects use 151; existing 150 projects keep their declared runtime.

The browser host runs the authoritative game; RTC guests receive scenes/media and send input. Joining does not automatically install a project, but joined players can request a copy when the host provides project export. RTC transport workers handle communication queues; the simulation/rendering still depends on the host tab. Manual offer/answer pairing can operate without Homegames signaling, but the manual UI does not supply TURN or live microphone/camera transport.

Common's `rtc-signaling.js` attaches `/rtc` WebSocket upgrades and `GET /rooms` discovery to a Node HTTP server. `api/index.js` enables it by default; `RTC_ENABLED=false` disables it. The active API supplies no catalog resolver, so it cannot create catalog-backed public rooms. The generated website no longer uses that path or the public room feed. Website, Studio and portable HTML use private invitations. Rooms, capabilities and leases are in memory. Signaling never runs game code or transports gameplay frames. Current automatic host/guest clients nevertheless close peers when the signaling connection ends; use the separate manual-pairing path when avoiding that dependency. Automatic rooms cap capacity at 17 including the host.

## Scenes and recipient filtering

Squish provides Game/GameNode, shapes/text/assets, serialization and versioned behavior. Squish 1.5.1's `Squisher` owns its tick timer, subscriptions and recipient filtering. Common's `session-runtime.js` supplies the game's declared codec through the explicit `encodeNode`/`decodeNode` options and closes the Squisher at session end. Traversal records each node's inherited audience while serializing the combined host tree. Ordered audience ranges let recipient frames select the encoded records without repeatedly walking the scene. Common packs those records into an exact-size byte buffer. Every ancestor scope is applied; empty `playerIds` inherits the ancestor audience. Both Node/WebSocket and LocalSession/RTC use this filter, including spectators and players without explicitly scoped nodes.

A private child cannot become public under a private ancestor. `[0]` excludes live players but still costs host serialization work. Detach unused scene nodes. Scopes govern scene visibility, not input permissions or privacy of room-wide media bytes. Games must validate actions and keep unrevealed simulation data out of the render tree.

`game-dispatch.js` handles shared input; `media-upload.js`, `media-session.js` and `cursor.js` support session media and cursor state. `local-game-assets.js` binds filesystem assets on the Node loader path; portable assets resolve through the project reader.

## Home server and Node sessions

`homegames/index.js` supervises Core. `homegames-core/index.js` starts Core promptly and handles discovery/certificates in the background. `game_server.js` normally creates the dashboard, shared GameSessionManager and Homenames. The dashboard offers browser play and household room discovery, with Node/WebSocket hosting as a separate path.

With `START_PATH`, direct-start games default to `START_MODE: "browser"`; Core serves source/assets to a host tab on `HOME_PORT`. `START_MODE: "server"` selects Node/WebSocket execution. The localhost dashboard’s `/library/import` endpoint validates portable ZIPs before installing immutable revisions under app data. The library reads their manifests without executing source; Node sessions load the selected entry when launched. The default dashboard catalog adapter scans local folders. Bundles use local `/rtc` signaling without STUN/TURN; `--offline` overrides saved HTTPS/discovery preferences for that run.

`GameSessionManager` allocates child-session ports and prefers Docker. If Docker is unavailable it forks only when `allowFork` or `FORK_SESSIONS_ENABLED` permits it. `docker-helper.js` supplies resource-limited live containers and a separate no-network publish-validation sandbox. Core provides the child entry point and runner image. Homenames remains a management service with a separate port, not the website's browser-game transport.

## Connection API

`api/index.js` loads `connection-api.js`, `connection-service.js` and RTC signaling. Health/IP and certificate operations are the active HTTP surface; account, content, hosted project, publishing and docs-AI routes return 404. Certificate storage/jobs use MongoDB lazily; signaling can start without MongoDB, JWT secrets, Forgejo or the old router.

The API runs its own certificate queue and ACME/DNS issuer. It does not use RabbitMQ or the sibling `worker` for current issuance. Legacy API handlers and publish workers remain on disk for historical data/tooling, but the new entry point does not load or expose them. Deploy the new entry point and stop obsolete worker services separately; this source change does not erase hosted data.

## Website delivery

`homegamesio/scripts/build-site.js` reads game directories and explicit paths from `site.config.json` or CLI flags, validates/packages source folders or portable ZIPs, and generates the whole site under `web/`. Home/catalog/game-page content is ordinary HTML with real links; search is progressive enhancement. `play.js` loads a static pack and the built runtime into an opaque-origin iframe with the portable save bridge. Public-room registration is not used.

`app.js` serves the generated build (plus separately configured server-download artifacts), so local previews match publication. The authoring guide, policy pages, Studio templates, game packs and hashed client runtime are included. `prepare-rtc-site.js` stages the same build at an alternate destination; `deploy.sh` uploads the full output and removes known retired page objects without deleting release-download history. Backend shutdown is separate work.

## Game-defined user exports

Both Node GameSession and browser LocalSession inject `createExport(name, bytes)` and a constructor-time `userExports` map. A game chooses a single filename and `Uint8Array` contents; the session owns the storage location. Same-name writes replace that export. Games choose formats: JSON line coordinates, WAV, arbitrary binary, or several independent files.

```js
constructor({ createExport, userExports = {} }) {
    super();
    this.createExport = createExport;
    this.design = userExports['monster.json']
        ? JSON.parse(new TextDecoder().decode(userExports['monster.json']))
        : defaultDesign;
}
// Called by the game's own save action:
await this.createExport('monster.json', new TextEncoder().encode(JSON.stringify(this.design)));
```

`user-exports.js` validates names and bytes, clones inputs, serializes writes and exposes acknowledged snapshots. Paths, directory separators, reserved filenames and case collisions are rejected. Limits are 128 files, 16 MiB each, 64 MiB total. `userExports` is an initial snapshot, not a filesystem handle; mutating it does not persist a change. Games must handle rejected writes and validate their own input formats.

`user-exports-node.js` writes raw files atomically beneath the game folder's `user-exports/`. A user can edit those files and restart the game to load the new bytes. Browser hosts store overrides in installation/game/revision-scoped IndexedDB through an explicit player adapter. Exported HTML is not rewritten in place: download a new copy to keep those changes outside browser storage.

GameSession's normal project-transfer capability waits for pending writes and packages the source plus `user-exports/`. ZIPs and RTC copies contain ordinary files; HTML embeds the ZIP as base64. The game's original JavaScript and bundled default assets remain unchanged. Export files are treated as data even with a `.js` suffix and cannot be imported as source modules. The host never calls a game-specific export hook. Ordinary Studio source exports use its editor files; preview player downloads include changes saved during play, which can be imported into Studio.

The same protocol supports `kind: 'export-list'` (name/size metadata) and `kind: 'export'` (one named file), independent of access to game source. File transfers use acknowledged 64 KiB chunks with a 16 MiB file cap, membership checks, timeouts and cancellation. A failed write does not appear in the list; existing acknowledged files remain readable. The browser client's shared **View exports** dialog uses these operations for local, RTC and WebSocket sessions. Previews never execute text/HTML/SVG as documents. Isolated players ask the explicit parent adapter to show the same viewer; the parent owns the user-initiated download. There is no game-specific DOM or browser-storage interface. Exports are room-wide data, not private player assets.

Squish still carries scene state. User exports belong to the session, independently of any renderer or browser. Recording requests use the existing session media protocol; a capable client owns device access and consent. `attachSaveHost` handles progress only; `attachPlayerHost` explicitly combines progress, user exports, recording and player downloads for a browser embedding.
