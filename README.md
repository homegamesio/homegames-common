# homegames-common

Shared Homegames runtime, portable-project tooling, configuration and authoring reference. Node consumers use `index.js`; browser consumers import individual browser-compatible modules through `homegames-client`. There is no build step in this package.

This documentation describes the current working-tree implementation, reviewed October 17, 2026. It does not establish what is deployed. Start with [SYSTEM.md](docs/SYSTEM.md) for the platform map.

## Current product paths

Studio in `homegamesio` creates account-free browser projects. Source, media and snapshots live in IndexedDB; projects export as ZIPs and playable HTML. Games run in a browser host and can invite RTC guests. Studio uses local projects only. The active API exposes connection helpers; legacy account/content source remains on disk but is not registered by its entry point.

**Share a copy** in Studio and new portable HTML exports sends the project ZIP over a separate private RTC connection. `homegames-client/src/rtc-copy*.js` handles consent, bounded transfer and integrity validation; signaling carries no archive payloads. The generic `/game-app.html` receiver builds and saves a self-contained playable HTML using the static site's trusted runtime. Recipients can download it, open it offline and share onward. Locally generated manifests identify individual game apps; saved app launches open the game directly. For peer copies, iOS users must receive/import inside the installed app because Safari storage is separate. Catalog links use this same player with a pinned static pack: a fresh Home Screen app downloads its own copy automatically on its first online launch, then starts locally thereafter. Studio remains the authoring tool, with explicit ZIP import for editing. Live **Share** still only joins the running host.

Core also supports the home dashboard, browser-hosted play and optional Node/WebSocket game sessions. Browser play does not start a Docker container. The self-hosted dashboard reads its local library, imports portable ZIPs on localhost, and current bundles include local game media and RTC signaling for offline LAN play.

Browser players share `player-toolbar.js`: one top row. Catalog play shows Home, title, Invite, Download app and More. More exposes additional player tools; the game details page also provides installation instructions. Self-hosted and standalone players retain View exports and More. Portable player tools include game downloads, save import/export, copy sharing and manual pairing. Invite is unavailable for solo games; Share a copy can still send a separate playable copy to a friend. The trusted parent owns this toolbar when a game runs in an opaque iframe, and `portable-client.js` carries client controls/state across its private MessagePort. Games and Squish do not depend on this browser UI.

## Modules

| Area | Implementation |
| --- | --- |
| Portable format | `portable-project.js`: derives a format-2 descriptor from static game metadata and the Squish import, validates paths/source/media without executing game code, and keeps format-1 packages readable; reads/writes ZIPs with a generated integrity inventory. `portable-project-node.js` adapts filesystem access. |
| Portable execution | `portable-runtime.js`: explicit-trust loader and project-scoped asset reads. `portable-html.js`: opaque-origin iframe players for Studio and HTML exports. The loader alone is not a sandbox. |
| Portable progress | `portable-saves.js`: private MessagePort between game and parent; installation/schema-scoped IndexedDB, transaction acknowledgments, conflicts and JSON save import/export. |
| Local/catalog loading | `local-play.js`, `local-play-shared.js`, `local-game-assets.js`: source maps, asset bundles and file-backed assets. Catalog asset IDs are a retained path, separate from portable file assets. |
| Runtime | `game-session.js`: Node game lifecycle. `game-dispatch.js`: shared input dispatch. `session-runtime.js`: owned tick timer and per-recipient scene filtering for Node/WebSocket and LocalSession/RTC. |
| Media | `media-upload.js`, `media-session.js`, `cursor.js`: file uploads, live media, per-player cursor declarations; Stream nodes are native to Squish 1.4.6. |
| RTC | `rtc-signaling.js`: room discovery, invitations, host leases and SDP/ICE signaling. It does not run games or carry gameplay frames. |
| Node orchestration | `game-session-manager.js`, `docker-helper.js`: ports, Docker/fork sessions, health, logs, lifecycle and publish-validation containers. |
| Saves/config | `save-games.js`: retained Node/browser save backends. `index.js`: config, utilities, `authoringDocPath` and `getAuthoringDoc()`. |

## Squish versions and loading

`game-loader.js` exports `squishMap`, `DEFAULT_SQUISH_VERSION` (`150`), AST version parsing/detection, game class loaders and Forgejo archive loading. `detectSquishVersion(code)` is exported and supplies a fallback for raw-source sessions.

Current Node and browser maps contain only **150**, installed as the pinned `squish-150` alias for MIT Squish 1.5.0.
New games export a class from `index.js` with static metadata containing a stable
UUID `gameId`, `name` and an explicit integer `maxPlayers` from 1 to 255. The runtime
version comes from `require('squish-NNN')`; no authored `homegame.json`, duplicate
`squishVersion` or `services` list is needed. `saveSchemaVersion` defaults to `1`.
The shared AST parser reads metadata without executing game code. Format-1
manifests retain their custom entry paths, identities, save schemas and revisions;
import does not silently convert them. See the [authoring contract](docs/homegames-context.md#2-project-validation-and-authoring-constraints).

`link-squish.js` exposes this package's `squish-*` dependencies to consumers that use its postinstall hook. After a runtime change, install dependencies and rebuild the browser bundle and any affected Docker image. An already-exported HTML retains its embedded runtime.

## Sessions

`GameSession` handles player lifecycle, capacity (`metadata().maxPlayers`, explicitly required for new portable games; legacy omission retains 64), spectator views, input, media and optional dashboard framing. `session-runtime.playerFrame` filters the combined serialized scene for **every** recipient, including inherited `playerIds` scopes; it never substitutes an unfiltered frame for a player without scoped nodes. This does not authorize game actions or make room-wide asset bytes private.
Multiplayer capability comes from `maxPlayers > 1`, which is not a minimum-player
requirement. Automatic RTC rooms currently cap participants at 17 including the
host. Removed service declarations are not a route to server-side capabilities.

The dispatcher's file-input envelope is capped at 8 MiB; the shared media registration helper accepts supported image/audio/video files up to **5 MiB**. These are different limits.

Text, file and hover callbacks require an attached target in an interactive layer visible to the authenticated player through every ancestor. Authorization reads the current tree, including permission changes made without a render notification; private branches are pruned before inspecting their children or decoding uploads. Spectators cannot drive game callbacks, but can use their own frame controls. A held node that is removed or becomes private receives one release callback to clear held controls, then stops receiving drag input. Active press checks validate the captured ancestor path instead of searching the entire scene. Games still validate their own turn, ownership and input-value rules; visibility alone does not grant those permissions.

`GameSessionManager.startSession` accepts Forgejo coordinates, a local game path or raw code. It prefers Docker when ready. Without Docker it requires `allowFork` or `FORK_SESSIONS_ENABLED: true`; otherwise launch fails. Forked code runs with the host user's permissions. The manager defaults to ports 7002–7099, 50 sessions, a 3-second lifecycle check and a 30-second empty-session grace period; callers can override these. Core's source config uses 8300–8400. Persistent sessions bypass empty-session cleanup.

Docker sessions mount game code read-only, use resource limits, and can mount save data/certs. `docker-helper.validateGame` is the retained hosted-publishing sandbox; it is not invoked by portable ZIP export.

## Configuration

`getConfigValue` checks environment variables first (`true`/`false` strings are converted to booleans), then the merged config. `getConfig` selects the first base `config.json` from cwd, main-module directory or this package; without a base it uses `DEFAULT_CONFIG`. The application-data `config.json` overlays that base key by key. `setConfigValue` updates the user overlay and clears the cache. Ports/TLS still need the appropriate listener restart.

`HG_APP_DATA_DIR` overrides the normal per-OS application-data directory. Explicit defaults at call sites also matter; consult the code instead of assuming every missing key is merged from `DEFAULT_CONFIG`.

## Documentation and checks

This package is licensed under MIT; see [LICENSE.md](LICENSE.md). Homegames core and Squish use the same license. Dependency and media notices remain applicable.

- [SYSTEM.md](docs/SYSTEM.md), [ARCHITECTURE.md](docs/ARCHITECTURE.md), [FLOWS.md](docs/FLOWS.md), [DATA-MODEL.md](docs/DATA-MODEL.md), [INFRA.md](docs/INFRA.md), [OPERATIONS.md](docs/OPERATIONS.md): current platform/reference paths and retained services.
- [legacy-hosted-publishing.md](docs/legacy-hosted-publishing.md): historical account/publishing behavior, excluded from the default authoring context.
- [homegames-context.md](docs/homegames-context.md): shared game-authoring and platform reference, consumed by Studio's Guide and authoring tools; the website serves it at `/authoring-guide.md`.

`npm test` runs the Common regression suites, including input authorization on every supported Squish version. Integration coverage also lives in `homegames-core/test` and `homegamesio/test`. Core's `npm run stage:runtime` builds local package candidates and verifies their installation across consumers; see its README for the distinction between that candidate and published lockfile dependencies. An already-exported HTML retains its embedded runtime and must be regenerated to include a fix.

Games receive `createExport(name, Uint8Array)` and a `userExports` byte map from their session. Hosts own storage paths and include these files in game copies. See [the user export contract](docs/ARCHITECTURE.md#game-defined-user-exports).
