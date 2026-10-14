# homegames-common

Shared Homegames runtime, portable-project tooling, configuration and authoring reference. Node consumers use `index.js`; browser consumers import individual browser-compatible modules through `homegames-client`. There is no build step in this package.

This documentation describes the current working-tree implementation, reviewed October 11, 2026. It does not establish what is deployed. Start with [SYSTEM.md](docs/SYSTEM.md) for the platform map.

## Current product paths

Studio in `homegamesio` creates account-free browser projects. Source, media and snapshots live in IndexedDB; projects export as ZIPs and playable HTML. Games run in a browser host and can invite RTC guests. Studio uses local projects only. The active API exposes connection helpers; legacy account/content source remains on disk but is not registered by its entry point.

**Share a copy** in Studio and new portable HTML exports sends the project ZIP over a separate private RTC connection. `homegames-client/src/rtc-copy*.js` handles consent, bounded transfer and integrity validation; signaling carries no archive payloads. The generic `/game-app.html` receiver builds and saves a self-contained playable HTML using the static site's trusted runtime. Recipients can download it, open it offline and share onward. Locally generated manifests identify individual game apps; saved app launches open the game directly. For peer copies, iOS users must receive/import inside the installed app because Safari storage is separate. Catalog links use this same player with a pinned static pack: a fresh Home Screen app downloads its own copy automatically on its first online launch, then starts locally thereafter. Studio remains the authoring tool, with explicit ZIP import for editing. Live **Share** still only joins the running host.

Core also supports the home dashboard, browser-hosted play and optional Node/WebSocket game sessions. Browser play does not start a Docker container. The self-hosted dashboard reads its local library, imports portable ZIPs on localhost, and current bundles include local game media and RTC signaling for offline LAN play.

Browser players share `player-toolbar.js`: one top row. Catalog play shows Home, title, Share and Download, with other tools linked from the static game details page. Self-hosted and standalone players keep View exports and More. Portable players put game downloads, save import/export, copy sharing and manual pairing in More; catalog installation instructions are reached from the game details page. The trusted parent owns this toolbar when a game runs in an opaque iframe, and `portable-client.js` carries client controls/state across its private MessagePort. Games and Squish do not depend on this browser UI.

## Modules

| Area | Implementation |
| --- | --- |
| Portable format | `portable-project.js`: validates manifest, paths, source imports and media without executing game code; reads/writes ZIPs with a generated integrity inventory. `portable-project-node.js` adapts filesystem access. |
| Portable execution | `portable-runtime.js`: explicit-trust loader and project-scoped asset reads. `portable-html.js`: opaque-origin iframe players for Studio and HTML exports. The loader alone is not a sandbox. |
| Portable progress | `portable-saves.js`: private MessagePort between game and parent; installation/schema-scoped IndexedDB, transaction acknowledgments, conflicts and JSON save import/export. |
| Local/catalog loading | `local-play.js`, `local-play-shared.js`, `local-game-assets.js`: source maps, asset bundles and file-backed assets. Catalog asset IDs are a retained path, separate from portable file assets. |
| Runtime | `game-session.js`: Node game lifecycle. `game-dispatch.js`: shared input dispatch. `session-runtime.js`: owned tick timer and per-recipient scene filtering for Node/WebSocket and LocalSession/RTC. |
| Media | `media-upload.js`, `media-session.js`, `cursor.js`: file uploads, live media, per-player cursor declarations; Stream nodes are native to Squish 1.4.6. |
| RTC | `rtc-signaling.js`: room discovery, invitations, host leases and SDP/ICE signaling. It does not run games or carry gameplay frames. |
| Node orchestration | `game-session-manager.js`, `docker-helper.js`: ports, Docker/fork sessions, health, logs, lifecycle and publish-validation containers. |
| Saves/config | `save-games.js`: retained Node/browser save backends. `index.js`: config, utilities, `authoringDocPath` and `getAuthoringDoc()`. |

## Squish versions and loading

`game-loader.js` exports `squishMap`, `DEFAULT_SQUISH_VERSION` (`142`), AST version parsing/detection, game class loaders and Forgejo archive loading. `detectSquishVersion(code)` is exported and supplies a fallback for raw-source sessions.

Current Node map: **142, 143, 145, 146**. The 146 dependency is the sibling `squish` checkout; other entries are npm aliases. The browser's static map in `homegames-client/src/squish-map.js` includes **142, 143, 145**. Node availability does not imply browser support. Portable validation requires the manifest, source import and metadata to agree on a supported runtime.

`link-squish.js` exposes this package's `squish-*` dependencies to consumers that use its postinstall hook. After a runtime change, install dependencies and rebuild the browser bundle and any affected Docker image. An already-exported HTML retains its embedded runtime.

## Sessions

`GameSession` handles player lifecycle, capacity (`metadata().maxPlayers`, default 64), spectator views, input, media and optional dashboard framing. `session-runtime.playerFrame` filters the combined serialized scene for **every** recipient, including inherited `playerIds` scopes; it never substitutes an unfiltered frame for a player without scoped nodes. This does not authorize game actions or make room-wide asset bytes private.

The dispatcher's file-input envelope is capped at 8 MiB; the shared media registration helper accepts supported image/audio/video files up to **5 MiB**. These are different limits.

`GameSessionManager.startSession` accepts Forgejo coordinates, a local game path or raw code. It prefers Docker when ready. Without Docker it requires `allowFork` or `FORK_SESSIONS_ENABLED: true`; otherwise launch fails. Forked code runs with the host user's permissions. The manager defaults to ports 7002–7099, 50 sessions, a 3-second lifecycle check and a 30-second empty-session grace period; callers can override these. Core's source config uses 8300–8400. Persistent sessions bypass empty-session cleanup.

Docker sessions mount game code read-only, use resource limits, and can mount save data/certs. `docker-helper.validateGame` is the retained hosted-publishing sandbox; it is not invoked by portable ZIP export.

## Configuration

`getConfigValue` checks environment variables first (`true`/`false` strings are converted to booleans), then the merged config. `getConfig` selects the first base `config.json` from cwd, main-module directory or this package; without a base it uses `DEFAULT_CONFIG`. The application-data `config.json` overlays that base key by key. `setConfigValue` updates the user overlay and clears the cache. Ports/TLS still need the appropriate listener restart.

`HG_APP_DATA_DIR` overrides the normal per-OS application-data directory. Explicit defaults at call sites also matter; consult the code instead of assuming every missing key is merged from `DEFAULT_CONFIG`.

## Documentation and checks

This package is licensed under GPLv3 (`GPL-3.0-only`); see [LICENSE.md](LICENSE.md). Homegames core and Squish use the same license. Dependency and media notices remain applicable.

- [SYSTEM.md](docs/SYSTEM.md), [ARCHITECTURE.md](docs/ARCHITECTURE.md), [FLOWS.md](docs/FLOWS.md), [DATA-MODEL.md](docs/DATA-MODEL.md), [INFRA.md](docs/INFRA.md), [OPERATIONS.md](docs/OPERATIONS.md): current platform/reference paths and retained services.
- [homegames-context.md](docs/homegames-context.md): shared game-authoring and platform reference, consumed by Studio's Guide and the worker; the website serves it at `/authoring-guide.md`.

`npm test` here is still a placeholder that exits unsuccessfully. Integration coverage lives in `homegames-core/test` and `homegamesio/test`; run the checks relevant to a changed module. Consumer package manifests determine which siblings must be installed. A local `file:` dependency is not proof that a running deployment has the latest files.

Games receive `createExport(name, Uint8Array)` and a `userExports` byte map from their session. Hosts own storage paths and include these files in game copies. See [the user export contract](docs/ARCHITECTURE.md#game-defined-user-exports).
