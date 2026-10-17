# Homegames — Data model

Reviewed against current code on October 11, 2026. Browser projects/progress and retained backend data have different identities and persistence. No live database inventory is implied.

## Portable files and identity

`homegames-common/portable-project.js` defines the format:

- `homegame.json`: `formatVersion: 1`, UUID `gameId`, JS `entry`, `runtime.squishVersion`, positive integer `saveSchemaVersion`.
- Project files: JS source, authored media and supporting files with validated relative paths. Assets declare `new Asset({ path: './assets/hero.png', type: 'image' })`; media bytes are inside the project.
- `.homegame/inventory.json`: generated `formatVersion`, `revision`, and per-file path/byteLength/mediaType/SHA-256 records. The revision hashes manifest and file inventory; it is not a catalog commit or a signature.

The current format caps projects at 512 files, 16 MiB per file, 64 MiB total, 65 MiB archive input, and 1 MiB per JS file. Each authored asset record must fit 10 MiB; larger collections travel as several packets containing complete Squish records. Runtime support is supplied by the caller; the browser currently supports Squish 1.5.0/143/145/146.

`gameId` identifies the package across copies. A separate, trusted **installation ID** identifies a local copy's storage. Imports get a new installation; template copies also get a fresh game UUID. HTML exports embed a fresh installation ID. Copying the same HTML preserves that ID, but another browser/origin does not inherit its storage.

The static website build (October 12) writes `games.json` with each selected game's URL slug, UUID, revision, local archive/thumbnail URLs and display metadata. These records are build artifacts, not MongoDB catalog entries. Source folders without a manifest receive a deterministic UUID based on their folder slug; existing manifests retain their UUID. Website play uses `builtin-<gameId>` as the installation ID and the manifest's save schema, preserving progress across content revisions. Opening a built-in pack in Studio creates a separate local installation. Website RTC invitations are private rooms.

## Studio IndexedDB

`homegamesio/studio-project-store.js` opens `homegames-studio-projects` version 2:

| Store | Records |
| --- | --- |
| `projects` | Draft `id`, `name`, `files` (bytes by path), `activeFile`, `generation`, `updatedAt`. |
| `summaries` | Library list metadata without file contents. |
| `snapshots` | Immutable `id`, `projectId`, `name`, `files`, `activeFile`, source generation, `createdAt`, `message`. Indexed by `projectId`. |
| `snapshotSummaries` | History metadata without file contents, also indexed by project. |

Version 1 drafts survive the version 2 migration. Writes check the current generation in the same transaction. Snapshot restore atomically creates a backup and replaces draft files/name. Invalid source can be saved as a draft/snapshot; play/export validate later. ZIP/HTML exports carry a selected version, not this database or its history.

Previous guest drafts have a separate recovery path in `studio-portable.js`; their original localStorage copy is retained. This is not automatic migration of hosted account projects.

Studio imports may carry a pinned `runtimeUrl`; `homegames-studio-runtimes-v1` Cache Storage retains that runtime independently of editor-shell updates. Game-copy receipts do not write to Studio's project database.

## Individual game apps

`homegames-game-copies-v1` Cache Storage holds complete generated HTML bundles keyed by game UUID and content revision, with a fresh trusted installation UUID in the response header. The HTML contains an inert `homegames-project` JSON block with the editable ZIP, isolated runtime document and save identity. HTML imports extract only the ZIP and rebuild using the trusted site's runtime; incoming HTML wrappers never execute in the parent. Stored runtime documents execute only in opaque iframes.

`homegames-game-manifests-v1` contains locally generated per-game manifests. Their `id` and `start_url` identify `/game-app.html?game=<uuid>&revision=<hash>`, with an optional private invitation fragment on the start URL for initial receipt into fresh app storage. Catalog start URLs also carry `builtin=<slug>` so the app can download the exact content-versioned ZIP from the static host on its first launch; the app identity remains the UUID/revision. `homegames-game-shell-<build>` caches only the generic player/bootstrap assets. The worker serves cached manifest JSON but never serves peer game HTML as a same-origin navigation. Nothing in these caches is uploaded or registered on the server. Each revision has a distinct app identity; updates are explicit new copies, not automatic replacement. Installed iOS apps have storage separate from Safari. Progress remains in the separate installation/schema-scoped save store.

## Portable progress

`portable-saves.js` opens `homegames-portable-saves` version 1, with `saves` keyed by `[installationId, versionId]`. The version ID is `save-schema:N`, derived from the manifest, not a source revision. Envelopes contain `gameKey: project:<installationId>`, `gameId`, `versionId`, `savedAt` and JSON `data`; stored generations detect competing writes.

The parent owns storage. A MessagePort supplies the game with `saveData` and `saveGame`; a successful write Promise acknowledges the IndexedDB commit. Data is capped at 1 MiB UTF-8 JSON. Explicit `saveCompatibility: ['save-schema:1']` can allow older schema reads; it is not an automatic migration.

Restoring source does not roll back progress. ZIP import/new HTML export does not copy progress. Download save/Load save handles compatible progress transfer separately. Browser eviction, clearing site data and quota failures still matter.

## Other save backends

The retained catalog LocalSession uses browser save envelopes with catalog identity and version compatibility. Core's file backend stores per-game/per-version data under application data `.save-data`; concurrent sessions can share that slot. With disk saves disabled, the broadcast backend sends envelopes to browsers and needs an explicit launch-time restore handoff. These paths use `save-games.js`/client save-store code and do not share portable IndexedDB's installation/schema semantics.

## RTC rooms and scene data

`rtc-signaling.js` holds rooms in a process-local Map: random room/invite IDs, host connection, peers, visibility, optional verified catalog game, player count/capacity and timestamps. Public rooms require a published multiplayer game. Catalog leases are 90 seconds; private portable rooms are not catalog entries. API `recordRtcSession` can persist activity separately; the live room is not restored from MongoDB after a restart.

Game state stays in the host instance. Squish frames are transient serialized render trees, filtered per recipient by `session-runtime.js`; room discovery does not persist a game save or editable source. Asset bundles and live streams have their own transport behavior and should not be treated as private merely because a scene node is scoped.

## Retained MongoDB and Forgejo data

The content/account source remains on disk, but its routes are no longer registered by `api/index.js`. The following describes retained data, not current API availability. `api/db.js`, `auth.js`, `handlers.js`, `studio-handlers.js` and `worker.js` define its operations; database name defaults to `homegames`.

| Data | Purpose / representative fields |
| --- | --- |
| `users` | Internal `userId`, display name/email, password hash/salt, verification/reset fields, `isAdmin`, profile and Forgejo-account state. |
| `games` | `gameId`, `developerId`, name/description, `forgejoRepo`, thumbnail, featured/NSFW flags. |
| `gameVersions` | Published version ID, game ID, pinned `commitSha`, publication metadata/flags. |
| `publishRequests` | Request/user/game/commit identity, status, result/error and timestamps. |
| `builds` | Forgejo webhook build records. |
| `assets` / `documents` | Asset metadata and BSON binary file data; public download by asset ID. |
| `sessions` | Catalog session/activity records, separate from live RTC room memory. |
| `supportMessages`, `blog` | Contact messages and retained content. |
| `llmRequests`, `docsQuestions` | Legacy edit and docs-question requests. |
| `workerJobs`, `workerResults` | Durable background execution/delivery records used by `worker/lib/jobs.js`. |

This is a map of relevant code paths, not an exhaustive production schema. Legacy `developerId` references an internal user ID; display names are separate. Forgejo repositories are owned by that internal user identity, and published commit SHAs pin catalog source. API-derived Forgejo credentials and account verification are irrelevant to a portable project's local installation identity.

Studio account removal did not delete these collections, repositories or asset bytes. Backup/migration decisions must cover them separately from browser-local projects.
