# homegames-common

Shared Node library for the Homegames platform, consumed by every other repo as a `file:../homegames-common` dependency. No build step, no framework. It bundles four things:

1. **Utilities & config** — `getConfigValue` (env var → `config.json` → defaults), `getAppDataPath` (per-OS app-data dir), `log`, `getHash` (md5), `getUrl`, `guaranteeDir`.
2. **The canonical squish version map + game loading** — `game-loader.js`.
3. **The game-session runtime and orchestration** — `GameSession` and `GameSessionManager` (Docker or fork).
4. **The game authoring contract** — `docs/squishjs-game-authoring.md`, exposed via `getAuthoringDoc()` / `authoringDocPath` and used to ground the LLM game-generation flow in [worker](../worker).

## Squish versioning (`game-loader.js`, `link-squish.js`)

This repo is the **single owner of squish versions**. It declares each release of [squish](../squish) as an npm alias (`"squish-142": "npm:squishjs@1.4.2"`, `"squish-143": "npm:squishjs@1.4.3"`) and exports the canonical `squishMap` + `DEFAULT_SQUISH_VERSION` (`'142'`).

Because npm doesn't hoist a `file:` dependency's transitive deps, consumers (homegames-core, homegames-client) run `link-squish.js` as a postinstall step: it symlinks each `squish-*` package from this repo's `node_modules` into the consumer's, so bare `require('squish-142')` calls in game code resolve everywhere.

`game-loader.js` also provides:

- `parseSquishVersion(codePath)` — acorn AST parse of a game file to extract `metadata().squishVersion` without `require`-ing untrusted code
- `loadGameClass(code, tmpDir)` / `loadGameClassFromPath(path)` — load a game class (cache-busting)
- `fetchGameFromForgejo({forgejoUrl, forgejoToken, owner, repo, ref})` — download + extract a game repo archive, find the entry point, parse its squish version
- `downloadToFile`, `findEntryPoint`

## Game sessions

### `GameSession` (`game-session.js`)

The in-process game runtime — one instance per running game. Resolves the squish package (`SQUISH_PATH` env override, else `squishMap[squishVersion]`), instantiates its `Squisher`, and handles:

- Player lifecycle: `addPlayer`/`removePlayer` (capacity from `metadata().maxPlayers`, default 64), spectators, per-player info/settings/clientInfo maps, Homenames integration when configured
- Input dispatch: click hit-testing with bezel coordinate transforms, keydown/keyup, hover, gamepad, and file uploads (base64 or Uint8Array, 8MB cap, magic-byte sniffing — mirrored in homegames-client's `LocalDispatcher`)
- Broadcasting: coalesces node mutations into one squish+send per event-loop turn; per-player frames honor `playerIds` visibility
- Navigation opcodes to clients: `[5, portHi, portLo]` (join/move), `[6, ...]` (spectate)
- Optional "frame" mode (bezel + HomegamesRoot handler) vs bare no-frame sessions

### `GameSessionManager` (`game-session-manager.js`)

Give it a game — `{versionId, owner, repo, ref}` (Forgejo), `{gamePath}` (local), or `{code}` (raw source) — and it returns a port running a WebSocket game server. Used by the homegames-core Dashboard and by Homenames for API-created sessions.

- **Docker path** (preferred when available): runs the game in the `homegames-runner` image via `docker-helper.js` — game code mounted read-only at `/app/game`, save data at `/app/save`, optional certs at `/certs`, `CapDrop ALL`, memory/pids/cpu limits, `AutoRemove`, host-gateway access back to Homenames.
- **Fork path** (fallback): `fork()`s the consumer's `child_game_server.js` with a strict env allowlist (no secret leakage), `NODE_PATH`/`SQUISH_PATH` wired so `require('squish-NNN')` resolves, and a `--max-old-space-size` derived from `CHILD_SESSION_MEMORY_LIMIT` (default `196m`).
- Port pool (default 7002–7099, overridable — homegames-core passes 8300–8400), max 50 sessions, lifecycle monitor that stops sessions empty past a grace period (default 30s) unless marked persistent, health checks via each session's `GET /health`, log streaming, and IPC/HTTP request-response to sessions.

### `docker-helper.js`

Dockerode-based helpers: `isDockerAvailable`, `ensureImage`/`buildImage` (tars the Dockerfile dir straight to the Engine API — no shell), `runGameContainer` (live sessions, described above), and `validateGame` — the publish-time sandbox used by the [api](../api)'s worker: runs `validate.js` with `NetworkMode: 'none'`, read-only rootfs, 30s timeout, and parses a JSON verdict from stdout. The Dockerfile and container entry scripts live in the consumer (homegames-core's `docker/`); this module only builds/runs them.

## docs/

- **`squishjs-game-authoring.md`** — the load-bearing, actively maintained authoring contract (verified against `squishjs@1.4.2`): what a game is, the AST-scan + Docker-sandbox constraints, the 0–100 coordinate model, hosted vs local sessions. Consumed by the worker's LLM prompts and mirrored on homegames.io at `/authoring-guide`.
- **`homegames-knowledge.md`** — a compact whole-platform reference (playing, studio, publishing, self-hosting, how it works) that grounds the [worker](../worker)'s docs assistant ("ask something" box on homegames.io/docs.html).
- `SYSTEM.md`, `ARCHITECTURE.md`, `FLOWS.md`, `DATA-MODEL.md`, `INFRA.md`, `OPERATIONS.md` — whole-platform background docs with self-described `TODO: confirm` markers; useful context, not authoritative per-repo documentation.

## Configuration

`getConfigValue(key, default)`: `process.env[key]` wins (with `'true'`/`'false'` coercion), then the first `config.json` found in app-data dir → cwd → main-module dir → this package's dir, then `DEFAULT_CONFIG`/the passed default. `DEFAULT_CONFIG` doubles as the shared config schema for consumers (`API_URL: https://api.homegames.io`, `LINK_URL: wss://homegames.link`, `LINK_PROXY_URL: wss://public.homegames.link:81`, ports, etc.) — most of those keys are read by consumers, not by this library itself.

## Consumers

All via local `file:` links (nothing resolves from the npm registry): [homegames-core](../homegames-core) (heaviest — sessions, config, loader), [homegames-web](../homegames-web), [homegames-client](../homegames-client), [worker](../worker) (authoring doc only), homedome (validation pipeline), [homegames.link](../homegames.link) (an older published version).

## Known issues (as of this writing)

- **Bug:** `game-session-manager.js` imports `detectSquishVersion` from `game-loader`, which doesn't export it — any `startSession({code})` (raw-code) call throws. The Forgejo and `gamePath` paths are unaffected.
- `postUrl` (index.js) and the `stateHistory` field in `GameSession` are dead; `loadGameClassFromPath` is imported but unused in the manager.
- `lifecycleCheckMs` JSDoc says 10000 but the code default is 3000.
- The `hg-games/` directory is an empty leftover; nothing here uses it.
- There are no tests (`npm test` errors).
