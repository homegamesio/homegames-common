# Homegames — Architecture

Component-by-component. For where these physically run, see INFRA.md; for traces
through them, see FLOWS.md.

---

## squish (npm: `squishjs`)

The shared contract between server and client — a compact binary serialization
of a game's scene graph, plus the node types and base classes games are built
from.

- **Node types** (`GameNode`): `Shape` (polygons/lines), `Text`, `Asset` (image/audio).
  Everything is positioned in a virtual **0–100 coordinate plane**.
- **`squish(node)` / `unsquish(bytes)`** (`src/squish.js`): TLV-style encoder.
  Each node frame starts with magic byte `3`, a class code, then per-property
  sub-frames (color, coordinates, text, asset, playerIds, etc.), each with its
  own type tag + length. Numbers are stored as integer + 2-decimal-fraction byte
  pairs (~0.01 resolution).
- **`Game` / `ViewableGame`** base classes: games extend these. `ViewableGame`
  adds a large world "plane" + `ViewUtils.getView()` for per-player cameras into
  a world bigger than one screen.
- **`Squisher`** (`src/Squisher.js`): walks a game's layer tree, squishes every
  node, builds **per-player frames** (via `playerIds` filtering — this is how
  hidden info / private UI works and why it's bandwidth-efficient and
  cheat-resistant), bundles binary assets, and coalesces per-tick mutations into
  one broadcast.
- **Versioning:** published as pinned versions; the canonical map is
  `homegames-common/game-loader.js → squishMap`. A game's `squishVersion` selects
  which package both server and client use. **Image cropping / spritesheets
  require `squish-140`+.**

Authoring contract: **squishjs-game-authoring.md** (this folder).

---

## homegames-common

The shared backend library. Notable modules:

- **`game-loader.js`** — `squishMap` (version → npm alias, **single source of
  truth**), `parseSquishVersion` (AST-reads a game's `squishVersion`),
  `loadGameClass*`, and `fetchGameFromForgejo` (download a game's repo archive,
  find `index.js`).
- **`docker-helper.js`** — the isolation layer. `runGameContainer` (live session:
  read-only code mount, mem/CPU/PID limits, `CapDrop: ALL`, tmpfs, auto-remove)
  and `validateGame` (publish gate: `--network=none`, read-only rootfs, noexec
  tmpfs, timeout). Uses `dockerode`.
- **`game-session-manager.js`** — starts a session by `versionId` (fetch from
  Forgejo) or path; **uses Docker when available, falls back to `fork()` when
  not** (see security_notes.md — fail closed in production).
- **`index.js`** — config, logging, `getAppDataPath`, and the **authoring-doc
  accessor** (`authoringDocPath`, `getAuthoringDoc()`) so every consumer reads
  one doc.
- **`docs/`** — this documentation.

---

## homegames-core (game-session server)

Runs a single published game and streams it to players.

- Loads the game class for the requested `squishVersion`, instantiates it,
  constructs a `Squisher`, and on each tick/state-change squishes the scene and
  **broadcasts frames over WebSocket**. Receives input messages (click/key/etc.)
  and routes them to the game instance's handlers.
- **Per-session isolation:** each live game runs in a `homegames-runner` Docker
  container (built from `homegames-core/docker/`: `Dockerfile`,
  `container-entry.js`, and `validate.js` used by the publish gate).
- Session orchestration / port assignment / handing players to the right session
  is done with the **Homenames** registry and the socket layer (`src/util/socket.js`),
  which also speaks the binary client protocol (init / asset bundle / state /
  port-redirect / aspect-ratio messages).
- Built-in games live in `src/games/` (e.g. `image-test`, `singularity`,
  `enhanced-view-test`). Published user games are fetched from Forgejo at run time.

---

## homegames-client (browser renderer)

The engine that turns squished frames into pixels.

- `src/index.js` — `HomegamesClient`: WebSocket lifecycle (inline or via a Web
  Worker, `socket-worker.js`), handles the binary message types, picks the right
  `unsquish` by version (`squish-map.js`), runs a rAF render loop that only
  repaints when state actually changed.
- `src/renderer.js` — draws polygons/text/images/audio + effects; records
  hit-test data; applies image **crop** (9-arg `drawImage`).
- `src/input.js` — mouse/touch/keyboard/gamepad → game protocol messages;
  point-in-polygon hit-testing; held-key repeat throttled to ~30/s; clears stuck
  mouse state on blur / off-window release.
- `src/assets.js` — decodes the binary asset bundle (image/audio/font) and caches.
- Built to `dist/homegames-client.js` (webpack) and served to players.

---

## homegamesio (the website)

Static site on S3+CloudFront; `app.js` is the Node origin that maps URL paths to
HTML files. Surfaces:

- **Landing / catalog / play / view** pages.
- **Studio** (`studio.html` + `studio.js`) — the in-browser game editor: code
  editor + file tree, live **Preview**, **Versions** history, **AI Edit**, a
  consolidated **Settings** panel (description / thumbnail / clone), one-click
  **Publish**, and a full **Assets** workspace (Upload / Draw / Record / Keyboard).
  Top-level UI is two modes: **GAMES** and **ASSETS**. (Redesigned to an
  "analog dashboard" — big labeled buttons, progressive disclosure.)
- **Admin** (`admin.html` + `admin.js`) — moderation console at `/admin`,
  admin-only: inspect/search/delete users, games, assets; publish-request review;
  support messages; stats. (One-click "delete user + everything they made"
  cascades Mongo + Forgejo repos + the Forgejo account.)
- **Reset-password / verify** pages.
- Talks to `api.homegames.io` for everything dynamic; serves the **authoring
  guide** at `/authoring-guide.md` (read from `homegames-common`).

---

## api (backend REST + publish worker)

Node HTTP API. Routing in `router.js` (regex → handler, with `requiresAuth` /
`requiresVerified` gates). Key areas:

- **auth.js** — signup (internal `userId` ≠ immutable `displayName`), login (by
  display name or email), **email verification by 6-digit code**, **password
  reset by code** (anti-enumeration). JWT in `crypto.js`.
- **studio-handlers.js** — the Studio backend: provisions a per-user Forgejo
  account (password derived via HMAC from a server secret), creates/edits game
  repos, lists versions, restores, sets thumbnail, submits **publish requests**
  (rate-limited), receives Forgejo **push webhooks** (HMAC-verified), and queues
  build/LLM jobs.
- **handlers.js** — catalog, asset upload (**calls `nsfw.js` `classifyImage`
  in-process at upload time** — TensorFlow `nsfwjs`), admin endpoints, delete
  (game/asset/developer with cascade), email-verify/reset handlers.
- **worker.js** — the **publish-validation worker** (consumes the
  `publish_requests` RabbitMQ queue): checks `index.js` + GPLv3 LICENSE, size
  limits, runs **`ast-scanner.js`** over every JS file, then **`validateGame`**
  (Docker sandbox: loads/instantiates/runs the game ~5s, no network), reads NSFW
  flags, and on success writes a `gameVersions` record with `published: true`.
- **forgejo.js** — admin-token client for the Forgejo server (create user/repo,
  files, webhooks, archives, delete user/repo).
- **nsfw.js / detect.js / ast-scanner.js / crypto.js / db.js / queue.js / email.js**
  — moderation model, mime detection, the static-analysis gate, JWT+hashing,
  Mongo access, RabbitMQ publishing, SES email.

Note the API is a **monolith process** that also embeds the NSFW model — NSFW
moderation is *not* a separate worker.

---

## worker (LLM "AI edit")

Runs on the Mac Studio (MLX needs Apple Silicon).

- `index.js` (Node) — pulls LLM jobs from the EC2's RabbitMQ, manages a
  long-lived Python child, posts results back to the API (authenticated with
  `LLM_WORKER_SECRET`).
- `llm/model_server.py` (MLX) — holds a warm code model (Qwen2.5-Coder), prefills
  the **authoring guide** as the system prompt (resolved from `homegames-common`
  via `AUTHORING_DOC_PATH`), rewrites a game's `index.js` from a natural-language
  request, with validation-error retry.
- The result is dropped into the Studio editor as an unsaved change for the user
  to review and save.

---

## Supporting services (on the EC2 host)

- **MongoDB** — all application data (users, games, versions, assets, etc.). See DATA-MODEL.md.
- **RabbitMQ** — job queues: `publish_requests` (publish validation) and the
  unified jobs queue (`homegames-jobs`, incl. `LLM_REQUEST`, `BUILD_GAME`).
- **Forgejo** — git server; one repo per game; the canonical store of game source.
