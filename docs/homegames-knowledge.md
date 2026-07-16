# Homegames — Platform Knowledge Reference

This document is the grounding context for the docs assistant ("ask something" box on
homegames.io/docs.html). It condenses everything in the public docs — what Homegames is, how to
play, how to make and publish games, and how self-hosting works. It is a reference for ANSWERING
QUESTIONS, not a game-generation contract (the full authoring contract is
`squishjs-game-authoring.md`).

## What Homegames is

Homegames is a free, open-source (GPLv3) platform for making, sharing, and playing simple
multiplayer browser games. Nothing to install: games run in any web browser, and phones work as
first-class controllers and screens. Games are small JavaScript programs, usually a single file.
Everything — platform code, website, and every published game — is open source at
github.com/homegamesio. Created and maintained by Joseph Garcia as a mostly-solo project since 2018.

Two ways to use it:
1. **The website (homegames.io)** — browse the catalog and play published games, or build your own
   in the browser-based Developer Studio.
2. **Self-hosting** — run a Homegames server on a machine at home; everyone on the network gets a
   game dashboard by typing `homegames.link` into any browser.

## Playing games

- Browse the catalog at homegames.io/catalog.html. Game pages show description, published versions,
  comments, active sessions, and browsable source code.
- **Single-player games**: clicking Play runs the game entirely in your browser tab (a "local
  session") — no server involved after the initial load, no account needed.
- **Multiplayer games**: "Play with friends" starts a hosted session on the platform and gives the
  creator a shareable link. Anyone who opens the link joins the same game from their own device.
  Share links are date-bound (valid the day minted plus the next day).
- **Download**: many games can be downloaded as a single self-contained HTML file (game + runtime +
  assets) that runs offline. Downloaded copies run as solo local sessions — multiplayer features
  don't work offline.
- No account is needed to play.

## Accounts

- Needed only to save games to the cloud, run online multiplayer previews, and publish. Playing and
  guest-mode Studio use need no account.
- Signup: display name + email + password. Email verification is a 6-digit code; publishing and
  asset uploads require a verified email.
- Password reset: emailed code flow at homegames.io/reset-password.html.
- Developer profiles (bio, image, optional BTC address, published games) are public pages.

## The Developer Studio (homegames.io/studio.html)

A browser IDE for making games. Features:
- **Guest mode**: pick a template, edit, and run local previews with no account. The draft persists
  in the browser; creating an account later claims it.
- **Templates**: starter games (blank, click, keyboard, multiplayer, text input, image, animation,
  scroll, buttons, glow) targeting squish-142.
- **Editing**: file tree + tabbed editor with syntax highlighting. "Save Version" commits — game
  source is Git-backed, so versions have real history; any version can be viewed and restored.
- **Preview**: "local" runs the game instantly in-tab; "online" hosts a real multiplayer session
  with a shareable link (account required).
- **Assets**: upload images/audio/fonts (drag & drop), draw images on a canvas, record audio, tag
  and describe assets, mark them public/private.
- **Publish**: submit a saved version to the catalog (see Publishing below).
- **AI editing is currently disabled.** The Studio previously had an "ask AI to edit my game"
  feature; it is turned off for now because locally-hosted models aren't good or fast enough for
  full game generation. The docs assistant (this Q&A) answers questions but does not write games.

## Making games (essentials)

Full tutorial: homegames.io/docs.html. Full technical reference: the authoring guide (served at
/authoring-guide, also available via the Studio's Guide button — it's written to work as context
for an external AI assistant too).

- A game is a JavaScript class exported from `index.js` (`module.exports = MyGame`), extending
  `Game` (or `ViewableGame` for scrolling worlds) from a versioned squish package:
  `const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');`
- Required surface: `static metadata()` (must include `squishVersion` matching the require; plus
  `name`, `author`, `description`, `aspectRatio`, optional `tickRate`, `maxPlayers` (default 64),
  `services`, `assets`), a constructor calling `super()`, and `getLayers()` returning
  `[{ root: this.base }]`.
- `metadata()` must be a pure object literal — the platform statically parses it (never executes
  it) to decide play modes. `services: ['multiplayer']` = multiplayer game; omit `services` for
  single-player (instant play + downloadable).
- **The screen is a 100×100 grid** — all positions/sizes are 0–100 percentages, top-left origin.
  The grid stretches to the declared aspect ratio (use `{x:1, y:1}` for true circles/angles).
- **Three node types**: `GameNode.Shape` (polygons; `ShapeUtils.rectangle/triangle` helpers),
  `GameNode.Text`, `GameNode.Asset` (images/audio). Nodes form a tree; later nodes draw on top.
- **Colors** are `[r, g, b, alpha]` arrays, each 0–255, plus ~100 named colors on `Colors.COLORS`
  (RED, HG_BLUE, GOLD, ...). Invented color names are `undefined` and render invisibly.
  Out-of-range channels wrap rather than clamp.
- **State changes must be signaled**: after mutating node properties, call
  `this.base.node.onStateChange()` once. Tree operations (addChild/removeChild) notify
  automatically. Forgetting this is the most common bug.
- **Players are numbers**: `handleNewPlayer({ playerId, info })`, `handlePlayerDisconnect(playerId)`.
  Every input arrives with the acting player's id. `playerIds` on a node controls *visibility*
  (empty = everyone, `[42]` = only player 42, `[0]` = nobody) — it is not ownership; don't scope
  shared entities like ships or bullets.
- **Input**: `onClick(playerId, x, y)` on Shape and Asset nodes (NOT Text — build buttons as a
  clickable Shape with a Text label on top); `handleKeyDown/Up(playerId, key)` for keyboards (held
  keys repeat ~30/sec); `input: {type: 'text', oninput}` for a text prompt;
  `input: {type: 'file', oninput: (playerId, bytes, meta)}` for image/audio uploads from players
  (5 MB cap; `meta.kind` is 'image'/'audio' sniffed from the file's bytes). `onHover`/`offHover`
  exist but only fire on nodes that also have `onClick` or `input`, and touch devices have no hover.
- **Game loops**: set `metadata().tickRate` (15–30 for action games) and implement `tick()`. It
  starts firing the moment the game is constructed — gate it on a phase variable and create every
  node it touches in the constructor. Use `this.setTimeout`/`this.setInterval` (auto-cleaned).
- **Assets in games**: declare in `metadata().assets` as
  `new Asset({ id: '<asset-id>', type: 'image' })`, then place with a `GameNode.Asset` whose
  `assetInfo` gives `pos`/`size` (and optional crop fields for spritesheets). Audio is a zero-size
  Asset node: add it to the tree to play, remove to stop. Asset ids come from uploads in the
  Studio's Assets panel — invented ids render nothing.
- **Sandbox constraints**: games may only require squish and their own files. No Node built-ins,
  no network, no filesystem, no `eval`, no browser globals (`window`, `document`, `alert`,
  `location.reload()` all crash — the game may run in Node on a server).
- Common gotchas: screen not updating = missing `onStateChange()`; button not working = `onClick`
  on Text or something invisible covering it; crash on menu = `tick()` touching a not-yet-created
  node or a browser global; `\n` doesn't line-break Text (one node per line); negative coordinates
  pin to 0 (not off-screen); `Shapes.CIRCLE` doesn't render (build a many-sided polygon); fade with
  `color` alpha, not `fill` alpha.

## Publishing

From the Studio, on a saved version (verified account required):
1. The game needs a description, a thumbnail, and edits beyond the starter template.
2. Automated validation runs: static analysis of the source (only squish + own files allowed; no
   Node built-ins/network/filesystem/eval/dynamic require), size limits (5 MB per file, 20 MB
   total), a GPLv3 LICENSE file, and a real sandboxed run in a container with no network — the game
   must load, render, and not crash for a few seconds.
3. On passing, the game is publicly listed in the catalog. Featured games are hand-picked by a
   human (there is no review step just to get listed). Uploaded images are automatically screened
   for NSFW content.
4. Every published game is GPLv3 and its source is browsable from its game page ("View Source").

Publish requests can take a few minutes to process; status is shown in the Studio.

## Assets (platform-side)

- Developers upload images, audio, and fonts in the Studio (verified account; ~6 MB max per asset,
  100 assets per user). Supported types are detected from the file's actual bytes: images
  (JPEG/PNG/GIF/WebP/BMP), audio (MP3/WAV/OGG/FLAC/MP4), fonts (TTF/OTF).
- Assets get stable ids; games reference them by id in `metadata().assets`. Public assets appear in
  the shared asset catalog. Tags and descriptions are editable; NSFW flags apply.

## Self-hosting

Guide: homegames.io/self-hosting.html. Summary:

- Run a Homegames server on a machine at home (Windows/macOS/Linux, Node.js 18+, git). Clone the
  repos side by side (homegames-common, homegames-core, homegames-client, homegames-web,
  homegames), then in `homegames/`: `npm install`, `npm run build`, `sudo node index.js` (sudo
  because the web server binds ports 80/443).
- Then any device on the same network plays by visiting `homegames.link` in a browser. The server
  registers itself with the homegames.link service (outbound connection only — no port forwarding
  or router config needed), which redirects browsers on the same network to it.
- **HTTPS on a LAN**: each network gets its own `*.homegames.link` subdomain pointed at the
  server's local address, with a real TLS certificate. The server generates its key locally and
  submits only a signing request — the private key never leaves the machine. First boot takes a
  minute or two while the cert is issued ("setting up a secure connection" page auto-refreshes).
  Certs renew automatically.
- Internet is needed for initial setup (cert + downloading games); play itself is LAN-local.
- LAN ports used: 80/443 (web client), 9801 (dashboard), 8300–8400 (game sessions). Firewalls or
  wifi "AP/client isolation" blocking these are the usual cause of "dashboard loads but games
  don't" or "works on the server but not on phones".
- "No Homegames servers found" at homegames.link usually means the visiting device and server
  aren't on the same network from the internet's point of view (guest wifi, VLANs, VPNs).
- Config lives in `config.json` (env vars override): `LINK_ENABLED`, `HOME_PORT` (9801),
  `GAME_SERVER_PORT_RANGE_MIN/MAX` (8300–8400), `START_PATH` (boot into one game), etc.
- Dev mode: run homegames-core (`npm start`) and homegames-web (`npm run build && sudo npm start`)
  directly for plain-HTTP LAN play without the cert flow.
- Hosting the entire platform (your own catalog/API) is possible — everything is open source — but
  is a much bigger project (MongoDB, RabbitMQ, a Forgejo git server, Docker).

## How the platform works (under the hood)

- Games are **server-authoritative scene trees**: the game maintains a tree of shape/text/asset
  nodes; the platform renders it and routes input back. Games never draw pixels or open sockets.
- The tree travels as **squish**, a compact binary serialization format (npm package `squishjs`),
  versioned so old games keep working — each game pins its `squishVersion`.
- The browser side is `homegames-client`: connects over WebSocket, decodes squish frames onto a
  canvas, sends input as JSON. The same engine powers the website player, hosted sessions,
  self-hosted dashboards, and offline downloads.
- Hosted multiplayer sessions run as isolated processes (locked-down containers where available),
  one per session, managed by a small session API. Single-player "local sessions" run the whole
  loop in the browser tab.
- Game source lives in a Git server behind the platform API; Studio saves are commits.
- Main repos (github.com/homegamesio): `squish` (game library + serialization), `homegames-core`
  (game/session server + built-in games), `homegames-client` (browser engine), `homegames-web`
  (web server for the client), `homegames` (self-host launcher), `homegames-common` (shared
  library), `homegames-api` (platform backend), `homegames.link` (LAN discovery), `worker`
  (background jobs: certs, this assistant), `homegamesio` (the website).

## Misc facts

- License: everything is GPLv3, including published games.
- Contact/support: email joseph@homegames.io, or open a GitHub issue (github.com/homegamesio).
- Bugs/ideas: GitHub issues on the relevant repo under github.com/homegamesio.
- The demo instance picodeg.io hosts a hosted Homegames dashboard.
- There is a Homegames podcast (episodes listed via the site).

## Answering guidance

- If a question is about game code specifics beyond this document (exact node options, advanced
  patterns like cameras/spritesheets/bots), point to the docs page (homegames.io/docs.html) and the
  full authoring guide (/authoring-guide) rather than guessing.
- If asked to generate a full game or large amounts of code: explain that this assistant doesn't
  write games, and point to the Studio's templates and docs. Small illustrative snippets are fine.
- If the question is unrelated to Homegames, say you can only help with Homegames.
