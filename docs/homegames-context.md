# Homegames — Master LLM Context

> This is the single grounding document for every Homegames AI task: generating and editing games, and answering questions about the platform. **Part I** is the whole-platform reference — what Homegames is, how playing, making, publishing, and self-hosting work, and how the system works under the hood. **Part II** is the authoritative squish.js game-authoring contract, verified against the real code (the squish library, the server's click/frame pipeline, the browser client, and the publish validator). When you write or edit game code, Part II is the contract — follow it exactly; code that violates its Hard Constraints is auto-rejected by the publishing pipeline before a human ever sees it.

---

# PART I — The Homegames platform

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
  comments, active sessions, and browsable source code ("View Source", published commits only).
- **Single-player games**: clicking Play runs the game entirely in your browser tab (a "local
  session") — no server involved after the initial load, no account needed.
- **Multiplayer games**: "Play with friends" starts a hosted session on the platform and gives the
  creator a shareable link. Anyone who opens the link joins the same game from their own device.
  Share links are date-bound (valid the day minted plus the next day, UTC). Sessions can be marked
  private (unlisted — joinable by link only). Creating a session requires no account.
- **Download**: games can be downloaded as a single self-contained HTML file (game + runtime +
  assets) that runs offline. Downloaded copies run as solo local sessions — multiplayer features
  don't work offline.
- No account is needed to play.
- Comments on game pages: up to 200 characters; signed-in comments are attributed; anonymous
  comments are allowed (rate-limited to about one per hour per network).

## Accounts

- Needed only to save games to the cloud, run online multiplayer previews, and publish. Playing and
  guest-mode Studio use need no account.
- Signup: display name (3–20 chars, letters/digits/`_`/`-`) + email + password. Log in with either
  the display name or the email. Email verification is a 6-digit code (24h expiry, resendable);
  publishing, asset uploads, and all Studio cloud saves require a verified email.
- Password reset: emailed 8-character code (1h expiry) at homegames.io/reset-password.html.
- Developer profiles (bio, image, optional BTC address, published games, download/session totals)
  are public pages.

## The Developer Studio (homegames.io/studio.html)

A browser IDE for making games. Features:
- **Guest mode**: pick a template, edit, and run local previews with no account. The draft persists
  in the browser; creating an account later claims it (verified email required to claim).
- **Templates**: starter games — blank, click, keyboard, multiplayer, text input, image upload,
  animation, scrolling world, buttons, glow & fade — all targeting squish-142.
- **Editing**: file tree (folders, drag-to-move) + tabbed editor with syntax highlighting. "Save
  Version" commits — game source is Git-backed (each game is a real git repo on the platform's git
  server), so versions have real history; any version can be viewed and restored.
- **Preview**: "local" runs the game instantly in-tab (with a debugging inspector: frame recording,
  input timeline, node highlighting, simulated extra players); "online" hosts a real multiplayer
  session with a shareable link (account required).
- **Assets**: upload images/audio/fonts (drag & drop), draw images on a canvas, record audio, tag
  and describe assets, mark them public/private.
- **Guide button**: shows this authoring reference in-app and copies it to the clipboard for use as
  context with an external AI assistant.
- **AI editing**: the Studio has an end-to-end AI feature (an "AI Edit" button on existing games and
  a "Generate with AI" option when creating one) backed by a model running on Homegames' own
  hardware. The server-side endpoint is gated by a flag (`AI_EDITS_ENABLED`) that is **currently
  off**, so AI edits may be unavailable; the docs assistant ("ask something" on
  homegames.io/docs.html) is live but answers questions only — it does not write games.
- **Publish**: submit a saved version to the catalog (see Publishing below).

## Making games (essentials — the full contract is Part II)

- A game is a JavaScript class exported from `index.js` (`module.exports = MyGame`), extending
  `Game` (or `ViewableGame` for scrolling worlds) from a versioned squish package:
  `const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');`
- Required surface: `static metadata()` (must include `squishVersion` matching the require, plus
  `name`, `author`, `description`, `aspectRatio`, optional `tickRate`, `maxPlayers` (default 64),
  `services`, `assets`), a constructor calling `super()`, and `getLayers()` returning
  `[{ root: this.base }]`.
- The screen is a 100×100 grid; three node types (Shape, Text, Asset); colors are `[r,g,b,a]`
  0–255 arrays; state changes must be signaled with `onStateChange()`; players are numbers and
  `playerIds` on a node controls visibility, not ownership. All of this — and every gotcha — is
  specified precisely in Part II.

## Publishing

From the Studio, on a saved version (verified account required):
1. The game needs a description, a thumbnail, and edits beyond the starter template.
2. Automated validation runs:
   - `index.js` at the repo root, ≤ 5 MB per file, ≤ 20 MB total, no symlinks.
   - A **GPLv3 `LICENSE` file containing the exact GPLv3 text** (whitespace-normalized match).
   - A **substantive `README`** — at least ~40 characters of real content beyond headings.
   - `static metadata()` must contain **literal** `squishVersion` and `name` values (statically
     parsed, never executed).
   - An AST scan of every JS file: only `squish-NNN` and the game's own relative files may be
     required — no Node built-ins, no npm packages, no network, no filesystem, no `eval` /
     `new Function` / dynamic `require` / dynamic `import`.
   - A real sandboxed run in a network-isolated container: the game must load, render, and survive
     ~5 seconds of ticking **and simulated play** — two players join, keys are pressed, up to 25
     clickable nodes are clicked, a player disconnects. A throw during require, construction,
     `handleNewPlayer`, or `tick()` is a hard reject (input-handler throws are recorded as warnings).
3. On passing, the game is listed in the catalog automatically — there is no human review step just
   to get listed. Featured games are hand-picked. Uploaded images are automatically screened for
   NSFW content.
4. Every published game is GPLv3 and its source is browsable from its game page.

Publish requests can take a few minutes to process; status is shown in the Studio. Supported squish
versions for new publishes are 142/143/144 (default and recommended: 142).

## Assets (platform-side)

- Developers upload images, audio, and fonts in the Studio (verified account; 6 MB max per asset,
  100 assets per user). Supported types are detected from the file's actual bytes: images
  (JPEG/PNG/GIF/WebP/BMP), audio (MP3/WAV/OGG/FLAC/MP4/WebM), fonts (TTF/OTF).
- Assets get stable ids; games reference them by id in `metadata().assets`. Public assets appear in
  the shared asset catalog. Tags and descriptions are editable; NSFW flags apply (automatic
  screening plus admin override).

## Self-hosting

Summary of the current architecture (guide page: homegames.io/self-hosting.html):

- Run a Homegames server on a machine at home (Windows/macOS/Linux, Node.js 18+, git, and Docker
  for isolated game sessions). Clone the repos side by side — `homegames`, `homegames-core`,
  `homegames-client`, `homegames-common`, `squish` — `npm install` where needed, run
  `npm run build` in **homegames-client** (the core server serves its built bundle), then in
  `homegames/`: `node index.js`. **No sudo needed** — nothing binds ports 80/443.
- The launcher forks **homegames-core**, which is the whole server: one process on port **9801**
  serves the dashboard, the browser client, and the game WebSocket, and auto-opens a browser when
  ready. (homegames-web, the old separate static web server on 80/443, is legacy for local
  instances.)
- Then any device on the same network plays by visiting `homegames.link` in a browser. The server
  registers itself with the homegames.link service over an outbound connection only (no port
  forwarding or router config), heartbeating every ~10s; homegames.link matches visitors to servers
  by shared public IP and redirects the browser to the server's LAN address.
- **HTTPS on the LAN is opt-in** (`HTTPS_ENABLED`, default off; toggled from the dashboard's
  settings UI). When enabled, the network gets its own `*.homegames.link` subdomain (derived from
  the network's public IP) pointed at the server's LAN address, with a real Let's Encrypt
  certificate. The server generates its key locally and submits only a signing request — the
  private key never leaves the machine. The cert is issued in the background (a "setting up a
  secure connection" page auto-refreshes meanwhile) and takes effect after a restart, which the
  settings UI performs. Certs renew automatically (checked daily, renewed within 14 days of expiry,
  hot-swapped without restart).
- Game sessions run one per **Docker container** (image `homegames-runner`), on ports from
  `GAME_SERVER_PORT_RANGE_MIN/MAX` (8300–8400); players' browsers are redirected into that range,
  so the LAN must reach those ports. Firewalls or wifi "AP/client isolation" blocking 9801 or
  8300–8400 are the usual cause of "dashboard loads but games don't".
- ~50 built-in games ship with homegames-core; catalog games are browsed and downloaded from the
  platform API via the dashboard.
- Internet is needed for homegames.link discovery, catalog downloads, and certs; fully-offline LAN
  play works by visiting `http://<server LAN IP>:9801` directly.
- "No Homegames servers found" at homegames.link usually means the visiting device and server
  aren't on the same network from the internet's point of view (guest wifi, VLANs, VPNs) — or the
  server isn't running / hasn't heartbeated in the last 90 seconds.
- Config: the repo's `config.json`, overridden key-by-key by a user config in the OS app-data
  directory (written by the dashboard settings UI), overridden by env vars. Notable keys:
  `LINK_ENABLED`, `HOME_PORT` (9801), `GAME_SERVER_PORT_RANGE_MIN/MAX` (8300–8400), `HTTPS_ENABLED`,
  `START_PATH` (boot straight into one game instead of the dashboard), `PUBLIC_GAMES` (connect
  sessions to a public relay so internet players can join via a 4-character server code).
- Dev mode: `npm start` in homegames-core alone gives plain-HTTP LAN play on 9801.
- Hosting the entire platform (your own catalog/API) is possible — everything is open source — but
  is a much bigger project (MongoDB, RabbitMQ, a Forgejo git server, Docker, plus the api,
  homegamesio, worker, and homegames.link services).

## How the platform works (under the hood)

- Games are **server-authoritative scene trees**: the game maintains a tree of shape/text/asset
  nodes; the platform renders it and routes input back. Games never draw pixels or open sockets.
- The tree travels as **squish**, a compact binary serialization format (npm package `squishjs`),
  versioned so old games keep working — each game pins its `squishVersion`. Versioned aliases
  (`squish-142` = squishjs@1.4.2, etc.) are what games require; 142 is the platform default, and
  142/143/144 are the currently supported versions.
- The browser side is **homegames-client**: connects over WebSocket, decodes squish frames onto a
  canvas, sends input as JSON. The same engine powers the website player, hosted sessions,
  self-hosted dashboards, and offline downloads. It also contains **LocalSession** — a full
  in-browser runtime (the real squish engine plus a faithful port of the server's input pipeline)
  that runs single-player games entirely client-side.
- Hosted multiplayer sessions run **one Docker container per session**, managed by a session API
  ("Homenames") and a session manager that owns a port pool and tears down sessions ~30s after the
  last player or spectator leaves. Player ids run 1–127 (relay players 128–255); input is
  rate-limited to ~120 messages/sec per connection.
- **The platform API** (api.homegames.io) is a plain Node service backed by **MongoDB** (users,
  games, versions, assets, comments, publish/AI requests). Game source lives in a **Forgejo git
  server** behind the API — Studio saves are real commits. Background work flows through
  **RabbitMQ**: a `publish_requests` queue (publish validation worker) and a `homegames-jobs` queue
  consumed by a self-hosted worker that handles TLS certificate issuance (Let's Encrypt dns-01),
  AI game generation/editing, and docs questions. The AI jobs run on a local model served by
  LM Studio on Homegames' own hardware, grounded in this document.
- Main repos (github.com/homegamesio): `squish` (game library + serialization), `homegames-core`
  (game/session server + built-in games; serves the web client for local instances),
  `homegames-client` (browser engine + LocalSession), `homegames-common` (shared library: game
  loading, sessions, local play, saves, Docker helper — and this document), `homegames` (self-host
  launcher/supervisor), `homegames-api` / `api` (platform backend), `homegames.link` (LAN
  discovery + subdomain/DNS service), `worker` (background jobs: certs, AI, docs assistant),
  `homegamesio` (the website + Studio), `homegames-web` (legacy standalone web server).

## Misc facts

- License: everything is GPLv3, including published games.
- Contact/support: email joseph@homegames.io, or open a GitHub issue (github.com/homegamesio).
- Bugs/ideas: GitHub issues on the relevant repo under github.com/homegamesio.

## Answering guidance (for the docs assistant)

- If a question is about game code specifics, answer from Part II below — it is the authoritative
  reference. If it's still not covered, point to the docs page (homegames.io/docs.html) and the
  full guide (served at /authoring-guide, also via the Studio's Guide button) rather than guessing.
- If asked to generate a full game or large amounts of code: explain that this assistant doesn't
  write games, and point to the Studio's templates and docs. Small illustrative snippets are fine.
- If the question is unrelated to Homegames, say you can only help with Homegames.

---

# PART II — SquishJS Game Authoring: the contract for valid games

> Technical reference for writing Homegames games, verified against the real platform code — the squish library (`squish-142`, the default), the server's click/frame pipeline, the browser client, and the publish validator. If you generate a game, follow this contract exactly. Code that violates the **Hard Constraints** section will be auto-rejected by the publishing pipeline before a human ever sees it.

---

## 1. What a Homegames game is

A Homegames game is a **single JavaScript class** that extends `Game` from a versioned SquishJS package (the entry point is `index.js`, but the game may be split across as many of its own files as it likes via relative `require`s — see §2). The Homegames runtime instantiates the class, repeatedly serializes ("squishes") its scene graph into a compact binary form, and feeds it to a renderer. That runtime exists in **two places, and the same game code must run identically in both**:

- **Hosted session (multiplayer):** a Node server runs the game; every player's browser connects over WebSocket, renders frames, and sends input back. One shared instance serves all players.
- **Local session (single-player / instant play / downloads):** the player's own browser runs the game — the platform ships your source files to a `LocalSession` that executes the class client-side with the *same* squish engine, tick loop, input pipeline, and per-player frame logic. No server involved. This is how games on homegames.io play instantly, and how a downloaded game (a single self-contained HTML file) runs offline.

Your game cannot tell which one it's in, and must never try. Same constructor arguments, same handler payloads, same rendering — the deliberate differences are that a local session has exactly **one player** (id `1`), stubbed services, and no spectators. Persistence (`saveGame`/`saveData`, §3) works in both: hosted sessions save on the host (or deliver saves to players' browsers, per server config), local sessions save in browser storage.

Key mental model:

- **You never render or draw.** You build and mutate a tree of nodes (`Shape`, `Text`, `Asset`). The client draws them.
- **The node tree is the wire payload, not your data model.** Every dirty tick the whole tree is re-serialized and shipped to every player, so the tree should contain exactly what players need to **see, hear, and interact with right now — and nothing else**. Everything else the game knows (upcoming waves, the rest of the deck, the hidden word, long-term scores, entities outside the current fight) lives in **plain instance variables**, and only becomes nodes at the moment a player should experience it. When a player is done with something — a menu dismissed, a round ended, a screen replaced — its nodes come **out of the tree** (`removeChild`/`clearChildren`); the state they represented stays in your variables. There is no "keep it in the tree but hidden" optimization: a hidden node costs what a visible node costs (§4.1, §8). `ViewableGame` (§13) is this same idea extended to worlds bigger than one screen — each player's rendered view is just their current window into a larger space you model in data.
- **You never write networking.** The runtime multiplexes all players into one shared game instance. Player input arrives as method calls.
- **Treat browser globals as nonexistent.** There is no `window`, `document`, `location`, `alert`, `localStorage`, or DOM in your game's world. Hosted sessions run in Node, where `location.reload()` in a "play again" handler throws a `ReferenceError` and crashes the session. Beware the trap: a browser-side local session does NOT block these globals — a `window`-using game *appears to work* in local preview and then dies the moment it runs hosted. The same file must run in both runtimes, so the rule is absolute. Restart/replay is always done by **resetting your own state in place** — clear the relevant nodes, reset your variables, rebuild the play field.
- **The coordinate plane is `0–100` on both axes**, regardless of screen size or aspect ratio. `(0,0)` is top-left, `(100,100)` is bottom-right. Think percentages.
- **State changes are not automatic.** After you mutate a node, you must signal it (see §4). This is the #1 mistake — read §4 carefully.
- **The game is shared, not per-player.** One instance serves all players. Per-player visuals are done with `playerIds` (see §8), not separate instances.
- **Single-player is a first-class product path.** A game that does not declare the `multiplayer` service (§5) is presented on homegames.io with an instant in-browser "Play" button and is downloadable as an offline file. A game that *only* works with 2+ humans demos badly everywhere (§14.3).

---

## 2. Hard Constraints (your code is validated automatically)

The publish pipeline checks repo shape, statically parses metadata, runs an AST scan of every JS file, then loads and runs your game in a network-isolated Docker sandbox for ~5 seconds of simulated play. To pass:

1. **Entry point is `index.js` at the repo root** and it must `module.exports = YourGameClass;` (a class, not an instance). No symlinks anywhere in the repo.
2. **`require` only the SquishJS package and your own local files.** Use `require('squish-142')`. Do **not** require Node built-ins (`fs`, `http`, `https`, `net`, `child_process`, `os`, `path`, `crypto`, `cluster`, `dgram`, `vm`, `worker_threads`, etc.) — and **no npm packages either**; the only legal requires are `/^squish-\d+$/` and relative paths to the game's own files. Do not make network requests, touch the filesystem, spawn processes, or read `process.env`. Browser globals (`window`, `document`, `location`, `navigator`, `alert`) **do not exist** in hosted sessions — referencing any of them throws at runtime.
3. **No dynamic code execution:** no `eval`, no `new Function(...)`, no `require(variable)`, no dynamic `import()`, no string arguments to `setTimeout`/`setInterval`, no `constructor.constructor` tricks. And never call `process.exit()` — the validator treats it as a crash.
4. **`static metadata()` is required** and must return an object literal whose **`squishVersion` and `name` are literal values** (the pipeline statically parses them without executing your code — a computed value here fails publish outright), with `squishVersion` matching the package you imported (`'142'` for `squish-142`). If present, `tickRate` must be 1–120, `name` ≤ 100 chars, `description` ≤ 1000 chars.
5. **It must not throw** during `require`, construction, or the validation run. The sandbox doesn't just tick the game — it **simulates play**: two players join (`handleNewPlayer` throwing is a hard reject), keys are pressed (w/a/s/d/space/Enter/arrows), the mouse moves, **up to 25 clickable nodes get clicked at their centers**, and a player disconnects, all while `tick()` runs at your declared rate. Any `tick()` throw or uncaught exception = rejected. Exceptions inside input handlers (`onClick`, key handlers) are recorded as *warnings*, not failures — so a typo there can still ship and crash a real session. And code behind deeper phase gates (a second menu, a game-over screen) may never execute during validation at all. §15.1 tells you how to write that code so a typo can't hide in it. The initial scene must also squish cleanly (≤ 10,000 nodes at boot).
6. **Size limits:** total game ≤ 20 MB, any single file ≤ 5 MB. Keep assets external (referenced by id), not inlined.
7. **License and README:** published games are GPLv3 — a `LICENSE` file containing the exact GPLv3 text is required at publish time, **and so is a substantive `README`** (at least ~40 characters of real content beyond headings). Neither is your concern when generating game code itself, but don't add a conflicting license header.

Default to **`squish-142` / `squishVersion: '142'`** for all new games. The platform currently supports versions `142`, `143`, and `144` for new publishes (older versions like `1006`, `0767`, `136`, `138` exist in old games but can no longer be published); the version in the `require` and in `metadata()` must always match. `142` includes image cropping / spritesheets (§7.3.1) and shadow/glow effects (§7.4).

---

## 3. The Game class contract

Extend `Game` and implement these. Only `metadata()`, the constructor, and `getLayers()` are mandatory; the rest are optional hooks the server calls when present.

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');
const { COLORS } = Colors;

class MyGame extends Game {
    // REQUIRED. Static. Describes the game. squishVersion must match the require above.
    static metadata() { return { squishVersion: '142', name: 'My Game' /* ... */ }; }

    // REQUIRED. Build your initial scene graph. ALWAYS call super() first.
    constructor() {
        super();
        // build this.base and children here
    }

    // REQUIRED. Return the layer list. Almost always a single root.
    getLayers() {
        return [{ root: this.base }];
    }

    // OPTIONAL HOOKS (implement the ones you need):

    // A player joined. info.name is their display name.
    handleNewPlayer({ playerId, info, settings, clientInfo }) {}

    // A player left. Clean up their nodes/state.
    handlePlayerDisconnect(playerId) {}

    // Keyboard input. key is like 'ArrowUp', 'w', 'a', ' ', 'Enter', etc.
    handleKeyDown(playerId, key) {}
    handleKeyUp(playerId, key) {}

    // Pointer stream beyond clicks (see §9 for the press/drag model):
    handleMouseMove(playerId, { x, y }) {}   // while a pointer is held down
    handleMouseUp(playerId, data) {}         // pointer released

    // Called every frame. CAREFUL: defining tick() starts the loop even if you
    // never set metadata().tickRate — it then runs at a DEFAULT 60 fps. For
    // event-driven games, don't define tick() at all; for tick games, always
    // declare tickRate explicitly.
    tick() {}

    // Called when a LOCAL (in-browser) session ends; hosted sessions end by
    // process exit and never call it. Base Game.close() clears tracked timers
    // (see §10). Override to also remove nodes, but you usually don't need to.
    close() { super.close?.(); }
}

module.exports = MyGame;
```

**Save games (optional).** The constructor's option bag includes `saveGame` and `saveData`:

```js
constructor({ saveGame, saveData }) {
    super();
    // saveData: the previously saved JSON (or undefined on first play)
    this.clickCount = (saveData && saveData.clickCount) || 0;
    this.saveGame = saveGame; // call whenever your state is worth keeping
}
// later, e.g. at the end of a round:
//   this.saveGame({ clickCount: this.clickCount });
```

- `saveGame(data)` takes any JSON-serializable value (≤1 MB) and returns a Promise. The platform debounces writes (bursts coalesce, last call wins), so call it freely at natural checkpoints. Where the save lands — host filesystem, the players' browsers, or browser storage in local play — is the platform's business; identical in all environments.
- `saveData` is the loaded save (or `undefined`). **Treat it as untrusted input**: on some servers it round-trips through players' browsers, so guard every field access and validate shapes/ranges before using them.
- One save slot per game per version. To accept saves from earlier versions of your game, declare `saveCompatibility: ['<older-versionId>', ...]` in `metadata()`. Resolution is by **priority order, not timestamp**: the current version's own save is tried first, then each `saveCompatibility` entry in the order you declared it — the first save found wins. List newer versions first.
- Games decide *when* to save; there is no auto-save on disconnect or shutdown.

**Method signatures are exact and important:**
- `handleNewPlayer` receives a **single object** `{ playerId, info, settings, clientInfo, requestedGame }` — destructure it. `playerId` is a number. `info.name` is the player's name.
- `handlePlayerDisconnect(playerId)` receives the **bare id**, not an object. (If a player id reconnects while already connected, the runtime fires `handlePlayerDisconnect` for the old connection and then `handleNewPlayer` again.)
- `handleKeyDown(playerId, key)` / `handleKeyUp(playerId, key)` — two positional args.
- A node's `onClick` receives `(playerId, x, y)` — see §9.
- Other real hooks the runtime calls when present: `handleMouseMove(playerId, {x, y})` / `handleMouseUp(playerId, data)` (held-pointer stream, §9), `handleGamepadInput(playerId, input)` (repeated normalized gamepad input; see below), `handlePlayerUpdate(playerId, { info, settings })` (a player renamed themselves or changed settings).

> **If the runtime doesn't call it, it doesn't exist.** The hooks above are the complete lifecycle — there is no duck typing. A plausible-looking method the runtime never calls (`canAddPlayer()` as a join gate) is pure dead code: the game runs, the method sits there looking load-bearing, and everyone assumes it works. That's worse than an error — join capacity is *only* `metadata().maxPlayers`. When a behavior must exist, verify the mechanism is one named here (or a node `onClick`/`input`), and **delete** anything else so it can't mislead a later reader. (One method that IS honored despite looking optional: a `getAssets()` returning `{ key: Asset }` is merged into the asset bundle by the hosted engine — but the static parser that decides play modes only sees `metadata().assets`, so declare assets in the metadata literal anyway.)

---

## 4. The single most important rule: state changes need `onStateChange()`

Node properties (`coordinates2d`, `fill`, `color`, `text`, `playerIds`, ...) are **plain fields with no setters**. Mutating them updates your data but does **not** push anything to clients. You must notify after mutating:

```js
// Move a node and recolor it:
this.player.node.coordinates2d = ShapeUtils.rectangle(newX, newY, 5, 5);
this.player.node.fill = COLORS.RED;
this.base.node.onStateChange();   // <-- REQUIRED. Without this, nothing updates on screen.
```

Rules of thumb:
- After a batch of direct property mutations, call `onStateChange()` **once** on your root node (`this.base.node.onStateChange()`).
- The convenience methods that change tree structure already notify for you: `addChild`, `addChildren`, `removeChild`, `clearChildren`, and `BaseNode.update(...)`. You do **not** need an extra `onStateChange()` after those.
- In a `tick()` loop, do all your mutations, then one `onStateChange()` at the end.

Two equivalent ways to change a node:

```js
// (a) BaseNode.update() — sets fill and/or coordinates2d AND notifies:
this.box.update({ fill: COLORS.GREEN, coordinates2d: ShapeUtils.rectangle(10, 10, 20, 20) });

// (b) Direct field mutation + explicit notify:
this.box.node.fill = COLORS.GREEN;
this.base.node.onStateChange();
```

To change text, reassign the whole `text` object (then notify):

```js
this.scoreText.node.text = { text: `Score: ${this.score}`, x: 50, y: 10, size: 3, align: 'center', color: COLORS.WHITE };
this.base.node.onStateChange();
```

### 4.1 What a notify costs — and the node-pooling rule

Every notify — an explicit `onStateChange()` **or** one fired for you by `addChild`/`removeChild`/`clearChildren` — marks the tree dirty; at the end of the current event-loop turn the server **re-squishes the ENTIRE tree and re-broadcasts it to every player**. Bursts coalesce (mutating 50 nodes in one tick still produces one squish + one broadcast), so you don't pay per call — you pay **per dirty tick, proportional to total node count × players**. Consequences, in order of how badly generated games get them wrong:

1. **Only notify when something actually changed.** An unconditional `this.base.node.onStateChange()` at the bottom of `tick()` re-squishes and re-broadcasts the whole tree `tickRate` times per second even when the game is sitting on a menu. Track a `changed` flag and notify once, only when true (see §14.2).

2. **The tree holds what players are experiencing NOW; everything else is plain variables.** Every node in the tree is serialized on every dirty flush whether anyone can see it or not — a "hidden" node (`playerIds: [0]`, transparent fill, zero size) costs exactly what a visible node costs in squish CPU, and worse, `[0]`-scoped nodes still reach some clients (§8). So do **not** park inactive content in the tree as an "optimization": no pre-built menu screens waiting behind the gameplay, no ended-round scoreboards kept around invisibly, no roster of nodes for entities that aren't on screen. Model those in instance variables and **build nodes when a player should experience them, remove them when they're done** (`addChild`/`removeChild` at a screen transition is one structural notify — cheap, and it makes every subsequent flush smaller). The test for any node: *is some player seeing, hearing, or able to interact with this right now?* If not, it shouldn't be a node.

3. **Pool particle/trail/projectile nodes — never create/remove nodes per tick.** Per-tick `new GameNode.Shape(...)` + `addChild` + later `removeChild` churn (explosions, engine trails, bullets) grows the tree, generates garbage, and — because tree ops each mark the tree dirty — guarantees a full re-squish every single tick. It's also where orphan bugs hide (a node created but never added, or added but never removed on some code path, leaks forever). The correct pattern is a **fixed pool created once in the constructor, mutated in place, hidden when idle**:

```js
// Constructor: fixed pool, all hidden (zero-size, transparent).
this.particles = [];
for (let i = 0; i < 48; i++) {
    this.particles.push({
        active: false, x: 0, y: 0, vx: 0, vy: 0, life: 0,
        node: new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0),
            fill: [0, 0, 0, 0],
            color: [255, 255, 255, 255]
        })
    });
    this.base.addChild(this.particles[i].node);
}

// Emit: claim inactive slots (if none are free, just emit fewer — the pool is the budget).
emitBurst(x, y, fill, count) {
    for (const p of this.particles) {
        if (count <= 0) break;
        if (p.active) continue;
        count--;
        p.active = true; p.life = 20; p.x = x; p.y = y;
        /* set vx/vy */ p.node.node.fill = fill;
    }
}

// tick(): mutate in place; on death hide, don't remove. Fade via `color` alpha (§7.4).
for (const p of this.particles) {
    if (!p.active) continue;
    p.x += p.vx; p.y += p.vy; p.life--;
    if (p.life <= 0) {
        p.active = false;
        p.node.node.coordinates2d = ShapeUtils.rectangle(0, 0, 0, 0);
        p.node.node.fill = [0, 0, 0, 0];
        continue;
    }
    p.node.node.coordinates2d = ShapeUtils.rectangle(p.x, p.y, 0.6, 0.6);
    p.node.node.color = [255, 255, 255, Math.round(255 * p.life / 20)];
}
// ... then ONE onStateChange() for the whole tick.
```

   The same applies to enemies and pickups in wave games: cap the population, reuse dead slots. `addChild`/`removeChild` is for structural moments (screen transitions, players joining/leaving), not for the per-frame lifecycle of effects.

   **Pooling is the narrow exception to rule 2, not a license to hoard.** A pool exists for things that blink on and off many times per second *during active play* — where per-tick create/remove churn would cost more than the idle slots do. It is sized to the effect's peak (a few dozen nodes), and the whole pool should still come out of the tree at structural moments if the game leaves the phase that uses it. "Pool the particles" does not generalize to "keep everything ever created in the tree and hide it."

4. **Update `Text` by reassigning `node.text` — never remove-and-recreate the text node** to change a score/label. Recreation is churn, and it reorders the node's draw position in the tree.

5. **Budget node count and glow.** Total bandwidth ≈ node count × ~55 bytes × tickRate × players — keep the tree in the low hundreds of nodes. And the client renders `effects.shadow` with canvas `shadowBlur`, one of the most expensive canvas operations: glow a **handful of focal nodes** (title, the player's ship, a boss), not every enemy, particle, and pickup, or client framerate dies even when the server is fine.

---

## 5. `metadata()` reference

```js
static metadata() {
    return {
        squishVersion: '142',          // REQUIRED. Must match require('squish-142').
        name: 'Hot Potato',            // Display name.
        author: 'Your Name',           // Creator.
        description: 'One-line pitch shown in the catalog.',
        aspectRatio: { x: 16, y: 9 },  // Display aspect ratio. Common: {16,9}, {4,3}, {1,1}.
        thumbnail: 'asset-id-hash',     // Optional asset id used as the catalog thumbnail.
        tickRate: 20,                   // Frames/sec for tick(). If you define tick(), ALWAYS
                                        // declare this (an undeclared rate defaults to 60).
                                        // Must be 1-120. No game loop? Don't define tick() at all.
        maxPlayers: 8,                  // Optional session capacity (default 64). Joins beyond
                                        // this are refused by the platform — there is no
                                        // canAddPlayer() hook; capacity is this field.
        services: ['multiplayer'],      // Platform capabilities (see below). Omit entirely for
                                        // a single-player game — that is the common case.
        assets: {                       // Optional. Images/audio/fonts (see §11).
            'potato': new Asset({ id: '48685183f94c7a3c14f315444c6460bd', type: 'image' })
        }
    };
}
```

**`services` — how a game declares what it needs from the platform:**

- **Omit it (or leave out `'multiplayer'`) for single-player games.** The game gets an instant in-browser "Play" button on its homegames.io page (it runs client-side in a local session — no server, no waiting) and can be downloaded as a single offline HTML file.
- **`'multiplayer'`** — declares a multiplayer game. Its page gets a "Play with friends" flow: the platform spins up a hosted server session and gives the creator a shareable link that friends open to join. Multiplayer games are *also* playable/downloadable locally as a solo session (labeled "Play offline"), so they should still behave sensibly with one player (§14.3).
- **`'contentGenerator'`** — the game depends on the platform's server-side content-generation service. This **opts the game out of local play and downloads** entirely (the browser can't provide the service). Don't declare it unless the game actually uses it.

**`metadata()` must return an object literal, and the platform-facing fields must be literal values.** The platform decides a game's play modes (instant play, download eligibility, multiplayer) by **statically parsing the source** — it reads `squishVersion`, `name`, `services`, `assets`, and `thumbnail` out of the AST without ever executing your code, and the publish pipeline **rejects** a game whose `squishVersion` or `name` isn't a plain literal. Computed values for the other parsed fields (`services: SERVICE_LIST`, spread objects) are silently invisible — the game gets misclassified (e.g. a multiplayer game treated as single-player). Write the whole thing as a boring literal.

> **Which fields may derive from a tuning object (§15.2):** `tickRate` and `maxPlayers` are read at **runtime** from the executed `metadata()`, not by the static parser — so `tickRate: TUNING.TICK` and `maxPlayers: TUNING.MAX_PLAYERS` are safe and are the right way to keep those numbers in one place. The fields that must stay literal are exactly the statically-parsed ones: `squishVersion`, `name`, `services`, `assets`, `thumbnail`.

- The plane is always `0–100`; `aspectRatio` only controls how that square is presented (letterboxing on the client). Build your layout in `0–100` space and pick an aspect ratio that suits it.
- **Aspect-ratio distortion gotcha:** because the `0–100` square is stretched to fill the aspect rectangle, an x-unit and a y-unit are **not** the same size on screen unless the ratio is `{1,1}`. At `{16,9}` everything is wider than tall — a "square" looks like a rectangle, a `polyCircle` looks like an ellipse, and a 45° heading doesn't look like 45°. For UI/party games this is fine. For **rotation- or distance-based geometry** (twin-stick shooters, anything with circles, orbits, or true angles), prefer **`aspectRatio: { x: 1, y: 1 }`** so the math matches the pixels, or compensate for the ratio in your trig. To draw a **physically square** rect at ratio `{x, y}`, use `height = width * (x / y)` (e.g. at `{16,9}` a `2 × 3.56` rect renders square; at `{9,16}` use `2 × 1.13`).
- **Text size is relative to canvas WIDTH only.** A `size: s` line of text is `s%` of the canvas width tall in pixels — which is `s * (aspectX / aspectY)` **y-units** tall on the plane. At `{1,1}` a size-2 text is ~2 y-units tall; at `{16,9}` it's ~3.6; at `{9,16}` it's ~1.1. Use this to vertically center a label in a box: `textY = boxY + (boxH - size * aspectX / aspectY) / 2`. **Text width is NOT knowable server-side**: each client's canvas resolves the font (default `sans-serif`) with its own metrics, with advance widths anywhere from ~0.6 to ~0.85 of the font size. Budget wide (~`0.85 * size` x-units per character) when sizing boxes/wrapping so wide fonts don't overflow, and never position anything by summing character widths — to place a cursor or caret, embed it in the string itself (a `'▌'` glyph appended to the text lands exactly after the last character on every client; see the Typewriter game).
- `tickRate` is frames per second for `tick()`, bounded 1–120 at publish. **Every tick with a state change re-squishes and re-broadcasts the whole tree**, so high rates cost real bandwidth. In practice: **15–30 for action games** (shipped catalog games use 15–20 and feel snappy), **8–15 for casual/UI-driven games**. For purely event-driven games (click/turn-based) that update only in handlers, **don't define a `tick()` method at all** — merely defining one starts the loop, at a default **60 fps** if no `tickRate` is declared. Express all in-game durations as `seconds * TICK_RATE` so pacing tweaks don't silently change timers.

---

## 6. Coordinates and colors

**Coordinates** are `[x, y]` pairs in `0–100` space. A shape's `coordinates2d` is an array of vertices. Build rectangles and triangles with `ShapeUtils`:

```js
ShapeUtils.rectangle(x, y, width, height)
// returns [[x,y],[x+w,y],[x+w,y+h],[x,y+h],[x,y]]  (top-left origin, closed loop)

ShapeUtils.triangle(x1, y1, x2, y2, x3, y3)
// returns [[x1,y1],[x2,y2],[x3,y3],[x1,y1]]
```

You can also pass a raw vertex array for arbitrary polygons: `coordinates2d: [[10,10],[90,10],[50,90],[10,10]]`.

**Reading a rectangle's position/size back** (common in physics/collision code):

```js
const x = node.node.coordinates2d[0][0];
const y = node.node.coordinates2d[0][1];
const w = node.node.coordinates2d[1][0] - x;
const h = node.node.coordinates2d[2][1] - y;
```

> **Precision gotcha:** coordinates are serialized as an integer + a 2-decimal fraction, so the on-screen resolution is **~0.01 units** in `0–100` space. Movement smaller than that per frame rounds away — a `tick()` that adds `0.005` to a position will visually stutter or not move at all. Keep per-frame deltas ≥ ~0.05, or accumulate sub-unit motion in a plain variable and only write the rounded value into `coordinates2d`.

> **Off-plane / negative coordinates:** off-plane geometry is pinned at serialization, on every session type. The wire clamp is `[0, 255]`: **negatives pin to `0`** (there is no off-screen left or top — ever), and `100–255` survives serialization so content *may* slide off the right/bottom of a frameless canvas, but in a framed hosted session (where the platform bezel surrounds the game) it renders pinned against or under the frame instead. Since the same game runs in every session type, treat pinning as the rule everywhere: nothing is ever "just off-screen" — an enemy spawned at `y = -2` renders sitting *on* the edge, and content sliding off the right smears along the border instead of exiting cleanly. For entrances **and** exits, keep logical position in plain variables and only draw the node while it's fully on the plane (hide/remove it otherwise) — see the walk-on pattern below.
>
> **Walk-on entrances — hide until *fully* on-plane.** The variables-first pattern above generalizes: logical position lives in plain vars (negative values are fine there — `r.x = -4 - i * 7` staggers an entering crowd correctly), and the node is drawn only once the entity's **entire rendered box** fits on the plane. The gate is the sprite's **half-width, not zero**: an 8-wide sprite centered at `x` draws from `x - 4`, so the draw condition is `x >= 4` — below that, hide the node (`if (r.x < 4) { hideSprite(n); continue; }`). This bug is invisible in code review because the movement math is *correct* — only the draw smears along the edge. Audit every spawn-at-edge and walk-on entrance for it.

> **Vertex-count cap:** a node's `coordinates2d` is serialized into a length-limited wire frame — **at most 126 vertices per node** (verified: 126 round-trips, 127 breaks the frame). For detailed silhouettes (terrain skylines, rings, long strips) budget vertices: e.g. a destructible terrain polygon works at 96 columns (~100 vertices), and a "thick outline" strip that traces a path top-and-bottom doubles its vertex count — sample every other point to stay under the cap. Split very detailed geometry across multiple nodes.

**Colors** are `[r, g, b, a]` arrays, each `0–255`. `a` (alpha) of `0` is fully transparent, `255` fully opaque.

> **Color channels must be integers `0–255` — out-of-range values WRAP, they don't clamp.** Channels are written raw into the frame's byte buffer, so a computed value like `alpha: life * 8` that reaches `400` wraps to `144` mid-fade (the fade visibly flickers back on), and negatives wrap high. Clamp anything you compute: `Math.max(0, Math.min(255, Math.round(v)))`.

```js
const { COLORS } = Colors;
COLORS.RED;            // [255, 0, 0, 255]
COLORS.HG_BLUE;        // [148, 210, 230, 255]  (Homegames brand blue)
[0, 0, 0, 0];          // transparent (useful for invisible click targets / hit boxes)
Colors.randomColor();  // a random named color
Colors.randomColor(['BLACK', 'WHITE', 'ALMOST_BLACK']); // random, excluding by NAME
```

> **`randomColor` excludes by color NAME (string), not by value.** The exclusion list is matched against palette key names like `'BLACK'`/`'HG_BLUE'`, **not** color arrays — `Colors.randomColor([COLORS.BLACK])` silently excludes nothing (you passed an array, not the name). To keep, say, ships off a dark background, pass the names: `Colors.randomColor(['BLACK','ALMOST_BLACK','HG_BLACK','CHARCOAL'])`.

The complete named palette — these are the ONLY valid `COLORS.*` names:

```
ALMOST_BLACK, ALMOST_WHITE, ANTIQUE_WHITE, AQUA, AQUAMARINE, BEIGE, BIG_GRAY, BLACK, BLAY, BLUE,
BLUE_WHISPER, BLEEN, BLOOD, BOOGER, BRIGHT_GRAY, BRONZE, BROWN, CANDY_GREEN, CANDY_PINK, CANDY_RED,
CHARCOAL, CALM_BLUE, COOL_BLUE, COOL_GREEN, CORAL, CORPORATE_BEIGE, CREAM, CREAMSICLE, CYAN,
DARK_TURQUOISE, DEEP_BLUE, DEEP_PURPLE, DEEP_RED, DIM_GRAY, DULL_BLUE, EMERALD, EVERGREEN,
FRIENDLY_BLUE, FUCHSIA, FUNNY_PURPLE, GOLD, GOLDMEMBER, GRAY, GREEN, GUN_METAL_GRAY, HARD_ORANGE_RED,
HARD_PINK, HG_BLACK, HG_BLUE, HG_RED, HG_YELLOW, INTERIOR_RED, INVITATION_BLUE, KHAKI, LAVENDER,
LIGHT_CORAL, LIGHT_SEA_GREEN, NAVY, MAGENTA, MAROON, MEAN_SEA, MERLOT, MINT, MUSTARD, NEON_BOOGER,
NEON_PINK, ORANGE, ORANGE_RED, PALE_TURQUOISE, PEACH, PERFUME_PINK, PERRYWINKLE, PINK, POWDER_BLUE,
PURPLE, REAL_ESTATE_BLUE, RED, RUST, SALMON, SEA_GREEN, SHARP_YELLOW, SILVER, SIMPLE_GRAY,
SLEEPY_PINK, SMOKE, SMOOTH_BLUE, SOFT_GREEN, SOFT_MINT, SOFT_PINK, STRESSED_PURPLE, SKY_BLUE,
STANDARD_GRAY, STORM_GRAY, SUCCESS_GREEN, TEAL, TENSE_SKY, TERRACOTTA, THICK_LUXURY, TURQUOISE,
WALLPAPER_BEIGE, WALLPAPER_GREEN, WHITE, YELLOW
```

> **An invented color name fails SILENTLY as an invisible shape.** `COLORS.CHOCOLATE` or `COLORS.DARK_SAGE` isn't an error — it's `undefined`, and undefined fields are skipped at serialization, so the node renders with **no fill at all**. A "background that doesn't show up" or "shape that never appears" is very often a made-up palette name. If the exact color you want isn't in the list above, use an explicit `[r,g,b,a]` array (e.g. chocolate ≈ `[123, 63, 0, 255]`).

---

## 7. Node types

There are exactly three, all created via `GameNode`. All accept an optional numeric `id` and `playerIds`. `Shape` and `Asset` also accept `onClick`, `onHover`, `offHover`; `Text` accepts none of them (see §7.2).

### 7.1 `GameNode.Shape` — polygons, rectangles, lines

```js
const box = new GameNode.Shape({
    shapeType: Shapes.POLYGON,                      // POLYGON | LINE  (do NOT use CIRCLE)
    coordinates2d: ShapeUtils.rectangle(10, 10, 30, 20),
    fill: COLORS.CORAL,                             // interior color (RGBA). PREFER fill.
    color: [0, 0, 0, 255],                          // STROKE color — required if you set border
    border: 6,                                       // optional outline WIDTH (a number, see below)
    onClick: (playerId, x, y) => { /* ... */ },     // optional; makes it interactive
    effects: { shadow: { color: [0,255,255,255], blur: 12 } },  // optional neon glow (§7.4)
    playerIds: [42]                                  // omit entirely for visible-to-everyone. See §8.
});
```

- `shapeType` comes from `Shapes`: `Shapes.POLYGON` (the workhorse) or `Shapes.LINE`.
- **`Shapes.CIRCLE` exists as a constant but is NOT rendered — do not use it.** Approximate a circle with a many-sided polygon (see the helper below).
- **Use `fill` for the shape's interior color.** `color` is the **stroke** color, used together with `border`.
- **`border` is a single NUMBER, not an object.** It's an outline width on a `0–255` scale (the client renders it as `(border/255) * 0.1 * canvasWidth`, so small numbers like `2`–`10` are thin lines). The stroke is drawn in the node's **`color`** field — so **if you set `border` you MUST also set `color`**: a border with no color throws inside the client's render loop and **permanently freezes every player's screen** on the last painted frame. There is **no `border.color`/`border.width` object** — `border: { color, width }` squishes to garbage. Outlined shape = `fill` (interior) + `color` (stroke) + `border` (numeric width).
- Rectangles and arbitrary polygons via `POLYGON` cover ~95% of needs. `coordinates2d` is just a vertex list, so you can build **any polygon and rotate it with plain trig** — e.g. a ship triangle that points along an angle, or a round shape:

```js
// A round-ish polygon (since CIRCLE doesn't render). sides ~16 looks smooth.
const polyCircle = (cx, cy, r, sides = 16) => {
    const pts = [];
    for (let i = 0; i <= sides; i++) {
        const a = (i / sides) * Math.PI * 2;
        pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]);
    }
    return pts;   // closed loop (last point == first)
};
// A triangle rotated to face `angle` (radians), centered at (x,y):
const facing = (x, y, angle, size) => ShapeUtils.triangle(
    x + Math.cos(angle) * size,        y + Math.sin(angle) * size,
    x + Math.cos(angle + 2.6) * size,  y + Math.sin(angle + 2.6) * size,
    x + Math.cos(angle - 2.6) * size,  y + Math.sin(angle - 2.6) * size,
);
// A thick line / "stick" from (x1,y1) to (x2,y2) as a 4-corner polygon
// (paddles, chopsticks, laser beams, limbs — anything long and rotatable):
const thickLine = (x1, y1, x2, y2, width) => {
    const a = Math.atan2(y2 - y1, x2 - x1);
    const dx = Math.sin(a) * width / 2, dy = Math.cos(a) * width / 2;
    return [[x1 - dx, y1 + dy], [x2 - dx, y2 + dy], [x2 + dx, y2 - dy], [x1 + dx, y1 - dy], [x1 - dx, y1 + dy]];
};
```

> When a game has **mirrored geometry** (a left and a right of anything), compute it with ONE helper like the above called twice with mirrored arguments — never as two copy-pasted trig blocks. See §15.1 for why this rule exists.

- Transparent fill `[0,0,0,0]` + an `onClick` makes an invisible hit-box / button overlay (but see §9's hit-test rules — an invisible node still swallows clicks for things drawn beneath it). Zeroing a node's size and fill (`rectangle(0,0,0,0)`, `[0,0,0,0]`) is how a **pooled effect node** idles between uses (§4.1) — that's the only "hide in place" case. Anything hidden for longer than an effect's off-beat should be **removed from the tree** instead: hidden nodes are still serialized and shipped on every dirty flush, and `playerIds = [0]` doesn't even reliably hide (it leaks to spectators and frame-less players — §8).
- A `Shape` can also carry an `input` field (to act as an on-screen text box) and `onHover`/`offHover` callbacks — see §9.

### 7.2 `GameNode.Text`

```js
const label = new GameNode.Text({
    textInfo: {
        text: 'Hello',
        x: 50, y: 20,        // anchor position in 0–100 space
        size: 2,             // relative font size (1 ≈ small, 3 ≈ large heading)
        align: 'center',     // 'left' | 'center' | 'right'
        color: COLORS.WHITE,
        font: 'default'      // optional
    }
});
```

Note the field is `textInfo` in the constructor, but it is stored on the node as `node.text` (so you update it via `label.node.text = {...}`, see §4).

> **Always set `color` on Text.** Omitting it doesn't default to black — it crashes serialization. Treat `color` as required.

> **No newlines, no wrapping.** The client draws each `Text` node with a single canvas `fillText` call: a `'\n'` in the string does NOT line-break (the whole thing renders as one line), and long text never wraps on its own. For multi-line text (instructions, "GAME OVER\nFinal Score" screens), create **one `Text` node per line** and space them vertically — line height in y-units is `size * (aspectX / aspectY)` (§5), so at `{16,9}` size-2.5 lines sit nicely ~5 y-units apart.

> **Hard length cap: ~154 characters per Text node.** A Text node's wire subframe is length-limited; beyond ~154 characters (fewer with a long font name) the frame silently corrupts — the text truncates and other node fields break, with no error. Keep every Text node's string well under this (it's far more than fits on screen at readable sizes anyway); long passages are multiple nodes.

> **Text nodes are NOT clickable.** On `squish-142` (the default) the `Text` constructor only accepts `{ textInfo, playerIds, input, node, id }` — `onClick`/`onHover`/`offHover` are silently dropped. On `squish-144` the constructor accepts them, but it makes no practical difference: the server's click hit-test only considers nodes with `coordinates2d`, which Text doesn't have, so a Text `onClick` is still unreachable. **To make a clickable text label / "button", put the click handler on a `Shape` and render the `Text` on top of it** — see §7.2.1.

#### 7.2.1 Text is not a button — build buttons from a Shape + Text

There is no button node and text cannot receive clicks. A "button" is just a **clickable `Shape` polygon with a `Text` node positioned on top of it**. The `Shape` carries the `onClick` and the visible background; the `Text` carries the label and must be drawn *after* (or as a sibling added after) the shape so it sits on top. Size the shape — not the text — to define the tap target, and center the text over it.

```js
// Reusable helper: a rectangular button at (x,y) sized (w,h) with a centered label.
makeButton({ x, y, w, h, label, fill, onClick }) {
    const bg = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(x, y, w, h),
        fill,
        onClick   // the SHAPE is what's clickable
    });
    const text = new GameNode.Text({
        textInfo: {
            text: label,
            x: x + w / 2,        // horizontal center of the shape
            y: y + h / 2 - 1.5,  // nudge up so the text baseline looks vertically centered
            size: 2,
            align: 'center',     // pairs with x being the center
            color: COLORS.WHITE
        }
        // NO onClick here — it would be ignored. The bg shape handles the tap.
    });
    bg.addChild(text);           // text rides along as a child of the button background
    return bg;
}

// usage:
const startBtn = this.makeButton({
    x: 35, y: 45, w: 30, h: 12, label: 'Start', fill: COLORS.GREEN,
    onClick: (playerId, x, y) => this.startGame(playerId)
});
this.base.addChild(startBtn);
```

Notes:
- The text's `x`/`y` are independent plane coordinates, **not** relative to the parent shape — compute them from the shape's position (`x + w/2`, etc.). Adding the text as a child of the shape only affects render order and tree cleanup, not positioning.
- Because the text is a child of the button shape, removing the button (`removeChild(bg.id)`) removes the label with it.
- The whole shape is the hit target, so the player can tap anywhere on the button — including directly on the letters — and the shape's `onClick` fires. The text being non-interactive doesn't create a "dead zone".
- For an invisible text-over-image button, use the same pattern with a transparent fill `[0,0,0,0]` or an `Asset` node as the background.

### 7.3 `GameNode.Asset` — images and audio

```js
const sprite = new GameNode.Asset({
    coordinates2d: ShapeUtils.rectangle(30, 35, 40, 30),  // click/tap bounds of the node
    assetInfo: {
        'potato': {                       // KEY must match a key in metadata().assets
            pos:  { x: 30, y: 35 },       // where the image's top-left sits, 0–100 space
            size: { x: 40, y: 30 }        // image width/height, 0–100 space
        }
    }
    // playerIds omitted -> visible to everyone (§8); scope only genuinely private UI
});
```

> **The picture and the hit area are independent.** The image is drawn from `assetInfo`'s `pos`/`size`; clicks and hover hit-test against the node's separate `coordinates2d`. Keep them aligned (same x/y/w/h, as above) or the tap target won't match what the player sees.

Audio is also an `Asset` node — give it zero size and a `startTime` (seconds into the clip):

```js
const sound = new GameNode.Asset({
    coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0),
    assetInfo: {
        'hiss': { pos: { x: 0, y: 0 }, size: { x: 0, y: 0 }, startTime: 0 }
    }
});
// Add it to the tree to play; remove it to stop:
this.base.addChild(sound);
this.setTimeout(() => this.base.removeChild(sound.id), 250);
```

The `assetInfo` key (`'potato'`, `'hiss'`) is a **reference to `metadata().assets`** — you do not embed image/audio bytes in the game; you reference them by the asset id declared in metadata.

> **Audio is deduped by asset KEY, not by node.** The client tracks playing sounds per key: two nodes with the same key play one sound, and a sound only restarts after its key has been absent from at least one rendered frame — a remove + re-add in the same tick won't re-trigger it, and a sound that finished playing won't replay while its node just sits in the tree. So the pattern is always **add to play, remove when done, re-add to replay**. Two platform behaviors games don't manage: browsers keep all audio silent until the player's first tap/click/keypress (autoplay policy — don't front-load a sound before any interaction), and players who mute sound in their settings simply don't get audio; games do nothing about either.

### 7.3.1 Cropping an image / spritesheets (`squish-139`+)

An image `Asset` can show just a **rectangular sub-region** of its source image instead of the whole thing, via four optional fields inside `assetInfo[key]`:

```js
const tile = new GameNode.Asset({
    coordinates2d: ShapeUtils.rectangle(10, 10, 10, 10),
    assetInfo: {
        'sheet': {
            pos:  { x: 10, y: 10 },
            size: { x: 10, y: 10 },
            // Crop: percentage (0–100) of the SOURCE image to cut off EACH edge.
            cropLeft: 0, cropTop: 0, cropRight: 50, cropBottom: 50   // show the top-left quarter
        }
    }
});
```

- The crop fields are an **inset per edge, in percent of the source image** — `cropLeft: 25` drops the left 25% of the image, `cropRight: 25` drops the right 25%, etc. All default to `0` (whole image).
- The surviving sub-region is then **stretched to fill `pos`/`size`** (no automatic aspect-ratio preservation) — so pick a `size` whose aspect matches the cropped region if you don't want distortion.
- `cropLeft + cropRight` (and `cropTop + cropBottom`) must be `< 100`; an inset that collapses the region is ignored and the full image is drawn.

This unlocks **spritesheets and tilemaps from a single asset** — pack many frames/tiles into one image and crop to the one you want. To select frame `(col, row)` from a `cols × rows` grid:

```js
const frameCrop = (col, row, cols, rows) => ({
    cropLeft:   (col / cols) * 100,
    cropRight:  ((cols - 1 - col) / cols) * 100,
    cropTop:    (row / rows) * 100,
    cropBottom: ((rows - 1 - row) / rows) * 100,
});
// animate by reassigning assetInfo each tick:
this.sprite.node.asset = { 'sheet': { pos, size, ...frameCrop(this.frame, this.facing, 8, 4) } };
this.base.node.onStateChange();
```

> **Version gate:** cropping requires **`squish-139` or newer** — included in the default `142`. On `138` and earlier the crop fields are silently ignored (the image renders whole, no error).

### 7.3.2 Sprite-with-shape-fallback — developing before the art lands

§11 says "no real asset ids → draw with shapes." The production version of that advice is a **hybrid system**: every visual is created through one factory that returns a real `Asset` node when its id is registered and a colored placeholder `Shape` otherwise, so art can land incrementally with zero call-site changes. Four rules make it hold up:

1. **One factory, one placement method.** `mkSprite(key, fallbackFill)` tags sprite nodes (`n._sprite = true; n._key = key`), and **all** positioning flows through a single `placeSprite(n, key, x, y, w, h)` that writes both `coordinates2d` and the `asset` field (with an optional key swap for animation/type changes). If a squish version ever renames the placement field, the fix is one method, not a hundred call sites. Pair it with a `hideSprite(n)` that zeroes both.

2. **Grouped assets activate all-or-nothing.** If a pooled node swaps between asset keys at runtime (four enemy breeds on one node, three weapon icons), the sprite path must activate only when **every** key in the group is registered — otherwise a mid-game key swap points at a missing asset. One readiness check per group (`lemonSpritesReady()`), passed into the factory as an override.

3. **Shapes tint; sprites can't — design a parallel signal per mode.** Placeholder shapes convey state by fill color (windup = red flash, drained = gray). Sprites need a different channel: windup = 25% size puff, broken structure = shrunken node, invulnerability = blink the sprite on/off, damage = lean on the impact splash + floating number. Decide the signal at each call site with an `if (node._sprite)` branch. A tint-only telegraph **silently disappears the day real art lands** — which is exactly when nobody is retesting telegraphs.

4. **Placeholder chrome must self-hide.** Labels and signs that exist only to decorate a fallback shape (a "LEMONADE" text on a placeholder stand) need `if (node._sprite)` guards so they vanish when the real art arrives.

### 7.4 Effects (glow) and transparency — the rules that actually work

**Glow / shadow.** `Shape` and `Asset` nodes accept an `effects` field; the only supported effect is a drop shadow, which doubles as a **neon glow** — the signature look of the first-party catalog:

```js
const glow = (color, blur) => ({ shadow: { color: [color[0], color[1], color[2], 255], blur } });

new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(40, 40, 20, 20),
    fill: [0, 255, 255, 255],
    effects: glow([0, 255, 255, 255], 14)   // cyan glow, blur 14
});
```

- `blur` is a number (canvas `shadowBlur` pixels); `6–12` is a subtle glow, `16–30` dramatic, `40` an explosion flash.
- To remove an effect, set `node.node.effects = null` (never `{}` — an empty object crashes serialization).
- **`Text` nodes do NOT accept `effects`.** To give a title/banner a glow, fake it with **4 dim offset copies under a bright core** — the standard pattern:

```js
makeGlowText(text, x, y, size, color, glowColor, playerIds) {
    const gc = glowColor || color;
    const offsets = [[-0.25, 0], [0.25, 0], [0, -0.25], [0, 0.25]];
    const nodes = offsets.map(o => new GameNode.Text({
        textInfo: { x: x + o[0], y: y + o[1], text, size, align: 'center', font: 'monospace', color: [gc[0], gc[1], gc[2], 140] },
        playerIds
    }));
    nodes.push(new GameNode.Text({ textInfo: { x, y, text, size, align: 'center', font: 'monospace', color }, playerIds }));
    return nodes;   // add all to the tree; the bright core is last so it draws on top
}
```

**Transparency and fading — `fill` alpha is nearly binary; real fades use `color` alpha.** The client renders `fill`'s alpha byte through CSS, which clamps it: `fill[3] = 0` is invisible, but **any `fill[3] ≥ 1` renders essentially opaque** — you cannot fade a shape by animating `fill` alpha. What actually fades a node is the **`color` field's alpha**, which drives the canvas global alpha for that node:

```js
// Fade a node out over time (e.g. a particle or a "derez" trail):
node.node.color = [r, g, b, Math.round(255 * lifeRemaining / lifeTotal)];
this.base.node.onStateChange();
```

The glow fades along with the node (the shadow is composited under the same per-node alpha), so no special handling is needed when fading a glowing node. This all applies to **`Asset` image nodes too**: their `color` alpha fades the image, and they honor `effects.shadow`.

**The pooled-fade recipe** (hit splashes, expanding rings, attack flashes). Anything created with a translucent-looking fill like `[r, g, b, 110]` and never fixed will render **fully opaque** and look like a paint blob — a very common shipped bug because it's only wrong on screen, not in code. The working pattern: fill carries the hue at full alpha; `color` carries the fade. Setting `color` on a shape with no `border` is legal and does nothing *except* drive alpha — that's the whole trick:

```js
// creation (pooled, hidden): fill fully opaque, color channel holds the translucency
mk([255, 230, 80, 255], { color: [255, 255, 255, 210] })

// per-tick fade-out:
const k = f.ttl / f.max;                                  // 1 -> 0
node.node.fill  = [f.color[0], f.color[1], f.color[2], 255];
node.node.color = [255, 255, 255, Math.round(210 * k)];   // the actual fade (clamp per §6)
```

---

## 8. Player visibility model (`playerIds`)

Every node has `playerIds`, an array controlling who sees it. **Get these semantics right — they are commonly stated backwards:**

- `[]` (empty — the default when you omit `playerIds`) → **visible to all players.**
- `[42]` → visible only to player `42`.
- `[42, 99]` → visible to players `42` and `99`.
- `[0]` → scoped to a player id that never exists (real ids start at 1), so **no player's filtered frame includes it**. This exists so a per-player node's visibility set can go empty — it's what `hideFor` leaves behind when the last viewer is removed. It is **NOT a general "hide this node" switch**: the node is still serialized into the master state on every dirty flush, and any client that receives the *unfiltered* state — **any player with zero scoped nodes, and spectators in frameless sessions** (see the privacy caveat below) — receives it and **renders it on screen**. A node nobody should experience anymore doesn't get `[0]` — it gets **removed from the tree** (a JOIN button once everyone has joined is a `removeChild`, and its "joined" state is a variable).

> **`playerIds` is VISIBILITY, not ownership — do NOT tag gameplay entities with their controller's id.** The most common generated-game bug: giving each player's ship/avatar `playerIds: [playerId]` "because it's theirs". That **hides every ship from every other player** — in multiplayer everyone sees an empty arena with enemies chasing invisible targets. Nodes need no player tag to be controlled by a player; input is already routed per player via the `playerId` argument to `handleKeyDown`/`onClick`. Leave shared-world entities (avatars, ships, bullets, enemies, pickups) **unscoped** (omit `playerIds` entirely), and scope only genuinely private UI: a hand of cards, a personal HUD, a "YOU" marker.
>
> Relatedly: **player ids are the numbers the server hands you** in `handleNewPlayer`/input handlers. Never invent or renumber them (e.g. `Object.keys(this.players).indexOf(id) + 1`) — ids are not dense, don't start at your join order, and a derived id scopes the node to the wrong player or to nobody. (For reference: hosted ids come from a 1–127 pool, with 128–255 reserved for relay-joined players; each connection's input is rate-limited to ~120 messages/sec.)

Scoping applies to the **whole subtree**: keep a child's `playerIds` a **subset of its parent's** (same set, or narrower). A child scoped to a player *outside* its parent's set is a bug that half-works — the squisher will still put that child in the outside player's frame (rendered floating without its parent's visuals), but the click pipeline walks the tree top-down and stops at the parent, so that player can see it and never click it. For a scoped button, set the same `playerIds` on both the shape and its label. Clicks respect scoping — a node scoped away from a player can't be clicked by them (§9).

This is how you build per-player UI (private hands, individual HUDs, "your turn" prompts) in a single shared game. Helpers on every node:

```js
node.showFor(playerId);   // add a player to the visibility set (and drop a hiding 0)
node.hideFor(playerId);   // remove a player; if none left, sets [0] (hidden from everyone)
// CAREFUL: showFor/hideFor do NOT notify — like direct mutation, they need an
// onStateChange() afterward or nothing changes on screen:
node.node.playerIds = [playerId];   // (direct set, same deal)
this.base.node.onStateChange();
```

> **Privacy caveat (secrets games, frameless sessions):** the server builds a filtered frame only for connections that appear in **at least one node's `playerIds`**. A connected player with **zero** nodes scoped to them falls back to the raw unfiltered state — i.e. **they receive everyone's "private" nodes, and every `[0]`-"hidden" node too**. In framed sessions the platform chrome scopes a node to every player and spectator, masking this; in frameless sessions (studio / website hosted-play flows) it's live for players and spectators alike. If your game has real secrets (hidden words, private hands), give **every connected player** a persistent scoped node in `handleNewPlayer` — a zero-size invisible "privacy anchor" is enough:
>
> ```js
> handleNewPlayer({ playerId }) {
>     const anchor = new GameNode.Shape({
>         shapeType: Shapes.POLYGON,
>         coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0),
>         playerIds: [playerId]
>     });
>     this.anchors[playerId] = anchor;
>     this.base.addChild(anchor);
>     // remove it in handlePlayerDisconnect
> }
> ```

> **Frameless identity:** don't rely on the platform frame to tell players who they are — frameless sessions have no chrome, and `info.name` can be absent (fall back to `'PLAYER ' + playerId`). Wherever the game shows a roster (lobby list, scoreboard, turn order), add a small **"YOU" marker scoped to each player** next to their own entry, and when a player is assigned a color/avatar, show them a scoped "YOU ARE THE CYAN SHIELD"-style banner.

Example — give each player their own colored marker only they can see:

```js
handleNewPlayer({ playerId }) {
    const marker = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(45, 90, 10, 5),
        fill: Colors.randomColor(),
        playerIds: [playerId]   // only this player sees it
    });
    this.players[playerId] = marker;
    this.base.addChild(marker);
}
```

---

## 9. Input

### Clicks / taps
Attach `onClick` to a **`Shape` or `Asset`** node (the only node types that accept it — **`Text` does not**, see §7.2). Signature: **`(playerId, x, y)`** — the clicking player's id, and the click position in `0–100` plane space. To make a clickable label, put the `onClick` on a `Shape` and lay a `Text` node on top of it (§7.2.1).

```js
const button = new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(40, 40, 20, 20),
    fill: COLORS.GREEN,
    onClick: (playerId, x, y) => {
        // Only the owner may press their button:
        if (Number(playerId) === Number(this.ownerId)) this.doThing();
    }
});
```

Clicks and taps are unified — `onClick` fires for both mouse and touch. Make tap targets generously sized for mobile.

**What a HELD press does depends on the squish version:**
- On **`squish-142`/`143`** (the default), a held pointer **re-fires `onClick` on the pressed node every ~30 ms** for as long as it's held. Held-tap "auto-repeat" is free (nice for hold-to-move buttons), but expensive `onClick` bodies get hammered — keep them cheap, or debounce with a tick counter.
- On **`squish-144`+**, a press fires `onClick` **once**; while held, the client streams pointer moves that drive `game.handleMouseMove(playerId, {x, y})` and the pressed node's **`onDrag(playerId, x, y)`**; release fires the node's **`offClick(playerId, x, y)`** and `game.handleMouseUp(playerId, data)`. Releases are closed out robustly (off-canvas release, tab blur, the node being removed mid-drag) — this is the drag-and-drop API.

#### 9.1 Click routing: the topmost node wins, clickable or not

The server resolves a click to the **topmost node whose polygon contains the point** — draw order (parent before children, siblings in insertion order; later = on top). Crucially, **it does not skip non-clickable nodes**: if the topmost containing node has no `onClick`, the click is **silently dropped** — it does not fall through to a clickable node underneath. Two consequences:

1. **Container/layer nodes must be zero-size.** The common pattern of grouping nodes under invisible full-screen `Shape` "layers" (HUD layer, particle layer, overlay) will **swallow every click on anything drawn beneath them** if those containers are `rectangle(0, 0, 100, 100)`. Make containers `rectangle(0, 0, 0, 0)` — children render and receive clicks normally, and the container itself can never intercept a click:

```js
makeContainer() {
    return new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0)   // zero-size: never swallows clicks
    });
}
```

2. **Full-screen tap steering needs a dedicated tap-catcher.** Putting `onClick` on your background/root doesn't work once anything is drawn over it — taps land on trails, enemies, terrain, etc. and die there. Instead add a transparent full-screen `Shape` **above the playfield but below the UI buttons**, and put the tap handler on it (buttons must be later siblings so they still win):

```js
this.tapCatcher = new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),   // no fill -> invisible, still clickable
    onClick: (playerId, x, y) => this.handleTap(playerId, x, y)
});
// draw order: playfield layers, THEN tapCatcher, THEN hud/overlay (buttons)
this.base.addChildren(this.trailLayer, this.particleLayer, this.tapCatcher, this.hud, this.overlay);
```

Also: `playerIds` scoping applies to clicks (a node hidden from a player can't be clicked by them — this is how per-player buttons work), and `Text` nodes never intercept clicks (no `coordinates2d`), so a button's label can't create a dead zone.

### Keyboard
Implement `handleKeyDown(playerId, key)` / `handleKeyUp(playerId, key)`. `key` is the standard browser key string: `'ArrowUp'`, `'ArrowDown'`, `'ArrowLeft'`, `'ArrowRight'`, `'w'`, `'a'`, `'s'`, `'d'`, `' '` (space), `'Enter'`, single characters, etc. The client forwards printable characters (`' '`–`'z'`, including capitals and digits), the arrow keys (plus `Home`), `Backspace`, `Enter`, and `Meta` — nothing else, and **no keys at all while Meta is held** (so OS shortcuts pass through). Support both arrows and WASD for movement.

**How held keys actually arrive:** the client sends one `keydown` on the physical press, then **re-sends `keydown` every ~33ms while the key is held — with NO initial delay** — and sends a debounced `keyup` on release. This is ideal for movement (hold-to-move just works) and catastrophic for typing: a normal ~100ms keystroke delivers 3–4 duplicate `keydown`s, so naive `buffer += key` types `"hhhh"`.

#### Live typing (a text editor that feels like a document)

`input: { type: 'text' }` (below) opens a **modal prompt** — fine for one-shot entry (a name, a guess), wrong for live typing. For text that appears on screen as the player types, build on raw `handleKeyDown` and reconstruct real keyboard feel by gating the 33ms re-sends like an OS keyboard: a key not seen recently is a fresh press (types instantly); while held, the re-sends are a *hold heartbeat* that only types after an initial delay, then at a fast repeat rate. This also makes held-Backspace erase properly.

```js
// per player: writer.keys = {}
handleKeyDown(playerId, key) {
    if (key !== 'Backspace' && key !== 'Enter' && key.length !== 1) return;
    const now = Date.now();
    const state = this.writers[playerId].keys[key];

    if (!state || now - state.lastSeen > 400) {          // fresh physical press
        this.writers[playerId].keys[key] = { lastSeen: now, repeatAt: now + 450 };
        this.applyKey(playerId, key);                     // type it IMMEDIATELY
        return;
    }
    state.lastSeen = now;                                 // held: heartbeat
    if (now >= state.repeatAt) {                          // repeat after 450ms,
        state.repeatAt = now + 55;                        // then ~18 chars/sec
        this.applyKey(playerId, key);
    }
}
handleKeyUp(playerId, key) { delete this.writers[playerId].keys[key]; }
// applyKey: append / Backspace-slice / '\n' on Enter, re-render the text
// nodes, then onStateChange() — mutate in the handler, not in tick(), so
// letters land on screen with zero added latency.
```

The 400ms staleness check doubles as a safety net: if a `keyup` is ever lost, the key un-sticks by itself. See `src/games/text-input` (Typewriter) in homegames-core for the complete pattern with wrapping, a blinking cursor, and a tap-to-type prompt fallback for phones.

> Mobile players have no physical keyboard. If your game needs keyboard control, also provide on-screen `onClick` buttons (or the `input:{type:'text'}` prompt for text), or design click/tap-first.

### Gamepad input

Games do not import Homepad. The platform normalizes controllers and routes them to the same player in hosted and local play. To reuse your keyboard handlers, add a literal `gamepadBindings` object to `metadata()`:

```js
gamepadBindings: {
    ArrowLeft: ['DIRECTION_LEFT', 'STICK_1_LEFT'],
    ArrowRight: ['DIRECTION_RIGHT', 'STICK_1_RIGHT'],
    ArrowUp: ['DIRECTION_UP', 'STICK_1_UP'],
    ArrowDown: ['DIRECTION_DOWN', 'STICK_1_DOWN'],
    ' ': 'FACE_1',
}
```

Bindings call `handleKeyDown` repeatedly while held and `handleKeyUp` on release. An array means either control activates that key. Button names are positional: `FACE_1/2/3/4` are bottom/right/left/top, regardless of printed labels. Other controls include `LEFT_TRIGGER`, `RIGHT_TRIGGER`, `LEFT_SHOULDER`, `RIGHT_SHOULDER`, `START`, `SELECT`, and `STICK_CLICK_1/2`. Both sticks support `_LEFT`, `_RIGHT`, `_UP`, `_DOWN` bindings (threshold 0.5 after the dead zone).

For analog control or button edges:

```js
handleGamepadInput(playerId, { input, gamepadIndex, connected, deltaTime, pressed, released }) {
    // sticks are -1..1 after dead-zone removal; buttons have { value, pressed }.
    const x = input.sticks.STICK_1_X.value;
    const y = input.sticks.STICK_1_Y.value;
    // Apply speed * deltaTime for movement; deltaTime is seconds, capped at 0.1.
    // pressed.includes('FACE_1') fires once, even if the button stays held.
    // connected === false has neutral inputs and deltaTime === 0: clear stored state.
}
```

Delivery repeats up to 30 Hz, including unchanged held controls; it is not tied to screen refresh rate. The rate is reduced for more than two controllers sharing one player to keep the total at 60 messages/second. Focus loss, hiding the page, disconnecting a controller, and detaching input send neutral releases. Button edge arrays are calculated per player/controller. The platform combines keyboard and mapped controller keys so one source's release does not cancel another's hold. A game's `handlePlayerDisconnect` must still clean up that player's state.

Both hooks run if you implement raw input and declarative bindings. Do not move the same entity twice. See `src/games/gamepad-test` for a complete bindings/diagnostic example, `move-test` for analog movement, and `halloween-words` for bindings added to a keyboard game.

### Text input (on-screen fields)

Besides clicks and keyboard there is a third input path: a node can act as a **text entry point** via an `input` property. It is accepted on **`Shape` and `Text`** nodes (not `Asset`). Tapping the node opens the browser's native **one-shot text prompt** (a modal — nothing is rendered inline over the node); when the player submits, your `oninput(playerId, value)` is called **once** with the full submitted string (cancelling sends nothing):

```js
const searchBox = new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(20, 5, 60, 10),
    fill: COLORS.WHITE,
    input: {
        type: 'text',
        oninput: (playerId, value) => {
            this.query = value;             // `value` is the full current text, not one keystroke
            this.runSearch(playerId);       // mutate state, then onStateChange()
        }
    }
});
```

- `oninput` fires once per submission; treat `value` as the field's entire submitted string, not a keystroke.
- This is exactly the mechanism the Homegames dashboard's own search box uses, so it is the same well-trodden path the platform relies on.
- Scope the field with `playerIds` (§8) so only the intended player sees it. Note that unlike clicks, `oninput` and hover events are routed by node id **without a server-side scope check** — visibility scoping is a rendering concern, not a security boundary, so validate inside the handler (check the `playerId` argument) if it matters who submits.
- There is also `type: 'file'` for uploads (images and audio). Its handler is `oninput(playerId, bytes, meta)`: `bytes` is a **`Buffer`** (hosted sessions) or **`Uint8Array`** (local play) — array-like binary data, never a plain JS array — and `meta` is `{ kind, contentType, fileName }` where `kind` is `'image'`, `'audio'`, or `null` (sniffed from the file's magic bytes, falling back to the client-reported `contentType` prefix when sniffing fails — prefer checking `kind`, but treat all of `meta` as advisory). Uploads are capped at 5 MB by the file picker; oversized **images** are transparently re-encoded/shrunk to fit rather than rejected (animated GIFs flatten to their first frame), while oversized audio is rejected. The server itself accepts up to 8 MB. To use an upload, wrap the bytes in an `Asset` typed by `meta.kind` and register it via the `addAsset` constructor option, then reference it from a `GameNode.Asset` as usual (audio plays while its node is in the tree):

```js
constructor({ addAsset }) {
    super();
    this.addAsset = addAsset;
    // ...
    input: {
        type: 'file',
        oninput: (playerId, bytes, meta) => {
            if (!meta.kind) return;   // not a recognized image/audio file
            const key = `upload-${meta.kind}-${++this.uploadCount}`;
            this.addAsset(key, new Asset({ id: key, type: meta.kind }, bytes)).then(() => {
                // now reference `key` from a GameNode.Asset (see §7.3)
            });
        }
    }
}
```
  See `src/games/input-test` in homegames-core for a complete image + audio upload example (including replaying an uploaded sound).

### Hover

`Shape` and `Asset` nodes also accept `onHover(playerId)` and `offHover(playerId)` (pointer enter / leave). Use them only for cosmetic affordances — **touch devices have no hover**, so never gate a mechanic on it.

> **Hover only fires on nodes the client considers interactive.** On `squish-142`/`143` the hover handlers themselves are never serialized — the client reports hover only for nodes it indexed as clickable (`onClick` present) or as inputs, so a node with `onHover` but **no `onClick` and no `input` never receives hover events**. Give hover-only nodes a no-op `onClick: () => {}` to make them hoverable (harmless on every version). On `squish-144`+ the presence of `onHover` is serialized and hover-only nodes work natively.

---

## 10. Timing and game loop

> **`tick()` starts at construction and never pauses.** The server starts the tick interval the moment your game is instantiated — before any player joins, before any "start" button is pressed, and it keeps firing on menus and game-over screens. Two consequences:
> 1. **Gate the game loop on a phase.** Without an early `if (this.phase !== 'playing') return;`, enemies spawn, waves advance, and power-ups accumulate behind your start screen.
> 2. **Never let `tick()` touch a node a later phase creates.** `this.scoreText.node.text = ...` in `tick()` when `scoreText` is only built inside `startGame()` throws `TypeError` on a lobby that sits idle — and a throw in `tick()` crashes the session (auto-reject per §2). Create every node `tick()` references in the constructor, or guard each access.
> 3. **Re-check the phase *between subsystems inside* a tick.** Gating the entry isn't enough: any damage call can end the phase mid-tick — a stray projectile downs the last player, an enemy finishes the base, and suddenly `gameOver()` has run and torn down phase state while the rest of the tick executes against it. After every update that can reach `damagePlayer` / `damageStructure` / `gameOver` — directly or transitively — re-check before touching more state, and bail out of multi-target damage loops the same way:
>
> ```js
> this.updateEnemies();
> if (this.phase !== 'playing') return;
> this.updatePlayers();
> if (this.phase !== 'playing') return;   // a hit may have wiped the crew
> this.updateProjectiles();
> ```

- Set `metadata().tickRate` (FPS) and implement `tick()` for continuous simulation (movement, physics, timers counting down). Do mutations in `tick()` and end with one `onStateChange()` — **only when something changed** (§4.1).
- For delayed / repeating logic, **use the tracked timer helpers from the base `Game` class**, not the globals — they are auto-cleared when the session closes, preventing leaks:

```js
this.setTimeout(() => this.explode(), 5000);          // tracked
this.setInterval(() => this.spawnEnemy(), 1000);      // tracked
```

`Game.close()` clears all timers created via `this.setInterval` / `this.setTimeout`. If you use the global `setTimeout`/`setInterval`, you are responsible for clearing them yourself in `close()`.

**Idiom — prefer a tick counter over timers for cooldowns/durations in tick-driven games.** When you already have a `tick()` loop, the cleanest way to do fire cooldowns, respawn delays, spawn protection, etc. is to keep an incrementing tick count and compare against it — it's deterministic, needs no cleanup, and can't leak:

```js
constructor() { super(); this._t = 0; /* ... */ }
tick() {
    this._t++;
    // fire on a cooldown:
    if (firePressed && this._t >= player.fireReady) { this.fire(player); player.fireReady = this._t + 16; }
    // respawn after ~2.5s (at tickRate 60):
    if (!player.alive && this._t >= player.respawnAt) this.respawn(player);
    // ... mutate, then ONE onStateChange() ...
    this.base.node.onStateChange();
}
```

---

## 11. Assets (images, audio, fonts)

1. Declare them in `metadata().assets`, keyed by a short name, each an `Asset` instance with an `id` (the asset's hash in the Homegames asset store) and `type`:

```js
const { Asset } = require('squish-142');
// ...
assets: {
    'hero':   new Asset({ id: 'c0ffee...hash', type: 'image' }),
    'jump':   new Asset({ id: 'deadbe...hash', type: 'audio' }),
}
```

2. Reference them by key in `GameNode.Asset` `assetInfo` (see §7.3). Images use real `size`; audio uses zero size + `startTime`.
3. `type` is `'image'`, `'audio'`, or `'font'`. Keep total size within the limits in §2.

> When generating a game from scratch with no real asset ids available, prefer **drawing with shapes and text** rather than inventing fake asset ids (a fake id will load nothing). Only use `Asset` nodes when you have, or are given, valid asset ids.

---

## 12. Utilities

- `ShapeUtils.rectangle(x,y,w,h)`, `ShapeUtils.triangle(...)` — vertex builders (§6).
- `Colors.COLORS.*`, `Colors.randomColor(exclusions?)` — palette (§6).
- `GeometryUtils.checkCollisions(root, node, filter?)` — returns nodes under `root` that overlap `node` (axis-aligned rectangle test). Optional `filter(node) => boolean` to limit candidates — **always pass one**: with no filter, the tested node itself (and the root) are candidates, so an in-tree node "collides" with itself. Useful but simple; many games hand-roll AABB checks for control (see §14).
- `ViewUtils.getView(plane, view, playerIds, translation?, scale?)` — projects a slice of a large world into the `0–100` viewport; optional `translation`/`scale` inset the projection into part of the screen (see §13 / §13.1).
- `Shapes.POLYGON | LINE` — shape type enum (`CIRCLE` exists but is not rendered).
- `Physics.getPath(...)` — **straight-line paths only** (no gravity, no arcs). For ballistics (artillery arcs, thrown objects), integrate yourself in `tick()`: `vy += GRAVITY; x += vx; y += vy;` with a few substeps per tick so fast projectiles don't tunnel through thin geometry.
- `TerrainGenerator` — generates **maze-style wall grids** (cells with open/blocked edges), not heightmaps. For rolling-hills/silhouette terrain, build your own heightmap (layered sines work well) and render it as one polygon — mind the ~126-vertex cap (§6).

---

## 13. Large scrolling worlds and per-player cameras (`ViewableGame`)

Everything above renders directly into the shared `0–100` plane, where every player sees the same thing. For games with a **world larger than one screen** (scrolling levels, top-down arenas, anything with a camera) or **per-player cameras** (each player sees their own region), extend **`ViewableGame`** instead of `Game`.

`ViewableGame` gives you a large square **world plane** of size `planeSize × planeSize` (in its own world units), plus a separate **view root** that is what clients actually render. The rendered viewport is **always `0–100`** — you project a rectangular slice of the big world into that `0–100` viewport, per player. This is how you get cameras, scrolling, and split per-player views in one shared game.

This is the §1 tree model made explicit: the world can be as large as you like **because it isn't what goes over the wire** — what ships is each player's projected view, exactly the slice they're currently experiencing. The same discipline applies at world scale: model the world in plain data (Approach B below makes this literal), and let nodes exist only where a camera is looking.

### Setup

```js
const { ViewableGame, GameNode, Colors, Shapes, ShapeUtils, ViewUtils } = require('squish-142');

class MyWorld extends ViewableGame {
    constructor() {
        super(1000);   // world is 1000 x 1000 world-units. Call super(planeSize), NOT super().
        this.playerViews = {};
        // ... build world content (Approach A) or keep entities as plain data (Approach B)
    }

    getLayers() {
        return [{ root: this.getViewRoot() }];   // render the VIEW root, not the world plane
    }
}
```

API added by `ViewableGame`:
- `super(planeSize)` — **required**; sets up the world plane and the view root. (Plain `Game` uses `super()` with no args; `ViewableGame` needs the size.)
- `getPlane()` — the world plane `Shape` (size `planeSize`). For the built-in projection approach, add your world content as children of this.
- `getPlaneSize()` / `updatePlaneSize(n)` — read / change the world size.
- `getViewRoot()` — the **render root**. It starts **empty**. Whatever you want on screen must be added here, normally per-player view roots restricted with `playerIds`.

> **Critical:** with `ViewableGame`, `getViewRoot()` is empty by default and the world plane is **not** rendered directly. If you build a world in `getPlane()` but never put a projected view under `getViewRoot()`, **players see a blank screen.**

A "view" is a rectangle into the world: `{ x, y, w, h }` in world units. You render the slice of the world inside that rectangle, scaled to fill the `0–100` viewport.

### Approach A — built-in projection with `ViewUtils.getView`

Build the world once in `getPlane()`, then per player project a view window into a render root. `ViewUtils.getView(plane, view, playerIds)` clones the world nodes inside `view`, translates/clips them into `0–100`, and tags them for `playerIds`. (It has two more optional args, `translation` and `scale`, for placing the projection in only part of the screen — see §13.1.):

```js
handleNewPlayer({ playerId }) {
    const view = { x: 0, y: 0, w: 100, h: 100 };   // window into the world, in world units

    // A solid backdrop this player always sees, so they never see blank space:
    const playerRoot = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),
        fill: Colors.COLORS.BLACK,
        playerIds: [playerId]
    });
    playerRoot.addChild(ViewUtils.getView(this.getPlane(), view, [playerId]));

    this.playerViews[playerId] = { view, root: playerRoot };
    this.getViewRoot().addChild(playerRoot);
}

// To move a player's camera, recompute the view and rebuild that player's projection:
panCamera(playerId, dx, dy) {
    const pv = this.playerViews[playerId];
    pv.view = { ...pv.view, x: pv.view.x + dx, y: pv.view.y + dy };
    pv.root.node.clearChildren();
    pv.root.node.addChild(ViewUtils.getView(this.getPlane(), pv.view, [playerId]));
    pv.root.node.onStateChange();
}
```

### Approach B — manual projection (best for camera-follow / many moving entities)

Keep world entities as **plain data** (not nodes), and rebuild each player's view nodes yourself whenever they move or each tick. Full control — e.g. a camera centered on the player. World→view transform: `viewCoord = ((world − viewOrigin) / viewSize) * 100`.

```js
createPlayerView(playerId) {
    const player = this.players[playerId];
    const { w: viewW, h: viewH } = player.view;     // camera window size, in world units
    const viewX = player.x - viewW / 2;             // center the camera on the player
    const viewY = player.y - viewH / 2;

    const viewRoot = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),   // viewport is always 0–100
        fill: [50, 50, 50, 255],
        playerIds: [playerId]
    });

    const toView = (wx, wy, wsize) => ({
        x: ((wx - viewX) / viewW) * 100,
        y: ((wy - viewY) / viewH) * 100,
        size: (wsize / viewW) * 100
    });

    // player is always drawn centered:
    const ps = (player.size / viewW) * 100;
    viewRoot.addChild(new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(50 - ps / 2, 50 - ps / 2, ps, ps),
        fill: player.color, playerIds: [playerId]
    }));

    for (const e of this.enemies) {
        const r = toView(e.x, e.y, e.size);
        viewRoot.addChild(new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(r.x - r.size / 2, r.y - r.size / 2, r.size, r.size),
            fill: e.color, playerIds: [playerId]
        }));
    }
    return viewRoot;
}

// On movement, swap the player's view root under getViewRoot():
updatePlayerView(playerId) {
    const player = this.players[playerId];
    if (player.viewRoot) this.getViewRoot().removeChild(player.viewRoot.node.id);
    player.viewRoot = this.createPlayerView(playerId);
    this.getViewRoot().addChild(player.viewRoot);
    player.viewRoot.node.onStateChange();
}
```

### 13.1 Projecting into a sub-region (static frame around a scrolling viewport)

`getView` takes two optional trailing arguments that let you place the projection somewhere other than the full screen:

```js
ViewUtils.getView(plane, view, playerIds, translation, scale)
```

- `translation` — `{ x, y, filter? }`. After a node is projected, shift it by `x`/`y` (plane units). The optional `filter(node) => boolean` applies the shift to only the nodes it returns true for.
- `scale` — `{ x, y }`. Multiplies the projected coordinates per axis; values `< 1` shrink the projection so it fills only part of the viewport.

Per-vertex transform order is: subtract the view origin and clamp to `0–100`, **then** multiply by `scale`, **then** add `translation`, then clamp again.

This is how you keep **static UI fixed on screen while a world region scrolls inside an inset panel** — the exact pattern the Homegames dashboard uses: a search box and scroll arrows are plain `0–100` nodes, and the scrollable game grid is a `getView` projection scaled down and pushed below them.

```js
renderForPlayer(playerId) {
    const root = this.playerRoots[playerId];          // full-screen node tagged [playerId]

    // 1) static chrome: plain nodes, fixed position, NOT projected
    root.node.addChild(this.buildToolbar(playerId));  // e.g. the search field from §9

    // 2) the scrollable world, projected into the lower/inset part of the screen
    const view = this.playerStates[playerId].view;     // { x, y, w, h } in world units
    root.node.addChild(ViewUtils.getView(
        this.getPlane(), view, [playerId],
        { x: 12.5, y: 18 },        // push the projection right + down, clear of the toolbar
        { x: 0.75, y: 0.75 }       // shrink it to leave margins
    ));
    root.node.onStateChange();
}
```

Gotchas:
- The projection includes only nodes that **overlap** the `view` rectangle (a collision test against the plane's children), so off-screen world content is free — but a **Shape** straddling the view edge has its vertices **clamped to `0–100` individually**, which can distort a shape that's half in and half out (image **Assets** at the edge are handled: the projection auto-crops them instead of squashing). Size views so shapes aren't sliced, or accept the clamp.
- `getView` returns a brand-new subtree each call (clones keep the source nodes' ids, so re-projection doesn't spam hover/press state). To scroll or pan, rebuild that player's projection (`clearChildren()` + re-add, or swap the subtree) and `onStateChange()` — see the `panCamera` example above.
- **`onClick` survives projection for `Shape` nodes only** — `Asset` and `Text` clones silently DROP their `onClick`/`input` on the way through `getView`, so a clickable image in world space goes dead in every projected view. Make world-space tap targets Shapes (a transparent Shape over the Asset works), or handle taps with a per-player tap-catcher. And even for Shapes, the clones cover the viewport, so a **tap-anywhere steering control needs a per-player tap-catcher drawn above the projected view** (§9.1) — an `onClick` on the player's backdrop node gets swallowed by the world clones on top of it.
- **`getView` overwrites `playerIds` on every clone** with the viewing player's id. World-space nodes cannot stay private through projection — a node scoped to player A in the world will still appear in player B's projected view if it's inside B's view rectangle. Keep per-player-secret UI in **screen space** (plain `0–100` nodes with `playerIds`), not in the world.
- **Cost scales with visible nodes × players × ticks** — every camera update clones every node in view. Keep the world sparse (dozens of nodes in view, not hundreds), tick at 10–20, and prefer a camera-follow clamp like `view.x = clamp(shipX - 50, 0, WORLD - 100)`.

**Choosing:** use plain `Game` for single-screen games (most party/casual games). Use `ViewableGame` only when the world exceeds one screen or players need different cameras. Approach A is less code when the world is mostly static nodes; Approach B is better for smooth camera-follow and lots of moving entities. Either way: clean up a player's view root in `handlePlayerDisconnect`, and `getLayers()` returns `[{ root: this.getViewRoot() }]`.

---

## 14. Complete, correct examples

### 14.1 Single-player click game (event-driven, no tick)

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');
const { COLORS } = Colors;

class ClickCounter extends Game {
    static metadata() {
        return {
            squishVersion: '142',
            name: 'Click Counter',
            author: 'AI',
            description: 'Tap the square to score points.',
            aspectRatio: { x: 16, y: 9 }
        };
    }

    constructor() {
        super();
        this.score = 0;

        this.base = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),
            fill: COLORS.HG_BLUE
        });

        this.scoreText = new GameNode.Text({
            textInfo: { text: 'Score: 0', x: 50, y: 12, size: 4, align: 'center', color: COLORS.WHITE }
        });

        this.button = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(35, 35, 30, 30),
            fill: COLORS.CANDY_RED,
            onClick: (playerId, x, y) => {
                this.score += 1;
                this.scoreText.node.text = {
                    text: `Score: ${this.score}`, x: 50, y: 12, size: 4, align: 'center', color: COLORS.WHITE
                };
                this.base.node.onStateChange();   // REQUIRED after mutating text
            }
        });

        this.base.addChildren(this.scoreText, this.button);
    }

    getLayers() {
        return [{ root: this.base }];
    }
}

module.exports = ClickCounter;
```

### 14.2 Multiplayer movement game (players join, move with keys, tick loop)

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');
const { COLORS } = Colors;

class Movers extends Game {
    static metadata() {
        return {
            squishVersion: '142',
            name: 'Movers',
            author: 'AI',
            description: 'Everyone gets a square. Move with arrows or WASD.',
            aspectRatio: { x: 16, y: 9 },
            tickRate: 30
        };
    }

    constructor() {
        super();
        this.players = {};          // playerId -> { node, vx, vy }
        this.base = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),
            fill: COLORS.ALMOST_BLACK
        });
    }

    handleNewPlayer({ playerId, info }) {
        const square = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(47, 47, 6, 6),
            fill: Colors.randomColor(['ALMOST_BLACK'])   // exclude by NAME (string)
        });
        const name = new GameNode.Text({
            textInfo: { text: info?.name || 'player', x: 50, y: 5, size: 1.5, align: 'center', color: COLORS.WHITE },
            playerIds: [playerId]   // each player sees only their own name banner
        });
        this.players[playerId] = { node: square, vx: 0, vy: 0 };
        this.base.addChildren(square, name);
    }

    handlePlayerDisconnect(playerId) {
        const p = this.players[playerId];
        if (p) {
            this.base.removeChild(p.node.id);
            delete this.players[playerId];
        }
    }

    handleKeyDown(playerId, key) {
        const p = this.players[playerId];
        if (!p) return;
        if (key === 'ArrowUp' || key === 'w') p.vy = -1;
        else if (key === 'ArrowDown' || key === 's') p.vy = 1;
        else if (key === 'ArrowLeft' || key === 'a') p.vx = -1;
        else if (key === 'ArrowRight' || key === 'd') p.vx = 1;
    }

    handleKeyUp(playerId, key) {
        const p = this.players[playerId];
        if (!p) return;
        if (key === 'ArrowUp' || key === 'w' || key === 'ArrowDown' || key === 's') p.vy = 0;
        if (key === 'ArrowLeft' || key === 'a' || key === 'ArrowRight' || key === 'd') p.vx = 0;
    }

    tick() {
        let changed = false;
        for (const id in this.players) {
            const p = this.players[id];
            if (p.vx === 0 && p.vy === 0) continue;
            const x = p.node.node.coordinates2d[0][0];
            const y = p.node.node.coordinates2d[0][1];
            const nx = Math.max(0, Math.min(94, x + p.vx));   // clamp to plane (square is 6 wide)
            const ny = Math.max(0, Math.min(94, y + p.vy));
            p.node.node.coordinates2d = ShapeUtils.rectangle(nx, ny, 6, 6);
            changed = true;
        }
        if (changed) this.base.node.onStateChange();   // ONE notify per tick
    }

    getLayers() {
        return [{ root: this.base }];
    }
}

module.exports = Movers;
```

### 14.3 Bots and enemy AI (games must be fun with one player)

A game that needs 2+ players demos badly — and on today's platform, **solo is the front door**: the catalog's instant "Play" button and every downloaded game run as a **single-player local session** (one player, id `1`), including for games that declare `multiplayer` (§5). The first experience most people have with any game is alone in their own browser. The shipped catalog pattern: **bots fill empty slots at match start, and a disconnecting player's avatar is handed to a bot brain** (`agent.playerId = null; agent.isBot = true;`) so rounds never break. Keep entities as plain data (`{ x, y, angle, isBot, ... }`) and run bot logic in `tick()`.

> **Last-man-standing logic must special-case solo play.** The naive check `if (alivePlayers.length === 1) declareWinner(...)` ends a single-player session **the instant it starts** — the only player is always the last one alive. Either require ≥2 participants at round start (fill with bots), or in solo sessions switch the win condition to survival time / score and only use "last alive" when the round began with multiple combatants.

Two building blocks cover most enemies:

```js
// Wander: walk forward, turn away from walls, jitter occasionally.
botWander(bot) {
    const aheadX = bot.x + Math.cos(bot.angle) * 0.7;
    const aheadY = bot.y + Math.sin(bot.angle) * 0.7;
    if (this.isBlocked(aheadX, aheadY)) {
        bot.angle += (Math.random() < 0.5 ? 1 : -1) * (Math.PI / 2 + (Math.random() - 0.5) * 0.8);
    } else if (Math.random() < 0.04) {
        bot.angle += (Math.random() - 0.5) * 1.2;   // occasional random turn
    }
    this.moveWithCollision(bot, 0.75);
}

// Line of sight: sample the segment between two entities for obstacles.
hasLineOfSight(from, to) {
    const dist = Math.hypot(to.x - from.x, to.y - from.y);
    for (let step = 0.3; step < dist - 0.2; step += 0.3) {
        const t = step / dist;
        if (this.isBlocked(from.x + (to.x - from.x) * t, from.y + (to.y - from.y) * t)) return false;
    }
    return true;
}
```

**The fairness rules — this is what separates a fun bot from an aimbot.** A bot that acquires a target and fires in the same tick with perfect aim is unbeatable and feels terrible. Combat bots must run a three-state loop:

1. **Acquire** — scan a few times per second (not every tick), only when the bot's own cooldown is ready, only within a capped engage range, and only with line of sight.
2. **Telegraph** — on acquiring, the bot **stops moving and visibly turns toward the target for 0.5–1s** (`aimTicks` countdown, rotating a capped amount per tick). This is the victim's window to dodge or fight back. Cancel the aim if the target breaks line of sight, leaves range, or becomes invulnerable.
3. **Fire with error** — when the telegraph expires, fire with **aim error that grows with distance** (`angle = perfect + (Math.random() - 0.5) * (0.1 + dist * 0.05)`), then take a **cooldown 2–3× longer than a human's**.

Difficulty knobs, in order of impact: telegraph duration, aim-error slope, bot cooldown, engage range. Tune by simulation: a *stationary* target at mid-range should survive ~2s after being spotted; a moving one much longer. Also respect spawn-protection windows, and never let bots re-acquire while still cooling down.

### 14.4 Pseudo-3D: a first-person raycaster (yes, really)

Because every player can have a fully private view (`playerIds`), and a view is just rectangles, the server can render **real-time first-person 3D**: give each player a strip of vertical wall-slice rects and recompute them every tick with a grid raycast. This is the most advanced pattern in the catalog (`prism-3d`), and it works — a multiplayer FPS in one file.

The essentials:

- **One slice rect per screen column, created ONCE per player at join** (stable node ids — never recreate them), scoped `playerIds: [pid]`. ~48–56 columns reads convincingly retro. Each tick, mutate every slice's `coordinates2d` + `fill`, then one `onStateChange()`.
- **DDA raycast per column** (Lodev camera-plane style — use the *perpendicular* distance so walls don't fisheye):

```js
const dirX = Math.cos(p.angle), dirY = Math.sin(p.angle);
const planeX = -dirY * 0.66, planeY = dirX * 0.66;        // ~66° FOV
for (let col = 0; col < COLS; col++) {
    const cameraX = (2 * col) / (COLS - 1) - 1;
    // step the ray cell-by-cell through the grid (DDA) until it hits a wall,
    // tracking which axis was crossed last (side) and the perpendicular dist
    const { dist, side, wallType } = this.castRay(p.x, p.y, dirX + planeX * cameraX, dirY + planeY * cameraX);
    const h = Math.min(100, HEIGHT_K / dist);              // wall slice height
    const shade = Math.max(0.1, 1.15 / (1 + dist * 0.24)) * (side ? 0.72 : 1);
    slice.node.coordinates2d = ShapeUtils.rectangle(col * COL_W, 50 - h / 2, COL_W + 0.05, h);
    slice.node.fill = wallColor(wallType).map(c => Math.round(c * shade));
    this.lastDists[col] = dist;                            // saved for sprite occlusion
}
```

- **Ceiling, floor, and horizon are identical for everyone → shared nodes** (no `playerIds`). Same for the minimap and score strip. Only the slices and sprites are per-player.
- **Other entities are billboard sprites**: camera-plane transform (`transX/transY`), screen x = `50 * (1 + transX / transY)`, height = `K / transY`, and **occlude by comparing `transY` against `lastDists[column]`** from the wall pass. One rect + one detail rect per visible entity is plenty.
- **Budget honestly**: per-player bandwidth ≈ (shared nodes + own scoped nodes) × ~55 bytes × tickRate. 56 columns at tickRate 12 ≈ 100 KB/s per player — fine on LAN, borderline over a relay. `COLS` and `tickRate` are the knobs; cap humans at ~4 (bots need no view). tickRate 10–14 reads as intentionally retro.
- Movement: apply moves on input events (key repeat / held-tap re-clicks give continuity), slide along walls by resolving the x and y axes independently, and keep a body radius so players don't clip corners.
- Controls: tap left/right thirds = turn, center = forward, plus a FIRE button — with the tap catcher **above the slices, below the buttons** (§9.1), and the crosshair *below* the catcher so it can't eat center taps.

---

## 15. Idioms and anti-patterns

### 15.1 Write code where a typo can't hide

The validation sandbox simulates a little play (§2) — but **exceptions inside input handlers are logged as warnings, not failures**, and anything behind a second-layer gate (a submenu, a game-over screen, a specific key combo) may never execute at all. So a broken `onClick` or key handler still ships. When a generated game crashes in production, it is nearly always a `ReferenceError` in exactly that under-exercised code, and nearly always from the same cause: **two near-identical copy-pasted blocks with a fleet of similar positional locals** (`leftPivotX`, `pivotY`, `leftTipX`, `leftTipY`, `leftX1`, `leftY2`, `rightX1`, ...) where one block references a name that was never defined (`leftPivotY` in a scope that only has `pivotY`). The variable soup makes the typo invisible to a re-read, and the input gate makes it invisible to the sandbox. Three rules:

1. **Mirrored or repeated geometry comes from ONE helper called N times — never from duplicated blocks.** Left/right chopsticks, two paddles, four walls, per-player HUDs: write the math once (like `thickLine` in §7.1), call it with mirrored arguments. Fewer variable names means fewer chances to typo one, and the single implementation gets exercised on every path instead of hiding a broken copy.

```js
// GOOD — one implementation, two calls:
this.leftStick.node.coordinates2d  = thickLine(cx - gap / 2, py, cx - gap / 4, ty, 1.5);
this.rightStick.node.coordinates2d = thickLine(cx + gap / 2, py, cx + gap / 4, ty, 1.5);

// BAD — 20 lines of trig duplicated for "left" and "right" with 16 similar
// local names; this is where `leftPivotY` (undefined) slips in unnoticed.
```

2. **Initialize every field you'll later test, at creation time.** `if (obj.captured === false)` is never true when `captured` was never assigned — `undefined === false` is `false`, so the mechanic silently never fires. Set `captured: false` in the object literal when you create the entity, and prefer truthiness checks (`if (!obj.captured)`), which treat "unset" and "false" the same.

3. **Before you output, execute every gated method in your head once.** For each key handler, `onClick`, and phase-gated branch: read every identifier and confirm it is defined in that scope, and confirm every `this.foo` was assigned in the constructor. This five-second pass is the test the sandbox cannot run for you.

### 15.2 Centralize tunables — the dev tuning menu pattern

Put **every gameplay number** in one `TUNING` object at the top of the file, directly under the asset registry — not "some constants," every number a designer might turn: round lengths, HP, spawn formulas, yields, ranges, economy. Master knobs first (the dials you touch most), then grouped by system:

```js
const TUNING = {
    DIFFICULTY: 1.0,
    ROUND_SECONDS: 40,
    TICK: 20,          // safe to reference from metadata(): tickRate is runtime-read (§5)
    MAX_PLAYERS: 4,    // same — maxPlayers may be TUNING.MAX_PLAYERS in metadata()

    PLAYER:  { hp: 3, speed: 0.95, invulnTicks: 26 },
    START:   { money: 5, inv: { water: 100, sugar: 50 } },
    ENEMIES: { baseHp: 2, spawnCdBase: 70, capBase: 3 /* ... */ }
};
```

Four practices make it actually work instead of just looking organized:

1. **Derive aliases so the game body doesn't change.** `const TICK = TUNING.TICK;` etc. keeps a thousand lines of existing code untouched while the numbers move — retrofitting tuning into a finished game becomes a rename job, not a rewrite.

2. **Size render pools *from* tuning values.** If `TUNING.GATHER.wells` says 2 wells, the per-player node pool must be built by looping over that same value — a hand-written array of two nodes crashes the render loop the day someone sets it to 3. Any tunable that controls "how many of X exist" must drive its pool size, or it isn't really tunable. Conversely, pool ceilings (`MAX_ENEMIES`, `MAX_FX`) are **memory/bandwidth budgets, not design knobs** — keep them in the tuning section but labeled as hard caps, and have every count formula clamp against them (`Math.min(MAX_ENEMIES, formula)`) so a wild setting degrades gracefully instead of overflowing a pool.

3. **Copy config objects, never hand them out.** `this.inv = TUNING.START.inv` aliases the config, and the first purchase mutates your "constant." Use `Object.assign({}, TUNING.START.inv)` everywhere starting state is applied — constructor **and** every reset path.

4. **A master difficulty knob scales quantities, not behavior.** `DIFFICULTY` should multiply HP, on-screen caps, and spawn tempo — and deliberately *not* touch movement speed or AI ranges. Scaling speed changes what enemies *are* (a 1.5× erratic hopper is undodgeable; kiting distances break); scaling counts and toughness changes how *hard* they are while every breed stays readable. Tempo knobs divide cooldowns, quantity knobs multiply counts (clamped by pool caps), and results get `Math.round` plus a floor of 1 so fractional multipliers can't produce 0-HP enemies or 0-tick cooldowns.

### 15.3 Two small ones that ship constantly

- **Upgrade buttons advertise the *next* state, not the current one.** A "TURRET 2/4" label after two turrets are built reads as "buy turret #2" — off-by-one against what confirming will actually purchase. Label with `(count + 1)`. Applies to any incremental purchase.
- **Voted actions re-vote on state change.** Any majority-vote flow (recipe confirm, shared purchase) must reset its votes when the thing being voted on changes — the proposal switches, the recipe is adjusted, or a voter disconnects (recount against the new majority threshold, and re-check whether the vote now passes with fewer players).

---

## 16. Quick reference card

```
require('squish-142')  ->  { Game, GameNode, Colors, Shapes, ShapeUtils, GeometryUtils, Asset, Physics, ... }

Runtime:      one game class (entry index.js; split across as many local files as you like), two homes —
              hosted Node session (multiplayer) or browser LocalSession (instant play / offline download;
              exactly one player, id 1, stubbed services, frameless). Identical contract —
              never detect or branch on which. saveGame/saveData work in BOTH (§3):
              saveGame(json) -> Promise (debounced, ≤1 MB), saveData = loaded save or undefined
              (UNTRUSTED — validate every field); saveCompatibility: [...versionIds] in metadata()
              accepts older versions' saves.
metadata():   pure OBJECT LITERAL — statically parsed (never executed) to decide play modes.
              services: ['multiplayer'] -> "Play with friends" hosted sessions + shareable link;
              omit services -> single-player instant play + downloadable offline HTML file;
              'contentGenerator' -> REMOVES local play/downloads (server-only service).
              maxPlayers: N -> session capacity (default 64); the only capacity mechanism
              (no canAddPlayer hook is called by the runtime).
              LITERAL fields (statically parsed): squishVersion, name, services, assets, thumbnail —
              publish REJECTS non-literal squishVersion/name. tickRate/maxPlayers are runtime-read
              and MAY derive from TUNING (§5). tickRate 1-120 when present.
Dead hooks:   no duck-typed lifecycle — a method the runtime doesn't document calling
              (canAddPlayer, ...) is dead code that LOOKS load-bearing: delete it (§3).
              (Exception: getAssets() IS merged into the hosted asset bundle — but declare
              assets in metadata anyway; the static parser only sees the literal.)

Game hooks:   metadata() [static, required] · constructor()->super() · getLayers()->[{root}]
              handleNewPlayer({playerId,info,settings,clientInfo}) · handlePlayerDisconnect(playerId)
              handleKeyDown(playerId,key) · handleKeyUp(playerId,key) · tick() · close()
              handleMouseMove(pid,{x,y}) · handleMouseUp(pid,data) · handleGamepadInput(pid,input)
              handlePlayerUpdate(pid,{info,settings})   // rename / settings change

Tree model:   the tree IS the wire payload — nodes are ONLY what players currently see/hear/touch;
              all other game state (decks, upcoming waves, hidden words, off-screen entities) lives in
              plain instance variables and becomes nodes when experienced, removeChild when done (§1, §4.1).
              There is NO "keep it in the tree but hidden" optimization: hidden nodes squish+ship like
              visible ones, and playerIds=[0] still renders for spectators/frame-less players (§8)

Nodes:        GameNode.Shape({ shapeType, coordinates2d, fill, color, border, onClick, effects, playerIds })  // clickable
              border = NUMBER (outline width), NOT an object; stroke uses `color` -> set both. fill=interior.
              round shape: build a many-sided polygon (CIRCLE doesn't render). rotate verts with trig (§7.1).
              max ~126 vertices per node (§6). effects:{shadow:{color,blur}} = glow; clear with null, never {} (§7.4).
              GameNode.Text({ textInfo:{ text,x,y,size,align,color,font }, playerIds })       // NO onClick
              GameNode.Asset({ coordinates2d, assetInfo:{ key:{pos:{x,y},size:{x,y},startTime} }, playerIds })  // clickable
              image drawn from assetInfo pos/size; clicks hit coordinates2d -> keep them aligned (§7.3)
              audio = zero-size Asset; add to tree = play, remove = stop; deduped by KEY — the key must
              leave a frame before it re-triggers (§7.3). never invent asset ids: no assets -> shapes/text.
              Asset crop (squish-139+): assetInfo.key.{cropLeft,cropTop,cropRight,cropBottom} = % inset per edge -> spritesheets (§7.3.1)
Button:       no button node + Text isn't clickable -> clickable Shape (onClick) with a Text node on top (§7.2.1)

Tree ops:     n.addChild(c) · n.addChildren(a,b) · n.removeChild(id) · n.clearChildren([keepIds])
              n.findChild(id) · n.update({fill,coordinates2d}) · n.showFor(pid) · n.hideFor(pid)
NOTIFY:       n.node.onStateChange()   // after direct field mutation; tree ops notify for you
Cost:         every notify re-squishes + re-broadcasts the WHOLE tree to every player (bursts coalesce
              into one flush per turn) -> notify once per tick, ONLY when changed; POOL particle/trail/
              bullet nodes (create once, mutate, idle at zero-size + fill [0,0,0,0]) — never addChild/
              removeChild per tick. Pooling = high-frequency fx ONLY; structural moments (menus, rounds,
              screens) add/remove nodes normally — one cheap notify, smaller flushes after (§4.1);
              glow a few focal nodes only (shadowBlur is expensive)
Env:          Node on the server — NO window/document/location/alert; "play again" = reset state in place,
              never location.reload() (§1)
tick():       starts at construction, fires on menus too -> gate on phase; create every node tick()
              touches in the constructor (a throw in tick = crashed session = rejected) (§10)
              defining tick() with NO tickRate runs it at a DEFAULT 60 fps — event-driven games
              must not define tick() at all; tick games always declare tickRate (§3, §5)
              re-check phase BETWEEN subsystems too — any damage call can gameOver() mid-tick and the
              rest of the tick runs against torn-down state (§10)

Shapes:       Shapes.POLYGON | LINE   (CIRCLE constant exists but does NOT render — don't use)
Coords:       ShapeUtils.rectangle(x,y,w,h) · ShapeUtils.triangle(x1,y1,x2,y2,x3,y3) · plane is 0..100
Colors:       Colors.COLORS.RED ... ([r,g,b,a] 0..255) · Colors.randomColor(['BLACK',...])  // exclude by NAME, not value
              channels are raw bytes: out-of-range WRAPS (alpha 400 -> 144) -> clamp computed values (§6)
              ONLY the ~100 names listed in §6 exist — an invented name = undefined = invisible shape (no error)
Text limits:  '\n' does NOT line-break (single fillText call) -> one Text node per line (§7.2)
              hard cap ~154 chars per Text node — beyond that the frame silently corrupts (§7.2)
Typo safety:  validation pokes inputs but handler throws are WARNINGS only (tick/join throws are
              fatal) -> mirrored geometry = ONE helper called twice (thickLine, §7.1);
              init fields you'll test (captured: false); hand-trace every gated handler before output (§15.1)
Off-plane:    coords clamp to [0,255] on the wire — negatives pin to 0 (no off-screen left/top);
              100..255 = off right/bottom; enter from left/top by spawning AT the edge moving inward;
              walk-ons: keep pos in plain vars, hide node until FULLY on-plane (x >= half-width) (§6)
Aspect:       plane is 0..100 but stretched to aspectRatio -> use {1,1} for circles/orbits/true angles (§5)
              text height in y-units = size * (aspectX/aspectY); square rect: h = w * (x/y) (§5)
"Hiding":     done-with content comes OUT of the tree (removeChild + state in variables) — zero-size +
              fill [0,0,0,0] is only how POOLED fx idle between uses; playerIds=[0] is what hideFor
              leaves when a scoped node's viewer set empties, NOT a hide switch (leaks to spectators, §8)
Fade a node:  animate `color` alpha (fill alpha is opaque for any value >= 1); pooled fx recipe:
              fill = solid hue, color = [255,255,255,a] — a translucent-looking fill ([r,g,b,110])
              renders as an opaque paint blob (§7.4)
Sprites:      shape-fallback hybrid: ONE factory + ONE placeSprite() for all placement; grouped keys
              activate all-or-nothing; every tint signal needs a sprite equivalent (size puff/blink);
              placeholder chrome self-hides behind if(node._sprite) (§7.3.2)
Tuning:       every gameplay number in ONE TUNING object; alias into old const names; pools sized FROM
              tuning counts + formulas clamp to pool caps; copy config objs (Object.assign), never alias;
              difficulty knob scales counts/hp/tempo, NOT speed/behavior; tickRate/maxPlayers may
              derive from TUNING but squishVersion/name/services/assets must stay literals (§15.2, §5)
onClick:      (playerId, x, y) => {}    // Shape/Asset only
Held press:   142/143: onClick RE-FIRES ~every 30ms while held (keep handlers cheap);
              144+: one onClick, then node onDrag(pid,x,y) + game handleMouseMove while held,
              node offClick(pid,x,y) + game handleMouseUp on release (§9)
Click routing: topmost CONTAINING node wins, clickable or not -> containers must be rectangle(0,0,0,0);
              full-screen taps need a tap-catcher above the playfield, below the buttons (§9.1)
              oninput/hover are routed by node id with NO server-side scope check -> validate the
              playerId inside the handler when it matters (§9)
text input:   Shape/Text input:{ type:'text', oninput:(playerId, value)=>{} }  // MODAL prompt; one-shot entry
file upload:  input:{ type:'file', oninput:(playerId, bytes, meta)=>{} }  // bytes = Buffer/Uint8Array (<=5MB),
              meta = { kind:'image'|'audio'|null, contentType, fileName }; register via addAsset (§9)
Live typing:  held keys re-send keydown every ~33ms with NO delay -> gate them like an OS keyboard:
              fresh press (not seen >400ms) types instantly; held repeats after 450ms at ~18cps (§9 Keyboard)
hover:        Shape/Asset onHover(pid) / offHover(pid)   // cosmetic only; no hover on touch;
              on 142/143 only fires on nodes with onClick or input — hover-only nodes need a
              no-op onClick (native on 144+) (§9)
playerIds:    [] / omitted = everyone (default) · [id,...] = only those · [0] = no live player
              (still squished + shipped to unfiltered receivers — not a hide mechanism, see "Hiding")
              VISIBILITY, not ownership: leave avatars/ships/bullets UNSCOPED or other players can't
              see them; input already routes per player via handler args; never derive ids from indices (§8)
              child scopes must be a SUBSET of the parent's (outside scope = rendered parentless,
              unclickable); players with NO scoped nodes get the UNFILTERED state ->
              secrets games: per-player zero-size privacy anchor + scoped "YOU" markers (§8)

Rounds:       last-man-standing must special-case solo (1 player alive at spawn != winner) — require >=2
              at round start or fill with bots (§14.3)

Bots:         fill empty slots at match start; hand disconnected players' avatars to a bot brain (§14.3)
              fair combat bots: acquire (LOS + range + own cooldown) -> TELEGRAPH 0.5-1s (stop, turn toward
              target) -> fire with distance-scaled aim error -> 2-3x human cooldown. NEVER snap-fire.
3D:           per-player raycast view = N playerIds-scoped slice rects (stable ids) mutated per tick (§14.4)
              share floor/ceiling/HUD; occlude sprites vs per-column wall dists; COLS x tickRate = bandwidth

Big worlds:   extend ViewableGame · super(planeSize) · getPlane()/getPlaneSize() = world
              getViewRoot() = render root (starts EMPTY) · getLayers()->[{root:getViewRoot()}]
              ViewUtils.getView(plane,{x,y,w,h},[pid], translation?, scale?) projects a world slice into 0..100
                translation={x,y,filter?} scale={x,y} -> inset the projection (static frame + scroll region, §13.1)
                clones keep onClick for SHAPES ONLY (Asset/Text clones drop handlers) and always
                get the viewing player's playerIds — no private world-space nodes (§13.1)
```

