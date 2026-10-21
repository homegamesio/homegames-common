# Homegames reference

> Grounding reference for Homegames platform questions and SquishJS game authoring. **Part I** describes the product and implementation; **Part II** describes the game contract, for portable browser games and optional home-server sessions.
>
> **Checked against source: October 20, 2026.** Covers Studio, exports, browser saves and RTC. Existing downloaded HTML files retain the runtime bundled when they were exported.

---

# PART I — The Homegames platform

## What Homegames is

Homegames is an open-source platform for making, sharing and playing
multiplayer browser games, created and maintained by Joseph Garcia since 2018.
Games are JavaScript programs built with SquishJS; phones can be controllers and
screens. Platform repositories are under github.com/homegamesio.

The primary product is a **portable game**: source and media in an ordinary ZIP,
plus an exportable self-contained HTML player. The website's existing Studio is
an interface to the user's browser storage. Creating, editing, playing, saving,
exporting and inviting friends require no account in this local-first workflow.

There are two execution paths:
1. **Browser host:** a Studio preview or downloaded HTML runs the game simulation.
   Friends connect to that tab over WebRTC and receive their own views.
2. **Optional self-hosted server:** Core serves a dashboard and browser games, and can
   run Node/WebSocket sessions on the user's machine. homegames.link discovery and
   HTTPS certificates are separate optional services.

The website ships a static catalog, game pages, downloads and Studio. The active
API handles connection helpers (RTC signaling and optional HTTPS certificate jobs),
not account-backed game authoring or publishing. Old hosted content code remains
for migration; it is outside the default game contract. See the
[historical publishing reference](legacy-hosted-publishing.md) only when maintaining
or converting that code.

## Playing and sharing games

- Website Play loads a portable pack from the static build into an isolated browser
  host. Home/catalog/game-page content and downloads work without JavaScript; play
  and Studio need it. All current website invitations are private; there is no public
  room feed or account-backed publication. The older catalog RTC backend still exists.
- Open a playable `.html` file directly in a browser, or run a project in Studio.
  The downloaded HTML contains game source, runtime and authored media; local play
  works without Homegames services. Studio caches its existing editor/player, templates, examples and guide after
  its first secure load; the catalog itself still needs a network load.
- **Session invitations:** the host tab runs the authoritative simulation and stays open.
  Guests render per-player Squish frames and media, and send inputs back over RTC.
  Joining does not automatically install a game. Joined players can request source
  when the host provides project export. **Share with friends** in the player menu
  is a separate action that sends the portable ZIP
  through another private RTC connection, after the recipient accepts.
- **Keep a copy:** `/game-app.html` validates peer-transferred source/media and
  builds a self-contained HTML file using the static site's trusted runtime.
  Download it, open it offline in a desktop browser, and share it onward. The
  game-only receiver can also keep it locally for direct offline launches.
  Each game UUID/revision has a locally generated app manifest and launch URL;
  the server does not register or receive user-created games. Studio remains
  the authoring editor, with explicit project ZIP import for editing.
  On iOS, add this game's page to the Home Screen, open its icon, then receive
  or import the game there: Safari and app storage are separate. The initial
  app launch retains the invitation fragment. HTML/progress backups protect
  against clearing/eviction; RTC copies exclude progress and snapshot history.
  Physical iOS installation remains a release check.
  Catalog Play and Keep on this device links use the same player. A fresh Home
  Screen app downloads the pinned built-in game on its first online launch;
  “Ready offline” confirms its local copy. Later launches need no catalog/API.
- Automatic invitations use configured signaling/player endpoints, defaulting to
  `wss://api.homegames.io/rtc` and `https://homegames.io/play.html`. Signaling arranges
  the connection; gameplay uses peer connections, with TURN relaying if configured
  and required by the network. Public guests need a compatible deployed player.
- **Manual connection:** both people open a player first. The host creates an offer,
  sends the complete text privately, the friend returns an answer, and the host
  applies it. Repeat for each friend. This works without Homegames signaling; if
  the website is unavailable, both people need downloaded players. Public Google
  STUN is on by default and can be disabled for LAN pairing. Some NAT/firewall
  combinations need TURN; the manual UI does not configure TURN, so service outages
  cannot be promised to work on every network. Manual mode supports scene/media
  files/input, but not live microphone/camera streams.
- Closing the host ends the game. Automatic RTC currently closes peers when its
  signaling connection ends, even though frames travel over peer connections. Manual
  pairing is the separate path without Homegames signaling; reconnecting needs a
  new connection/handshake.
- Self-hosted Node/WebSocket sessions remain available (see Self-hosting).

## Browser projects, progress and accounts

These are three different kinds of persistence:

| Data | Current local-first storage | Portable backup |
| --- | --- | --- |
| Saved source and authored media | Studio IndexedDB project library after explicit Save | Project `.zip`, playable `.html`, or full Studio backup |
| Source snapshots | Every explicit Save adds an immutable History entry | Full Studio backup includes history; individual game exports do not |
| Game progress | Installation-scoped IndexedDB saves, when the game calls `saveGame` | Download save / Load save JSON |

Unsaved source stays in memory until Save; a full Studio backup also captures that working copy.
No account or cloud sync is involved. Clearing/evicting browser storage can lose
projects and progress. Optional persistent-storage permission is best-effort;
keep file backups. Importing a ZIP makes a new installation, and each newly
exported HTML has its own installation identity. Copying an existing HTML preserves
its embedded identity, though another browser/storage context may not have its saves.
A package's `gameId` identifies
the game for compatibility, not permission to read another copy's saves. See §3.

## The Developer Studio (homegames.io/studio.html)

The local-first implementation is integrated into the **existing Studio**, using
its editor, file tree, tabs, preview and asset tools. `studio-local.html` redirects
there; it is not a separate product.

- **Games:** opens a switcher over the main editor, with New game and Import game
  (HTML or ZIP). Templates are static portable projects; no account is needed.
- **Editing and Save:** edits remain in memory until explicit Save / Ctrl+S / Cmd+S.
  Each successful Save atomically keeps source/media and adds an immutable History
  snapshot. The optional save message names it; blank messages use Save N. Incomplete
  code can be saved. Play, asset insertion and exports do not save the working copy.
  Generation checks prevent stale tabs overwriting newer edits; failed writes keep
  the working copy and message available for retry.
- **History:** sits left of Files. Snapshots are read-only and can be played or exported.
  Back to editing restores the in-memory working copy. Restore loads snapshot files
  as unsaved edits; Save keeps them. Switching games or restoring over unsaved work
  asks before discarding it. Source restoration does not roll back player progress.
- **Assets:** a reusable browser library. Upload, Draw, Record and Keyboard keep
  originals there. Add to game copies selected files into the current project;
  Save keeps that project change. Authored references use relative asset paths,
  not hosted IDs. Session uploads from players are a separate mechanism (§9).
- **Preview:** Play runs current source in an isolated iframe. Options provides
  inspection and a second local test player; the Homegames menu connects real RTC guests.
  Editing the source requires restarting Play to see the change.
- **Export & share:** ZIP contains editable source/media; HTML is a playable copy.
  Neither contains full source history or existing progress. Inviting players keeps
  the running browser tab as host; Share a copy transfers a separate editable pack.
- **Settings:** appearance, browser storage, and full-workspace backup/restore.
  A .homegames-backup includes games, history, original assets, preview saves/exports,
  preferences, and the current unfinished source without making an extra snapshot.
  Restore replaces the workspace atomically and keeps an Undo last restore copy.
- **Learn:** interactive examples, a getting-started tutorial, searchable API topics,
  and task-oriented snippets with labeled insertion points. Copy full reference
  keeps this document available for an external coding assistant.

The isolated player cannot access the Studio's DOM or project storage. It receives
its project bytes and explicit channels for installation-bound progress, exports and player controls. This
protects the editor origin; it is not a CPU/memory limit or a guarantee that arbitrary
game code is safe. The older CLI `html --trusted` builder still uses a separate
explicit-trust execution path. See the portable implementation reference below.

## Making games (essentials — the full contract is Part II)

- Export a JavaScript class from `index.js` (`module.exports = MyGame`), extending
  `Game` or `ViewableGame` from one pinned Squish package, such as
  `const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-151');`.
- Put a stable UUID `gameId`, `name` and integer `maxPlayers` from 1 to 255 in the class's
  `static metadata()`. That is the authored source of game information. New games
  need no `homegame.json`, duplicate `squishVersion` or `services` declaration.
  `maxPlayers: 1` is solo; a value above one identifies multiplayer capability.
  It does not declare a minimum number of people required to play.
- Include useful `author`, `description` and `aspectRatio` values. Add `tickRate`
  only for games with a tick loop, and declare file media in `assets`. Keep the
  metadata readable as static data (§2 and §5); validation never executes it.
- Keep the ID when updating the same game, and preserve its save schema unless
  you deliberately change the progress format. A new independently authored game
  needs a new UUID. Older format-1 packages remain readable, including custom entry
  paths and their original IDs/revisions; conversion is explicit (§2).
- Call `super()` in the constructor and return `[{ root: this.base }]` from
  `getLayers()`. Build in a `0–100` plane; notify after changing node properties.
  Use runtime-supplied player IDs. Visibility scopes restrict delivery and input
  lookup; the game still validates ownership, turn order and input values.
- Bundle media at relative paths. `new Asset({ path: './assets/tile.png', type:
  'image' })` declares a project asset. No account, upload service or hosted asset
  ID is needed. ZIP/HTML recipients can inspect source and media.

## Self-hosting

Core is an optional home server. The launcher (`homegames/index.js`) supervises it
and opens the ready URL reported by Core. In the Core checkout, run `npm ci` and
`npm start` to use its pinned published dependencies. The client package includes
its built browser bundle. The launcher is an optional supervisor with its own
dependency pins; keep those aligned when preparing a server release.

- The normal dashboard serves its client on `HOME_PORT`, browses built-in/installed
  games and can download catalog games. Play hosts games in the browser with RTC
  guests and household discovery. Host with WebSocket is a separate Node option.
- With `START_PATH`, direct-start games default to `START_MODE: "browser"`: Core
  serves game files on the main port and returns before constructing the normal
  dashboard/Homenames stack. `START_MODE: "server"` selects Node/WebSocket execution.
- Node child sessions prefer Docker (`homegames-runner`). Without it, explicit
  `allowFork`/`FORK_SESSIONS_ENABLED` permission is required. Otherwise starts fail.
  Browser-hosted games do not use this container/fork path.
- Source config uses main port 9801, Homenames 7400 and child ports 8300–8400.
  The downloadable bundle builder instead chooses 7001, 7100 and 7002–7099,
  disables discovery, HTTPS and fork fallback initially. Environment and
  user overrides can change these. Use the logged ready URL, not an assumed port.
- homegames.link discovery registers the server over an outbound connection and
  redirects visitors on the same public connection to its LAN address. It is not
  a tunnel; an internet friend cannot reach that private address through discovery.
- HTTPS is optional. Core generates a local private key and sends a CSR to the API. Its background
  certificate runner keeps jobs in MongoDB; ambiguous issuance pauses for review. Initial activation needs restart; an active TLS
  listener can reload renewal certificates. Certificates are checked daily and
  renewed within 14 days of expiry. Use the issued hostname rather than raw IP for TLS.
- `RTC_SIGNAL_URL`, `RTC_JOIN_URL`, `RTC_SHARE_ORIGIN`, `RTC_ICE_SERVERS` and
  `RTC_ICE_TRANSPORT_POLICY` configure Core's browser-sharing path. Signaling/ICE
  requirements are separate from homegames.link LAN discovery.
- Config precedence is environment → user application-data overlay → first base
  config. With no base, common uses its built-in defaults (which enable HTTPS);
  Core's checked-in config disables HTTPS. `HG_APP_DATA_DIR` overrides the state root.
- Direct `npm start` has no launcher to restart Core after dashboard restart actions.
  `npm run develop` references a missing `hotload.js`; do not use it as the start path.
- Offline use requires local game/media files and appropriate disabled network
  features. Browser RTC needs a reachable peer path; manual pairing can bypass
  signaling but does not guarantee all networks work. Node clients need the configured
  server/child ports. The host-only library import path accepts portable ZIPs; keep its runtime
  packages aligned with the browser exports.

See homegames.io/self-hosting.html for the source/bundle workflows. Rehosting Studio
needs the static files/templates and client bundle. Editing and local browser play
need no account backend. Shared-runtime packages and generated bundles must be
rebuilt together to include fixes.


## How the platform works (under the hood)

- Games are **host-authoritative**: one browser or Node instance owns the simulation.
  Guests render nodes and send inputs. Game authors use the shared game API rather
  than implementing sockets or rendering pixels.
- **Each player receives only their current view.** The host serializes its combined
  render tree internally, then `homegames-common/session-runtime.js` filters records
  for each recipient, honoring every ancestor's `playerIds` and audio settings.
  Both Core/WebSocket and LocalSession/RTC call this boundary. A private descendant
  cannot escape a private ancestor. Players with no scoped nodes and spectators
  still receive filtered frames; there is no unfiltered-state fallback (§8).
- Camera culling belongs to the game/view builder: keep the world in plain data and
  attach only current camera projections. The transport enforces declared visibility;
  it does not infer camera bounds from arbitrary coordinates. RTC currently sends
  full **per-player view snapshots**, not deltas or the entire combined host tree.
  Identical frames can be skipped and queued obsolete frames coalesced.
- Squish is the versioned binary node format. Default authoring target: `squish-151`
  (`squishjs@1.5.1`). The browser bundle and shared Node loader support
  **151** and **150** (Squish 1.5.0). The supported version is inferred from the source
  import. Portable validation rejects unavailable or conflicting versions rather
  than substituting another runtime.
  Imports older than 150 must be migrated explicitly before use.
- **homegames-client** renders Squish onto canvas, handles input/media and contains
  LocalSession. A browser host supports multiple local/RTC players. RTC communication
  workers handle transport queues; simulation, Squish serialization and canvas work
  remain on Window. Workers do not make a suspended/closed host continue running.
- **Portable projects:** `portable-project.js` validates source metadata and media as
  data, synthesizes the format-2 project descriptor and produces ordinary ZIPs with a generated SHA-256 inventory. Source execution
  is a separate operation. `portable-runtime.js` supplies project-scoped asset reads;
  `portable-html.js` builds isolated Studio/HTML players. `portable-saves.js` binds
  progress storage to the trusted parent's installation identity.
- **Studio storage:** drafts/snapshots use IndexedDB, not MongoDB or Forgejo. Its
  opaque game frame has no project-storage access; a private MessagePort provides
  progress and explicit export/player operations. See §3 for acknowledgments, conflicts, schemas and backups.
- **Retained operational services:** API RTC signaling/optional relay configuration,
  durable certificate jobs in the API process, and homegames.link discovery/DNS remain
  useful. Manual RTC can bypass signaling. Browser play does not require a Node
  server or HTTPS certificate issuance; optional self-hosted HTTPS still does.
- Main repos: `squish` (authoring/serialization), `homegames-common` (shared sessions,
  input, frames, project packaging and saves), `homegames-client` (rendering,
  LocalSession and RTC), `homegames-core` (Node server, built-ins, tests and tooling),
  `homegamesio` (website/Studio), `homegames` (launcher), `api` (backend), `worker`
  (retired external-worker code), `homegames.link` (discovery/DNS), `homegames-web` (legacy server).

## Implementation references

The shared package’s `docs/` directory includes `ARCHITECTURE.md`, `FLOWS.md`,
`DATA-MODEL.md` and `OPERATIONS.md` for implementation details, storage identities
and release procedures. These are also included in the downloadable authoring
context. For the website guides, see [How it works](https://homegames.io/how_it_works.html)
and [Self-hosting](https://homegames.io/self-hosting.html).

Core's integration tests include portable import/export, Studio/HTML saves, manual RTC and Aquarium with eight players. Local browser tests do not establish performance on physical phones, constrained home uploads or WAN/TURN connections. Measure those environments when setting game capacity.

## Misc facts

- Licensing: Homegames-authored code, templates and cleared media are MIT licensed.
  Keep the license and copyright notices in copies. Third-party material and imported
  projects retain their own terms; do not overwrite their notices. New builds bundle
  MIT Squish 1.5.1 (`squish-151`) and retain MIT 1.5.0 (`squish-150`) for existing projects.
  Portable validation does not verify ownership.
- Contact/support: email joseph@homegames.io, or open a GitHub issue (github.com/homegamesio).
- Bugs/ideas: GitHub issues on the relevant repo under github.com/homegamesio.

## Using this reference

Use Part II for game code and API signatures. Prefer the portable contract unless
the task explicitly concerns historical formats. Generate complete runnable games
when requested, use fresh UUIDs for new games, and exercise their input/lifecycle
paths. If an API is not documented or present in the source, do not invent it.
When editing an existing game, preserve its identity, saves, source and notices.

---

# PART II — SquishJS Game Authoring: the contract for valid games

> Technical reference checked against the shared runtime, browser client and SquishJS (`squish-151` by default). Target portable projects. Static import/export validation reads data without running gameplay (§2); it is not a playthrough or a resource sandbox.

---

## 1. What a Homegames game is

A Homegames game is a **JavaScript class** extending `Game` (or `ViewableGame`)
from a pinned SquishJS package. Export the class from `index.js`. Older format-1
packages may retain their declared custom entry path. Relative CommonJS files are
supported.
One runtime instance owns the shared simulation and feeds serialized nodes to players:

- **Browser host (LocalSession):** Studio or downloaded HTML runs the game. Local
  and RTC players share that instance. Remote guests receive views/assets and send
  inputs; the runtime does not ship them the game source for simulation.
- **Node host (Core/WebSocket):** a server runs the game and browsers render its
  per-player frames. Storage and optional network features depend on configuration.
  Core's file loader binds relative asset paths to files beside the game entry;
  the session uses the existing type-4 encoder for authored video.

Use the shared constructor/hooks in either runtime. Do not assume one player or
hardcode player `1`; use IDs provided by the runtime. Multiplayer is inferred from
`maxPlayers > 1`; no service declaration is needed. Automatic RTC currently caps a
room at 17 participants including the host, even if metadata permits more. Persistence uses `saveGame`/`saveData` (§3),
with storage and durability details depending on the embedding.

Key mental model:

- **You build nodes; the client draws them.** Nodes describe what a player can see,
  hear and interact with now. Keep simulation state, off-camera entities and future
  content in plain variables. Attach/detach views as needed; `ViewableGame` (§13)
  supports world projection but ordinary `Game` can also build per-player subtrees.
- **Per-player views are a core design requirement.** The host may serialize a
  combined tree internally, but each connection receives only public nodes and its
  own visible subtree. Put each camera's projected nodes under `playerIds: [id]`;
  visibility is inherited. Do not send the whole world and rely on clients to hide it.
  The game selects what is in the camera; the runtime enforces the scopes (§8).
- **Host work and network work are different.** Every attached node contributes to
  host serialization. Per-guest bandwidth depends on that guest's filtered view.
  Removing unused nodes saves host work; marking them `[0]` prevents delivery to
  players but leaves serialization work (§4.1).
- **One shared game, many players.** Networking is provided by the runtime. Inputs
  arrive with player IDs; use scopes for visibility, not ownership of an avatar.
- **Do not depend on browser or Node globals.** Game logic should not use DOM,
  `location`, direct storage, sockets or filesystem APIs. Node has no browser DOM;
  isolated portable players cannot access the parent editor or its storage. Use
  injected helpers for saves/uploads/media. Restart by resetting game state in place.
- **The coordinate plane is `0–100` on both axes.** `(0,0)` is top-left; `(100,100)`
  is bottom-right. Camera/world coordinates must be projected into this space.
- **State changes need notification.** After direct node mutation, signal it (§4).
- **Solo play still matters.** Browser multiplayer usually starts with one person;
  bots or a useful solo mode keep it playable while friends join (§14.3).

---

## 2. Project validation and authoring constraints

**New portable projects** contain `index.js`, optional relative modules, and local
media. The exported class's `static metadata()` is the source of game information:

```js
const { Game } = require('squish-151');
class MyGame extends Game {
    static metadata() {
        return {
            gameId: '6c6ccf39-7738-4df7-bcb1-4a276038c6aa', // Generate once for a new game.
            name: 'My Game',
            maxPlayers: 1,
            saveSchemaVersion: 1 // Optional; defaults to 1.
        };
    }
    // Constructor, scene and hooks: §3 and complete examples in §14.
}
module.exports = MyGame;
```

- Do not create a competing manifest or duplicate the imported runtime version.
  The parser infers `151` from the static `require('squish-151')` and creates an
  internal `project.manifest` with `formatVersion: 2`, identity, `entry: 'index.js'`,
  runtime and save schema for storage/export tooling. It is generated bookkeeping,
  not a second authored file. Do not edit the generated integrity inventory either.
- `metadata()` must contain one return of a literal object. Fields may use literals
  or top-level `const` literals, including nested properties such as
  `TUNING.tickRate`. Calls, spreads, getters and runtime computations are rejected.
  `assets` uses literal `new Asset({ path, type })` declarations (§5). The shared
  AST parser reads this data without evaluating the class, its constructor or modules.
- Require only one supported Squish version and project-relative JavaScript or JSON
  modules. Module paths resolve relative to the importing file; assets resolve from
  the project root (§11). The browser bundles **151** and **150**.
  Conflicting/unavailable imports fail validation. Do not use Node built-ins,
  external npm packages, direct networking/filesystem/storage, dynamic imports,
  dynamic `require`, `eval`, `new Function`, or browser/Node globals in game logic.
- `gameId` is a UUID. Preserve it when updating the same game. `maxPlayers` is an
  explicit integer from 1 to 255; new projects do not silently become 64-player games.
  Solo is `1`; values above `1` indicate multiplayer capability. The runtime's own
  capacity and transport limits still apply. There is no authored `services` list.
- Paths cannot escape the project or collide by case. Current limits: 512 authored
  files, 16 MiB/file, 64 MiB total, 1 MiB/JavaScript file, 65 MiB archive. Each asset
  including its 44-byte Squish header must fit 10 MiB; larger collections travel in
  several bounded packets. Supported media: raster images, static SVG, fonts, audio
  and video. Generated `Asset(info, bytes)` values can use `getAssets()` or `addAsset`.
- Export produces an ordinary `.zip` with generated `.homegame/inventory.json`
  hashes. Import checks exact bytes without executing JavaScript. Hashes establish
  integrity, not authorship or safety. Include the appropriate license and media
  attribution files; no hosted publication job or account is required.
- Playing runs code. An isolated browser player protects the editor origin and
  binds save access to its installation, but does not impose CPU/memory limits or
  prove arbitrary code safe. A Node fork runs with its host user's permissions.
  Review unfamiliar source before allowing server execution. Test input paths,
  timers, phase changes, joins/leaves and restore logic; passing import is not a
  gameplay test.

**Older projects remain compatible.** Format-1 `homegame.json` packages retain
custom entry paths, UUIDs, save schemas and byte-derived revisions. Missing legacy
`maxPlayers` retains its old default of 64; legacy empty or `['multiplayer']`
service lists are accepted for compatibility only. A matching old `squishVersion`
can be read, but new source should derive the version from its import. Legacy
`contentGenerator` and other server-dependent services are unsupported; convert
those behaviors instead of substituting silent no-op helpers. To migrate a v1
package, put its existing ID/schema in the entry metadata, set the intended
capacity, move the entry to `index.js` if necessary and update relative imports,
then remove the old manifest/duplicates. That intentional source change creates a
new revision; simple reimport/repacking must not rewrite an old revision or its ID.

---

## 3. The Game class contract

Extend `Game` and implement these. Only `metadata()`, the constructor, and `getLayers()` are mandatory; the rest are optional hooks the runtime calls when present.

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-151');
const { COLORS } = Colors;

class MyGame extends Game {
    // REQUIRED. Generate a new UUID once; preserve it for updates to this game.
    static metadata() {
        return { gameId: '6c6ccf39-7738-4df7-bcb1-4a276038c6aa', name: 'My Game', maxPlayers: 1 };
    }

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

    // A player changed their name in the player menu. Refresh their labels.
    handlePlayerUpdate(playerId, { info, settings }) {}

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

**Save games (optional).** The constructor receives `saveGame` and `saveData`.
The game must both write its progress and restore it; exporting a checkpoint alone
or saving source in Studio does not implement resume.

```js
constructor({ saveGame, saveData }) {
    super();
    this.clickCount = Number.isSafeInteger(saveData?.clickCount) && saveData.clickCount >= 0
        ? saveData.clickCount : 0;
    this.saveGame = saveGame;
    // Build scene nodes from the restored values.
}
// At a natural checkpoint, in an async method:
// try { await this.saveGame({ clickCount: this.clickCount }); }
// catch (error) { /* Surface the failure; do not claim progress was saved. */ }
```

- `saveGame(data)` accepts JSON-serializable data and returns a Promise. Portable
  saves are limited to **1 MiB of UTF-8 JSON**, not one million JavaScript characters.
  Save plain state, not nodes, timers, functions, live streams or asset objects.
- `saveData` is loaded before construction, or absent on first play. Treat it as
  untrusted and validate every field, including after explicit save-file import.
- **Studio and isolated HTML:** a private MessagePort lets the game request only
  progress get/put. The parent selects the installation identity and stores data in
  `homegames-portable-saves` IndexedDB. Portable writes cross the boundary immediately;
  success means the storage transaction committed. Legacy local/hosted backends
  retain their own debounce/storage behavior; do not assume the same acknowledgment.
- A portable slot is keyed by **installation + `save-schema:N`**, with `N` from
  `metadata().saveSchemaVersion` (default `1`; older v1 packages use their manifest). Editing source or restoring a source snapshot
  does not reset progress if that identity/schema is unchanged. ZIP imports and new
  HTML exports get fresh installation identities, so source copies do not share saves.
- For a schema change, declare `saveCompatibility: ['save-schema:1']` (for example)
  and implement any migration in the constructor. The current schema is tried first,
  then compatibility entries in declared order, not by timestamp. The next save writes
  the current schema; older slots remain. Legacy hosted games instead use their
  version IDs in `saveCompatibility`.
- Generation checks reject stale concurrent host writes. Storage/quota failures are
  visible and writes reject; latest session data remains available for Download save.
  Download save/Load save moves JSON progress explicitly between compatible copies;
  import checks game ID/schema. ZIP/source snapshots do not include progress.
- Studio Stop/restart drains pending saves, including writes initiated synchronously
  by the game's `close()` hook, before removing the iframe. Abrupt tab/process/OS
  termination can still lose unacknowledged writes. Save at natural checkpoints;
  do not rely on asynchronous unload work. Clearing/evicting browser storage can
  remove saves, so keep backups. Portable shared progress lives with the host, not
  automatically in each RTC guest's browser.

**Save cost and teardown.** Serialize compact progress at meaningful checkpoints
(purchases, round ends, completed edits), with a bounded debounce for frequent
changes and an explicit flush when leaving that activity. Do not call `saveGame`
every tick: JSON encoding, boundary copies and durable writes all cost work. Keep
at most a bounded amount of pending state, handle rejected writes, and show failure
without claiming success. Save before teardown where possible; a synchronous
`close()` callback can initiate a final write, but it cannot guarantee survival
of tab/OS termination. Stop tracked timers with `super.close()` and release your
own phase/player nodes, held-input state and media references on departure/reset.
Test save/reopen, invalid imported data, quota failure, source-history restore and
old-schema migration. Keep schema migrations deterministic and avoid mutating the
loaded save object before it has been validated.

**Lifecycle signatures:**
- `handleNewPlayer` receives a **single object** `{ playerId, info, settings, clientInfo, requestedGame }` — destructure it. `playerId` is a number. `info.name` is the player's name.
- Players initially get a random two-word name. **More → Your name → Save name** changes it and remembers it in that browser. Local, RTC (including manual connections), and WebSocket sessions call `handlePlayerUpdate(playerId, { info, settings })` for a rename; `info.name` contains the new name and settings are preserved. Update any cached roster or label in this hook. Names are non-unique display text, 1–32 characters, never an identity or authorization key; use `playerId` for session state. Browser preferences stay outside game ZIPs/HTML, so recipients use their own names.
- `handlePlayerDisconnect(playerId)` receives the **bare id**, not an object. (If a player id reconnects while already connected, the runtime fires `handlePlayerDisconnect` for the old connection and then `handleNewPlayer` again.)
- `handleKeyDown(playerId, key)` / `handleKeyUp(playerId, key)` — two positional args.
- A node's `onClick` receives `(playerId, x, y)` — see §9.
- Other real hooks the runtime calls when present: `handleMouseMove(playerId, {x, y})` / `handleMouseUp(playerId, data)` (held-pointer stream, §9), `handleGamepadInput(playerId, input)` (repeated normalized gamepad input; see below), `handlePlayerUpdate(playerId, { info, settings })` (a player renamed themselves or changed settings).

The runtime calls the lifecycle hooks listed above. An unrecognized method such as `canAddPlayer()` does not enforce admission; use `metadata().maxPlayers` for capacity. `getAssets()` is supported on Node and portable hosts and returns `{ key: Asset }`. Generated assets must supply bytes. Declare file assets in `metadata().assets`, use `addAsset` for later additions, and the injected helper for player uploads.

---

## 4. Notify scene changes with `onStateChange()`

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

### 4.1 Serialization and allocation costs

`onStateChange()` and tree operations mark the scene dirty. Notifications coalesce into a flush. The host serializes the attached tree, records inherited audiences and builds each recipient's ordered frame from those records. Every attached node costs host work, including nodes excluded from all player views. RTC sends full filtered snapshots; it can skip identical frames and replace obsolete queued frames, but it does not send node deltas.

Notify once after a batch of changes. Avoid dirtying an unchanged scene. Keep simulation state in ordinary data and attach the nodes needed for rendering and interaction; detach obsolete views and completed screens.

Reuse nodes when it reduces allocation and tree churn, especially frequently updated labels and effects. Pools have a tradeoff: inactive attached slots still cost serialization. Measure reuse against attaching only active nodes, and detach a pool when its phase ends. Pool sizes are game decisions, not a framework requirement to reduce visual complexity.

Measure host serialization, per-player frame bytes, transport queues and client paint time separately. Canvas shadows, text and large images can cost more than simple polygons, so node count alone is not a rendering budget. Optimize the measured cost before changing the game's visuals or population.

### 4.2 Set and measure a budget before raising player counts

Choose an intended player count and a realistic host upload budget. Do not infer
capacity from localhost FPS or the signaling room limit. For scene traffic:

```text
host scene upload (bits/sec) ≈ sum of each remote view's sent bytes/sec × 8
steady uniform case          ≈ guests × bytes per view × sent updates/sec × 8
```

For example, reserving **4 Mbps** for scenes with **seven remote guests at 20
updates/sec** allows roughly **3,570 bytes per guest update before overhead**.
A 20 KiB view at that same rate would require about 23 Mbps across those guests.
These are budget calculations, not platform limits or measured game results.
Leave additional headroom for transport overhead, assets, live media and other
household traffic. TURN relays those bytes; it does not reduce the host's upload.

- Start with a bounded camera projection and explicit caps for visible entities,
  text, particles and live media. One person's small view can coexist with a large
  simulated world. Recompute only the affected views, and detach phase-specific
  roots/pools when the phase ends. Do not lower privacy guarantees to save work.
- Separate simulation rate from visual change where practical. Update counters
  only when their displayed value changes. A stationary player holding a key at
  a wall should not mark an unchanged view dirty. An idle menu should send no
  repeated scene changes after its initial state; identical-frame suppression is
  a backstop, not a reason to rebuild the same nodes every tick.
- Measure **actual received scene bytes and sent update frequency per guest**, plus
  total host upload, host serialization time, input-to-paint delay and client
  rendering time. Include initial asset transfer and peak action, not just a quiet
  lobby. Media transfer is a separate cost from scene snapshots.
- Test one player, the intended full room, joining mid-round, different camera
  regions, spectators, reconnects and repeated restarts. Use a constrained upload
  and a slower phone. Run long enough to find growing node counts, stale per-player
  views, unreleased media, queued saves and memory growth.
- Optimize the measured cost: smaller visible trees/less text for scene bytes,
  fewer dirty flushes for host work, fewer glows/video decoders for canvas time,
  smaller encoded files for startup transfer. Reducing source-file size usually
  does not fix ongoing gameplay bandwidth.

The RTC protocol sends full filtered snapshots. Reusing node IDs helps avoid
allocations and preserves live-media playback, but is not delta compression.

---

## 5. `metadata()` reference

```js
static metadata() {
    return {
        gameId: 'e02fe012-b563-4765-9685-b0b12f58d923', // Stable UUID; keep across updates.
        name: 'Hot Potato',            // Display name.
        author: 'Your Name',           // Creator.
        description: 'One-line pitch shown in the catalog.',
        aspectRatio: { x: 16, y: 9 },  // Display aspect ratio. Common: {16,9}, {4,3}, {1,1}.
        tickRate: 20,                   // Frames/sec for tick(). If you define tick(), ALWAYS
                                        // declare this (an undeclared rate defaults to 60).
                                        // Must be 1-120. No game loop? Don't define tick() at all.
        maxPlayers: 8,                  // Required integer 1–255. 1 = solo; >1 = multiplayer.
                                        // Session capacity, not a minimum player count.
        saveSchemaVersion: 1,           // Optional; defaults to 1. Change only with save migration.
        assets: {                       // Optional portable media. File must exist (§11).
            'potato': new Asset({ path: './assets/potato.png', type: 'image' })
        }
    };
}
```

**Multiplayer comes from `maxPlayers`.** No service flag is needed. Joins above
the game capacity are refused; `canAddPlayer()` is not a hook. The current automatic
RTC signaling limit is 17 participants including the host, so a larger authored
capacity does not guarantee that many network guests. A two-person game may need
both people, or may be fun alone: describe minimum/recommended players in the
instructions and implement a useful waiting/solo state. Do not invent a minimum
from the maximum. Server-dependent services such as `contentGenerator` are not
available in portable games.

Keep `gameId` stable across updates and source restores. `saveSchemaVersion` is a
positive integer, default `1`; it versions progress data, not the source/runtime.
A source edit changes the package revision without requiring a save schema bump.

**Portable `metadata()` returns one object whose fields can be read without executing code.**
Use literals or top-level `const` values initialized from literals, including nested
properties such as `TUNING.tickRate`. Keep these constants immutable. Calls,
spreads, getters and runtime calculations are unsupported. The asset map still
uses literal `new Asset({ path, type })` declarations. Import never runs game code.

- The plane is always `0–100`; `aspectRatio` only controls how that square is presented (letterboxing on the client). Build your layout in `0–100` space and pick an aspect ratio that suits it.
- **Aspect-ratio distortion gotcha:** because the `0–100` square is stretched to fill the aspect rectangle, an x-unit and a y-unit are **not** the same size on screen unless the ratio is `{1,1}`. At `{16,9}` everything is wider than tall — a "square" looks like a rectangle, a `polyCircle` looks like an ellipse, and a 45° heading doesn't look like 45°. For UI/party games this is fine. For **rotation- or distance-based geometry** (twin-stick shooters, anything with circles, orbits, or true angles), prefer **`aspectRatio: { x: 1, y: 1 }`** so the math matches the pixels, or compensate for the ratio in your trig. To draw a **physically square** rect at ratio `{x, y}`, use `height = width * (x / y)` (e.g. at `{16,9}` a `2 × 3.56` rect renders square; at `{9,16}` use `2 × 1.13`).
- **Text size is relative to canvas WIDTH only.** A `size: s` line of text is `s%` of the canvas width tall in pixels — which is `s * (aspectX / aspectY)` **y-units** tall on the plane. At `{1,1}` a size-2 text is ~2 y-units tall; at `{16,9}` it's ~3.6; at `{9,16}` it's ~1.1. Use this to vertically center a label in a box: `textY = boxY + (boxH - size * aspectX / aspectY) / 2`. **Text width is NOT knowable server-side**: each client's canvas resolves the font (default `sans-serif`) with its own metrics, with advance widths anywhere from ~0.6 to ~0.85 of the font size. Budget wide (~`0.85 * size` x-units per character) when sizing boxes/wrapping so wide fonts don't overflow, and never position anything by summing character widths — to place a cursor or caret, embed it in the string itself (a `'▌'` glyph appended to the text lands exactly after the last character on every client; see the Typewriter game).
- `tickRate` is frames per second for `tick()`, bounded 1–120 by portable validation. **A dirty tick serializes the host render tree and prepares each player's filtered view**, so high rates cost real bandwidth. In practice: **15–30 for action games** (shipped catalog games use 15–20 and feel snappy), **8–15 for casual/UI-driven games**. For purely event-driven games (click/turn-based) that update only in handlers, **don't define a `tick()` method at all** — merely defining one starts the loop, at a default **60 fps** if no `tickRate` is declared. Express all in-game durations as `seconds * TICK_RATE` so pacing tweaks don't silently change timers.

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

> **Coordinate precision:** serialized positions have approximately 0.01-unit precision. Keep logical movement in ordinary numeric state so sub-unit motion accumulates; avoid rounding the simulation position after each tick.

> **Off-plane coordinates:** polygon positions clamp to `[0, 255]` on the wire. Negative positions become zero; coordinates from 100 to 255 can extend beyond a frameless canvas. Scaled game layers clip to their 0–100 plane before applying the surrounding frame. Keep off-screen simulation positions in ordinary data and clip or hide their rendered geometry as needed.

> **Vertex-count cap:** a node's `coordinates2d` is serialized into a length-limited wire frame — **at most 126 vertices per node** (verified: 126 round-trips, 127 breaks the frame). For detailed silhouettes (terrain skylines, rings, long strips) budget vertices: e.g. a destructible terrain polygon works at 96 columns (~100 vertices), and a "thick outline" strip that traces a path top-and-bottom doubles its vertex count — sample every other point to stay under the cap. Split very detailed geometry across multiple nodes.

**Colors** are `[r, g, b, a]` arrays, each `0–255`. `a` (alpha) of `0` is fully transparent, `255` fully opaque.

> **Color channels must be integers `0–255`. Out-of-range channels wrap when packed into transport bytes.** Channels are written raw into the frame's byte buffer, so a computed value like `alpha: life * 8` that reaches `400` wraps to `144` mid-fade (the fade visibly flickers back on), and negatives wrap high. Clamp anything you compute: `Math.max(0, Math.min(255, Math.round(v)))`.

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

> **Use a defined palette name or an explicit color array.** `COLORS.CHOCOLATE` or `COLORS.DARK_SAGE` isn't an error — it's `undefined`, and undefined fields are skipped at serialization, so the node renders with **no fill at all**. A "background that doesn't show up" or "shape that never appears" is very often a made-up palette name. If the exact color you want isn't in the list above, use an explicit `[r,g,b,a]` array (e.g. chocolate ≈ `[123, 63, 0, 255]`).

---

## 7. Node types

The basic node types are `Shape`, `Text` and `Asset`, all created via `GameNode`. Squish 1.5.1 also provides native `GameNode.Stream` for live media (see §9, Live microphone and camera). All accept an optional numeric `id` and `playerIds`. Shape, text and asset nodes accept pointer callbacks; use a shape with an explicit hit area for predictable button sizing (see §7.2).

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
    playerIds: [42]                                  // omitted = inherit parent visibility. See §8.
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

- Transparent fill `[0,0,0,0]` + an `onClick` makes an invisible hit-box / button overlay (but see §9's hit-test rules — an invisible node still swallows clicks for things drawn beneath it). Zeroing a node's size and fill (`rectangle(0,0,0,0)`, `[0,0,0,0]`) is how a **pooled effect node** idles between uses (§4.1) — that's the only "hide in place" case. Anything hidden for longer than an effect's off-beat should be **removed from the tree** instead: attached nodes still cost host serialization. Zero-size public nodes also remain in player frames; `playerIds = [0]` excludes nodes from player frames but does not remove the host cost (§8).
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

> **A text label needs a separate click target.** Squish 1.5.1 accepts pointer callbacks on `Text`, but the shared click hit-test requires `coordinates2d`, which the Text constructor does not create. **To make a clickable label or button, put the click handler on a `Shape` and render the `Text` on top of it** — see §7.2.1. This also gives the label a generously sized, predictable touch target.

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
    // playerIds omitted -> inherits parent visibility (§8); use scopes for per-player views/UI
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

The `assetInfo` key (`'potato'`, `'hiss'`) names a **logical entry in `metadata().assets`**, whose value loads bytes from a project path (portable) or hosted asset ID (legacy). Keep the key stable; it is not itself a database ID or a file path.

> **Each audio node plays once.** The client tracks playback by node ID plus asset key. A fresh `GameNode.Asset` can replay the same clip; two separate nodes can play it at the same time. Leaving a finished node attached does not loop it. Remove old sound nodes to stop playback and avoid accumulating them; use a fresh node for the next play. Reusing the exact same node requires its sound to be absent from a rendered frame before it can restart. Start audio from a player action so browser autoplay rules allow it. Muted players do not hear audio.

### 7.3.1 Cropping an image / spritesheets

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

> Cropping is supported by the bundled Squish 1.5.1 runtime.

### 7.3.2 Sprite-with-shape-fallback — developing before the art lands

§11 says to draw with shapes when media is unavailable. A **hybrid system** creates every visual through one factory that returns an `Asset` node when its logical key is registered and a colored placeholder `Shape` otherwise, so art can land incrementally with zero call-site changes. Four rules make it hold up:

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

Every node has `playerIds`. Visibility is inherited through **all ancestors**:

- `[]` / omitted adds no restriction: public beneath a public root, private beneath
  a private ancestor. It does not reset inherited scopes.
- `[42]` restricts this node and its descendants to player `42`.
- `[42, 99]` allows those players, subject to ancestor restrictions.
- `[0]` includes no live player. `hideFor` uses it when the last viewer is removed.
  Current shared frame filtering excludes it even for spectators and players with
  no scoped nodes. It still costs host serialization; detach unused nodes instead
  of treating `[0]` as a performance optimization.

A child cannot broaden its parent's audience. Parent `[42]` plus child `[99]`
reaches neither player. Parent `[42]` plus child `[]` reaches only `42`. A scoped
button's descendant label can inherit the scope; it need not duplicate it.
Current shared input dispatch enforces these ancestor scopes for clicks and
node-ID text, file and hover callbacks. The node must remain attached to an
interactive layer. Games still enforce turn, ownership and value rules (§9).

**Visibility is not controller ownership.** In a shared arena, tagging each ship
with its controller's ID hides it from opponents. Leave shared arena visuals
public. With independent cameras, put **each viewer's projection** under that
viewer's scoped root; that projection can include other players' avatars. Scope
private hands, HUDs and “YOU” markers the same way. The world simulation stays in
plain data; only the currently visible camera contents become attached nodes.

Use the IDs supplied by `handleNewPlayer` and input handlers. Do not derive IDs
from array indices, join order or an assumption that local sessions have one seat.
Legacy Node sessions use a 1–127 pool and 128–255 relay IDs; other adapters own their
allocation. Scope to the actual numeric ID you receive.

```js
node.showFor(playerId);   // add a viewer to this node's own set; ancestors still apply
node.hideFor(playerId);   // remove a viewer; [0] when the set becomes empty
// These helpers do not notify; signal after changes:
this.base.node.onStateChange();
```

**Filter before sending.** `session-runtime.playerFrame` is the shared Core/RTC
boundary. It filters every recipient, including players with no explicitly scoped
nodes and spectators; an empty view clears old visuals. Do not fall back to raw
`squisher.state` or bypass this function with the older package's frame helper.
The earlier unfiltered fallback and need for “privacy anchors” are obsolete in the
current runtime. Old downloaded runtimes require regeneration to get the fix.

Scene filtering controls node payloads, not all session data. Asset bundles can be
sent to all guests, and live-media tracks currently have room-wide distribution.
Do not embed secrets in shared media or mistake hidden nodes for authorization.
RTC guests do not receive host source, but anyone given a ZIP/HTML can inspect its
source and bundled assets.

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

The runtime supplies the authenticated session player ID and checks whether a
node is currently attached, interactive and visible through all its ancestors.
That does not establish ownership, turn order, resources or valid game actions.
Keyboard/gamepad/pointer handlers also need a valid player record and phase gate.
Bound text lengths, parse numbers with range checks, and validate uploaded content
before it affects the simulation. Never use a player name or an ID inside uploaded
JSON as authority. A visible purchase button still needs an affordability check:

```js
buyUpgrade(playerId) {
    const player = this.players[playerId];
    if (!player || this.phase !== 'playing') return;
    if (this.turnPlayerId !== playerId || player.coins < this.upgradeCost) return;
    // Only the authenticated player's own state changes; all rules checked first.
    player.coins -= this.upgradeCost;
    player.level += 1;
    this.refreshPlayerView(playerId);
}
```

Recheck current state on every action, including callbacks from held controls.
Removing or hiding a pressed node can trigger a release callback for cleanup;
release alone must not award points or finalize a privileged action. Test that
another player, a spectator and a stale node ID cannot operate private controls.

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

**A held press fires `onClick` once.** While held, pointer moves drive `game.handleMouseMove(playerId, {x, y})` and the pressed node's **`onDrag(playerId, x, y)`**. Release fires the node's **`offClick(playerId, x, y)`** and `game.handleMouseUp(playerId, data)`. Off-canvas release, tab blur, node removal and visibility changes also clear held controls. For hold-to-move or repeated actions, record pressed state and advance it in `tick()`; do not depend on repeated `onClick` calls. Keep drag callbacks inexpensive and notify once after a meaningful state change.

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
- Scope the field with `playerIds` (§8) so only the intended player sees and addresses it. Current shared dispatch checks every ancestor against the authenticated sender for text, file and hover callbacks, before decoding file bytes. Detached nodes and layers marked `interactive: false` reject input. Older embedded runtimes may lack these checks, so regenerate exports when upgrading. Validate the supplied value and game-specific permissions inside the handler: a visible field does not by itself establish whose turn it is or who owns an item.
- Permission changes take effect on the next input even without a render notification. Notify the renderer too so players see the change. Removing or hiding a held node ends its press with one `offClick` cleanup callback; do not interpret cleanup alone as permission to award a result. Input lookup prunes private branches but still traverses visible content, so keep inactive screens detached and avoid high-frequency node-ID messages. Held-press checks reuse the captured ancestor path.
- `type: 'file'` opens the device's picker for **images, audio and video** when a player clicks the node. Its handler is `oninput(playerId, bytes, meta)`: `bytes` is a **`Buffer`** or **`Uint8Array`**, and `meta` is `{ kind, contentType, fileName }`, with kind `'image'`, `'audio'`, `'video'`, or `null`. Metadata is advisory: the shared classifier checks the file's signature and uses MIME/name hints to distinguish audio-only files in containers such as MP4 and WebM. It does not validate codecs or fully parse the file.
- Accept `handleFileUpload` in the game constructor and call `await handleFileUpload(playerId, bytes, meta)`. It validates the active player and a **5 MiB** limit, copies the bytes, and returns a registered Squish `Asset` with `asset.key` and `asset.info.type`. Reference that key in a `GameNode.Asset`; do **not** register it again with `addAsset` or add it to `getAssets()`. The same helper works in browser/RTC and Core/WebSocket sessions. It distributes assets to current players and retains them in session memory for late joins, without uploading them to the API.
- The picker shrinks oversized images where possible (animated images may flatten); it rejects oversized audio/video. The helper enforces its own 5 MiB cap even though the underlying input decoder accepts up to 8 MiB.

```js
constructor({ handleFileUpload }) {
    super();
    // Create this.base and your other scene nodes first.
    this.base.addChild(new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(40, 10, 20, 10),
        fill: COLORS.YELLOW,
        input: {
            type: 'file',
            oninput: async (playerId, bytes, meta) => {
                try {
                    const asset = await handleFileUpload(playerId, bytes, meta);
                    this.base.addChild(new GameNode.Asset({
                        assetInfo: {
                            [asset.key]: {
                                pos: { x: 10, y: 30 },
                                size: { x: 80, y: 50 },
                                startTime: 0
                            }
                        }
                    }));
                    this.onStateChange();
                } catch (error) {
                    // Show an appropriate message in your game's UI.
                    console.error(error.message);
                }
            }
        }
    }));
}
```

Images display in the node's rectangle; audio plays without drawing; video draws decoded frames into the canvas and continues animating even when the scene does not change. Audio/video play once from `startTime` (seconds). Remove the node to stop playback; replace it with a new node to replay. Each device controls its own playback clock, so late joins begin at `startTime`, not at the host's current position. Games should handle replacement, cleanup and upload failures; Input Test demonstrates those paths.

Browsers may require a tap/click on the canvas to enable sound; video can begin muted. Supported codecs depend on the browser. Uploaded clips are complete files, not live camera/microphone streams. See `src/games/input-test` in homegames-core for the image/audio/video example, and Common’s `media-upload.js` for the runtime contract and limits.

### Live microphone and camera

Browser/RTC sessions inject `media` into the game constructor. `await media.request(playerId, { audio: true, video: false, transmitting: false, pushToTalk: true })` asks that player to confirm capture in a platform dialog and returns a session-scoped stream handle. Catch denial, cancellation, unavailable devices and disconnect errors. Only one capture can be active per player.

Reference its ID with native `GameNode.Stream`, available in `squish-151`. Import that version when using streams; the runtime version is inferred from the import. Squish serializes the stream reference and presentation properties; the session/client transports the live media separately.

```js
const { GameNode } = require('squish-151');
const node = new GameNode.Stream({
    streamId: stream.id,
    pos: { x: 10, y: 20 }, size: { x: 40, y: 30 },
    audio: true,
});
this.base.addChild(node);
```

Audio-only streams need no position/size. Own-source sound is always muted. `audio: false` mutes this node's playback. Preserve node IDs across UI updates to preserve playback. Removing a node stops its playback; `media.stop(stream.id)` releases the capture. Streams are live references, not uploaded assets: do not put them in `getAssets()`, `addAsset`, asset bundles or saves.

Use `media.setTransmitting(id, true/false)` on press/release for push-to-talk. The client also enforces a held canvas pointer/touch or Space key when `pushToTalk` is true and silences capture on release, cancellation, blur, hiding or input detach. This guard prevents delayed game messages from enabling a microphone after release. `transmitting` defaults to true for ordinary capture; explicitly start false for push-to-talk. `media.onChange(listener)` reports `{ id, playerId, audio, video, transmitting, state }` with state `ready`, `changed` or `ended`, and returns an unsubscribe function.

Current media distribution is room-wide: scene scoping and hidden nodes affect presentation, not who receives the tracks. The source is not recorded; late joiners receive live media without history. Manual RTC pairing does not support live streams. The API is present in Core/WebSocket-only sessions, where requests reject with a browser/RTC requirement. See `src/games/walkie-talkie` and Common’s `media-session.js` for the implementation.

### Recorded camera clips

Local, automatic-RTC and current Core/WebSocket games can call `await media.record(playerId, {
durationSeconds: 30, prompt: 'A self-warming spoon' })`. This is separate from live
streaming: the player's device shows an explicit camera/microphone consent dialog,
a muted preview with the prompt, and a Record button. A three-second countdown
precedes capture; the clip stops automatically (1–30 seconds, default 30).
No live tracks are published. The completed video returns as
`{ bytes, meta, durationSeconds }`; call `handleFileUpload(playerId, bytes, meta)`
to register it and display a `GameNode.Asset` as above. Registration shares the
clip with the room, so scene visibility is not a restriction on the file's bytes.

Catch denial, cancellation, missing devices, unsupported MediaRecorder, oversized
clips and disconnects. `media.cancelRecording(playerId)` rejects a pending request
and releases its capture. Hiding the source page cancels capture. The platform
also cleans up on leave/session close, caps clips at 5 MiB, and only accepts the
result from the player who owns the request. An optional `maxBytes` requests a
smaller recording budget (Pitch Pot uses 2 MiB). Games can pass a fourth argument
`{ slot: 'pitch' }` to `handleFileUpload` to replace that player's previous upload
in the same named slot. This bounds retained media across rounds; omit it for
the usual new asset per upload. One recording or live capture per
player may be active. Recording requires HTTPS/localhost and the updated client;
Manual-pairing sessions do not provide recording endpoints. Core/WebSocket endpoints support recorded files but not live tracks.
See Core's `src/games/pitch-pot` for a full record/screen/vote game.

To retain a completed recording as a downloadable file, call `await createExport(name, bytes)` with the recording's original bytes. Use `.mp4` for `meta.contentType` beginning with `video/mp4`, otherwise `.webm` for the current video recorder. `handleFileUpload` registers an asset for playback; it does not persist a user export. Live `GameNode.Stream` references are not recordings and cannot be exported as files. Pitch Pot saves completed pitches this way and players can preview and download them from **View exports** in the game frame. These exports are available to everyone in the session, including before the game's screening phase; they are not private attachments.

Downloaded HTML and Studio previews run in isolated players. Their explicit parent adapter owns the same recording consent UI and file viewer. Game code still uses only `media.record`, `handleFileUpload`, `createExport` and `userExports`; it must not inspect the browser, send parent-window messages, create download links, or access storage directly.

### Hover

`Shape` and `Asset` nodes also accept `onHover(playerId)` and `offHover(playerId)` (pointer enter / leave). Use them only for cosmetic affordances — **touch devices have no hover**, so never gate a mechanic on it.

> **Hover-only nodes work directly in Squish 1.5.1.** The presence of `onHover` is serialized so the client can report enter/leave events; the callback function stays in the game runtime. A no-op `onClick` is unnecessary. The shared dispatcher also checks attachment, interactivity and ancestor visibility before invoking the callback.

### Player cursors

The constructor receives `setCursor(playerId, descriptorOrNull)` in Core/WebSocket, local play, and browser-hosted RTC sessions. The game session owns cursor selection: the client does **not** choose a hand cursor for clickable nodes or change a cursor when hover changes. Each player starts with the native default cursor.

```js
constructor({ setCursor }) {
    super();
    this.setCursor = setCursor;
    this.base = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(20, 20, 30, 30),
        onClick: () => {}, // Optional click action; hover does not require it.
        onHover: playerId => setCursor(playerId, {
            assetKey: 'inspect-cursor',
            size: { width: 32, height: 40 },
            hotspot: { x: 8, y: 8 },
        }),
        offHover: playerId => setCursor(playerId, null),
    });
}
```

- `assetKey` names an image in the normal asset bundle (`metadata().assets`, `getAssets()`, `addAsset`, or a registered upload). Cursor images need no visible `GameNode.Asset`. Keys must be 1–32 printable ASCII characters and contain a non-space character.
- `size` is optional. Supply `{ width, height }` with integer dimensions from 1 to 128 to render the asset at that explicit cursor size. Without it, the asset keeps its native size. The client never chooses a size based on the canvas or hovered node.
- `hotspot` is optional and defaults to `{ x: 0, y: 0 }`. Its coordinates are nonnegative integers in the rendered cursor image's pixel coordinates, not the game's 0–100 coordinate space. When supplying `size`, choose the hotspot for that size.
- `pointerLock` is an optional boolean. Set it to `false` on a menu cursor to release mouse capture and suspend capture on canvas clicks. Returning to `null` (or a descriptor without this flag) permits capture again on the next physical gameplay click. It never enables capture unless the game opted in through `metadata.pointerLock`. This uses the same player-scoped cursor message over local, RTC and WebSocket sessions.
- `setCursor(playerId, null)` restores the native default cursor. A selection persists until the game changes it or that player's session ends. It affects only the selected player's game canvas; it does not affect other players or surrounding page controls.
- Calls return `true` for an active player and `false` for an absent/disconnected player (or an ended local session). Malformed descriptors for active players throw `TypeError`. The client displays the native default while an image is unavailable and applies the latest selection when the asset arrives.
- Reset cursors explicitly when tools, scenes, or modes change. Removing a hovered node does not automatically reset the cursor, and hover callbacks still depend on pointer input. Use `offHover` for ordinary pointer exits and explicit resets when game logic removes/replaces the target. Calls from remote-player hover callbacks take a round trip to the host.
- The cursor is presentation only. Keep touch and keyboard interactions usable without it. Studio's temporary node picker may show its own crosshair, then restores the game's selection.

`src/games/cursor-test` demonstrates one centered hover target using asset `a168ae244a71ea100ff1d9ca4c1fa101` at an explicitly requested 32×40 pixels.

---

### Optional mouse capture for first-person games

Set `pointerLock: true` in the game's literal `metadata()` to enable desktop
Pointer Lock on canvas clicks. Focusing the canvas alone does not capture the
mouse: acquisition requires a user gesture. Escape releases the cursor; blur,
session shutdown and disabling capture also release held keys/buttons. Touch and
unsupported browsers retain the ordinary drag controls. Games without this flag
keep their existing input behavior.

```js
handlePointerMove(playerId, { dx, dy }) {
    const player = this.players.get(playerId);
    if (player) player.angle += dx * 0.0028;
}
```

`dx`/`dy` are accumulated relative mouse deltas, independent of the 0–100 scene
coordinates. They arrive even without a held button, at a bounded cadence of
up to 60 updates/sec. Validate player/game state in the handler. The shared
dispatcher rejects non-finite deltas and magnitudes above 4096. These inputs do
not call `handleMouseMove` or node `onDrag`; those retain their held-pointer
contract. Captured clicks use the canvas center for the ordinary click/fire path.

Local play reads metadata directly; RTC and WebSocket clients receive an optional
input-flags byte after the length-delimited Squish version in their type-2 init
packet. Missing flags default to disabled. Portable HTML/Studio frames grant
`allow-pointer-lock` while retaining their opaque sandbox origin. Existing
downloaded players must be rebuilt to gain capture support. After Hours is the
example game; it keeps keyboard/touch aiming available as well.

After Hours uses a 32px authored cursor with `pointerLock: false` for its welcome,
map, help and voting screens. Its map/mode lobby stays inside the shared game:
the host resolves votes, readiness, balanced teams, flags and control points.
Five maps share the same grid raycaster and Squish projection; only visible
wall panels, props, actors and objectives enter each player's scoped scene.
Kitchen appliances use taller walls/props, while movement, weapons and the
network path remain shared across museum, kitchen, neon, foundry and orbital maps.

---

## 10. Timing and game loop

> **`tick()` starts at construction and never pauses.** The server starts the tick interval the moment your game is instantiated — before any player joins, before any "start" button is pressed, and it keeps firing on menus and game-over screens. Two consequences:
> 1. **Gate the game loop on a phase.** Without an early `if (this.phase !== 'playing') return;`, enemies spawn, waves advance, and power-ups accumulate behind your start screen.
> 2. **Never let `tick()` touch a node a later phase creates.** `this.scoreText.node.text = ...` in `tick()` when `scoreText` is only built inside `startGame()` throws `TypeError` on a lobby that sits idle — and a throw in `tick()` can break the session; static validation cannot catch it. Create every node `tick()` references in the constructor, or guard each access.
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

## 11. Authored assets and runtime uploads

For a portable project, bundle the files and declare them in literal entry-class
metadata. `Asset` comes from the pinned Squish import; the portable loader wraps it
with a project-scoped reader without modifying the released Squish class globally.

```js
const { Asset } = require('squish-151');
// Inside static metadata()'s returned object:
assets: {
    hero: new Asset({ path: './assets/hero.png', type: 'image' }),
    jump: new Asset({ path: './assets/jump.wav', type: 'audio' }),
    film: new Asset({ path: './assets/film.webm', type: 'video' })
}
```

- Paths are relative to the **project root**, not the current module's directory.
  Use forward slashes; no absolute paths, root escapes or remote URLs. A missing
  file fails validation; there is no hosted-ID/network fallback.
- Reference `hero`/`jump` from `GameNode.Asset.assetInfo` (§7.3). These are logical
  keys, not file paths. Images use position/size; audio uses zero size/startTime.
- Authored assets support **raster images, static SVG, fonts, audio and video**.
  SVG must contain no scripting, active elements or external resources.
- Games may generate media using `new Asset({ type, id }, bytes)`. Here `id` is a
  local label, not a hosted dependency. Supply valid encoded media bytes through
  `getAssets()` at startup or `addAsset(key, asset)` during play. No browser APIs
  are required in game code. Player uploads still use `handleFileUpload`.
- Large base64 artwork can live in a project-relative JSON module loaded with
  `require('./art-data.json')`; it is data, not executable JavaScript. The ordinary
  16 MiB file limit applies, while JavaScript retains its 1 MiB limit.
- Each Squish asset record must fit 10 MiB including its 44-byte header. Larger
  collections travel in multiple packets; package limits are in §2.
- Authored video uses the existing type-4 media bundle and node playback (§9).
  Each visible video node owns a decoder; use one node per screen, not raycast
  strips. Playback is local to each browser and does not loop automatically.
- Files selected **during play** use the injected `handleFileUpload` helper (§9),
  which supports image/audio/video in memory and distributes them to players. Such
  uploads do not become project files or durable progress automatically.
- Legacy hosted games use `new Asset({ id: 'actual-hosted-id', type: 'image' })`
  (also audio/font) and the API asset store. Convert their bytes/references to paths
  before portable import. Core's home-server browser-play manifest also includes
  relative-path assets, and its Node file loader supplies local bytes to existing
  Asset instances. On these disk-based paths, files resolve from the entry file's
  directory; keep `index.js` and `assets/` together. Missing/escaping files fail
  instead of falling back to the API. The legacy cloud API's ID-based manifest
  flow remains separate. Restart Core and open a new session after updating it
  so cached manifests/bundles and existing child sessions pick up the change.

If real media files or valid legacy assets are unavailable, draw with shapes/text.
Do not invent asset IDs or declare nonexistent placeholder paths.

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

A plain `Game` can render shared visuals or player-scoped views in the `0–100` plane. For a **world larger than one screen** or independent cameras, **`ViewableGame`** adds a world plane and projection helpers. It is optional: manually projecting plain-data entities into per-player subtrees of `Game` is equally valid.

`ViewableGame` gives you a large square **world plane** of size `planeSize × planeSize` (in its own world units), plus a separate **view root** that is what clients actually render. The rendered viewport is **always `0–100`** — you project a rectangular slice of the big world into that `0–100` viewport, per player. This is how you get cameras, scrolling, and split per-player views in one shared game.

This is the §1 tree model made explicit: the world can be as large as you like **because it isn't what goes over the wire** — what ships is each player's projected view, exactly the slice they're currently experiencing. The same discipline applies at world scale: model the world in plain data (Approach B below makes this literal), and let nodes exist only where a camera is looking.

### Setup

```js
const { ViewableGame, GameNode, Colors, Shapes, ShapeUtils, ViewUtils } = require('squish-151');

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

Keep world entities as **plain data** (not nodes), and update each player's scoped view when the camera or its visible contents change. Reuse stable nodes for moving visible entities, detach those leaving the view, and avoid rebuilding static UI every tick. The minimal example below rebuilds a projection for clarity. Full control — e.g. a camera centered on the player. World→view transform: `viewCoord = ((world − viewOrigin) / viewSize) * 100`.

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

## 14. Examples

### 14.1 Single-player click game (event-driven, no tick)

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-151');
const { COLORS } = Colors;

class ClickCounter extends Game {
    static metadata() {
        return {
            gameId: '0707d399-9175-4c9b-b34c-358cfa5d36b0',
            name: 'Click Counter',
            maxPlayers: 1,
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
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-151');
const { COLORS } = Colors;

class Movers extends Game {
    static metadata() {
        return {
            gameId: '8b831413-5764-467f-bb7d-f397c1f4e920',
            name: 'Movers',
            maxPlayers: 8,
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
        this.players[playerId] = { node: square, name, vx: 0, vy: 0 };
        this.base.addChildren(square, name);
    }

    handlePlayerDisconnect(playerId) {
        const p = this.players[playerId];
        if (p) {
            this.base.removeChild(p.node.id);
            this.base.removeChild(p.name.id);
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
            if (nx === x && ny === y) continue; // Held against a wall: no new frame.
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

### 14.3 Bots and solo play

A browser-hosted game usually begins with its host alone, even though Studio and downloaded HTML support RTC guests. Make that initial solo experience useful, and handle players joining/leaving during play. Do not assume a permanent single-player session or hardcode player ID `1`. The shipped catalog pattern: **bots fill empty slots at match start, and a disconnecting player's avatar is handed to a bot brain** (`agent.playerId = null; agent.isBot = true;`) so rounds never break. Keep entities as plain data (`{ x, y, angle, isBot, ... }`) and run bot logic in `tick()`.

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

### 14.4 First-person raycasting

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
- **Budget honestly**: per-player bandwidth ≈ (shared nodes + own scoped nodes) × ~55 bytes × tickRate. 56 columns × 55 bytes × 12 updates/sec is about 37 KB/s for those slices alone; shared nodes, sprites and transport overhead add to that. Measure actual per-player frame bytes and host upload rather than assuming a network budget. `COLS` and `tickRate` are the knobs; cap humans at ~4 (bots need no view). tickRate 10–14 reads as intentionally retro.
- Movement: apply moves on input events (key repeat / held-tap re-clicks give continuity), slide along walls by resolving the x and y axes independently, and keep a body radius so players don't clip corners.
- Controls: tap left/right thirds = turn, center = forward, plus a FIRE button — with the tap catcher **above the slices, below the buttons** (§9.1), and the crosshair *below* the catcher so it can't eat center taps.

---

## 15. Idioms and anti-patterns

### 15.1 Reuse geometry helpers

Static portable validation does not play the game. Exceptions inside dispatched
input handlers are logged and may leave the game in a partial state; deeper menus,
restart paths and uncommon key combinations need explicit exercise. Repeated
geometry blocks with similar positional locals make undefined-variable mistakes
hard to spot. Three rules:

1. **Mirrored or repeated geometry comes from ONE helper called N times — never from duplicated blocks.** Left/right chopsticks, two paddles, four walls, per-player HUDs: write the math once (like `thickLine` in §7.1), call it with mirrored arguments. Fewer variable names means fewer chances to typo one, and the single implementation gets exercised on every path instead of hiding a broken copy.

```js
// GOOD — one implementation, two calls:
this.leftStick.node.coordinates2d  = thickLine(cx - gap / 2, py, cx - gap / 4, ty, 1.5);
this.rightStick.node.coordinates2d = thickLine(cx + gap / 2, py, cx + gap / 4, ty, 1.5);

// BAD — 20 lines of trig duplicated for "left" and "right" with 16 similar
// local names; this is where `leftPivotY` (undefined) slips in unnoticed.
```

2. **Initialize every field you'll later test, at creation time.** `if (obj.captured === false)` is never true when `captured` was never assigned — `undefined === false` is `false`, so the mechanic silently never fires. Set `captured: false` in the object literal when you create the entity, and prefer truthiness checks (`if (!obj.captured)`), which treat "unset" and "false" the same.

3. **Before shipping, exercise every gated method and inspect its identifiers.** For each key handler, `onClick`, and phase-gated branch: read every identifier and confirm it is defined in that scope, and confirm every `this.foo` was assigned in the constructor. Then actually click through those paths in a preview; mental inspection alone is not a test.

### 15.2 Centralize tunables — the dev tuning menu pattern

Keep gameplay tunables together: round lengths, HP, spawn formulas, yields, ranges and economy. Portable metadata may reference top-level literal constants (§5); avoid runtime calculations there. Group the remaining knobs in one object:

```js
const TUNING = {
    DIFFICULTY: 1.0,
    ROUND_SECONDS: 40,

    PLAYER:  { hp: 3, speed: 0.95, invulnTicks: 26 },
    START:   { money: 5, inv: { water: 100, sugar: 50 } },
    ENEMIES: { baseHp: 2, spawnCdBase: 70, capBase: 3 /* ... */ }
};
```

Four practices make it actually work instead of just looking organized:

1. **Derive aliases so the game body doesn't change.** Use `const TICK = MyGame.metadata().tickRate;` after the class declaration, and aliases for gameplay-only `TUNING` fields, so existing logic can reuse the chosen values without computed portable metadata.

2. **Size render pools *from* tuning values.** If `TUNING.GATHER.wells` says 2 wells, the per-player node pool must be built by looping over that same value — a hand-written array of two nodes crashes the render loop the day someone sets it to 3. Any tunable that controls "how many of X exist" must drive its pool size, or it isn't really tunable. Conversely, pool ceilings (`MAX_ENEMIES`, `MAX_FX`) are **memory/bandwidth budgets, not design knobs** — keep them in the tuning section but labeled as hard caps, and have every count formula clamp against them (`Math.min(MAX_ENEMIES, formula)`) so a wild setting degrades gracefully instead of overflowing a pool.

3. **Copy config objects, never hand them out.** `this.inv = TUNING.START.inv` aliases the config, and the first purchase mutates your "constant." Use `Object.assign({}, TUNING.START.inv)` everywhere starting state is applied — constructor **and** every reset path.

4. **A master difficulty knob scales quantities, not behavior.** `DIFFICULTY` should multiply HP, on-screen caps, and spawn tempo — and deliberately *not* touch movement speed or AI ranges. Scaling speed changes what enemies *are* (a 1.5× erratic hopper is undodgeable; kiting distances break); scaling counts and toughness changes how *hard* they are while every breed stays readable. Tempo knobs divide cooldowns, quantity knobs multiply counts (clamped by pool caps), and results get `Math.round` plus a floor of 1 so fractional multipliers can't produce 0-HP enemies or 0-tick cooldowns.

### 15.3 Common input and color mistakes

- **Upgrade buttons advertise the *next* state, not the current one.** A "TURRET 2/4" label after two turrets are built reads as "buy turret #2" — off-by-one against what confirming will actually purchase. Label with `(count + 1)`. Applies to any incremental purchase.
- **Voted actions re-vote on state change.** Any majority-vote flow (recipe confirm, shared purchase) must reset its votes when the thing being voted on changes — the proposal switches, the recipe is adjusted, or a voter disconnects (recount against the new majority threshold, and re-check whether the vote now passes with fewer players).

---

## 16. Quick reference card

```
require('squish-151')  ->  { Game, GameNode, Colors, Shapes, ShapeUtils, GeometryUtils, Asset, Physics, ... }

Runtime:      one host-authoritative game instance: browser LocalSession (local + RTC players),
              or Node/Core with WebSocket clients. Use runtime-assigned player IDs, not fixed id 1.
              Session invitations join the running host. Source copies can be requested separately.
              Manual offer/answer bypasses Homegames signaling but cannot guarantee all NAT paths.
Portable:     ordinary .zip = index.js + source/media + generated inventory; .html = playable copy.
              New games: no authored manifest. Internal format-2 descriptor is derived from metadata.
              New games use squish-151; version comes from the import. Existing squish-150 projects remain supported.
              V1 manifests/custom entries remain supported with runtime 150 or 151; earlier runtimes are rejected.
Saves:        constructor({saveGame, saveData}); validate loaded JSON and rebuild nodes from state.
              Portable: <=1 MiB UTF-8 JSON; Promise resolves after IndexedDB commit, no write debounce.
              installation + save-schema:N slot; source snapshots don't roll back progress.
              saveCompatibility:['save-schema:1'] enables explicit older-schema restore (§3).
              ZIP imports/new HTML exports get fresh installations; Download save/Load save moves progress.
              Handle quota/conflicts; legacy backends have different storage/debounce behavior.
metadata():   portable: literals or top-level const literals/properties; no calls or spreads.
              gameId: stable UUID; name: display name; maxPlayers: required integer 1–255.
              maxPlayers:1 = solo; >1 = multiplayer capability, not a minimum count. No services list.
              Old omitted capacity stays 64 for compatibility; new projects must declare it.
              saveSchemaVersion: positive integer, default 1. No duplicated squishVersion.
              Automatic RTC room cap: 17 including host; no canAddPlayer hook.
              declare tickRate (1-120) for tick games; omitted rate defaults to 60.
Assets:       metadata.assets.hero = new Asset({path:'./assets/hero.png',type:'image'}) (§11).
              Path is project-root-relative; requires are source-file-relative. Raster images/audio/video.
              GameNode assetInfo keys reference these logical names. No hosted-ID/network fallback.
              Generated Asset(info, bytes): register via getAssets()/addAsset; uploads use handleFileUpload.
Dead hooks:   use documented hooks; plausible names such as canAddPlayer aren't invoked (§3).
              getAssets() works on both Node and portable hosts.

Game hooks:   metadata() [static, required] · constructor()->super() · getLayers()->[{root}]
              handleNewPlayer({playerId,info,settings,clientInfo}) · handlePlayerDisconnect(playerId)
              handleKeyDown(playerId,key) · handleKeyUp(playerId,key) · tick() · close()
              handleMouseMove(pid,{x,y}) · handleMouseUp(pid,data) · handleGamepadInput(pid,input)
              metadata.pointerLock:true → handlePointerMove(pid,{dx,dy}) for captured mouse (§9)
              handlePlayerUpdate(pid,{info,settings})   // rename / settings change

Tree model:   simulation/world state stays in plain variables; attach only current render content.
              Build per-camera subtrees with playerIds:[viewerId], including visible other avatars.
              Shared boundary filters each recipient BEFORE delivery; no unfiltered fallback (§8).
              Combined host node count is NOT a per-guest frame count.

Nodes:        GameNode.Shape({ shapeType, coordinates2d, fill, color, border, onClick, effects, playerIds })  // clickable
              border = NUMBER (outline width), NOT an object; stroke uses `color` -> set both. fill=interior.
              round shape: build a many-sided polygon (CIRCLE doesn't render). rotate verts with trig (§7.1).
              max ~126 vertices per node (§6). effects:{shadow:{color,blur}} = glow; clear with null, never {} (§7.4).
              GameNode.Text({ textInfo:{ text,x,y,size,align,color,font }, playerIds })       // no geometry for click hit-testing
              GameNode.Asset({ coordinates2d, assetInfo:{ key:{pos:{x,y},size:{x,y},startTime} }, playerIds })  // clickable
              image drawn from assetInfo pos/size; clicks hit coordinates2d -> keep them aligned (§7.3)
              audio = zero-size Asset; add to tree = play, remove = stop; tracked by node ID + asset key.
              Use a fresh node to replay a clip (§7.3). Remove old nodes; use bundled media.
              Asset crop: assetInfo.key.{cropLeft,cropTop,cropRight,cropBottom} = % inset per edge -> spritesheets (§7.3.1)
Button:       no button node + Text isn't clickable -> clickable Shape (onClick) with a Text node on top (§7.2.1)

Tree ops:     n.addChild(c) · n.addChildren(a,b) · n.removeChild(id) · n.clearChildren([keepIds])
              n.findChild(id) · n.update({fill,coordinates2d}) · n.showFor(pid) · n.hideFor(pid)
NOTIFY:       n.node.onStateChange()   // after direct field mutation; tree ops notify for you
Cost:         dirty flush serializes the combined host tree, then filters/copies each recipient's view.
              Network = sum of sent per-player snapshots, not whole tree times players (§4.1).
              Notify only on changes; reuse nodes for moving visuals; detach obsolete scenes/entities.
              Small transient effect pools can idle at zero size; hidden attached nodes still cost CPU.
              RTC skips identical/coalesces queued frames; it currently sends full views, not deltas.
Env:          game logic must work without DOM/direct storage/Node APIs; use injected helpers.
              "Play again" = reset game state, never location.reload() (§1).
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
Typo safety:  static validation does not exercise input handlers or lifecycle transitions.
              mirrored geometry = ONE helper called twice (thickLine, §7.1);
              initialize fields you'll test (captured: false); exercise gated handlers in preview (§15.1)
Off-plane:    coords clamp to [0,255] on the wire — negatives pin to 0 (no off-screen left/top);
              100..255 = off right/bottom; enter from left/top by spawning AT the edge moving inward;
              walk-ons: keep pos in plain vars, hide node until FULLY on-plane (x >= half-width) (§6)
Aspect:       plane is 0..100 but stretched to aspectRatio -> use {1,1} for circles/orbits/true angles (§5)
              text height in y-units = size * (aspectX/aspectY); square rect: h = w * (x/y) (§5)
"Hiding":     detach unused nodes. Zero-size nodes still serialize and can reach visible recipients.
              [0] excludes all live players but retains host serialization cost; no spectator leak (§8).
Fade a node:  animate `color` alpha (fill alpha is opaque for any value >= 1); pooled fx recipe:
              fill = solid hue, color = [255,255,255,a] — a translucent-looking fill ([r,g,b,110])
              renders as an opaque paint blob (§7.4)
Sprites:      shape-fallback hybrid: ONE factory + ONE placeSprite() for all placement; grouped keys
              activate all-or-nothing; every tint signal needs a sprite equivalent (size puff/blink);
              placeholder chrome self-hides behind if(node._sprite) (§7.3.2)
Tuning:       gameplay knobs in TUNING; pools sized from counts, formulas clamp to caps; copy config objects.
              Portable metadata accepts literals and top-level const properties; avoid runtime computations (§15.2, §5).
onClick:      (playerId, x, y) => {}    // Shape/Asset only
Held press:   one onClick, then node onDrag(pid,x,y) + game handleMouseMove while held,
              node offClick(pid,x,y) + game handleMouseUp on release (§9)
Click routing: topmost CONTAINING node wins, clickable or not -> containers must be rectangle(0,0,0,0);
              full-screen taps need a tap-catcher above the playfield, below the buttons (§9.1)
              oninput/hover require an attached, interactive node visible through every ancestor;
              handlers still validate game-specific turns, ownership and values (§9)
text input:   Shape/Text input:{ type:'text', oninput:(playerId, value)=>{} }  // MODAL prompt; one-shot entry
file upload:  input:{ type:'file', oninput:(playerId, bytes, meta)=>{} }  // bytes = Buffer/Uint8Array (<=5 MiB),
              meta = { kind:'image'|'audio'|'video'|null, contentType, fileName };
              await handleFileUpload(playerId, bytes, meta) -> registered Asset with .key (§9)
Live typing:  held keys re-send keydown every ~33ms with NO delay -> gate them like an OS keyboard:
              fresh press (not seen >400ms) types instantly; held repeats after 450ms at ~18cps (§9 Keyboard)
hover:        Shape/Asset onHover(pid) / offHover(pid)   // cosmetic only; no hover on touch;
              hover-only nodes are supported directly (§9)
cursor:       constructor receives setCursor(pid, { assetKey, hotspot:{x,y} }) or setCursor(pid, null)
              per-player image asset; session-owned until changed/reset; no automatic hover cursor (§9)
playerIds:    [] / omitted = inherit ancestors (public under public root); [id,...] narrows audience.
              [0] = no live player. Children cannot broaden parent scopes; [] never resets privacy.
              Players with no scoped nodes and spectators still get filtered frames; no anchors needed.
              VISIBILITY, not controller ownership: shared arena avatars public; camera copies scoped
              to their VIEWER. Use actual runtime IDs, never indices. Authorize input handlers too (§8).
              Asset bundles/live tracks may be room-wide; scene scopes don't make their bytes private.

Rounds:       last-man-standing must special-case solo (1 player alive at spawn != winner) — require >=2
              at round start or fill with bots (§14.3)

Bots:         fill empty slots at match start; hand disconnected players' avatars to a bot brain (§14.3)
              fair combat bots: acquire (LOS + range + own cooldown) -> TELEGRAPH 0.5-1s (stop, turn toward
              target) -> fire with distance-scaled aim error -> 2-3x human cooldown. NEVER snap-fire.
3D:           per-player raycast view = N playerIds-scoped slice rects (stable ids) mutated per tick (§14.4)
              share floor/ceiling/HUD; occlude sprites vs per-column wall dists; COLS x tickRate = bandwidth

Big worlds:   optional ViewableGame · super(planeSize) · getPlane()/getPlaneSize() = world
              getViewRoot() = render root (starts EMPTY) · getLayers()->[{root:getViewRoot()}]
              ViewUtils.getView(plane,{x,y,w,h},[pid], translation?, scale?) projects a world slice into 0..100
                translation={x,y,filter?} scale={x,y} -> inset the projection (static frame + scroll region, §13.1)
                clones keep onClick for SHAPES ONLY (Asset/Text clones drop handlers) and always
                get the viewing player's playerIds — no private world-space nodes (§13.1)
```


## User exports: game-defined files

Hosts inject `createExport(name, bytes)` and `userExports` into the game constructor. `name` is a single portable filename (for example `monster.json`); `bytes` is a `Uint8Array`. The session chooses the directory. Await writes and report failures. Reusing a name replaces that file. The constructor's `userExports[name]` contains initial bytes, or is undefined; decode and validate them in game code, with bundled defaults as fallback. Formats are game-defined and may mix JSON and binary files.

Node hosts store these under the game's `user-exports/`; users can edit files and restart. Browser hosts keep overrides locally. Game downloads and peer copies include acknowledged exports alongside unchanged source/default assets. Games do not handle browser downloads, paths, base64 packaging or storage APIs. Export data is separate from `saveGame` progress and is never executed as a source module. See [architecture](ARCHITECTURE.md#game-defined-user-exports) for limits and host details.

```js
constructor({ createExport, userExports = {} }) {
    super();
    this.createExport = createExport;
    this.lines = []; // bundled/default creation
    try {
        if (userExports['drawing.json']) {
            const data = JSON.parse(new TextDecoder().decode(userExports['drawing.json']));
            if (Array.isArray(data) && data.length <= 10000 && data.every(point =>
                Array.isArray(point) && point.length === 2 && point.every(Number.isFinite))) this.lines = data;
        }
    } catch (_) { /* Invalid user-edited data: keep the default. */ }
}
async saveDrawing() {
    try {
        await this.createExport('drawing.json', new TextEncoder().encode(JSON.stringify(this.lines)));
        // Show success in the game's scene.
    } catch (error) {
        // Show the storage/size failure in the game's scene, and allow retry.
    }
}
```

**View exports** in the shared player toolbar lists successfully saved files, with image/audio/video previews where supported, plain-text previews, and **Save file**. Unknown formats remain downloadable. It works through the session protocol for local, RTC and WebSocket clients. Files are shared with joined players, not scoped by `playerIds`. Opening the viewer does not call into a game instance. A client can also use `listExports()` and `readExport(name)` to obtain metadata or `{ name, bytes }`.

Website, self-hosted browser and downloaded HTML players use `homegames-common/player-toolbar.js`. Open the Homegames menu for invitations, **Share with friends**, downloads, editing and available player tools. Solo games omit session invitations but can still share independent copies. Opaque players expose client actions/state to their trusted parent through `portable-client.js`; they do not render a second menu inside the iframe.

To edit and re-import a creation, download the running player's **game ZIP** (or an updated HTML copy), which includes current `user-exports/` files. Import the ZIP into the existing Studio, edit or replace the files in that directory, save the project, and launch a new preview or download. On a Node host, edit the raw files in the game's `user-exports/` directory and restart the session. A new constructor receives those bytes through `userExports`; the game decides how to validate and apply them. The viewer's individual **Save file** button saves only that file, not a whole game or progress save. There is no automatic import of arbitrary files into game state from the viewer.

`userExports` is a constructor-time snapshot, not a live map: update game state yourself after writing. Names are single portable filenames, never paths; exports may mix data formats. Limits are 128 files, 16 MiB per file, 64 MiB total. Await and handle failures, choose stable names when replacing data, and make names unique when retaining multiple creations. Browser persistence does not modify an already-downloaded HTML file; download a fresh game copy to carry new creations to another installation. Studio's source export contains the editor files; use the running preview's download controls to capture files generated during play.
