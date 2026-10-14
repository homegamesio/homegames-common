# Homegames — System overview

Reviewed against the current local code on October 12, 2026, including uncommitted changes. This is an implementation map, not a statement about production hosts or deployed versions.

Homegames makes and plays JavaScript games using SquishJS. The current Studio is **account-free**: users create browser projects, edit source and media, save local snapshots, and export ZIPs or playable HTML. One browser runs the simulation; friends join that browser over WebRTC. A home server remains an optional way to discover/install games and run browser or Node/WebSocket sessions.

## What changed, and what remains

| Current path | State and dependencies |
| --- | --- |
| Studio projects | `studio-portable.js` + `studio-project-store.js`; IndexedDB on the current origin. No signup, verification, hosted source repository or cloud asset upload. |
| Portable exports | Common validates source/media/manifest and packages an ordinary ZIP or a self-contained HTML player. No publish job is needed. |
| Multiplayer | Browser host owns the game. Automatic invitations use RTC signaling and configured ICE servers; manual offer/answer can bypass Homegames signaling. |
| Website collection | Build-selected local folders/ZIPs become static HTML pages and portable packs. Website Play loads the pack into an isolated browser host; invitations are private. |
| Legacy catalog | Source and stored data remain for historical tooling; the active API no longer registers content endpoints. |
| Account backend | Account/profile/publishing routes are absent from the active API. No automatic hosted-data migration or deletion is performed. |
| Self-hosting | Core serves a dashboard/client, browser games and optional Node/WebSocket sessions. homegames.link discovery and certificate jobs remain separate services. |

Projects are not cloud-synchronized. Clearing browser storage can lose them. ZIP exports carry the selected source/media version; snapshot history and game progress need separate backups. Progress exists only when the game uses `saveGame`.

## Intended simplification and current gaps

The maintainer's intended destination is a static website serving bundled games and self-hosting downloads, an API limited to connection helpers (certificates, homegames.link and RTC), and player-owned games with bundled assets. Accounts, developer profiles and centralized publishing are to be retired. The website now builds that static collection from an explicit path list and serves game pages without JavaScript. The home dashboard now reads its local library. Legacy catalog/account source remains on disk, but the active API no longer loads those routes. Deployment retirement and historical-data migration are separate operational steps.

Self-hosting and browser RTC already coexist with optional Node/WebSocket hosting. WebSocket hosting is a separate session mode, not automatic failover for a running RTC game. Core's local library discovers compatible unpacked game folders containing `index.js`, including those under `src/games` or `LOCAL_GAME_DIRECTORY`; portable projects may also declare a nested entry in `homegame.json`. Use the localhost dashboard’s Import ZIP button to validate and install an archive under app data; dropping an arbitrary ZIP into `src/games` does not install it. Current bundles ship all visible built-ins with local media, local RTC signaling and an explicit offline launch override; homegames.link/certificates are optional online helpers. Both transports carry Squish scene frames, but input/signaling/control messages also use JSON and media has separate transfer paths. A live Share invitation joins the host session; Share a copy sends an editable portable ZIP over a separate private RTC channel to a generic game-only receiver. The recipient builds/downloads a self-contained HTML and can keep an individual game app locally. Per-game manifests and bundles live on the device; the server has no game registration. Studio remains the authoring tool.

The licensing policy is GPL or MIT for Homegames-authored components. Existing license notices and package metadata still need reconciliation, and bundled third-party material may carry other licenses. This policy does not by itself relicense that material. See the [licensing audit](../../homegamesio/docs/code-audit.md#licensing-policy-and-current-notices).

## Runtime and infrastructure

```text
Studio/static templates -> browser project library (IndexedDB)
                         -> portable ZIP / standalone HTML
                         -> isolated browser host <--- RTC ---> guest browsers
                                      |
                               signaling / ICE setup
                                      |
                      API /rtc, optional STUN/TURN

Downloaded HTML -> RTC copy -> generic receiver -> saved HTML / individual game app
Static website collection -> portable ZIP -> isolated browser host -> RTC guests
Home dashboard Library -> installed folders + validated portable ZIP imports

Home launcher -> Core dashboard -> browser play / household room discovery
                              \-> optional Node session -> WebSocket clients
```

Signaling arranges peers; it neither executes games nor receives their gameplay frames. TURN, when configured and needed, relays peer traffic. The host tab must remain alive; there is no host migration. Manual connections still depend on network reachability and may need infrastructure the manual UI does not configure.

## Repository responsibilities

| Repo | Current role |
| --- | --- |
| `homegamesio` | Static HTML game collection, portable packs, Studio project library, player and HTML guides. |
| `homegames-common` | Shared runtime/input/filtering, portable format/execution/saves, RTC signaling, Node orchestration, config and authoring reference. |
| `homegames-client` | Rendering/input, browser LocalSession, RTC host/guest transports and portable browser API. |
| `squish` | Versioned scene model and serialization, distributed as `squishjs` and pinned aliases. |
| `homegames-core` | Home dashboard, local library, Homenames, browser game serving, Node/WebSocket sessions and integration tests. |
| `homegames` | Launcher/supervisor and downloadable server bundle builder/publisher. |
| `api` | RTC signaling and IP/certificate helpers; legacy handlers/publish worker are not used by the active entry point. |
| `worker` | Durable certificate, docs-question and legacy AI jobs; model bridge is configurable. |
| `homegames.link` | LAN discovery/redirect and DNS registration; not a tunnel to private LAN addresses. |
| `homegames-web` | Separate older browser host; Core also serves its client directly. |

## Read next

- [ARCHITECTURE.md](ARCHITECTURE.md): modules and execution boundaries.
- [FLOWS.md](FLOWS.md): editing, exports, play, sharing and retained publishing.
- [DATA-MODEL.md](DATA-MODEL.md): browser projects/progress, room state and retained backend data.
- [INFRA.md](INFRA.md): dependencies, config and ports supported by code.
- [OPERATIONS.md](OPERATIONS.md): building, staging, backups and troubleshooting.
- [homegames-context.md](homegames-context.md): detailed authoring contract.

Source entry points: `homegamesio/studio.js`, `studio-portable.js`, `studio-project-store.js`, `client.js`, `play.html`; common `portable-*.js`, `rtc-signaling.js`, `session-runtime.js`; `api/index.js`, `router.js`; `homegames-core/game_server.js`. Follow executing branches rather than commented rollback implementations.
