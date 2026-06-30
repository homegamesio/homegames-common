# Homegames — System Brain Dump (start here)

> If you're reading this to take over or understand Homegames end-to-end, this is
> the front door. It's deliberately a complete "if I got hit by a bus" dump. The
> sibling docs in this folder go deeper:
>
> - **ARCHITECTURE.md** — every component, what it does, how they connect
> - **FLOWS.md** — end-to-end traces (play, author+publish, signup, moderation, AI edit)
> - **DATA-MODEL.md** — MongoDB collections, Forgejo repos, the asset store, identity
> - **INFRA.md** — what physically runs where, domains, secrets inventory
> - **OPERATIONS.md** — deploy/update/restart, logs, backups, failure playbook
> - **squishjs-game-authoring.md** — the contract for writing games (also fed to the LLM)

---

## What Homegames is

Homegames is a platform for **making and playing simple multiplayer games in the
browser with as little friction as possible.** No installs to play, a free
in-browser studio to build, one click to publish to a public catalog.

It started as an experiment: *could a server drive what a browser renders purely
by sending drawing instructions over a WebSocket?* That worked, and it grew into
a whole product — a serialization format (squish), a game runtime, a renderer, a
catalog, an in-browser code studio, an asset pipeline, and an LLM that can write
games for you. The guiding principle throughout is **minimum friction** for both
players (nothing to install) and developers (build, share, done).

Originally it was **self-hosted** (run the server at home, play on your LAN, and
optionally expose it to the internet through a relay). It is now also — and
primarily — offered as a **free hosted service at homegames.io**, so people can
use it without running anything themselves. (The self-host relay,
`homegames.link` / `public.homegames.link`, was a working experiment but is not
actively maintained; see INFRA.md.)

A second guiding principle is **operational simplicity**: the entire backend runs
on a **single EC2 host** on purpose, so that anyone can stand up their own
Homegames without orchestrating a fleet. (The one planned split is pulling the
game-session runtime onto its own host for scalability — see INFRA.md.)

---

## The 30,000-ft picture

```
            Players' browsers                 Developers' browsers
                  │                                   │
                  │ HTTPS (site, static)              │ HTTPS (studio UI + REST)
                  ▼                                   ▼
        ┌──────────────────┐                ┌──────────────────────────────┐
        │ homegames.io      │                │  api.homegames.io  (the API) │
        │ S3 + CloudFront   │                │  ── on ONE EC2 host: ──      │
        │ (static site +    │                │   • API (Node)               │
        │  studio + client) │                │   • MongoDB                  │
        └──────────────────┘                │   • RabbitMQ                 │
                  │ WebSocket (game frames)  │   • Forgejo (git for games)  │
                  ▼                          │   • homegames-core + Docker  │
        ┌──────────────────┐                │     (each live game session  │
        │ game session      │◄───────────────│      runs in a container)    │
        │ (homegames-core   │  spawns        │   • API worker (publish      │
        │  in a container)  │                │     validation; NSFW is      │
        └──────────────────┘                │     in-process in the API)   │
                                            └──────────────────────────────┘
                                                         ▲
                                                         │ pulls jobs from RabbitMQ
                                                         │ (LLM "AI edit" requests)
                                              ┌────────────────────────┐
                                              │ LLM worker (MLX)        │
                                              │ Joseph's Mac Studio     │
                                              │ (Apple Silicon, at home)│
                                              └────────────────────────┘
```

Everything except the website (S3/CloudFront) and the LLM worker (a Mac Studio)
runs on that **single EC2 instance**.

---

## The repos and what each is

| Repo | Role |
|------|------|
| **squish** (`squishjs` on npm) | The serialization format + game node types + `Game`/`ViewableGame` base classes. The shared contract between server and client. Published as many pinned versions (`squish-135`, `squish-138`, `squish-140`, …) so old games keep working. |
| **homegames-common** | Shared library used across the backend: game loading (`game-loader`), the Docker runner + per-session manager (`docker-helper`, `game-session-manager`), config/util, and **this documentation** (single source of truth, incl. the authoring guide). |
| **homegames-core** | The game-session server. Loads a published game, runs it, squishes its scene graph, and streams frames to connected browsers over WebSocket. Each live session runs in a Docker container (`docker/` holds the runner image + `validate.js`). |
| **homegames-client** | The browser rendering engine: connects over WebSocket, unsquishes frames, draws to a `<canvas>`, captures input, manages assets. Bundled and served to players. |
| **homegames-web** | A tiny static server for the self-host path (serves the client bundle + a config). Largely superseded by homegames.io for the hosted service. |
| **homegamesio** | The public website (`homegames.io`): landing pages, the **catalog**, the **play** page, the **Studio** (in-browser game editor), the **Admin** moderation console, and the password-reset/verify pages. Served from S3+CloudFront; `app.js` is the Node origin for HTML routes. |
| **api** | The backend REST API (`api.homegames.io`): auth (signup/login/email-verify/reset), the Studio backend (Forgejo-backed editing + publish requests), the catalog, asset upload (+ **in-process NSFW classification**), admin endpoints, and the **publish-validation worker** (`worker.js`). |
| **worker** | The **LLM worker** that processes Studio "AI edit" requests. A Node parent (`index.js`) pulls jobs from RabbitMQ and drives a long-lived Python **MLX** model server (`llm/model_server.py`). Runs on the Mac Studio. |

External services on the host: **MongoDB** (all app data), **RabbitMQ** (job
queues), **Forgejo** (a self-hosted GitHub-like git server — every game's source
lives in a Forgejo repo).

---

## Bus-factor essentials (the absolute must-knows)

1. **One EC2 host runs almost everything** (API, Mongo, RabbitMQ, Forgejo,
   homegames-core+Docker, the API worker) via **systemd services**; logs are in
   **journalctl**. See OPERATIONS.md.
2. **The website is static** (S3 + CloudFront), deployed with `homegamesio/deploy.sh`.
3. **The LLM worker is a Mac Studio at home** that pulls from the EC2's RabbitMQ.
   If it's off, "AI edit" in the Studio just doesn't process — nothing else breaks.
4. **Game source lives in Forgejo**, one repo per game, owned by the user's
   *internal id* (not their display name). MongoDB holds metadata + which commit
   is published. See DATA-MODEL.md.
5. **Publishing = running untrusted code.** A submitted game is AST-scanned and
   run in a locked-down Docker container before it's allowed to publish. The
   live containment and the validation gate are in `homegames-common/docker-helper.js`
   and `api/worker.js` + `api/ast-scanner.js`. Read `homegames-core/../security_notes.md`
   before scaling this up.
6. **squish is versioned and pinned.** A game declares `squishVersion`; the server
   squishes with that version and the client unsquishes with the matching one.
   Never break an old squish version — publish a new one.
7. **Secrets** (JWT, Forgejo webhook + user-password derivation, LLM worker, AWS,
   SES, Mongo) are inventoried in INFRA.md.
