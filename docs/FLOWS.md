# Homegames — End-to-End Flows

Traces through the system for the things that matter. See ARCHITECTURE.md for the
components named here.

---

## 1. Playing a game (hosted)

1. Player opens `homegames.io` (S3/CloudFront) and picks a game from the catalog,
   or hits a play link with a `gameId`/`versionId`.
2. The page asks the **API** to create/find a **session** for that published
   version. The API (via **Homenames** + homegames-core) ensures a
   **homegames-core session is running in a Docker container** for that game and
   returns a WebSocket endpoint/port.
3. The **homegames-client** (bundled in the page) opens the WebSocket. The server
   sends an **init** message (player id, aspect ratio, bezel, and the game's
   **squishVersion**), then the **asset bundle** (type 1), then **state frames**
   (type 3).
4. The client picks the matching `unsquish` for that squishVersion, decodes each
   frame, and **renders** polygons/text/images to the canvas (0–100 space → pixels).
5. Player input (click/key/touch) is normalized to 0–100 and sent back over the
   socket; homegames-core routes it to the game instance's handlers
   (`onClick`, `handleKeyDown`, …), which mutate state; the `Squisher` coalesces
   and broadcasts the next frame.
6. Per-player visibility (`playerIds`) means each player can receive a different
   frame — the server only squishes what that player should see.

Multiple players share **one** game instance (it's authoritative); there is no
per-player game process.

---

## 2. Authoring + publishing a game

**Author (in the Studio):**
1. User signs in to the Studio (`homegames.io/studio`). On first studio action the
   API lazily provisions them a **Forgejo account** (username = their internal
   `userId`; password derived by HMAC from `FORGEJO_USER_SECRET`).
2. "New Game" → API creates a **Forgejo repo** (`<userId>/<repo>`), commits a
   GPLv3 `LICENSE` + a chosen starter template, and a `games` record in Mongo.
3. Editing in the Studio writes files via the API → Forgejo commits (the **Save
   Version** path). They can Preview (a real session of the working tree), use
   **AI Edit**, set Description/Thumbnail in **Settings**, etc.
4. They can also `git clone` the repo (Settings → Clone) and push from the CLI.

**Publish pipeline:**
5. **Publish** (or a Forgejo push webhook) → the API enqueues a job on RabbitMQ.
   Webhooks are HMAC-verified (`FORGEJO_WEBHOOK_SECRET`).
6. The **API worker** (`api/worker.js`) consumes `publish_requests` and validates
   the target commit:
   - `index.js` exists; a **GPLv3 LICENSE** matches; size limits OK.
   - **AST scan** (`ast-scanner.js`) every `.js`: no banned `require`s (fs, net,
     child_process, …), no `eval`/`Function`, no dynamic `require`/`import`, etc.
   - **Docker validation** (`validateGame`): load the class, check `metadata()`
     + `squishVersion`, instantiate, run ~5s in a **no-network, read-only**
     container; collect asset ids.
   - **NSFW**: the game's assets already carry an `nsfw` flag (set at upload —
     see flow 6); if any are flagged, the version is marked nsfw.
7. On success it writes a `gameVersions` record with `published: true`
   (+ `commitSha`). The game is now in the catalog and launchable; sessions run
   that exact pinned commit.

> Trust boundary: publishing **is** running attacker-controlled code. The AST scan
> is a filter; the Docker container is the real boundary. See `security_notes.md`.

---

## 3. Developer signup + email verification

1. Studio signup form posts `{ displayName, email, password }` to `/auth/signup`.
2. API creates a user: generated internal **`userId`** (canonical identity),
   separate **immutable `displayName`**, `verified: false`, a hashed **6-digit
   code** (24h expiry). A JWT is returned (they're logged in but unverified).
3. SES emails the **code** (not a link — avoids email-client prefetch consuming
   it).
4. In the Studio, the unverified banner takes the code → `POST /auth/verify`
   (authenticated, scoped to the user) → `verified: true`.
5. **Gating:** unverified users can browse/edit but the API blocks the
   abuse-surface routes (`requiresVerified`): create game, save, publish, AI edit,
   asset upload, thumbnail. Playing/browsing is fully anonymous and ungated.

Forgot password (`/auth/forgot` → `/auth/reset`) mirrors this: anti-enumeration
(always 200), 8-char emailed code, 1h expiry, rate-limited; standalone page at
`/reset-password`.

---

## 4. Asset upload + moderation

1. Studio Assets workspace → Upload/Draw/Record/Keyboard → `POST /asset`.
2. The API stores asset metadata in `assets` and binary data in `documents`
   (MongoDB Binary), and **synchronously classifies the image** in-process
   (`nsfw.js`, TensorFlow `nsfwjs`); the `nsfw` flag is saved on the asset.
3. Assets are served back at `/assets/:id` and referenced from games by id.
4. Admins moderate via `/admin` (delete asset, flag/unflag NSFW). Publishing a
   game inherits its assets' NSFW status.

---

## 5. Moderation / admin

1. Admin (a user with `isAdmin: true` in Mongo — set manually to bootstrap) opens
   `/admin`.
2. The console lists/searches **users / games / assets** (paginated), shows
   **stats**, **publish requests** (approve/reject), and **support messages**
   (acknowledge) — all gated server-side on `isAdmin`.
3. **Delete user** (`DELETE /admin/developers/:id`) cascades: their Forgejo
   repos, the Forgejo account, search index entries, and all Mongo data (games,
   versions, publishRequests, builds, assets, documents, user). One click removes
   everything they made.

---

## 6. AI "edit my game" (LLM)

1. Studio → AI Edit → `POST /studio/games/:id/llm-modify` with a prompt; the API
   enqueues an `LLM_REQUEST` on RabbitMQ.
2. The **Mac Studio worker** pulls the job, the MLX model server rewrites
   `index.js` grounded by the **authoring guide** (system prompt), with
   validation-error retries.
3. The worker posts the result back to the API (auth'd by `LLM_WORKER_SECRET`);
   the Studio polls status and drops the rewrite into the editor as an **unsaved
   change** for the user to review + save.
4. If the Mac is offline, jobs simply wait — nothing else is affected.
