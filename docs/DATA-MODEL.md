# Homegames — Data Model

Where state lives: **MongoDB** (app data), **Forgejo** (game source), the **asset
store** (binaries in Mongo), and the **squish** wire format (transient, on the
wire). `> TODO: confirm` marks fields inferred from code that should be
spot-checked against a live DB.

---

## Identity model (important)

- **`userId`** — the canonical internal id (generated, `md5(uuid)`). Never shown.
  It's what the JWT carries, what `developerId` references, and the **Forgejo
  account/owner name**.
- **`displayName`** — chosen at signup, **immutable**, unique (case-insensitive).
  The only user-facing name.
- **`email`** — unique (case-insensitive), used for verification + reset.

This split was deliberate so display names can stay stable/independent of identity
and future-flexible. Anything that shows `developerId` as an author is showing the
opaque id — map to `displayName` for display. (`> TODO`: a sweep of catalog/profile
pages to show displayName everywhere.)

---

## MongoDB collections

Connection + helpers: `api/db.js`. DB name default `homegames`.

### `users`
`userId`, `displayName`, `displayNameLower`, `email`, `emailLower`, `verified`,
`verificationCodeHash`, `verificationCodeExpires`, `resetCodeHash`,
`resetCodeExpires`, `passwordHash`, `passwordSalt`, `created`, `isAdmin`,
`forgejoAccountCreated`, `forgejoPasswordSynced`, plus profile fields
(`image`, `description`, `btcAddress`). Password = pbkdf2(`crypto.js`). Codes are
stored **hashed** (`hashValue`/sha256).

### `games`
`gameId`, `name`, `description`, `developerId` (= `userId`), `created`,
`forgejoRepo` (`"<userId>/<repoName>"`), `featured`, `thumbnail` (an assetId),
`nsfw`.

### `gameVersions`
`versionId`, `gameId`, `commitSha`, `publishedAt`, `publishedBy`, `published`,
`approved`, `nsfw`. **This is what makes a game launchable** — a session runs the
`commitSha` of a published version.

### `publishRequests`
`requestId`, `gameId`, `commitSha`, `userId`, `status`
(`PENDING` → `PROCESSING` → `PUBLISHED` | `FAILED`; an older manual-approval path
uses `PENDING_PUBLISH_APPROVAL` → `REJECTED`), `created`, `completedAt`,
`versionId`, `error`, `adminMessage`. Rate-limited to 1 per 10 min per user.

### `builds`
`buildId`, `gameId`, `commitSha`, `commitMessage`, `triggeredBy`, `status`,
`error`, `created`, `completed`. Created on Forgejo push webhooks.

### `assets`
`assetId`, `developerId`, `name`, `type` (`image`/`audio`/`font`), `fileType`,
`nsfw`, `created`, `tags`, `description`, public/approval flags. `> TODO: confirm`
exact public/approval field names. Max 100 assets/user (`MAX_ASSETS_PER_USER`).

### `documents`
The **binary asset store**: `developerId`, `assetId`, `data` (BSON `Binary`),
`fileSize`, `fileType`. Served at `GET /assets/:id`.

### `supportMessages`
`id`, `created`, `ipHash`, `status` (`PENDING` → ack'd), `message`, `email`.

### `blog`
`id`, `publishedBy`, `created`, `title`, `content`.

`> TODO: confirm` any other collections in the live DB (sessions/homenames state, certs, etc.).

---

## Forgejo (game source of truth)

- A self-hosted Gitea fork. **One repo per game**, at `"<userId>/<repoName>"`,
  owned by the user's internal id. Created/managed by the API via the **admin
  token** (`api/forgejo.js`).
- Each user has a Forgejo account (username = `userId`); its password is **derived
  on demand** via `HMAC(FORGEJO_USER_SECRET, userId)` — nothing stored. CLI clone
  URLs embed those derived credentials.
- A game's `index.js` (and other files) are committed here; the published
  `commitSha` in `gameVersions` pins exactly what runs.
- Push webhooks (HMAC `FORGEJO_WEBHOOK_SECRET`) drive the build/publish pipeline.

---

## Asset store / serving

- Binaries live in Mongo `documents`; metadata in `assets`. Served by the API at
  `/assets/:id`.
- The squish `Asset` class (client + game code) references assets by **id**, and
  historically downloads from an asset endpoint (`api.homegames.io/assets`,
  older `assets.homegames.io`). `> TODO: confirm` whether any assets are also in
  S3 vs all in Mongo now.

---

## squish wire format (on the wire, not stored)

Transient binary frames between homegames-core and the browser. Full spec +
authoring rules: **squishjs-game-authoring.md**. In brief:

- A game's scene = a tree of `Shape`/`Text`/`Asset` nodes in 0–100 space.
- `squish()` encodes each node as `[3, len…, classCode, …sub-frames]`; each
  property (color, coordinates2d, text, asset, playerIds, …) is a typed,
  length-prefixed sub-frame. Numbers are integer + 2-decimal-fraction byte pairs.
- The server sends: **init** (player id, aspect ratio, squishVersion) →
  **asset bundle** → **state frames**, plus port-redirect / aspect-ratio messages.
- **Versioned**: `squishVersion` in a game's `metadata()` selects the pinned
  squish package used to encode (server) and decode (client). Never mutate a
  published version's format; ship a new version (see `game-loader.js → squishMap`).
