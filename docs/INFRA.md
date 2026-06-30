# Homegames — Infrastructure

What physically runs where, the domains, ports, and secrets. Design principle:
**keep it runnable on a single box** so others can self-host the whole thing
without orchestration. `> TODO: confirm` marks things to verify against the live
environment.

---

## Hosts

### 1. The single EC2 instance (the backend)
Everything below runs on **one EC2 host**, on purpose (simplest possible to run):

- **API** (`api.homegames.io`) — the Node monolith (`api/`). Also embeds the
  **NSFW model** in-process (TensorFlow `nsfwjs`).
- **API worker** — `api/worker.js`, the publish-validation consumer.
- **homegames-core** + **Docker** — game sessions, each in a `homegames-runner`
  container. **Planned split:** move homegames-core (and its Docker host duty)
  onto its **own instance** for scalability, keeping it separate from the API.
  This is the one intended departure from single-host.
- **MongoDB** — all app data.
- **RabbitMQ** — job queues (port 5672).
- **Forgejo** — git server (port 3000). `api/config.js` currently hardcodes
  `FORGEJO_URL = 'http://52.32.110.71:3000'` → that IP is the EC2 host.
  `> GOTCHA`: this is a hardcoded IP, not config/DNS — update it if the instance
  IP changes, and ideally move it to an env var.

### 2. Mac Studio (the LLM worker) — Joseph's personal machine, at home
- Runs `worker/` (Node `index.js` + Python MLX `llm/model_server.py`). MLX
  requires Apple Silicon, which is why this is not on EC2.
- **Pulls LLM jobs from the EC2's RabbitMQ** (`amqp://api.homegames.io:5672`) and
  posts results back to the API. AWS/networking was configured so the Mac can
  reach the queue. `> TODO: confirm` exactly how (security-group allowance for the
  Mac's IP to 5672? VPN?).
- If this machine is off, "AI edit" requests just queue and wait — nothing else
  is affected.

### 3. homegames.io (the website) — AWS S3 + CloudFront
- Static hosting for the site, Studio, Admin, client bundle, and assets like the
  authoring guide. `> TODO: confirm` the exact deploy story (see OPERATIONS.md —
  `deploy.sh` only pushes `bundle.js`; need to confirm how the HTML pages,
  `studio.js`, `admin.*`, `reset-password.*`, and `/authoring-guide.md` reach
  prod, i.e. whether CloudFront's origin is S3 or the EC2 `app.js`).

---

## Domains / DNS

- **`homegames.io`** — the website (S3/CloudFront).
- **`api.homegames.io`** — the API; also the RabbitMQ host (`:5672`), Homenames,
  and asset serving (`/assets/...`). `> TODO: confirm` it points at the EC2.
- **`homegames.link` / `public.homegames.link`** — the **relay** for the old
  self-hosted model (exposing a home instance to the public internet without
  port-forwarding). It worked but is **not maintained** now that the hosted
  service exists. Code references remain (`LINK_PROXY_URL`, port 81/82) but treat
  it as legacy unless revived.
- `> TODO: confirm` Route53 zones and the asset/cert domains (`homegames.link`
  cert domain appears in config).

---

## Ports (on the EC2 host)

| Port | Service | Notes |
|------|---------|-------|
| 80 / 443 | API (and/or web) | `> TODO: confirm` TLS termination (in-process? nginx? CloudFront?) |
| 3000 | Forgejo | hardcoded in `api/config.js` |
| 5672 | RabbitMQ | the Mac worker connects here |
| 27017 | MongoDB | `> TODO: confirm` |
| 7400 | Homenames | session/naming registry (`HOMENAMES_PORT`) |
| 8300–8400 | game sessions | per-session container ports (`GAME_SERVER_PORT_RANGE`) |
| 7001 / 9801 | self-host home port | legacy/self-host (`HOME_PORT`) |

---

## Secrets & credentials inventory

All currently provided via environment to the relevant service. **Bus-factor: know
where these are set** (`> TODO: confirm` — systemd unit `Environment=`/EnvironmentFile,
a `.env`, AWS SSM, etc.).

- **`JWT_SECRET`** (api) — signs user JWTs. If lost/rotated, everyone is logged out.
- **`FORGEJO_USER_SECRET`** (api) — HMAC key from which **every user's Forgejo
  password is derived**. If lost, you can't reproduce users' git credentials;
  rotating it requires re-syncing all users' Forgejo passwords
  (`rotate-forgejo-secret.js`).
- **`FORGEJO_WEBHOOK_SECRET`** (api + Forgejo) — verifies push webhooks.
- **Forgejo admin token** — the API does all Forgejo ops with an admin token.
  `> TODO: confirm` where it's stored.
- **`LLM_WORKER_SECRET`** (api + Mac worker) — authenticates the Mac worker
  posting results back to the API.
- **AWS credentials / IAM** — EC2 instance role (Route53, SES, possibly S3); the
  Mac's AWS config for queue access. `> TODO: confirm` the IAM role's exact
  permissions (least privilege — see security_notes.md re: IMDS).
- **SES** — `SES_FROM_ADDRESS` (verified identity), `SES_REGION`; account must be
  out of the SES sandbox for public email.
- **Mongo** — `DB_USERNAME` / `DB_PASSWORD` (if auth enabled).
- **TLS certs** — `> TODO: confirm` (Let's Encrypt? CloudFront-managed? the
  `acme-client` dep in the worker suggests ACME somewhere).

---

## squish version aliasing (deploy-relevant)

`squishjs` is published under many npm aliases (`squish-135`, `squish-138`,
`squish-140`, …) so every game keeps running on the exact version it declared.
The map is `homegames-common/game-loader.js → squishMap`. Adding a squish feature
= publish a new version + add the alias in **every consumer** (`api`,
`homegames-core`, `homegames-client`, `homegames-web`, `homegamesio`) and the map.
The image-crop / `getView` work lives in **`squish-140`**.
