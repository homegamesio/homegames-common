# Homegames — Operations / Runbook

How to deploy, restart, observe, and recover. `> TODO: confirm` marks gaps to fill
in with current practice.

---

## The host

The EC2 backend runs its services under **systemd**. Manage with `systemctl`,
read logs with `journalctl`.

```bash
# status / restart / logs (service names: > TODO confirm exact unit names)
systemctl status  homegames-core api homegames-worker
systemctl restart api
journalctl -u api -f                # follow API logs
journalctl -u homegames-core -f
journalctl -u homegames-worker -f
```

Services (one host today): **api**, **homegames-core**, **the API worker**, plus
**mongod**, **rabbitmq-server**, **forgejo**, and **docker**.
`> TODO: confirm` the exact systemd unit names and whether Mongo/Rabbit/Forgejo are
distro packages or also custom units.

---

## Deploying / updating

### API, homegames-core, API worker (on the EC2 host)
Current practice (`> TODO: confirm` precise steps):
```bash
cd <repo> && git pull
npm install            # if deps changed
systemctl restart <service>
journalctl -u <service> -n 100 --no-pager   # verify it came up
```
- After changing **homegames-common**, dependents that pin it via `file:` link
  pick it up on `npm install`; restart them.
- After changing the **Docker runner** (`homegames-core/docker/`), rebuild the
  `homegames-runner` image (the session manager can build it on boot if
  `dockerImageDir` is set; otherwise rebuild manually).

### Website (homegames.io — S3/CloudFront)
- `homegamesio/deploy.sh` currently does:
  `aws s3 cp bundle.js s3://homegames.io/bundle.js` + a CloudFront invalidation.
- `> TODO: CONFIRM (important)`: that script only pushes `bundle.js`, but the site
  also serves `index.html`, `studio.html`/`studio.js`, `admin.html`/`admin.js`,
  `reset-password.*`, `catalog.html`, etc., and `/authoring-guide.md`. **How do
  those reach production?** Either CloudFront's origin is the EC2 `app.js`
  (so HTML routes are dynamic), or all files must be `aws s3 sync`'d and the
  routing is S3/CloudFront behaviors. **This must be nailed down** — recent
  studio/admin/reset/authoring-guide changes only go live once this path is
  correct. (If S3-static, `deploy.sh` needs to sync those files too; if the EC2
  is the origin, `app.js` routes are what matter and `deploy.sh` is incomplete.)

### LLM worker (Mac Studio)
- Pull `worker/`, `npm install`, ensure the Python venv (`worker/llm/env`) +
  model are present, run `worker/index.js` (it spawns the MLX model server).
  `> TODO: confirm` how it's kept running (launchd? a `run.sh` in tmux? manual?)
  and how it's updated.
- It needs `homegames-common` installed (`npm install`) so it can resolve the
  authoring-guide path it feeds the model.

### Publishing a new squish version
1. Bump + `npm publish` `squishjs`. 2. Add the alias (`squish-<v>`) to **every**
consumer's `package.json` and to `homegames-common/game-loader.js → squishMap`.
3. `npm install` + restart consumers; rebuild the client bundle + the runner image.

---

## Bootstrapping / common tasks

- **Make someone an admin:** set `isAdmin: true` on their `users` doc directly in
  Mongo (there is intentionally no self-serve admin grant):
  `db.users.updateOne({ displayName: "X" }, { $set: { isAdmin: true } })`.
- **Wipe/reset:** the user model changed (internal id + email); a fresh start
  means clearing `users` (and dependent collections).
- **SES out of sandbox:** required before verification/reset emails can go to
  arbitrary addresses; set `SES_FROM_ADDRESS`/`SES_REGION`.

---

## Backups & disaster recovery

`> TODO: CONFIRM` — define and verify these, they're the bus-factor core:
- **MongoDB** — is there a scheduled `mongodump` / snapshot? Where to?
- **Forgejo** — game source lives here; is the Forgejo data dir / repos backed up
  (or the EBS volume snapshotted)?
- **Assets** — binaries are in Mongo `documents`, so covered by the Mongo backup
  (confirm).
- **Secrets** — where is the canonical copy of `JWT_SECRET`,
  `FORGEJO_USER_SECRET`, etc. so the host can be rebuilt? (Losing
  `FORGEJO_USER_SECRET` orphans every user's git credentials.)
- **EBS snapshots** of the single host would capture Mongo + Forgejo + configs in
  one shot — `> TODO` confirm a snapshot schedule exists.

---

## Failure playbook

| Symptom | Likely cause / check |
|---------|----------------------|
| Games won't start / blank | homegames-core or Docker down (`systemctl status docker homegames-core`). **Note:** the session manager falls back to in-process `fork()` if Docker is unavailable — for the public host this is a security risk; prefer fail-closed (see security_notes.md). |
| Publishes stuck in PENDING | API worker down, or RabbitMQ down (`systemctl status homegames-worker rabbitmq-server`); check `journalctl -u homegames-worker`. |
| "AI edit" never completes | Mac Studio worker offline or can't reach RabbitMQ. Safe to ignore short-term. |
| Verification / reset emails not arriving | SES in sandbox, `SES_FROM_ADDRESS` unset, or DKIM/SPF missing. With SES unset, the API logs the code instead of sending. |
| Site changes not live | the homegames.io deploy path (see TODO above) — invalidate CloudFront / sync S3. |
| Forgejo errors on publish/clone | Forgejo down or the hardcoded `FORGEJO_URL` IP changed (`api/config.js`). |
| Login broken for everyone | `JWT_SECRET` changed/lost. |

---

## Security posture (pointer)

The publish pipeline runs untrusted code; containment is the real boundary. Before
scaling or hardening, read **`homegames-core/../security_notes.md`** (Docker
fail-closed, IMDS/credential exposure from session containers, network egress,
least-privilege IAM, validation-vs-runtime parity). The single-host design means a
container escape reaches everything — weigh that as usage grows.
