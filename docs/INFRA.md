> Website infrastructure update, October 12: the complete `homegamesio/web/` output serves collection HTML, game packs, Studio templates, docs and the runtime. Website content no longer depends on the API/MongoDB/Forgejo paths described below for retired source. RTC signaling/ICE and self-hosting certificate/discovery services remain. See the [website README](../../homegamesio/README.md).

# Homegames — Infrastructure

Dependencies and defaults supported by the current code, reviewed October 11, 2026. Source code cannot establish live host placement, DNS, systemd unit names, TLS termination, backup schedules or which release is deployed. Earlier claims that everything runs on one EC2 instance or that the worker requires a particular Mac are not a deployment inventory.

## Dependencies by feature

| Feature | Needed infrastructure |
| --- | --- |
| Studio editing | Website/static templates + built client; browser IndexedDB. No account API, MongoDB, Forgejo or publishing worker for project edits. |
| Portable HTML solo play | Downloaded file + supported browser; no Homegames service. Browser storage is needed to persist progress. |
| Automatic RTC invites | Reachable signaling endpoint and guest player; STUN/TURN as required by the network. No Node game container. |
| Manual RTC | Loaded/downloaded players + offer/answer exchange and reachable ICE path. Optional STUN; manual UI does not provision TURN. |
| Collection | Generated static HTML, selected game ZIPs and bundled assets. No catalog database. |
| Home dashboard/Node sessions | Core, common, built client and local game files/assets. Docker for isolated child sessions, or explicit fork opt-in. |
| Discovery/HTTPS | homegames.link and its DNS integration; API/worker/queue/database/certificate authority for certificate requests. |
| Legacy account publishing | Retired from the active API. Old deployments/data need a separate shutdown/backup decision. |
| Docs | Static built guide; no API assistant route in the active service. |

## Website delivery

`homegamesio/app.js` serves the generated `web/` release (port 81 unless `PORT` overrides), plus configured self-hosting downloads. `scripts/build-site.js` includes the authoring guide, templates, catalog pages and game packs. `deploy.sh` uploads the complete build to S3/CloudFront; source code does not establish which revision is deployed.

## RTC configuration

`api/index.js` attaches common signaling unless `RTC_ENABLED=false`. `/rtc` must support WebSocket upgrades, and `/rooms` must reach that same service. Rooms live in that process's memory; restarting loses room registration. The service does not relay gameplay. Configure TURN separately for networks that cannot establish a direct path.

- `RTC_STUN_URLS`: comma-separated STUN URLs; default `stun:stun.l.google.com:19302`; explicitly empty means direct candidates only.
- `RTC_TURN_URLS` + `RTC_TURN_SECRET`: optional TURN URLs and HMAC credential generation (one-hour credentials).
- `RTC_TRUST_PROXY=true`: trusts `X-Real-IP` only from a loopback proxy; the proxy must overwrite that header.
- Core browser serving reads `RTC_SIGNAL_URL`, `RTC_JOIN_URL`, `RTC_SHARE_ORIGIN`, `RTC_ICE_SERVERS`, `RTC_ICE_TRANSPORT_POLICY`.

The website embeds Homegames API/player URLs in several files. Changing one backend config value does not retarget the whole website.

## Ports and defaults

| Component | Code/bundle default |
| --- | --- |
| Website `app.js` | 81; `PORT` override |
| API `index.js` | 80; `PORT` override |
| Core source `config.json` | Main 9801, Homenames 7400, child sessions 8300–8400 |
| Server bundle builder | Main 7001, Homenames 7100, child sessions 7002–7099 |
| Bare GameSessionManager | Child pool 7002–7099 unless caller overrides |
| Forgejo | API config currently hardcodes `http://52.32.110.71:3000`; this is a source value, not verified host placement |
| Database/queue | API and worker connection configuration determines addresses; do not infer a live instance from conventional Mongo/Rabbit ports |

Core's source config disables HTTPS; common's fallback `DEFAULT_CONFIG` enables it. Bundle generation disables discovery/HTTPS initially and enables fork fallback. Environment and the user config overlay can change those values. In direct-start browser mode, Core returns before creating the normal Homenames/session-manager stack.

## Credentials by retained service

Portable project editing introduces no user password or cloud-project credential. Existing services still read credentials for their own functions:

- Account/Forgejo credentials are not needed by the active API. Preserve them only for deliberately retained historical tooling.
- Database/queue connections for certificate jobs.
- Optional RTC TURN shared secret.
- AWS/DNS access in the certificate worker and discovery service.
- Local home-server TLS private keys under application data; the certificate request sends a CSR, not that private key.

This is a configuration inventory, not evidence that secrets are present or services enabled. Read config code and deployment definitions for the service being operated; never infer feature availability from a leftover UI or environment-file name.

## Network boundaries

homegames.link redirects a visitor to a LAN address; it does not make that address reachable from another network. Node/WebSocket clients connect to the home server's configured ports. Browser RTC is a separate host/guest path. Keep Homenames management access scoped to trusted callers; its listener is not inherently loopback-only.
