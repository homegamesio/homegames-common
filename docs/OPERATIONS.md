> Website build update, October 12: `homegamesio` now generates the complete static site from `site.config.json` or explicit game paths. See its [README](../../homegamesio/README.md) for current build, preview and deployment commands. Older catalog/backend procedures below apply only to retained services.

# Homegames — Operations

Code-based build and recovery notes, reviewed October 11, 2026. This repository does not establish current production host/unit names or backup automation. Use the deployment's actual service definitions for restarts and logs.

## Build the website/runtime

Install sibling dependencies from their manifests. Common currently also links the local `squish` package for 146; browser authoring supports 142/143/145. From each repository directory:

```sh
# homegames-client
npm install
npm run build
# homegamesio
npm install
npm run build
PORT=8187 node app.js
```

The client build produces `homegames-client/dist/homegames-client.js`; website webpack produces `homegamesio/web/bundle.js`. The Node website server reads scripts/HTML directly and serves the client-package bundle. Rebuild the client after common runtime changes; rebuild the website bundle after changing `client.js`. Restart `app.js` after routing changes.

Local website previews still use production API URLs in retained catalog/account entry points. Studio project editing uses local storage/static templates; RTC defaults still point to Homegames signaling. Use the same browser origin/port to see the same IndexedDB library.

## Stage a full website release

After building both bundles, run from `homegamesio`:

```sh
node scripts/prepare-rtc-site.js /tmp/homegames-site-review
```

This rebuilds the portable template catalog from `templates/`, stages ZIPs and selected site files, and pins player/Studio HTML to a content-hashed client. It does not deploy. Inspect the staged contents before uploading.

The staging file list includes the three HTML guides, but currently **omits `/authoring-guide.md`**, `view.html`, `dev.html`, policy/reset pages and some other ancillary routes. For static hosting, separately copy the current common `docs/homegames-context.md` to the served authoring-guide path and include any pages required by that deployment's links/routing. The Node origin reads the common file directly. Editing common alone does not refresh a static copy or an already-running model process.

`DISTRIBUTION_ID=… bash deploy.sh` builds and uploads only `web/bundle.js`, then invalidates `/bundle.js`. It does not publish HTML, Studio, templates, the client runtime or docs. Do not use it as a full-site release command. API-generated catalog HTML downloads also need the matching runtime via `CLIENT_BUNDLE_PATH`.

Server bundles are built/published by `homegames/build-bundle.js` and its publisher, independently from the website. `downloads.js` reads `/builds/manifest.json`. For local download checks, set `HOMEGAMES_BUILDS_DIR` to a staged build directory when starting `app.js`.

## Shared runtime / Node updates

- Check installed local dependency links/copies; a `file:` declaration does not update a running process or an embedded browser bundle by itself.
- Node's canonical Squish aliases live in common; browser static requires live in `homegames-client/src/squish-map.js`. Add compatible browser entries deliberately and rebuild. A new Node version is not automatically available in browsers.
- Core now prepares its Docker runner from installed production files on first use; the image tag includes a runtime-content hash. Updated code builds a new image without replacing containers that are still running. `node docker/prepare-context.js` prepares the same image explicitly. Existing downloaded HTML retains its embedded runtime until re-exported.
- Node sessions require Docker or explicit host permission through **Run games without Docker**. Docker availability is rechecked for each launch, so starting Docker or retrying a failed build does not require restarting Core. Core's new preparation flow requires publication and installation of the October 18 Common fixes.
- Worker changes require restarting the appropriate service: `api/worker.js` is publish validation; `worker/index.js` is certificate/docs/legacy AI work.

## Backups and recovery

| State | Backup/recovery |
| --- | --- |
| Studio drafts/media | Export project ZIPs. Browser data is origin/profile-specific; persistent-storage permission is best-effort. |
| Studio snapshots | Stored only in that browser's library; export desired snapshots individually. Export does not include full history. |
| Portable progress | Download save JSON; Load save checks game/schema compatibility. Source restore does not restore progress. |
| Cross-tab conflict | Keep unsaved edits as a copy or reload the saved version. A stale write/restore must not be forced over another tab. |
| Home server | Back up application data (config, certs, `.save-data`, asset cache, downloaded games) and custom game directories. `HG_APP_DATA_DIR` may relocate this state. |
| Retained backend | Back up MongoDB records/binaries, Forgejo source and necessary service configuration/credentials. Account UI removal does not make these disposable. |

Code does not prove a production backup schedule exists. Verify restores for the deployment you operate. Fresh ZIP installations and new HTML exports get independent progress slots; transfer progress explicitly instead of assuming source-copying transfers it.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Studio game missing | Same origin/browser/profile? Was data cleared/evicted? Import a saved ZIP; there is no account cloud sync. |
| Not saved / quota error | Keep the tab open, preserve a copy and free space. Check both project and progress status. |
| ZIP/HTML export fails | Manifest/runtime agreement, literal metadata, relative imports, actual media bytes and format limits. Draft persistence does not imply portable validation success. |
| Share fails / room missing | Host alive, signaling WebSocket reachable, `RTC_ENABLED`, player build compatibility, ICE/TURN and visibility. Portable rooms are private/unlisted. |
| Catalog Play fails | Published local manifest/source/assets and browser runtime; do not start by assuming Docker is down. |
| Node-hosted session fails | Docker image/readiness or explicit fork opt-in, session logs and configured child-port access. |
| Docs question unavailable | API feature admission and background model/queue/delivery state. Studio AI is disabled separately. |
| Legacy publish stuck | `api/worker.js`, RabbitMQ, reference license file and Docker validator. This is not part of portable export. |
| Certificate pending | API/worker/DNS/certificate-authority path; use local HTTP while appropriate and restart to activate initial TLS. |
| Updated guide still old | Static staging/upload includes the guide; caches/origin and installed common copy match. `deploy.sh` updates only catalog JavaScript. |

For docs-only changes, check diffs, local links, HTML structure/IDs and inline script syntax. Exercise changed complete code examples against their declared runtime. Do not report historical runtime tests as checks run during a documentation review.
