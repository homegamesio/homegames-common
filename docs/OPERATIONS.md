# Homegames operations

Build and recovery notes checked against source on October 20, 2026. Downloaded releases retain their bundled runtime; deployment configuration is managed separately.

## Build and preview the website

From `homegamesio`:

```sh
npm ci
npm run build
PORT=8187 node app.js
```

The build generates the complete site in `web/`: catalog and game pages, portable ZIPs, Studio, templates, examples, guides, policies and a content-hashed browser client. `app.js` serves that output, so HTML and script changes require another build. The catalog comes from `site.config.json` (`gamesDirs`, `games`, `featuredGames`) or explicit CLI overrides, not the old catalog API. See the [website README](../../homegamesio/README.md) for selection options.

Normal builds use the installed `homegames-client` bundle and `homegames-common/docs`. To preview documentation changes from the sibling Common checkout while retaining the installed runtime:

```sh
HOMEGAMES_AUTHORING_GUIDE=../homegames-common/docs/homegames-context.md npm run build
```

That override also selects the other shared documents for `homegames-chatgpt.txt`. It must be present on each build that should use those edits. Alternatively publish and install a Common release containing the updated docs. `npm run build:local` is for testing sibling runtime source as well as docs. Editing Common source does not update an already-installed package or exported HTML.

## Stage and deploy

`node scripts/prepare-rtc-site.js /tmp/homegames-site-review` builds the same complete site in a separate directory. It does not deploy. Check the generated pages, packs and runtime together.

`deploy.sh` rebuilds the site and uploads the complete output to S3. It uploads immutable dependencies before pages and service workers, keeps older game packs/runtimes for open or installed games, preserves the `builds/` download history, removes obsolete mutable site files, and invalidates CloudFront. It requires `DISTRIBUTION_ID` and AWS access. A previous local build is not reused: pass any documentation/runtime/config overrides to the deployment command too.

Server downloads are built and published separately by `homegames/build-bundle.js` and its publisher. Website `downloads.js` reads `/builds/manifest.json`; `HOMEGAMES_BUILDS_DIR` selects local download artifacts for preview. A website or npm release does not update an existing server download.

## Runtime updates

Common 1.7.6 and Client 0.2.3 support `squish-151` (Squish 1.5.1) and `squish-150` (1.5.0). The follow-up release uses the 1.5.1 Squisher for shared sessions while preserving each game’s declared codec. New projects use 151. Keep the 150 alias pinned to 1.5.0 for existing projects.

The Node map lives in Common's `game-loader.js`; the browser map is in Client's `src/squish-map.js`. Update both deliberately and rebuild the client. Check consumer lockfiles and installed copies as well as source manifests. Exported HTML must be regenerated to receive a runtime update.

Core prepares a Docker runner from installed production files. Its image tag includes a runtime-content hash; updated code builds a new image without replacing active containers. `node docker/prepare-context.js` prepares it explicitly. Node sessions require Docker unless the host enables **Run games without Docker**. Browser-hosted play does not use Docker.

The connection API owns certificate processing in its own process. Current issuance uses MongoDB-backed jobs and an ACME/DNS issuer; it does not require RabbitMQ or the sibling `worker` process. Restart the API to activate service-code changes. Legacy workers are separate retained programs, not part of the current website flow.

## Backups and recovery

| State | Backup and recovery |
| --- | --- |
| Studio projects, history, media and preview data | Full Studio backup (`.homegames-backup`); includes unsaved working edits. Restore is transactional and retains an undo backup. |
| One game's source and media | Export a ZIP or playable HTML. These do not include full Studio history or ordinary progress saves. |
| Game progress | Download save / Load save JSON; the game must implement `saveGame`. Source restoration does not restore progress. |
| Cross-tab conflicts | Save edits as a copy or reload the saved version. Generation and workspace checks reject stale writes. |
| Installed browser games | Keep HTML/ZIP and progress backups; browser storage can be cleared or evicted. |
| Home server | Back up application data, including config, certificates, `.save-data`, game files and game-generated `user-exports/`. `HG_APP_DATA_DIR` can relocate application data. |
| Retained hosted data | Back up any MongoDB/Forgejo data and service configuration that you still need. Removing account routes does not delete old records. |

Use the same browser origin/profile to access an existing Studio library. New ZIP imports and HTML exports receive separate installation identities; transfer progress explicitly when needed. Verify backups by restoring them in a separate browser profile or test installation.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Studio edits missing | Was Save completed? Same origin/profile? Import a backup if browser data was cleared. |
| Quota or save conflict | Keep the tab open, download a backup, and resolve storage or concurrent-tab changes. |
| Export fails | Supported runtime, literal metadata, relative imports, included media and package size limits. Saving unfinished source does not guarantee it can run/export. |
| RTC invitation fails | Host still open, signaling reachable, compatible player and ICE connectivity. Some networks require TURN. |
| Catalog game fails | Static pack, identity/revision checks and client runtime. Browser play does not require a Node session. |
| Node session fails | Docker readiness/image build, explicit fork setting, session logs and child-port access. |
| Certificate pending | API certificate health/configuration, MongoDB, DNS permissions and ACME issuer. |
| Guide still old | Installed Common docs or explicit guide override, then rebuilt site output and cache state. |

For documentation changes, check local links, HTML structure and changed examples. For runtime releases, exercise local play, RTC guests, input, saves and exports using the packages intended for publication.
