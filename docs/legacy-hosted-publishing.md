# Historical hosted publishing reference

This is historical context for maintaining or converting retired Homegames code.
It is **not the current authoring workflow or a deployment guide**. The active API
entry point exposes connection helpers; the current Studio uses local browser
projects and static templates. Retained account/content handlers and their old
validation code do not establish that those services are available.

For new games use [the current authoring guide](homegames-context.md): put a stable
UUID `gameId`, `name`, and explicit `maxPlayers` in the exported class's static
metadata, and infer the runtime from its versioned Squish import. Preserve existing
game IDs, source revisions and save schemas when converting older projects.

The notes below were retained from the October 16, 2026 reference. Their account,
asset, license and publishing requirements belong only to that older pipeline.
Do not add them to new portable templates or infer current licensing from them.

## Historical publishing behavior

This describes the existing account-backed publishing pipeline, **not** portable
ZIP export. Its UI is inactive in the local-first Studio; backend code/data remain.
In the hosted workflow, publishing a saved version requires a verified account:
1. The game needs a description, a thumbnail, and edits beyond the starter template.
2. Automated validation runs:
   - `index.js` at the repo root, ≤ 5 MB per file, ≤ 20 MB total, no symlinks.
   - A complete **MIT or legacy GPLv3 `LICENSE`**. The original GPL reference stays available for older projects; license checking never relabels submitted code/media.
   - A **substantive `README`** — at least ~40 characters of real content beyond headings.
   - `static metadata()` must contain **literal** `squishVersion` and `name` values (statically
     parsed, never executed).
   - An AST scan of every JS file: only `squish-NNN` and the game's own relative files may be
     required — no Node built-ins, no npm packages, no network, no filesystem, no `eval` /
     `new Function` / dynamic `require` / dynamic `import`.
   - A real sandboxed run in a network-isolated container: the game must load, render, and survive
     ~5 seconds of ticking **and simulated play** — two players join, keys are pressed, up to 25
     clickable nodes are clicked, a player disconnects. A throw during require, construction,
     `handleNewPlayer`, or `tick()` is a hard reject (input-handler throws are recorded as warnings).
3. On passing, a published version makes the game eligible for catalog listing; featuring is
   separate. Image classification depends on the API classifier being available.
4. The retained worker checks complete MIT/GPL text through `api/project-license.js`.
   New templates use MIT; existing projects keep their notices. Source is browsable from the game page.

Publish requests can take a few minutes. The runner image's bundled Squish map
controls accepted versions; rebuilding that image is separate from editing the
source map. See the version distinction under How the platform works.

## Assets (portable and legacy)

Portable projects bundle their media and declare `new Asset({ path: './assets/tile.png',
type: 'image' })` in literal `metadata().assets`. Paths resolve from the project
root, not from a source module's folder. Current authored portable assets support
raster images, audio and video; see §11 for limits and examples.

The retained hosted asset service works differently:

- Its retained API accepts images, audio, and fonts (verified account; 6 MB max per asset,
  100 assets per user). Supported types are detected from the file's actual bytes: images
  (JPEG/PNG/GIF/WebP/BMP), audio (MP3/WAV/OGG/FLAC/MP4/WebM), fonts (TTF/OTF).
- Assets get stable ids; games reference them by id in `metadata().assets`. Public assets appear in
  the shared asset catalog. Tags and descriptions are editable; NSFW flags apply (automatic
  screening plus admin override).

