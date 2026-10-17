/**
 * Local play support: lets games run entirely in the player's
 * browser (via homegames-client's LocalSession) with no game server.
 *
 * Canonical copy — shared by the platform API (games from Forgejo/Mongo) and
 * homegames-core (games from local disk), so "is this game local-playable"
 * and the bundle byte format are decided identically everywhere. The API
 * and Core both import this module.
 *
 * Pure logic only — no storage access — so it can be tested in isolation:
 *   - parseGameSourceMetadata: statically extract metadata() facts from game
 *     source (no code execution on the server, ever)
 *   - packAssetBundle: build the binary type-1 asset bundle, byte-identical
 *     to what squish's Squisher.initialize() sends a connected client
 *   - buildLocalHtml: compose a self-contained offline-playable HTML file
 */

const { readSourceMetadata, normalizeMetadata } = require('./game-metadata');

// One static reader for catalog, Studio and portable projects. Legacy hosted
// asset IDs remain supported here; portable packages validate their own media.
const parseGameSourceMetadata = (source, { includePathAssets = false } = {}) => {
    try {
        let inspected;
        try { inspected = readSourceMetadata(source, { strictAssets: false, requireExport: true }); }
        catch (exportError) {
            inspected = readSourceMetadata(source, { strictAssets: false });
            // Historical source-only fixtures/wrapped exports keep their reader.
            // New metadata-only games use the same exported-class contract as ZIPs.
            if (inspected.metadata.gameId && inspected.metadata.squishVersion === undefined) throw exportError;
        }
        const meta = normalizeMetadata(inspected.metadata, { runtime: inspected.runtime, legacy: !inspected.metadata.gameId || inspected.metadata.squishVersion !== undefined });
        const assets = new Map();
        for (const {key, info} of inspected.assets) {
            if (includePathAssets && typeof info.path === 'string' && info.path.length) assets.set(key, {key, path: info.path, type: info.type || 'image'});
            else if (info.id) assets.set(key, {key, id: info.id, type: info.type || 'image'});
        }
        return { ...meta, assets: [...assets.values()], thumbnail: meta.thumbnail || null, isTest: meta.isTest === true };
    } catch (error) { return { error: error.message }; }
};
const checkLocalPlayable = meta => meta.error ? { playable: false, reason: meta.error } : { playable: true };
const checkDownloadable = meta => meta.error ? { downloadable: false, reason: meta.error } : { downloadable: true };

// ---------------------------------------------------------------------------
// Asset bundle packing — the single implementation lives in
// local-play-shared.js (browser-safe, also bundled into homegames-client).
// This wrapper returns a Buffer for Node consumers (.toString('base64') etc).
// ---------------------------------------------------------------------------

const { packAssetBundle: packAssetBundleShared } = require('./local-play-shared');

const packAssetBundle = (entries) => Buffer.from(packAssetBundleShared(entries));

// ---------------------------------------------------------------------------
// Single-file HTML composition
// ---------------------------------------------------------------------------

// </script> (and friends) inside JSON would terminate the inline script tag;
// < is the JSON-safe universal escape.
const _jsonForInlineScript = (value) => JSON.stringify(value).replace(/</g, '\\u003c');

const buildLocalHtml = ({ name, gameKey, versionId, files, entryPoint, assetBundleBase64, clientBundleSource, sharing = {} }) => {
    const payload = _jsonForInlineScript({
        name: name || 'Homegames',
        gameKey,
        versionId,
        files,
        entryPoint,
        assetBundleBase64: assetBundleBase64 || null,
        sharing,
    });

    return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
<title>${(name || 'Homegames').replace(/</g, '&lt;')}</title>
<style>
html, body { margin: 0; padding: 0; height: 100%; background: #000; overflow: hidden; }
#homegames-main { width: 100vw; height: 100vh; }
</style>
</head>
<body>
<div id="homegames-main"></div>
<script>
${clientBundleSource}
</script>
<script>
window.__HG_LOCAL_GAME__ = ${payload};
</script>
<script>
(function() {
    var payload = window.__HG_LOCAL_GAME__;
    var assetBundle = null;
    if (payload.assetBundleBase64) {
        var bin = atob(payload.assetBundleBase64);
        assetBundle = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) assetBundle[i] = bin.charCodeAt(i);
    }
    var client = new HomegamesClient({
        containerId: 'homegames-main',
        localHome: false,
        share: payload.sharing || {},
        loadLocalGame: async function() { return {
            name: payload.name,
            gameKey: payload.gameKey,
            versionId: payload.versionId,
            files: payload.files,
            entryPoint: payload.entryPoint,
            assetBundle: assetBundle
        }; },
        onError: function(err) {
            console.error(err);
            var el = document.createElement('div');
            el.style.cssText = 'position:absolute;top:0;width:100%;text-align:center;color:#fff;font:16px monospace;padding:20px;';
            el.textContent = 'Error: ' + ((err && err.message) || err);
            document.body.appendChild(el);
        }
    });
    window.addEventListener('pagehide', function() { client.stop(); });
    client.startLocalGame({});
})();
</script>
</body>
</html>`;
};

module.exports = {
    parseGameSourceMetadata,
    checkLocalPlayable,
    checkDownloadable,
    packAssetBundle,
    buildLocalHtml,
};
