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

const acorn = require('acorn');

// ---------------------------------------------------------------------------
// Static metadata extraction
// ---------------------------------------------------------------------------

const _walk = (node, visit) => {
    if (!node || typeof node.type !== 'string') return;
    visit(node);
    for (const key of Object.keys(node)) {
        const value = node[key];
        if (Array.isArray(value)) {
            for (const child of value) {
                if (child && typeof child.type === 'string') _walk(child, visit);
            }
        } else if (value && typeof value.type === 'string') {
            _walk(value, visit);
        }
    }
};

const _propName = (prop) => {
    if (!prop.key) return null;
    return prop.key.type === 'Identifier' ? prop.key.name : prop.key.value;
};

const _literal = (node) => (node && node.type === 'Literal') ? node.value : undefined;

/**
 * Extracts { squishVersion, name, services, assets } from a game's entry
 * source by finding `static metadata()` and reading literal values out of its
 * returned object. Values that aren't static literals are simply omitted.
 * Returns { error } if the source doesn't parse or has no metadata method.
 */
const parseGameSourceMetadata = (source) => {
    let ast;
    try {
        ast = acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'script' });
    } catch (e) {
        try {
            ast = acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'module' });
        } catch (e2) {
            return { error: 'Source does not parse: ' + e2.message };
        }
    }

    let metadataReturn = null;
    _walk(ast, (node) => {
        if (metadataReturn) return;
        if (node.type === 'MethodDefinition' && node.static && node.key
            && (node.key.name === 'metadata' || node.key.value === 'metadata')) {
            _walk(node.value, (inner) => {
                if (!metadataReturn && inner.type === 'ReturnStatement'
                    && inner.argument && inner.argument.type === 'ObjectExpression') {
                    metadataReturn = inner.argument;
                }
            });
        }
    });

    if (!metadataReturn) {
        return { error: 'No static metadata() returning an object literal found' };
    }

    const meta = { squishVersion: null, name: null, services: [], assets: [], thumbnail: null, isTest: false };

    for (const prop of metadataReturn.properties) {
        const key = _propName(prop);
        if (key === 'squishVersion') {
            meta.squishVersion = _literal(prop.value) || null;
        } else if (key === 'name') {
            meta.name = _literal(prop.value) || null;
        } else if (key === 'thumbnail') {
            meta.thumbnail = _literal(prop.value) || null;
        } else if (key === 'isTest') {
            meta.isTest = _literal(prop.value) === true;
        } else if (key === 'maxPlayers') {
            const value = _literal(prop.value);
            if (Number.isInteger(value) && value > 0) meta.maxPlayers = value;
        } else if (key === 'services' && prop.value.type === 'ArrayExpression') {
            meta.services = prop.value.elements.map(_literal).filter(Boolean);
        } else if (key === 'assets' && prop.value.type === 'ObjectExpression') {
            // Keyed map, not array: duplicate keys in the object literal must
            // resolve last-wins, matching what the runtime object holds.
            const assetsByKey = {};
            for (const assetProp of prop.value.properties) {
                const assetKey = _propName(assetProp);
                const v = assetProp.value;
                if (v && v.type === 'NewExpression' && v.arguments && v.arguments[0]
                    && v.arguments[0].type === 'ObjectExpression') {
                    const info = {};
                    for (const infoProp of v.arguments[0].properties) {
                        info[_propName(infoProp)] = _literal(infoProp.value);
                    }
                    if (assetKey && info.id) {
                        assetsByKey[assetKey] = { key: assetKey, id: info.id, type: info.type || 'image' };
                    }
                }
            }
            meta.assets = Object.values(assetsByKey);
        }
    }

    return meta;
};

/**
 * Whether a game is eligible to run client-side. Multiplayer games qualify —
 * they run in a browser host and can admit RTC guests. Games that cannot run (parse
 * failures, services with no local fallback) opt out.
 */
const checkLocalPlayable = (meta) => {
    if (meta.error) return { playable: false, reason: meta.error };
    if (meta.services.includes('contentGenerator')) {
        return { playable: false, reason: 'Game requires the contentGenerator service' };
    }
    return { playable: true };
};

// Downloads use the same runtime and RTC sharing as browser Play.
const checkDownloadable = (meta) => {
    if (meta.error) return { downloadable: false, reason: meta.error };
    if (meta.services.includes('contentGenerator')) {
        return { downloadable: false, reason: 'Game requires the contentGenerator service' };
    }
    return { downloadable: true };
};

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
