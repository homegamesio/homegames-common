'use strict';

const fs = require('fs');
const path = require('path');
const { normalizePath } = require('./portable-project');

// The same project-relative paths used by portable bundles, resolved against
// the entry file rather than the server's working directory or asset-ID cache.
function gameProjectRoot(entryPath) {
    let directory = path.dirname(path.resolve(entryPath));
    // A portable manifest owns paths relative to its project, even if its
    // JavaScript entry lives in a nested folder.
    for (let parent = directory; parent !== path.dirname(parent); parent = path.dirname(parent)) {
        const file = path.join(parent, 'homegame.json');
        if (fs.existsSync(file)) {
            const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
            if (path.resolve(parent, normalizePath(manifest.entry)) === path.resolve(entryPath)) directory = parent;
            break;
        }
    }
    return fs.realpathSync(directory);
}

function readGameAsset(entryPath, assetPath) {
    const relative = normalizePath(assetPath);
    const root = gameProjectRoot(entryPath);
    const filename = fs.realpathSync(path.join(root, relative));
    if (!filename.startsWith(root + path.sep) || !fs.statSync(filename).isFile()) {
        throw new Error(`Asset must be a file inside the game directory: ${assetPath}`);
    }
    return fs.readFileSync(filename);
}

function bindGameAssets(GameClass, entryPath) {
    const bytes = new Map();
    const bind = assets => {
        if (!assets) return assets;
        return Object.fromEntries(Object.entries(assets).map(([key, asset]) => {
            if (!asset?.info || asset.info.path === undefined) return [key, asset];
            const relative = normalizePath(asset.info.path);
            if (!bytes.has(relative)) bytes.set(relative, readGameAsset(entryPath, relative));
            // Keep the existing Asset implementation and metadata. Supplying
            // local bytes uses its established getData() fast path.
            const local = Object.assign(Object.create(Object.getPrototypeOf(asset)), asset);
            local.data = bytes.get(relative);
            return [key, local];
        }));
    };
    class LocalAssetGame extends GameClass {
        static metadata() {
            const metadata = super.metadata?.() || {};
            return { ...metadata, assets: bind(metadata.assets) };
        }
        getAssets(...args) { return bind(super.getAssets?.(...args)); }
    }
    Object.defineProperty(LocalAssetGame, 'name', { value: GameClass.name });
    const { readDirectory, options } = require('./portable-project-node');
    return require('./game-project').bindGameProject(LocalAssetGame, () => readDirectory(gameProjectRoot(entryPath)), options,
        { open: () => require('./user-exports-node').openUserExports(gameProjectRoot(entryPath)) });
}

module.exports = { readGameAsset, bindGameAssets, gameProjectRoot };
