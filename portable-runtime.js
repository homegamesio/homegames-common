'use strict';

const { normalizePath, resolveModule, assetBundle } = require('./portable-project');
const decoder = new TextDecoder('utf-8', { fatal: true });

// This is a loader adapter, NOT a sandbox. Only a reviewed fixture or an
// explicitly trusted local project may enter it until Studio isolation lands.
// Each load gets its own Asset subclass; published Squish modules stay intact.
function loadTrustedGame(project, squishMap, { trusted = false } = {}) {
    if (!trusted) throw new Error('Portable game execution requires explicit trust; importing does not run code');
    const version = project.manifest.runtime.squishVersion;
    const squish = squishMap[version];
    if (!squish) throw new Error(`Runtime squish-${version} is not installed`);
    class ProjectAsset extends require('squish-146').Asset {
        constructor(info, supplied) {
            if (supplied !== undefined) {
                if (!(supplied instanceof ArrayBuffer) && !ArrayBuffer.isView(supplied) && !Array.isArray(supplied)) throw new Error('Generated assets need byte data');
                if ((supplied.byteLength ?? supplied.length) > 10 * 1024 * 1024 - 44) throw new Error('Generated asset exceeds the RTC packet limit');
                const data = supplied instanceof ArrayBuffer ? new Uint8Array(supplied)
                    : ArrayBuffer.isView(supplied) ? new Uint8Array(supplied.buffer, supplied.byteOffset, supplied.byteLength) : Uint8Array.from(supplied);
                require('./portable-media').validateAsset(info, data);
                super(info, data);
                return;
            }
            if (!info || info.id !== undefined) throw new Error('Portable assets must use project paths, not hosted asset IDs');
            const path = normalizePath(info.path);
            if (!project.assets.some(asset => asset.path === path && asset.type === info.type)) throw new Error(`Undeclared project asset: ${path}`);
            const data = project.reader.readFile(path);
            super({ ...info, path }, data);
        }
    }
    const runtime = { ...squish, Asset: ProjectAsset };
    const sources = Object.create(null), modules = Object.create(null);
    for (const path of project.reader.listFiles()) if (/\.(js|json)$/.test(path) && !path.startsWith('user-exports/')) sources[path] = decoder.decode(project.reader.readFile(path));
    const load = path => {
        if (modules[path]) return modules[path].exports;
        const module = { exports: {} };
        modules[path] = module;
        if (path.endsWith('.json')) { module.exports = JSON.parse(sources[path]); return module.exports; }
        const requireProject = request => request === `squish-${version}` ? runtime
            : load(resolveModule(sources, path, request));
        try {
            const execute = new Function('module', 'exports', 'require', '__filename', '__dirname', sources[path]);
            execute(module, module.exports, requireProject, path, path.split('/').slice(0, -1).join('/'));
        } catch (error) { delete modules[path]; throw error; }
        return module.exports;
    };
    const gameClass = load(project.manifest.entry);
    if (typeof gameClass !== 'function' || !(gameClass.prototype instanceof squish.Game)) throw new Error('Project entry must export a Squish Game class');
    return require('./game-project').bindGameProject(gameClass, () => project, { supportedRuntimes: Object.keys(squishMap) },
        { files: require('./user-exports').projectExports(project) });
}

function prepareTrustedLocalGame(project, squishMap, { trusted = false, installationId } = {}) {
    if (typeof installationId !== 'string' || !/^[a-zA-Z0-9-]{16,80}$/.test(installationId)) throw new Error('A trusted local installation ID is required for project saves');
    return {
        name: project.metadata.name || 'Homegame',
        author: project.metadata.author || project.metadata.createdBy,
        gameClass: loadTrustedGame(project, squishMap, { trusted }),
        // No authored media means no packet. RTC correctly rejects zero-byte
        // packets; uploads can still register assets later in the session.
        // assetBundle: assetBundle(project), // Retained before template migration.
        assetBundle: project.assets.length ? assetBundle(project) : null,
        gameKey: `project:${installationId}`,
        versionId: `save-schema:${project.manifest.saveSchemaVersion}`,
        packageRevision: project.revision,
    };
}

module.exports = { loadTrustedGame, prepareTrustedLocalGame };
