'use strict';

// Portable projects are data. Reading/validating/importing one NEVER evaluates
// its JavaScript. Execution is a separate, explicitly trusted operation.
const { zipSync, unzipSync } = require('fflate');
const acorn = require('acorn');
const { walk, literal, readSourceMetadata, rewriteMetadata, normalizeMetadata, validateGameId } = require('./game-metadata');
const { describeAsset } = require('./portable-media');
const { packAssetBundle } = require('./local-play-shared');

const MANIFEST = 'homegame.json';
const INVENTORY = '.homegame/inventory.json';
const LIMITS = Object.freeze({ files: 512, fileBytes: 16 * 1024 * 1024, totalBytes: 64 * 1024 * 1024,
    archiveBytes: 65 * 1024 * 1024, sourceBytes: 1024 * 1024 });
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const fail = message => { throw new Error(message); };
const bytes = value => typeof value === 'string' ? encoder.encode(value)
    : value instanceof Uint8Array ? new Uint8Array(value) : fail('Project files must contain text or Uint8Array bytes');
const text = value => decoder.decode(value);
const canonical = value => JSON.stringify(sort(value));
function sort(value) {
    if (Array.isArray(value)) return value.map(sort);
    if (value && typeof value === 'object') {
        const result = Object.create(null);
        for (const key of Object.keys(value).sort()) result[key] = sort(value[key]);
        return result;
    }
    return value;
}

// Version 1 deliberately uses portable ASCII filenames. Authored references
// may start with ./; archive members themselves must already be canonical.
function normalizePath(value) {
    if (typeof value !== 'string' || !value.length || value.length > 240) fail('Invalid project path');
    const path = value.startsWith('./') ? value.slice(2) : value;
    if (!/^[A-Za-z0-9_. /-]+$/.test(path)) fail(`Unsupported project path: ${value}`);
    for (const part of path.split('/')) {
        if (!part || part === '.' || part === '..' || /[ .]$/.test(part)
            || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)
            || ['__proto__', 'prototype', 'constructor'].includes(part)) fail(`Unsafe project path: ${value}`);
    }
    return path;
}

function validatePaths(names) {
    const seen = new Set();
    for (const name of names) {
        if (normalizePath(name) !== name) fail(`Non-canonical project path: ${name}`);
        const folded = name.toLowerCase();
        if (seen.has(folded)) fail(`Duplicate or case-colliding project path: ${name}`);
        seen.add(folded);
    }
    for (const name of seen) {
        const parts = name.split('/');
        while (parts.length > 1) {
            parts.pop();
            if (seen.has(parts.join('/'))) fail(`File/directory collision: ${name}`);
        }
    }
}

function json(data, name) {
    try { return JSON.parse(text(data)); }
    catch (_) { fail(`Invalid JSON or UTF-8 in ${name}`); }
}

async function sha256(data, options) {
    if (options.sha256) return options.sha256(data);
    if (!globalThis.crypto?.subtle) fail('This browser needs a secure context to validate a project');
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', data));
    return Array.from(digest, n => n.toString(16).padStart(2, '0')).join('');
}

function resolveModule(files, from, request) {
    if (typeof request !== 'string' || !/^\.\.?\//.test(request)) fail(`Unsupported module in ${from}: ${request}`);
    const parts = from.split('/').slice(0, -1);
    for (const part of request.split('/')) {
        if (part === '.') continue;
        if (part === '..') {
            if (!parts.length) fail(`Module escapes project root in ${from}: ${request}`);
            parts.pop();
        } else parts.push(part);
    }
    const base = normalizePath(parts.join('/'));
    if (base.startsWith('user-exports/')) fail('User exports are bytes, not executable modules');
    const found = [base, `${base}.js`, `${base}.json`, `${base}/index.js`].find(p => own(files, p));
    if (!found || !/\.(js|json)$/.test(found)) fail(`Missing JavaScript module or JSON data in ${from}: ${request}`);
    return found;
}

function inspectSource(files, manifest) {
    const trees = Object.create(null);
    for (const [path, data] of Object.entries(files)) {
        if (!path.endsWith('.js') || path.startsWith('user-exports/')) continue;
        if (data.length > LIMITS.sourceBytes) fail(`JavaScript file exceeds 1 MiB: ${path}`);
        try { trees[path] = acorn.parse(text(data), { ecmaVersion: 'latest', sourceType: 'script' }); }
        catch (error) { fail(`Cannot parse ${path}: ${error.message}`); }
    }
    const inspected = readSourceMetadata(text(files[manifest.entry]), { requireExport: manifest.formatVersion === 2 });
    const raw = inspected.metadata, assets = [], assetNodes = new Set();
    const versions = new Set();
    for (const tree of Object.values(trees)) walk(tree, node => {
        if (node.type === 'CallExpression' && node.callee.name === 'require') {
            const request = literal(node.arguments[0], 'require()');
            if (typeof request === 'string' && /^squish-[0-9]+$/.test(request)) versions.add(request.slice(7));
        }
    });
    if (versions.size > 1 || (manifest.formatVersion === 2 && versions.size !== 1)) fail('Project needs exactly one supported Squish runtime import');
    const runtime = [...versions][0] || manifest.runtime?.squishVersion;
    if (manifest.formatVersion === 1) {
        if (raw.squishVersion !== manifest.runtime.squishVersion) fail('metadata.squishVersion must match homegame.json');
        if (runtime !== manifest.runtime.squishVersion) fail('Runtime mismatch with homegame.json');
        if (raw.gameId !== undefined && raw.gameId !== manifest.gameId) fail('metadata.gameId must match homegame.json');
        if (raw.saveSchemaVersion !== undefined && raw.saveSchemaVersion !== manifest.saveSchemaVersion) fail('metadata.saveSchemaVersion must match homegame.json');
    } else {
        manifest.gameId = raw.gameId;
        manifest.saveSchemaVersion = raw.saveSchemaVersion ?? 1;
        manifest.runtime = { squishVersion: runtime };
    }
    const metadata = normalizeMetadata(raw, { runtime, legacy: manifest.formatVersion === 1 });
    for (const { key: assetKey, info, node } of inspected.assets) {
        if (info.id !== undefined) fail(`Asset ${assetKey} still uses a hosted asset ID; convert it to a project path`);
        const path = normalizePath(info.path);
        if (!own(files, path)) fail(`Missing asset "${assetKey}": ${path}`);
        const media = describeAsset(files[path], path);
        if (!['image', 'audio', 'video', 'font'].includes(info.type) || media.kind !== info.type) fail(`Unsupported or invalid ${info.type} asset "${assetKey}": ${path}`);
        assets.push({ key: assetKey, path, type: info.type });
        // The entry is parsed once here and once with its sibling modules.
        assetNodes.add(node.start);
    }
    for (const [path, tree] of Object.entries(trees)) walk(tree, node => {
        // Generated/uploaded media uses the standard Asset(info, bytes) and
        // getAssets()/addAsset contract. The runtime validates those bytes;
        // byte-less assets must still be declared project files.
        if (node.type === 'NewExpression' && node.callee.name === 'Asset' && !(path === manifest.entry && assetNodes.has(node.start))
            && node.arguments.length !== 2) fail(`Declare portable assets in the entry metadata.assets or supply bytes: ${path}`);
        if (node.type === 'CallExpression' && node.callee.name === 'require') {
            const request = literal(node.arguments[0], `require() in ${path}`);
            if (request === `squish-${manifest.runtime.squishVersion}`) return;
            if (typeof request === 'string' && request.startsWith('squish-')) fail(`Runtime mismatch in ${path}: ${request}`);
            const target = resolveModule(files, path, request);
            if (target.endsWith('.json')) json(files[target], target);
        }
    });
    return { metadata, assets };
}

function mediaType(path, data) {
    if (path.endsWith('.js')) return 'text/javascript';
    if (path.endsWith('.json')) return 'application/json';
    return describeAsset(data, path).contentType || 'application/octet-stream';
}

async function createProject(input, options = {}) {
    const names = Object.keys(input);
    if (names.length > LIMITS.files) fail('Project contains too many files');
    validatePaths(names);
    const files = Object.create(null);
    let total = 0;
    for (const name of names) {
        if (name.toLowerCase() === '.homegame' || name.toLowerCase().startsWith('.homegame/')) fail('The .homegame directory is reserved for generated inventory');
        const value = input[name];
        const length = typeof value === 'string' ? encoder.encode(value).length : value?.byteLength;
        if (!Number.isSafeInteger(length) || length > LIMITS.fileBytes || (total += length) > LIMITS.totalBytes) fail(`Project size limit exceeded at ${name}`);
        files[name] = bytes(value);
    }
    const exports = Object.fromEntries(Object.entries(files).filter(([name]) => name.startsWith('user-exports/')).map(([name, data]) => [name.slice(13), data]));
    require('./user-exports').validateFiles(exports);
    const manifest = own(files, MANIFEST) ? json(files[MANIFEST], MANIFEST) : { formatVersion: 2, entry: 'index.js' };
    if (own(files, MANIFEST) && manifest?.formatVersion !== 1) fail(`Unsupported project format: ${manifest?.formatVersion}`);
    if (normalizePath(manifest.entry) !== manifest.entry || manifest.entry.startsWith('user-exports/') || !manifest.entry.endsWith('.js') || !own(files, manifest.entry)) fail(`Missing or invalid entry: ${manifest.entry}`);
    const { metadata, assets } = inspectSource(files, manifest);
    validateGameId(manifest.gameId);
    if (!Number.isSafeInteger(manifest.saveSchemaVersion) || manifest.saveSchemaVersion < 1) fail('Invalid saveSchemaVersion');
    const version = manifest.runtime?.squishVersion;
    if (!Array.isArray(options.supportedRuntimes) || !options.supportedRuntimes.includes(version)) fail(`Unsupported runtime: squish-${version}. Supported: ${(options.supportedRuntimes || []).join(', ')}`);
    // Asset records travel in bounded batches. A single record must still fit
    // the RTC packet cap; the full game's assets need not fit one packet.
    if (assets.some(a => 44 + files[a.path].length > 10 * 1024 * 1024)) fail('An asset exceeds the current 10 MiB RTC packet limit');
    const inventory = [];
    // Sequential hashing bounds peak memory for large projects.
    for (const path of names.sort()) inventory.push({ path, byteLength: files[path].length,
        mediaType: mediaType(path, files[path]), sha256: await sha256(files[path], options) });
    const revision = await sha256(encoder.encode(canonical({ manifest, files: inventory })), options);
    const reader = Object.freeze({
        listFiles: () => [...names],
        readFile: path => { const key = normalizePath(path); if (!own(files, key)) fail(`Missing project file: ${key}`); return files[key].slice(); },
        stat: path => { const key = normalizePath(path); const record = inventory.find(r => r.path === key); if (!record) fail(`Missing project file: ${key}`); return { ...record }; },
    });
    return { manifest, metadata, assets, revision, inventory, reader };
}

async function exportArchive(project) {
    const entries = Object.create(null);
    for (const path of project.reader.listFiles()) entries[path] = project.reader.readFile(path);
    entries[INVENTORY] = encoder.encode(canonical({ formatVersion: 1, revision: project.revision, files: project.inventory }));
    return zipSync(entries, { level: 0, mtime: new Date(2020, 0, 1) });
}

// Validate the central directory before allocating/decompressing. fflate
// supplies ZIP compression; this guard enforces our narrower import policy.
function checkArchive(data, allowDirectories = false) {
    if (!(data instanceof Uint8Array) || data.length > LIMITS.archiveBytes || data.length < 22) fail('Invalid or oversized project archive');
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let end = data.length - 22;
    while (end >= Math.max(0, data.length - 65557) && view.getUint32(end, true) !== 0x06054b50) end--;
    if (end < Math.max(0, data.length - 65557)) fail('Damaged ZIP: missing directory');
    if (end + 22 + view.getUint16(end + 20, true) !== data.length || view.getUint16(end + 4, true)
        || view.getUint16(end + 6, true) || view.getUint16(end + 8, true) !== view.getUint16(end + 10, true)) fail('Unsupported multi-volume or damaged ZIP');
    const count = view.getUint16(end + 10, true), directorySize = view.getUint32(end + 12, true);
    const start = view.getUint32(end + 16, true);
    if (count > LIMITS.files + 1 || start + directorySize !== end) fail('Unsupported ZIP directory or too many files');
    let cursor = start, total = 0;
    const names = [], records = [];
    for (let i = 0; i < count; i++) {
        if (cursor + 46 > end || view.getUint32(cursor, true) !== 0x02014b50) fail('Damaged ZIP directory');
        const flags = view.getUint16(cursor + 8, true), method = view.getUint16(cursor + 10, true);
        const size = view.getUint32(cursor + 24, true), compressed = view.getUint32(cursor + 20, true);
        const nameLength = view.getUint16(cursor + 28, true), extra = view.getUint16(cursor + 30, true), comment = view.getUint16(cursor + 32, true);
        const offset = view.getUint32(cursor + 42, true), mode = view.getUint32(cursor + 38, true) >>> 16;
        if (flags & 1 || ![0, 8].includes(method) || view.getUint16(cursor + 34, true) || ![0, 0x4000, 0x8000].includes(mode & 0xf000)) fail('Encrypted files, links and this ZIP compression are unsupported');
        if (size > LIMITS.fileBytes || (total += size) > LIMITS.totalBytes + LIMITS.fileBytes) fail('Expanded ZIP exceeds project size limits');
        if (cursor + 46 + nameLength + extra + comment > end || offset + 30 > start) fail('Damaged ZIP entry');
        const name = text(data.subarray(cursor + 46, cursor + 46 + nameLength));
        if (allowDirectories && name.endsWith('/')) {
            if (normalizePath(name.slice(0, -1)) !== name.slice(0, -1) || size) fail('Invalid ZIP directory');
        } else names.push(name);
        if (view.getUint32(offset, true) !== 0x04034b50 || view.getUint16(offset + 6, true) !== flags || view.getUint16(offset + 8, true) !== method) fail('ZIP headers disagree');
        const localNameLength = view.getUint16(offset + 26, true), localExtra = view.getUint16(offset + 28, true);
        const dataStart = offset + 30 + localNameLength + localExtra;
        if (dataStart + compressed > start || text(data.subarray(offset + 30, offset + 30 + localNameLength)) !== name) fail('Damaged ZIP file bounds or name');
        records.push({ name, size, offset, end: dataStart + compressed });
        cursor += 46 + nameLength + extra + comment;
    }
    if (cursor !== end) fail('Damaged ZIP directory length');
    validatePaths(names);
    if (new Set(records.map(record => record.name.toLowerCase())).size !== records.length) fail('Duplicate ZIP entry');
    for (const record of records.filter(record => record.name.endsWith('/'))) {
        if (names.some(name => record.name.toLowerCase().startsWith(name.toLowerCase() + '/') || name.toLowerCase() === record.name.slice(0, -1).toLowerCase())) fail('File/directory collision');
    }
    records.sort((a, b) => a.offset - b.offset);
    if (records.some((r, i) => i && r.offset < records[i - 1].end)) fail('Overlapping ZIP entries');
    return records;
}

// The legacy Forgejo importer shares the same bounds/path/link policy without
// requiring a portable-project inventory. Directory entries are discarded.
function readArchiveFiles(data) {
    const records = checkArchive(data, true), unpacked = unzipSync(data), files = Object.create(null);
    let total = 0;
    for (const record of records) {
        const data = unpacked[record.name];
        if (data?.length !== record.size || (total += data.length) > LIMITS.totalBytes) fail('Expanded ZIP size mismatch');
        if (!record.name.endsWith('/')) files[record.name] = data;
    }
    return files;
}

async function importArchive(data, options = {}) {
    let records, files;
    try { records = checkArchive(data); files = unzipSync(data); }
    catch (error) { fail(`Cannot import project: ${error.message}`); }
    for (const record of records) if (files[record.name]?.length !== record.size) fail(`Damaged ZIP file: ${record.name}`);
    if (!own(files, INVENTORY)) fail('Missing project inventory');
    const inventory = json(files[INVENTORY], INVENTORY);
    delete files[INVENTORY];
    const project = await createProject(files, options);
    if (inventory?.formatVersion !== 1 || inventory.revision !== project.revision
        || canonical(inventory.files) !== canonical(project.inventory)) fail('Project integrity check failed: missing, changed or undeclared files');
    return project;
}

function assetBundle(project) {
    return packAssetBundle(project.assets.map(a => ({ key: a.key, type: a.type, data: project.reader.readFile(a.path) })));
}

function checkSyntax(source) {
    try { acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'script' }); return null; }
    catch (error) { return { message: error.message, line: error.loc?.line || 1 }; }
}

// Library artwork is read from the entry's literal metadata, even when an
// unrelated project file is unfinished. Never run game code to find an image.
function thumbnailPath(files) {
    try {
        const legacy = own(files, MANIFEST);
        const entry = legacy ? normalizePath(json(bytes(files[MANIFEST]), MANIFEST).entry) : 'index.js';
        const source = bytes(files[entry]);if(source.length > LIMITS.sourceBytes)return null;
        if (!legacy) {
            const { metadata } = readSourceMetadata(text(source), { requireExport: true, strictAssets: false });
            const path = normalizePath(metadata.thumbnail);
            return own(files, path) ? path : null;
        }
        const tree = acorn.parse(text(source), { ecmaVersion: 'latest', sourceType: 'script' });
        const methods = [], bindings = new Map();
        walk(tree, node => { if(node.type === 'MethodDefinition' && node.static && !node.computed && (node.key.name ?? node.key.value) === 'metadata')methods.push(node); });
        const body = methods[0]?.value.body.body;
        if(methods.length !== 1 || body.length !== 1 || body[0].type !== 'ReturnStatement' || body[0].argument?.type !== 'ObjectExpression')return null;
        for(const statement of tree.body)if(statement.type === 'VariableDeclaration' && statement.kind === 'const') {
            for(const declaration of statement.declarations)if(declaration.id.type === 'Identifier')bindings.set(declaration.id.name, declaration.init);
        }
        const property = body[0].argument.properties.find(prop => prop.type === 'Property' && !prop.computed && !prop.method && prop.kind === 'init' && (prop.key.name ?? prop.key.value) === 'thumbnail');
        if(!property)return null;
        const path = normalizePath(literal(property.value, 'thumbnail', bindings));
        return own(files, path) ? path : null;
    } catch (_) { return null; }
}

// Copying preserves identity; only an explicit new game/remix calls this helper.
function withGameId(input, gameId) {
    validateGameId(gameId);
    const files = Object.fromEntries(Object.entries(input).map(([name, value]) => [name, bytes(value)]));
    if (own(files, MANIFEST)) {
        const manifest = json(files[MANIFEST], MANIFEST);
        if (manifest.formatVersion !== 1) fail('Unsupported legacy project format');
        manifest.gameId = gameId;
        files[MANIFEST] = encoder.encode(JSON.stringify(manifest, null, 2) + '\n');
        // A transitional v1 source may repeat the identity; keep it consistent.
        const source = text(files[manifest.entry]);
        if (readSourceMetadata(source).metadata.gameId !== undefined) files[manifest.entry] = encoder.encode(rewriteMetadata(source, { gameId }));
    } else {
        if (!own(files, 'index.js')) fail('Missing index.js');
        files['index.js'] = encoder.encode(rewriteMetadata(text(files['index.js']), { gameId }, { requireExport: true }));
    }
    return files;
}

module.exports = { checkSyntax, thumbnailPath, MANIFEST, INVENTORY, LIMITS, normalizePath, resolveModule, canonical,
    createProject, exportArchive, importArchive, readArchiveFiles, assetBundle, withGameId };
