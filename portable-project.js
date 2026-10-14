'use strict';

// Portable projects are data. Reading/validating/importing one NEVER evaluates
// its JavaScript. Execution is a separate, explicitly trusted operation.
const { zipSync, unzipSync } = require('fflate');
const acorn = require('acorn');
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

function walk(node, visit) {
    if (!node || typeof node.type !== 'string') return;
    visit(node);
    for (const value of Object.values(node)) {
        if (Array.isArray(value)) value.forEach(child => walk(child, visit));
        else if (value && typeof value.type === 'string') walk(value, visit);
    }
}

function literal(node, label, bindings = new Map(), seen = new Set()) {
    if (!node) fail(`${label} must be declared as a literal`);
    if (seen.has(node) || seen.size > 64) fail(`Circular or excessive constant expression in ${label}`);
    seen = new Set(seen).add(node);
    const read = value => literal(value, label, bindings, seen);
    const resolve = (value, visited = new Set()) => {
        if (!value || visited.has(value) || visited.size > 64) fail(`Unresolved constant in ${label}`);
        visited.add(value);
        if (value.type === 'Identifier' && bindings.has(value.name)) return resolve(bindings.get(value.name), visited);
        if (value.type === 'MemberExpression') {
            const object = resolve(value.object, visited), key = value.computed ? read(value.property) : value.property.name;
            if (object.type === 'ObjectExpression') return resolve(object.properties.find(p => p.type === 'Property' && !p.computed && (p.key.name ?? p.key.value) === key)?.value, visited);
        }
        return value;
    };
    const resolved = resolve(node);
    if (resolved !== node) return read(resolved);
    if (node.type === 'Literal' && !(node.value instanceof RegExp)) return node.value;
    if (node.type === 'UnaryExpression' && ['-', '+', '!'].includes(node.operator)) {
        const value = read(node.argument);
        return node.operator === '!' ? !value : node.operator === '-' ? -value : +value;
    }
    if (node.type === 'ArrayExpression') return node.elements.map(read);
    if (node.type === 'ObjectExpression') {
        const out = Object.create(null);
        for (const p of node.properties) {
            if (p.type !== 'Property' || p.computed || p.method || p.kind !== 'init') fail(`${label} must use literal properties`);
            const key = p.key.name ?? p.key.value;
            if (own(out, key)) fail(`Duplicate ${label} property: ${key}`);
            out[key] = read(p.value);
        }
        return out;
    }
    fail(`${label} must be declared as a literal`);
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
    const metadataMethods = [];
    walk(trees[manifest.entry], node => {
        if (node.type === 'MethodDefinition' && node.static && !node.computed
            && (node.key.name ?? node.key.value) === 'metadata') metadataMethods.push(node);
    });
    const body = metadataMethods[0]?.value.body.body;
    if (metadataMethods.length !== 1 || body.length !== 1 || body[0].type !== 'ReturnStatement'
        || body[0].argument?.type !== 'ObjectExpression') fail('Portable games need one static metadata() returning a literal object');
    const metadata = Object.create(null), assets = [], assetNodes = new Set();
    const bindings = new Map();
    for (const statement of trees[manifest.entry].body) if (statement.type === 'VariableDeclaration' && statement.kind === 'const') {
        for (const declaration of statement.declarations) if (declaration.id.type === 'Identifier') bindings.set(declaration.id.name, declaration.init);
    }
    for (const prop of body[0].argument.properties) {
        if (prop.type !== 'Property' || prop.computed || prop.method || prop.kind !== 'init') fail('Portable metadata must use literal properties');
        const key = prop.key.name ?? prop.key.value;
        if (own(metadata, key)) fail(`Duplicate metadata property: ${key}`);
        if (key !== 'assets') { metadata[key] = literal(prop.value, `metadata.${key}`, bindings); continue; }
        if (prop.value.type !== 'ObjectExpression') fail('metadata.assets must be a literal object');
        metadata.assets = Object.create(null);
        for (const p of prop.value.properties) {
            if (p.type !== 'Property' || p.computed || p.method || p.kind !== 'init') fail('Asset declarations must use literal keys');
            const assetKey = p.key.name ?? p.key.value;
            if (!/^[A-Za-z0-9_-]{1,32}$/.test(assetKey) || ['__proto__', 'constructor', 'prototype'].includes(assetKey)) fail(`Invalid asset key: ${assetKey}`);
            if (own(metadata.assets, assetKey)) fail(`Duplicate asset key: ${assetKey}`);
            const node = p.value;
            if (node.type !== 'NewExpression' || node.callee.name !== 'Asset' || node.arguments.length !== 1) fail(`Asset ${assetKey} must use new Asset({ path, type })`);
            const info = literal(node.arguments[0], `Asset ${assetKey}`);
            if (info.id !== undefined) fail(`Asset ${assetKey} still uses a hosted asset ID; convert it to a project path`);
            const path = normalizePath(info.path);
            if (!own(files, path)) fail(`Missing asset "${assetKey}": ${path}`);
            const media = describeAsset(files[path], path);
            // Retained before authored video bundles used the existing video transport/renderer.
            // if (!['image', 'audio'].includes(info.type) || media.kind !== info.type) fail(`Unsupported or invalid ${info.type} asset "${assetKey}": ${path}. Version 1 supports raster images and audio`);
            if (!['image', 'audio', 'video', 'font'].includes(info.type) || media.kind !== info.type) fail(`Unsupported or invalid ${info.type} asset "${assetKey}": ${path}`);
            metadata.assets[assetKey] = info;
            assets.push({ key: assetKey, path, type: info.type });
            assetNodes.add(node);
        }
    }
    if (metadata.squishVersion !== manifest.runtime.squishVersion) fail('metadata.squishVersion must match homegame.json');
    if (metadata.services && (!Array.isArray(metadata.services) || metadata.services.some(s => s !== 'multiplayer'))) fail('This portable runtime supports only the multiplayer service');
    for (const [path, tree] of Object.entries(trees)) walk(tree, node => {
        // Generated/uploaded media uses the standard Asset(info, bytes) and
        // getAssets()/addAsset contract. The runtime validates those bytes;
        // byte-less assets must still be declared project files.
        if (node.type === 'NewExpression' && node.callee.name === 'Asset' && !assetNodes.has(node)
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
    if (!own(files, MANIFEST)) fail('Missing homegame.json');
    const exports = Object.fromEntries(Object.entries(files).filter(([name]) => name.startsWith('user-exports/')).map(([name, data]) => [name.slice(13), data]));
    require('./user-exports').validateFiles(exports);
    const manifest = json(files[MANIFEST], MANIFEST);
    if (manifest?.formatVersion !== 1) fail(`Unsupported project format: ${manifest?.formatVersion}`);
    if (typeof manifest.gameId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(manifest.gameId)) fail('homegame.json needs a UUID gameId');
    if (!Number.isSafeInteger(manifest.saveSchemaVersion) || manifest.saveSchemaVersion < 1) fail('Invalid saveSchemaVersion');
    const version = manifest.runtime?.squishVersion;
    if (!Array.isArray(options.supportedRuntimes) || !options.supportedRuntimes.includes(version)) fail(`Unsupported runtime: squish-${version}. Supported: ${(options.supportedRuntimes || []).join(', ')}`);
    if (normalizePath(manifest.entry) !== manifest.entry || manifest.entry.startsWith('user-exports/') || !manifest.entry.endsWith('.js') || !own(files, manifest.entry)) fail(`Missing or invalid entry: ${manifest.entry}`);
    const { metadata, assets } = inspectSource(files, manifest);
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
function checkArchive(data) {
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
        if (flags & 1 || ![0, 8].includes(method) || view.getUint16(cursor + 34, true) || (mode & 0xf000) === 0xa000) fail('Encrypted files, links and this ZIP compression are unsupported');
        if (size > LIMITS.fileBytes || (total += size) > LIMITS.totalBytes + LIMITS.fileBytes) fail('Expanded ZIP exceeds project size limits');
        if (cursor + 46 + nameLength + extra + comment > end || offset + 30 > start) fail('Damaged ZIP entry');
        const name = text(data.subarray(cursor + 46, cursor + 46 + nameLength));
        names.push(name);
        if (view.getUint32(offset, true) !== 0x04034b50 || view.getUint16(offset + 6, true) !== flags || view.getUint16(offset + 8, true) !== method) fail('ZIP headers disagree');
        const localNameLength = view.getUint16(offset + 26, true), localExtra = view.getUint16(offset + 28, true);
        const dataStart = offset + 30 + localNameLength + localExtra;
        if (dataStart + compressed > start || text(data.subarray(offset + 30, offset + 30 + localNameLength)) !== name) fail('Damaged ZIP file bounds or name');
        records.push({ name, size, offset, end: dataStart + compressed });
        cursor += 46 + nameLength + extra + comment;
    }
    if (cursor !== end) fail('Damaged ZIP directory length');
    validatePaths(names);
    records.sort((a, b) => a.offset - b.offset);
    if (records.some((r, i) => i && r.offset < records[i - 1].end)) fail('Overlapping ZIP entries');
    return records;
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

module.exports = { checkSyntax, MANIFEST, INVENTORY, LIMITS, normalizePath, resolveModule, canonical,
    createProject, exportArchive, importArchive, assetBundle };
