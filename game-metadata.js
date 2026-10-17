'use strict';
// Shared static inspection. This module never evaluates authored JavaScript.
const acorn = require('acorn');
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const fail = message => { throw new Error(message); };
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


function readSourceMetadata(source, { strictAssets = true, requireExport = false } = {}) {
    const tree = acorn.parse(source, { ecmaVersion: 'latest', sourceType: 'script' });
    const classes = new Map();
    for (const statement of tree.body) {
        if (statement.type === 'ClassDeclaration') classes.set(statement.id?.name, statement);
        if (statement.type === 'VariableDeclaration') for (const item of statement.declarations) {
            if (item.id.type === 'Identifier' && item.init?.type === 'ClassExpression') classes.set(item.id.name, item.init);
        }
    }
    const exports = tree.body.filter(node => node.type === 'ExpressionStatement').map(node => node.expression)
        .filter(node => node.type === 'AssignmentExpression' && node.operator === '=' && node.left.type === 'MemberExpression'
            && node.left.object.name === 'module' && (node.left.computed ? node.left.property.value : node.left.property.name) === 'exports');
    const target = exports[0]?.right;
    const exportedClass = target?.type === 'ClassExpression' ? target : target?.type === 'Identifier' ? classes.get(target.name) : null;
    if (requireExport && (exports.length !== 1 || !exportedClass)) fail('Entry must export its Game class directly with module.exports');
    const methods = [];
    const collectMethod = node => {
        if (node.type === 'MethodDefinition' && node.kind === 'method' && node.static && !node.computed
            && node.key.type !== 'PrivateIdentifier' && !node.value.async && !node.value.generator
            && (node.key.name ?? node.key.value) === 'metadata') methods.push(node);
    };
    if (requireExport) exportedClass.body.body.forEach(collectMethod);
    else walk(tree, collectMethod);
    const body = methods[0]?.value.body.body;
    if (methods.length !== 1 || body.length !== 1 || body[0].type !== 'ReturnStatement'
        || body[0].argument?.type !== 'ObjectExpression') fail('Games need one static metadata() returning a literal object');
    const object = body[0].argument, bindings = new Map(), metadata = Object.create(null), assets = [];
    for (const statement of tree.body) if (statement.type === 'VariableDeclaration' && statement.kind === 'const') {
        for (const declaration of statement.declarations) if (declaration.id.type === 'Identifier') bindings.set(declaration.id.name, declaration.init);
    }
    for (const prop of object.properties) {
        if (prop.type !== 'Property' || prop.computed || prop.method || prop.kind !== 'init') fail('Game metadata must use literal properties');
        const key = prop.key.name ?? prop.key.value;
        if (own(metadata, key)) fail(`Duplicate metadata property: ${key}`);
        if (key !== 'assets') { metadata[key] = literal(prop.value, `metadata.${key}`, bindings); continue; }
        if (prop.value.type !== 'ObjectExpression') fail('metadata.assets must be a literal object');
        metadata.assets = Object.create(null);
        for (const item of prop.value.properties) {
            if (item.type !== 'Property' || item.computed || item.method || item.kind !== 'init') fail('Asset declarations must use literal keys');
            const assetKey = item.key.name ?? item.key.value, node = item.value;
            if (!/^[A-Za-z0-9_-]{1,32}$/.test(assetKey) || ['__proto__', 'constructor', 'prototype'].includes(assetKey)) fail(`Invalid asset key: ${assetKey}`);
            if (strictAssets && own(metadata.assets, assetKey)) fail(`Duplicate asset key: ${assetKey}`);
            if (node.type !== 'NewExpression' || node.callee.name !== 'Asset' || node.arguments.length !== 1) fail(`Asset ${assetKey} must use new Asset({ path, type })`);
            let info;
            try { info = literal(node.arguments[0], `Asset ${assetKey}`, bindings); }
            catch (error) { if (strictAssets) throw error; else continue; }
            metadata.assets[assetKey] = info;
            assets.push({ key: assetKey, info, node });
        }
    }
    const versions = new Set();
    walk(tree, node => {
        if (node.type === 'CallExpression' && node.callee.name === 'require'
            && typeof node.arguments[0]?.value === 'string' && /^squish-[0-9]+$/.test(node.arguments[0].value)) versions.add(node.arguments[0].value.slice(7));
    });
    if (versions.size > 1) fail('Mixed Squish runtimes are unsupported');
    const runtime = [...versions][0];
    if (runtime && metadata.squishVersion !== undefined && runtime !== metadata.squishVersion) fail('metadata.squishVersion must match the Squish import');
    return { tree, object, bindings, metadata, assets, runtime };
}

// Surgical edits preserve unrelated source and comments, including during remixes.
function rewriteMetadata(source, updates, { remove = [], requireExport = false } = {}) {
    const { object } = readSourceMetadata(source, { requireExport });
    const removed = new Set(remove), edits = [], present = new Set();
    const tokens = [...acorn.tokenizer(source, { ecmaVersion: 'latest' })];
    const props = object.properties;
    for (let i = 0; i < props.length; i++) {
        const prop = props[i], key = prop.key.name ?? prop.key.value;
        present.add(key);
        if (Object.hasOwn(updates, key)) edits.push({ start: prop.start, end: prop.end, value: `${key}: ${JSON.stringify(updates[key])}` });
        else if (removed.has(key)) {
            const comma = tokens.find(t => t.type.label === ',' && t.start >= prop.end && t.end <= (props[i + 1]?.start ?? object.end));
            if (comma) edits.push({ start: prop.start, end: comma.end, value: '' });
            else {
                const previous = tokens.find(t => t.type.label === ',' && t.start >= (props[i - 1]?.end ?? object.start) && t.end <= prop.start);
                edits.push({ start: previous?.start ?? prop.start, end: prop.end, value: '' });
            }
        }
    }
    const added = Object.entries(updates).filter(([key]) => !present.has(key));
    if (added.length) {
        if (added.some(([key]) => !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key))) fail('Invalid metadata property name');
        // Insert before existing properties, so original trailing commas/comments stay valid.
        edits.push({ start: object.start + 1, end: object.start + 1,
            value: '\n            ' + added.map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join(',\n            ') + (props.length ? ',' : '') + '\n' });
    }
    // Adjacent removed properties can share their separating comma.
    const merged = [];
    for (const edit of edits.sort((a,b) => a.start - b.start || a.end - b.end)) {
        const prior = merged[merged.length - 1];
        if (prior && !prior.value && !edit.value && edit.start <= prior.end) prior.end = Math.max(prior.end, edit.end);
        else merged.push(edit);
    }
    for (const edit of merged.reverse()) source = source.slice(0, edit.start) + edit.value + source.slice(edit.end);
    return source;
}
module.exports = { walk, literal, readSourceMetadata, rewriteMetadata, ...require('./runtime-metadata') };
