const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const os = require('os');

// ---------------------------------------------------------------------------
// Canonical squish version → npm package mapping.
// SINGLE SOURCE OF TRUTH — all repos should import from here.
// ---------------------------------------------------------------------------
const squishMap = {
    '150': 'squish-150',
    '151': 'squish-151'
};

const DEFAULT_SQUISH_VERSION = '151';

// ---------------------------------------------------------------------------
// Parse squish version from a source string using AST (reliable, needs acorn).
// Throws when the source has no single Game/ViewableGame class; returns null
// when the class exists but declares no literal squishVersion.
// ---------------------------------------------------------------------------
const parseSquishVersionFromSource = code => {
    const { walk, readSourceMetadata } = require('./game-metadata');
    const tree = require('acorn').parse(code, { ecmaVersion: 'latest', sourceType: 'script' });
    const versions = new Set();
    walk(tree, node => {
        if (node.type === 'CallExpression' && node.callee.name === 'require'
            && typeof node.arguments[0]?.value === 'string' && /^squish-[0-9]+$/.test(node.arguments[0].value)) versions.add(node.arguments[0].value.slice(7));
    });
    if (versions.size > 1) throw new Error('Mixed Squish runtimes are unsupported');
    let inspected;
    try { inspected = readSourceMetadata(code, { strictAssets: false }); }
    catch (error) { if (!versions.size || /squishVersion must match/.test(error.message)) throw error; }
    const version = [...versions][0] || inspected?.metadata.squishVersion || null;
    if (inspected?.metadata.squishVersion && inspected.metadata.squishVersion !== version) throw new Error('metadata.squishVersion must match the Squish import');
    return version;
};

const bindRuntime = (GameClass, code) => {
    const { normalizeMetadata, bindRuntimeMetadata } = require('./runtime-metadata');
    return bindRuntimeMetadata(GameClass, normalizeMetadata(GameClass.metadata?.() || {},
        { runtime: parseSquishVersionFromSource(code), legacy: true }));
};

// Resolve imports through relative modules as well: an entry may extend a
// local base class that imports Squish. Reading files never executes them.
const parseSquishVersion = codePath => {
    const seen = new Set(), versions = new Set();
    const { walk } = require('./game-metadata');
    let total = 0, declared;
    const visit = filename => {
        filename = fs.realpathSync(filename);
        if (seen.has(filename)) return;
        seen.add(filename);
        if (seen.size > 512) throw new Error('Game source contains too many modules');
        const source = fs.readFileSync(filename, 'utf8');
        if (Buffer.byteLength(source) > 1024 * 1024 || (total += Buffer.byteLength(source)) > 64 * 1024 * 1024) throw new Error('Game source size limit exceeded');
        let found;
        try { found = parseSquishVersionFromSource(source); }
        catch (error) { if (!/Games need one static metadata/.test(error.message)) throw error; }
        if (found) versions.add(found);
        if (filename === fs.realpathSync(codePath)) declared = found;
        const tree = require('acorn').parse(source, { ecmaVersion: 'latest', sourceType: 'script' });
        walk(tree, node => {
            const request = node.type === 'CallExpression' && node.callee.name === 'require' && node.arguments[0]?.value;
            if (typeof request !== 'string' || !/^\.\.?\//.test(request)) return;
            const base = path.resolve(path.dirname(filename), request);
            const target = [base, base + '.js', base + '.json', path.join(base, 'index.js')].find(candidate => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
            if (target?.endsWith('.js')) visit(target);
        });
    };
    visit(codePath);
    if (versions.size > 1) throw new Error('Mixed Squish runtimes are unsupported');
    return [...versions][0] || declared || null;
};

// ---------------------------------------------------------------------------
// Detect the squish version of a raw source string (Studio previews send code,
// not files). Never throws: unparseable source or a missing/non-literal
// squishVersion falls back to DEFAULT_SQUISH_VERSION — the same fallback the
// path-based call sites apply around parseSquishVersion.
// ---------------------------------------------------------------------------
const detectSquishVersion = (code) => {
    try {
        return parseSquishVersionFromSource(code) || DEFAULT_SQUISH_VERSION;
    } catch (err) {
        return DEFAULT_SQUISH_VERSION;
    }
};

// ---------------------------------------------------------------------------
// Load a game class from a file path on disk.
// Clears require cache so re-loads get fresh code.
// ---------------------------------------------------------------------------
const loadGameClassFromPath = (gamePath) => {
    const resolved = path.resolve(gamePath);
    delete require.cache[require.resolve(resolved)];
    // return require(resolved); // Legacy asset-ID-only loading.
    const GameClass = require('./local-game-assets').bindGameAssets(require(resolved), resolved);
    const { normalizeMetadata, bindRuntimeMetadata } = require('./runtime-metadata');
    return bindRuntimeMetadata(GameClass, normalizeMetadata(GameClass.metadata?.() || {}, { runtime: parseSquishVersion(resolved), legacy: true }));
};

// ---------------------------------------------------------------------------
// Load a game class from a source code string.
// Writes to a temp file, requires it, then cleans up.
// ---------------------------------------------------------------------------
let tmpCounter = 0;

const loadGameClass = (code, tmpDir) => {
    const dir = tmpDir || path.join(os.tmpdir(), 'hg-game-loader');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const tmpPath = path.join(dir, `hg-game-${Date.now()}-${tmpCounter++}.js`);
    fs.writeFileSync(tmpPath, code);
    try {
        delete require.cache[require.resolve(tmpPath)];
        return bindRuntime(require(tmpPath), code);
    } finally {
        try { fs.unlinkSync(tmpPath); } catch (e) { /* best-effort cleanup */ }
    }
};

// ---------------------------------------------------------------------------
// Download a URL to a local file. Follows bounded same-origin redirects.
// ---------------------------------------------------------------------------
const downloadToFile = async (input, destPath, headers = {}, { timeoutMs = 30000, maxBytes = 65 * 1024 * 1024 } = {}) => {
    const { pipeline } = require('node:stream/promises');
    const { Transform } = require('node:stream');
    const signal = AbortSignal.timeout(timeoutMs);
    const original = new URL(input); let url = original;
    let created = false;
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Invalid archive URL');
    try {
        for (let redirects = 0; redirects <= 5; redirects++) {
            const response = await new Promise((resolve, reject) => {
                const request = (url.protocol === 'https:' ? https : http).get(url, { headers, signal }, resolve);
                request.on('error', reject);
            });
            if (response.statusCode >= 300 && response.statusCode < 400) {
                response.destroy();
                const next = new URL(response.headers.location, url);
                // Forgejo archives are same-origin; never send its token to a
                // redirect target on another host, port or transport.
                if (next.origin !== original.origin || next.username || next.password || redirects === 5) throw new Error('Unsafe archive redirect');
                url = next; continue;
            }
            if (response.statusCode !== 200) { response.destroy(); throw new Error(`Archive HTTP ${response.statusCode}`); }
            let size = 0;
            const limit = new Transform({ transform(chunk, encoding, callback) {
                size += chunk.length; callback(size > maxBytes ? new Error('Archive too large') : null, chunk);
            } });
            let file;
            try { file = await fs.promises.open(destPath, 'wx', 0o600); created = true; }
            catch (error) { response.destroy(); throw error; }
            await pipeline(response, limit, file.createWriteStream(), { signal });
            return;
        }
    } catch (error) { if (created) await fs.promises.unlink(destPath).catch(() => {}); throw error; }
};

// ---------------------------------------------------------------------------
// Find the shallowest index.js in a list of extracted files.
// Used after decompressing a zip archive.
// ---------------------------------------------------------------------------
const findEntryPoint = (files, extractPath) => {
    const indexFiles = files
        .filter(f => f.type === 'file' && f.path.endsWith('index.js'))
        .filter(f => !f.path.includes('node_modules'))
        .sort((a, b) => a.path.split('/').length - b.path.split('/').length);

    if (indexFiles.length === 0) {
        return null;
    }

    return path.join(extractPath, indexFiles[0].path);
};

// ---------------------------------------------------------------------------
// Fetch game source code from a Forgejo repository.
// Downloads the repo archive, extracts it, finds the entry point.
//
// Returns: { dir, entryPath, squishVersion, cleanup() }
// ---------------------------------------------------------------------------
const fetchGameFromForgejo = async ({ forgejoUrl, forgejoToken, owner, repo, ref = 'main' }) => {
    const { readArchiveFiles } = require('./portable-project');
    if ([owner, repo, ref].some(value => typeof value !== 'string' || !value || value.length > 256 || value === '.' || value === '..')) throw new Error('Invalid repository reference');
    const archiveUrl = `${forgejoUrl.replace(/\/$/, '')}/api/v1/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/archive/${encodeURIComponent(ref)}.zip`;
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hg-forgejo-'));
    const cleanup = () => fs.rmSync(tmpDir, { recursive: true, force: true });
    try {
        const zipPath = path.join(tmpDir, 'repo.zip'), extractPath = path.join(tmpDir, 'repo');
        await downloadToFile(archiveUrl, zipPath, forgejoToken ? { Authorization: `token ${forgejoToken}` } : {});
        const files = readArchiveFiles(fs.readFileSync(zipPath));
        for (const [name, data] of Object.entries(files)) {
            const dest = path.join(extractPath, name);
            fs.mkdirSync(path.dirname(dest), { recursive: true });
            fs.writeFileSync(dest, data, { flag: 'wx', mode: 0o600 });
        }
        const entryPath = findEntryPoint(Object.keys(files).map(name => ({ path: name, type: 'file' })), extractPath);
        if (!entryPath) throw new Error('No index.js found in repository');
        return { dir: extractPath, entryPath, squishVersion: parseSquishVersion(entryPath), cleanup };
    } catch (error) { cleanup(); throw error; }
};

module.exports = {
    squishMap,
    DEFAULT_SQUISH_VERSION,
    parseSquishVersion,
    detectSquishVersion,
    loadGameClass,
    loadGameClassFromPath,
    downloadToFile,
    findEntryPoint,
    fetchGameFromForgejo,
};
