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
    '061': 'squish-061',
    '063': 'squish-063',
    '0631': 'squish-0631',
    '0632': 'squish-0632',
    '0633': 'squish-0633',
    '0756': 'squish-0756',
    '0762': 'squish-0762',
    '0765': 'squish-0765',
    '0766': 'squish-0766',
    '0767': 'squish-0767',
    '1000': 'squish-1000',
    '1004': 'squish-1004',
    '1005': 'squish-1005',
    '1006': 'squish-1006',
    '1007': 'squish-1007',
    '1008': 'squish-1008',
    '1009': 'squish-1009',
    '1010': 'squish-1010',
    '110': 'squish-110',
    '120': 'squish-120',
    '130': 'squish-130',
    '135': 'squish-135',
    '136': 'squish-136',
    '138': 'squish-138',
};

const DEFAULT_SQUISH_VERSION = '135';

// ---------------------------------------------------------------------------
// Parse squish version from source file using AST (reliable, needs acorn)
// Falls back to regex if acorn is unavailable or parsing fails.
// ---------------------------------------------------------------------------
const parseSquishVersion = (codePath) => {
    const code = fs.readFileSync(codePath, 'utf-8');

    const { Parser } = require('acorn');
    const parsed = Parser.parse(code, { ecmaVersion: 'latest', sourceType: 'script' });

    const foundGameClasses = parsed.body.filter(
        n => n.type === 'ClassDeclaration' && n.superClass && (n.superClass.name === 'Game' || n.superClass.name === 'ViewableGame')
    );

    if (foundGameClasses.length !== 1) {
        throw new Error('Unable to parse squish version');
    }

    const metadataMethods = foundGameClasses[0].body.body.filter(
        n => n.key && n.key.name === 'metadata' && (n.kind === 'method' || n.static)
    );

    let foundVersion = null;

    metadataMethods[0].value.body.body.forEach(n => {
        if (n.type === 'ReturnStatement' && n.argument && n.argument.properties) {
            const versionNodes = n.argument.properties.filter(
                p => p.key && p.key.name === 'squishVersion'
            );
            if (versionNodes.length === 1 && !foundVersion) {
                foundVersion = String(versionNodes[0].value.value);
            }
        }
    });

    return foundVersion;
};

// ---------------------------------------------------------------------------
// Load a game class from a file path on disk.
// Clears require cache so re-loads get fresh code.
// ---------------------------------------------------------------------------
const loadGameClassFromPath = (gamePath) => {
    const resolved = path.resolve(gamePath);
    delete require.cache[require.resolve(resolved)];
    return require(resolved);
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
        return require(tmpPath);
    } finally {
        try { fs.unlinkSync(tmpPath); } catch (e) { /* best-effort cleanup */ }
    }
};

// ---------------------------------------------------------------------------
// Download a URL to a local file. Follows one level of redirects.
// ---------------------------------------------------------------------------
const downloadToFile = (url, destPath, headers = {}) => new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const writeStream = fs.createWriteStream(destPath);

    mod.get(url, { headers }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            writeStream.close();
            fs.unlinkSync(destPath);
            downloadToFile(res.headers.location, destPath, headers).then(resolve).catch(reject);
            return;
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
            writeStream.close();
            reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
            return;
        }

        res.pipe(writeStream);
        writeStream.on('finish', () => {
            writeStream.close();
            resolve();
        });
        writeStream.on('error', reject);
    }).on('error', (err) => {
        writeStream.close();
        reject(err);
    });
});

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
// Requires 'decompress' to be installed by the calling project.
//
// Returns: { dir, entryPath, squishVersion, cleanup() }
// ---------------------------------------------------------------------------
const fetchGameFromForgejo = ({ forgejoUrl, forgejoToken, owner, repo, ref }) => new Promise((resolve, reject) => {
    const decompress = require('decompress');
    const archiveRef = ref || 'main';
    const archiveUrl = `${forgejoUrl}/api/v1/repos/${owner}/${repo}/archive/${archiveRef}.zip`;

    const tmpDir = path.join(os.tmpdir(), `hg-forgejo-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    const zipPath = path.join(tmpDir, 'repo.zip');
    const extractPath = path.join(tmpDir, 'repo');

    const headers = {};
    if (forgejoToken) {
        headers['Authorization'] = `token ${forgejoToken}`;
    }

    downloadToFile(archiveUrl, zipPath, headers)
        .then(() => decompress(zipPath, extractPath))
        .then((files) => {
            const entryPath = findEntryPoint(files, extractPath);

            if (!entryPath) {
                reject(new Error('No index.js found in repository'));
                return;
            }

            const squishVersion = parseSquishVersion(entryPath);

            resolve({
                dir: extractPath,
                entryPath,
                squishVersion,
                cleanup: () => {
                    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { /* best-effort */ }
                },
            });
        })
        .catch(reject);
});

module.exports = {
    squishMap,
    DEFAULT_SQUISH_VERSION,
    parseSquishVersion,
    loadGameClass,
    loadGameClassFromPath,
    downloadToFile,
    findEntryPoint,
    fetchGameFromForgejo,
};
