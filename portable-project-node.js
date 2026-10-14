'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const project = require('./portable-project');

// Match the current browser build explicitly. Do not substitute runtime
// versions, or promise an offline export with an unavailable runtime.
const SUPPORTED_RUNTIMES = ['142', '143', '145', '146'];
const options = { supportedRuntimes: SUPPORTED_RUNTIMES,
    sha256: data => crypto.createHash('sha256').update(data).digest('hex') };

async function readDirectory(directory) {
    const root = path.resolve(directory);
    if (!fs.lstatSync(root).isDirectory() || fs.lstatSync(root).isSymbolicLink()) throw new Error('Project root must be an ordinary directory');
    const files = Object.create(null);
    let total = 0, count = 0;
    function visit(relative = '') {
        for (const name of fs.readdirSync(path.join(root, relative)).sort()) {
            const key = relative ? `${relative}/${name}` : name;
            project.normalizePath(key);
            const location = path.join(root, key), stat = fs.lstatSync(location);
            if (stat.isSymbolicLink()) throw new Error(`Project symlinks are unsupported: ${key}`);
            if (stat.isDirectory()) { visit(key); continue; }
            if (!stat.isFile()) throw new Error(`Not an ordinary project file: ${key}`);
            if (++count > project.LIMITS.files || stat.size > project.LIMITS.fileBytes || (total += stat.size) > project.LIMITS.totalBytes) throw new Error(`Project size limit exceeded at ${key}`);
            files[key] = fs.readFileSync(location);
        }
    }
    visit();
    return project.createProject(files, options);
}

async function readArchive(filename) {
    if (fs.statSync(filename).size > project.LIMITS.archiveBytes) throw new Error('Project archive is too large');
    return project.importArchive(fs.readFileSync(filename), options);
}

// Validation completes before touching the destination. A destination is
// always a NEW directory: this first milestone never replaces authored work.
async function restoreArchive(filename, destination) {
    const value = await readArchive(filename);
    const target = path.resolve(destination), parent = path.dirname(target);
    if (fs.existsSync(target)) throw new Error(`Destination already exists; choose a new directory: ${target}`);
    const lock = `${target}.homegame-import-lock`;
    fs.mkdirSync(lock);
    let staging;
    try {
        if (fs.existsSync(target)) throw new Error(`Destination already exists: ${target}`);
        staging = fs.mkdtempSync(path.join(parent, '.homegame-import-'));
        for (const name of value.reader.listFiles()) {
            const location = path.join(staging, name);
            fs.mkdirSync(path.dirname(location), { recursive: true });
            fs.writeFileSync(location, value.reader.readFile(name), { flag: 'wx' });
        }
        const restored = await readDirectory(staging);
        if (restored.revision !== value.revision) throw new Error('Restored bytes failed verification');
        if (fs.existsSync(target)) throw new Error(`Destination already exists: ${target}`);
        fs.renameSync(staging, target);
        staging = null;
        return restored;
    } finally {
        if (staging) fs.rmSync(staging, { recursive: true, force: true });
        fs.rmdirSync(lock);
    }
}

async function buildPlayableHtml(value, { clientBundleSource, sharing = {}, trusted = false } = {}) {
    if (!trusted) throw new Error('Review the project first, then pass --trusted to build executable HTML');
    return require('./portable-html').buildIsolatedHtml(value, { clientBundleSource, installationId: crypto.randomUUID(),
        sharing: { signalingUrl: 'wss://api.homegames.io/rtc', joinUrl: 'https://homegames.io/play.html', ...sharing } });
}

module.exports = { options, SUPPORTED_RUNTIMES, readDirectory, readArchive, restoreArchive, buildPlayableHtml };
