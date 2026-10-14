'use strict';

// Names are game-defined identifiers, never paths. Hosts own the directory.
const DIRECTORY = 'user-exports';
const LIMITS = Object.freeze({ files: 128, fileBytes: 16 * 1024 * 1024, totalBytes: 64 * 1024 * 1024 });
function validateName(name) {
    if (typeof name !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_. -]{0,119}$/.test(name)
        || /[ .]$/.test(name) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)
        || ['__proto__', 'prototype', 'constructor'].includes(name)) throw new Error('Export name must be a portable file name, not a path');
    return name;
}
function validateFiles(files) {
    const names = Object.keys(files), seen = new Set(); let total = 0;
    if (names.length > LIMITS.files) throw new Error('Too many user exports');
    for (const name of names) {
        validateName(name);
        const folded = name.toLowerCase();
        if (seen.has(folded)) throw new Error('Export names must differ ignoring capitalization');
        seen.add(folded);
        const bytes = files[name];
        if (!(bytes instanceof Uint8Array) || bytes.length > LIMITS.fileBytes || (total += bytes.length) > LIMITS.totalBytes) throw new Error('User export size limit exceeded');
    }
}
const copyFiles = files => Object.fromEntries(Object.entries(files).map(([name, bytes]) => [name, new Uint8Array(bytes)]));
function createUserExports(initial = {}, persist = async () => {}) {
    validateFiles(initial);
    let files = copyFiles(initial), tail = Promise.resolve(), closed = false, pending = 0;
    const failures = new Map();
    // A constructor-time snapshot: mutating the returned bytes cannot write a file.
    const userExports = Object.freeze(copyFiles(files));
    function createExport(name, bytes) {
        try {
            if (closed) throw new Error('Game session closed');
            validateName(name);
            if (!(bytes instanceof Uint8Array)) throw new Error('Export data must be Uint8Array bytes');
            if (bytes.length > LIMITS.fileBytes || pending >= 128) throw new Error('User export limit exceeded');
            bytes = new Uint8Array(bytes);
        } catch (error) { return Promise.reject(error); }
        pending++;
        const write = tail.then(async () => {
            const next = { ...files, [name]: bytes }; validateFiles(next);
            await persist(name, new Uint8Array(bytes));
            files = next; failures.delete(name);
        });
        tail = write.catch(error => { failures.set(name, error); }).finally(() => { pending--; });
        return write;
    }
    return { userExports, createExport,
        async list() { await tail; return Object.entries(files).map(([name, bytes]) => ({ name, size: bytes.length })); },
        async read(name) { validateName(name); await tail; if (!Object.hasOwn(files, name)) throw new Error('Export not found'); return new Uint8Array(files[name]); },
        async snapshot() { await tail; if (failures.size) throw failures.values().next().value; return copyFiles(files); },
        close() { closed = true; return tail; } };
}
function projectExports(project) {
    const files = Object.create(null);
    for (const path of project.reader.listFiles()) if (path.startsWith(DIRECTORY + '/')) {
        const name = path.slice(DIRECTORY.length + 1); validateName(name); files[name] = project.reader.readFile(path);
    }
    validateFiles(files); return files;
}
module.exports = { DIRECTORY, LIMITS, validateName, validateFiles, createUserExports, projectExports };
