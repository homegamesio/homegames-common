'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DIRECTORY, validateName, validateFiles, createUserExports } = require('./user-exports');

function openUserExports(root) {
    root = fs.realpathSync(root);
    const directory = path.join(root, DIRECTORY), files = Object.create(null);
    const checkDirectory = () => {
        if (fs.existsSync(directory) && (!fs.lstatSync(directory).isDirectory() || fs.lstatSync(directory).isSymbolicLink())) throw new Error('User exports must be an ordinary directory');
    };
    checkDirectory();
    if (fs.existsSync(directory)) for (const name of fs.readdirSync(directory).sort()) {
        validateName(name);
        const file = path.join(directory, name), stat = fs.lstatSync(file);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024 * 1024) throw new Error('Invalid user export file: ' + name);
        files[name] = new Uint8Array(fs.readFileSync(file)); validateFiles(files);
    }
    return createUserExports(files, async (name, bytes) => {
        checkDirectory(); fs.mkdirSync(directory, { recursive: true }); checkDirectory();
        const target = path.join(directory, name);
        if (fs.existsSync(target) && (!fs.lstatSync(target).isFile() || fs.lstatSync(target).isSymbolicLink())) throw new Error('Cannot replace a linked or non-file export');
        const temporary = path.join(directory, '.write-' + crypto.randomUUID());
        try { await fs.promises.writeFile(temporary, bytes, { flag: 'wx' }); await fs.promises.rename(temporary, target); }
        finally { await fs.promises.unlink(temporary).catch(() => {}); }
    });
}
module.exports = { openUserExports };
