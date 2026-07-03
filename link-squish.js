#!/usr/bin/env node
// Make homegames-common the single source of squish dependencies.
//
// npm does not hoist a `file:` dependency's deps into the consumer's
// node_modules, so bare require('squish-XXX') calls in consumers (game code,
// child_game_server, the client bundle) would fail to resolve. Consumers run
// this as a postinstall step to symlink every package in the canonical
// squishMap from homegames-common's node_modules into their own.
const fs = require('fs');
const path = require('path');
const { squishMap } = require('./game-loader');

const linkSquish = (consumerRoot) => {
    const targetDir = path.join(consumerRoot, 'node_modules');
    if (!fs.existsSync(targetDir)) {
        throw new Error(`No node_modules directory at ${consumerRoot} — run npm install first`);
    }

    for (const packageName of Object.values(squishMap)) {
        let source;
        try {
            source = path.dirname(require.resolve(`${packageName}/package.json`));
        } catch (err) {
            throw new Error(`${packageName} is not installed in homegames-common — run npm install in ${__dirname}`);
        }

        const dest = path.join(targetDir, packageName);
        fs.rmSync(dest, { recursive: true, force: true });
        fs.symlinkSync(source, dest, 'junction');
        console.log(`linked ${packageName} -> ${source}`);
    }
};

module.exports = linkSquish;

if (require.main === module) {
    linkSquish(process.cwd());
}
