'use strict';
// Project ownership belongs to the host's game loader, never to a renderer.
// Both disk and portable loaders register an immutable source provider here.
const { createProject } = require('./portable-project');
const { DIRECTORY, createUserExports } = require('./user-exports');
const projects = new WeakMap();
function bindGameProject(GameClass, readProject, options = {}, exports = {}) {
    projects.set(GameClass, { readProject, options, exports });
    return GameClass;
}
function sourceFor(GameClass) {
    let constructor = GameClass, source;
    while (constructor && !(source = projects.get(constructor))) constructor = Object.getPrototypeOf(constructor);
    return source;
}
function openGameExports(GameClass, { saved = {}, persist } = {}) {
    const source = sourceFor(GameClass);
    return source?.exports.open ? source.exports.open() : createUserExports({ ...source?.exports.files, ...saved }, persist);
}
async function exportGameProject(game, exports) {
    const source = sourceFor(game.constructor);
    if (!source) throw new Error('This host has no portable source package for this game');
    const snapshot = exports && await exports.snapshot();
    const project = await source.readProject();
    if (!exports) return project;
    const files = Object.fromEntries(project.reader.listFiles().map(name => [name, project.reader.readFile(name)]));
    for (const [name, bytes] of Object.entries(snapshot)) files[DIRECTORY + '/' + name] = bytes;
    return createProject(files, source.options);
}
module.exports = { bindGameProject, openGameExports, exportGameProject };
