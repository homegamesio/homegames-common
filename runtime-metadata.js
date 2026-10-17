'use strict';
// Effective runtime facts shared by browser and Node hosts. No code execution
// is needed for static inspection; class metadata is read only during play.
const bound = new WeakMap();
function validateGameId(value) {
    if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new Error('Game metadata needs a UUID gameId');
}
function normalizeMetadata(metadata, { runtime, legacy = true } = {}) {
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new Error('Invalid game metadata');
    if (metadata.services !== undefined && (!Array.isArray(metadata.services) || metadata.services.some(service => service !== 'multiplayer'))) {
        throw new Error('Unsupported legacy service: games requiring contentGenerator or other hosted services cannot run');
    }
    if (!legacy) {
        validateGameId(metadata.gameId);
        if (typeof metadata.name !== 'string' || !metadata.name.trim() || metadata.name.length > 100) throw new Error('Game metadata needs a name of 1–100 characters');
        if (metadata.services !== undefined) throw new Error('services is retired; declare maxPlayers instead');
        if (metadata.squishVersion !== undefined) throw new Error('Declare the runtime only in the Squish import, not metadata.squishVersion');
        if (metadata.multiplayer !== undefined) throw new Error('multiplayer is derived from maxPlayers');
        if (metadata.tickRate !== undefined && (!Number.isFinite(metadata.tickRate) || metadata.tickRate < 1 || metadata.tickRate > 120)) throw new Error('tickRate must be between 1 and 120');
    }
    const maxPlayers = metadata.maxPlayers ?? (legacy ? 64 : undefined);
    if (!Number.isSafeInteger(maxPlayers) || maxPlayers < 1 || maxPlayers > 255) throw new Error('maxPlayers must be an integer from 1 to 255');
    if (metadata.saveSchemaVersion !== undefined && (!Number.isSafeInteger(metadata.saveSchemaVersion) || metadata.saveSchemaVersion < 1)) throw new Error('Invalid saveSchemaVersion');
    if (runtime && metadata.squishVersion !== undefined && metadata.squishVersion !== runtime) throw new Error('metadata.squishVersion must match the Squish import');
    const result = { ...metadata, maxPlayers, multiplayer: maxPlayers > 1 };
    if (runtime || metadata.squishVersion) result.squishVersion = runtime || metadata.squishVersion;
    delete result.services;
    return result;
}
function bindRuntimeMetadata(GameClass, metadata) { bound.set(GameClass, metadata); return GameClass; }
function runtimeMetadata(GameClass) {
    const raw = typeof GameClass.metadata === 'function' ? GameClass.metadata() : {};
    let source = GameClass, resolved;
    while (source && !(resolved = bound.get(source))) source = Object.getPrototypeOf(source);
    return normalizeMetadata({ ...raw, ...(resolved ? { maxPlayers: resolved.maxPlayers } : {}) },
        { runtime: resolved?.squishVersion, legacy: true });
}
module.exports = { normalizeMetadata, validateGameId, bindRuntimeMetadata, runtimeMetadata };
