// Session orchestration uses the current engine; encodeNode/decodeNode below
// preserve each game's declared wire format, including existing 1.5.0 games.
const { Squisher } = require('squish-151');
const collectGameAssets = ({ game, customBottomLayer, customTopLayer }) => Object.assign({},
    game.constructor.metadata?.()?.assets, customBottomLayer?.assets,
    customTopLayer?.assets, game.getAssets?.());

const createSessionRuntime = (codec, game, options = {}) => {
    if (typeof codec?.squish !== 'function' || typeof codec?.unsquish !== 'function') throw new Error('Session needs an explicit Squish codec');
    const squisher = new Squisher({ ...options, game, encodeNode: codec.squish, decodeNode: codec.unsquish });
    let stopped = false;
    return { squisher,
        listExports() { if (stopped) return Promise.reject(new Error('Session closed')); return options.userExportsStore?.list() || Promise.resolve([]); },
        readExport(name) { if (stopped) return Promise.reject(new Error('Session closed')); return options.userExportsStore?.read(name) || Promise.reject(new Error('Export not found')); },
        exportProject() { if (stopped) return Promise.reject(new Error('Session closed')); return require('./game-project').exportGameProject(game, options.userExportsStore); },
        stop() { if (stopped) return; stopped = true; squisher.close(); options.userExportsStore?.close(); }
    };
};
const playerFrame = (squisher, playerId) => {
    const parts = squisher.getPlayerFrame(playerId);
    // Count and write directly into the transport-owned buffer. Array.flat()
    // first allocates a numeric-array entry for every byte, for every player/frame.
    // Preserve one-level flattening and skipped holes in numeric codec arrays.
    let length = 0;
    for (let i = 0; i < parts.length; i++) {
        if (!(i in parts)) continue;
        const part = parts[i];
        if (Array.isArray(part)) {
            for (let j = 0; j < part.length; j++) if (j in part) length++;
        } else length++;
    }
    const frame = new Uint8Array(length);
    let offset = 0;
    for (let i = 0; i < parts.length; i++) {
        if (!(i in parts)) continue;
        const part = parts[i];
        if (Array.isArray(part)) {
            for (let j = 0; j < part.length; j++) if (j in part) frame[offset++] = part[j];
        } else frame[offset++] = part;
    }
    return frame;
};
module.exports = { createSessionRuntime, playerFrame, collectGameAssets };
