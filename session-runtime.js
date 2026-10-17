const { Squisher } = require('squish-150');
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
const playerFrame = (squisher, playerId) => Uint8Array.from(squisher.getPlayerFrame(playerId).flat());
module.exports = { createSessionRuntime, playerFrame, collectGameAssets };
