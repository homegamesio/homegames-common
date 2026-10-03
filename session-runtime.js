// Older Squish packages start tick() in their constructor without exposing
// its timer. A local session must own that clock: unlike a hosted child, its
// process survives game shutdown. Suppress only the synchronous constructor's
// automatic clock, restore the game's method exactly, then start our own.
const createSessionRuntime = (Squisher, game, options = {}) => {
    const tick = game.tick;
    const descriptor = Object.getOwnPropertyDescriptor(game, 'tick');
    let squisher;
    try {
        if (typeof tick === 'function') Object.defineProperty(game, 'tick', { configurable: true, writable: true, value: undefined });
        squisher = new Squisher({ ...options, game });
    } finally {
        if (typeof tick === 'function') {
            if (descriptor) Object.defineProperty(game, 'tick', descriptor);
            else delete game.tick;
        }
    }
    const rate = game.constructor.metadata?.().tickRate || 60;
    let stopped = false;
    const timer = typeof tick === 'function' ? setInterval(() => {
        if (!stopped) tick.call(game);
    }, 1000 / rate) : null;
    return {
        squisher,
        stop() {
            if (stopped) return;
            stopped = true;
            if (timer !== null) clearInterval(timer);
        },
    };
};

// Both transports use the same scoped frame and byte conversion. Uint8Array
// truncates fractional Squish values exactly like Node's Buffer.from().
const playerFrame = (squisher, playerId) => {
    const frame = squisher.getPlayerFrame(playerId) || squisher.state;
    return frame ? Uint8Array.from(Array.isArray(frame) ? frame.flat() : frame) : null;
};

module.exports = { createSessionRuntime, playerFrame };
