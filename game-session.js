/**
 * GameSession — Unified game session for all Homegames contexts.
 *
 * Replaces both the old GameSession (homegames-core) and MiniGameSession
 * (homegames-common). One class, configurable via an options bag.
 *
 * Usage (minimal / no-frame):
 *   const session = new GameSession(game, squishVersion);
 *
 * Usage (full platform with bezel, spectators, homenames):
 *   const session = new GameSession(game, squishVersion, {
 *       frame: { root, topLayerRoot, assets, bezelX, bezelY, isDashboard, ... },
 *       homenames: homenamesHelper,
 *       spectators: true,
 *   });
 *
 * Consumers:
 *   - homegames-core/child_game_server.js   (no-frame OR full-frame, depending on mode)
 *   - homegames-common/game-session-manager.js
 */

const WebSocket = require('ws');
const { squishMap, DEFAULT_SQUISH_VERSION } = require('./game-loader');

// Simple name generator for anonymous players
const _NAME_WORDS = [
    'chocolate', 'iguana', 'cardigan', 'enormous', 'gargantuan', 'orangutan',
    'cookies', 'monstera', 'daisy', 'grapefruit', 'blueberry', 'mango',
    'elephant', 'bamboo', 'sapphire', 'papaya', 'waffle', 'turquoise',
    'aquatic', 'goblin', 'funky', 'hotdog', 'elegant', 'cascade', 'euphoria',
];
const _generateName = () => {
    const pick = () => _NAME_WORDS[Math.floor(Math.random() * _NAME_WORDS.length)];
    return pick() + ' ' + pick();
};

class GameSession {
    constructor(game, squishVersion, opts = {}) {
        const squishPkg = process.env.SQUISH_PATH
            || squishMap[squishVersion]
            || squishMap[DEFAULT_SQUISH_VERSION];
        if (!squishPkg) {
            throw new Error(`No squish package found for version "${squishVersion}"`);
        }
        const { Squisher } = require(squishPkg);

        this.game = game;
        this.squishVersion = squishVersion;
        this.port = opts.port || null;
        this.username = opts.username || null;

        // Frame / bezel setup
        this.frameEnabled = !!opts.frame;
        this.frame = opts.frame || null;

        const bezelX = this.frameEnabled ? (this.frame.bezelX ?? 10) : 0;
        const bezelY = this.frameEnabled ? (this.frame.bezelY ?? 10) : 0;
        this.bezelX = bezelX;
        this.bezelY = bezelY;
        this.scale = this.frameEnabled
            ? { x: (100 - bezelX) / 100, y: (100 - bezelY) / 100 }
            : { x: 1, y: 1 };

        // Squisher setup
        const squisherOpts = {
            game,
            scale: this.scale,
            onAssetUpdate: (newAssetBundle) => {
                for (const pid in this.players) {
                    this._send(this.players[pid], newAssetBundle);
                }
                for (const sid in this.spectators) {
                    this._send(this.spectators[sid], newAssetBundle);
                }
            },
        };

        if (this.frameEnabled) {
            squisherOpts.customBottomLayer = {
                root: this.frame.root,
                scale: { x: 1, y: 1 },
                assets: this.frame.assets || {},
            };
            squisherOpts.customTopLayer = {
                root: this.frame.topLayerRoot,
                scale: { x: 1, y: 1 },
            };
        }

        this.squisher = new Squisher(squisherOpts);
        // Coalesce broadcasts: a single game tick often mutates many nodes, each
        // firing onStateChange -> a listener call. Without coalescing that's one
        // full per-player send (frame.flat + Buffer.from + ws.send) per mutation.
        // We defer to the end of the current event-loop turn so a burst of
        // mutations produces a single broadcast carrying the final state.
        // (The squisher still recomputes this.state synchronously per mutation,
        // so getPlayerFrame/state stay fresh for the direct-send paths.)
        this._broadcastScheduled = false;
        this.squisher.addListener(() => this._scheduleBroadcast());

        this.gameMetadata = (typeof game.constructor.metadata === 'function') ? game.constructor.metadata() : {};
        this.maxPlayers = this.gameMetadata.maxPlayers || 64;
        this.aspectRatio = this.gameMetadata.aspectRatio || { x: 16, y: 9 };

        // Player / spectator maps  —  values are raw WebSocket objects
        this.players = {};
        this.spectators = {};
        this.playerInfoMap = {};
        this.clientInfoMap = {};
        this.playerSettingsMap = {};
        this.remotePlayerMap = {};
        this.stateHistory = [];

        // Optional subsystems
        this.spectatorsEnabled = !!opts.spectators;
        this.homenames = opts.homenames || null;

        // Frame handler (HomegamesRoot instance)
        this.frameHandler = (this.frame && this.frame.handler) || null;
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    initialize() {
        if (this._initialized) return Promise.resolve();
        if (this.squisher.initialize) {
            return this.squisher.initialize().then(() => { this._initialized = true; });
        }
        this._initialized = true;
        return Promise.resolve();
    }

    // -----------------------------------------------------------------------
    // Player management
    // -----------------------------------------------------------------------

    addPlayer(playerId, ws, playerOpts = {}) {
        // Reject if the game is at capacity
        if (Object.keys(this.players).length >= this.maxPlayers) {
            try { ws.close(); } catch (e) {}
            throw new Error('Game is full');
        }

        // If this ID is already connected, disconnect the old one first
        if (this.players[playerId]) {
            this.removePlayer(playerId);
        }

        this.players[playerId] = ws;
        this.playerInfoMap[playerId] = playerOpts.info || {};
        this.clientInfoMap[playerId] = playerOpts.clientInfo || {};
        this.playerSettingsMap[playerId] = playerOpts.settings || { SOUND: true };
        if (playerOpts.isRemote) this.remotePlayerMap[playerId] = true;

        if (this.squisher.assetBundle) {
            this._send(ws, this.squisher.assetBundle);
        }

        if (this.homenames) {
            const notifyPlayer = (extraInfo) => {
                if (!this.players[playerId]) return; // disconnected during async

                if (extraInfo) {
                    if (extraInfo.playerInfo) this.playerInfoMap[playerId] = extraInfo.playerInfo;
                    if (extraInfo.playerSettings) this.playerSettingsMap[playerId] = extraInfo.playerSettings;
                    if (extraInfo.clientInfo) this.clientInfoMap[playerId] = extraInfo.clientInfo;
                }

                const playerPayload = {
                    playerId,
                    settings: this.playerSettingsMap[playerId],
                    info: this.playerInfoMap[playerId],
                    clientInfo: this.clientInfoMap[playerId],
                    requestedGame: playerOpts.requestedGame || null,
                };

                try { this.homenames.addListener(playerId); } catch (e) {
                    console.error('[GameSession] homenames.addListener failed:', e.message);
                }

                try {
                    if (this.frameHandler && this.frameHandler.handleNewPlayer) {
                        this.frameHandler.handleNewPlayer(playerPayload);
                    }
                } catch (e) {
                    console.error('[GameSession] frameHandler.handleNewPlayer threw:', e);
                }

                try {
                    this.game.handleNewPlayer && this.game.handleNewPlayer(playerPayload);
                } catch (e) {
                    console.error('[GameSession] game.handleNewPlayer threw:', e);
                }

                this._sendPlayerFrame(playerId, ws);
            };

            const finishAdd = () => {
                Promise.all([
                    this.homenames.getPlayerInfo(playerId).catch(() => null),
                    this.homenames.getPlayerSettings(playerId).catch(() => null),
                    this.homenames.getClientInfo(playerId).catch(() => null),
                ]).then(([playerInfo, playerSettings, clientInfo]) => {
                    notifyPlayer({
                        playerInfo: playerInfo || this.playerInfoMap[playerId],
                        playerSettings: playerSettings || this.playerSettingsMap[playerId],
                        clientInfo: clientInfo || this.clientInfoMap[playerId],
                    });
                }).catch((err) => {
                    console.error('[GameSession] Homenames fetch failed:', err);
                    notifyPlayer();
                });
            };

            const info = playerOpts.info || {};
            if (info.name) {
                finishAdd();
            } else {
                const playerName = _generateName();
                this.homenames.updatePlayerInfo(playerId, { playerName })
                    .then(() => this.homenames.updateClientInfo(playerId, playerOpts.clientInfo || {}))
                    .then(() => finishAdd())
                    .catch(() => finishAdd());
            }
        } else {
            const playerPayload = {
                playerId,
                settings: this.playerSettingsMap[playerId],
                info: this.playerInfoMap[playerId],
                clientInfo: this.clientInfoMap[playerId],
                requestedGame: playerOpts.requestedGame || null,
            };

            try {
                if (this.frameHandler && this.frameHandler.handleNewPlayer) {
                    this.frameHandler.handleNewPlayer(playerPayload);
                }
            } catch (e) {
                console.error('[GameSession] frameHandler.handleNewPlayer threw:', e);
            }

            try {
                this.game.handleNewPlayer && this.game.handleNewPlayer(playerPayload);
            } catch (e) {
                console.error('[GameSession] game.handleNewPlayer threw:', e);
            }

            this._sendPlayerFrame(playerId, ws);
        }
    }

    removePlayer(playerId) {
        try {
            this.game.handlePlayerDisconnect && this.game.handlePlayerDisconnect(playerId);
        } catch (e) {
            console.error('[GameSession] game.handlePlayerDisconnect threw:', e);
        }

        try {
            if (this.frameHandler && this.frameHandler.handlePlayerDisconnect) {
                this.frameHandler.handlePlayerDisconnect(playerId);
            }
        } catch (e) {
            console.error('[GameSession] frameHandler.handlePlayerDisconnect threw:', e);
        }

        delete this.players[playerId];
        delete this.playerInfoMap[playerId];
        delete this.clientInfoMap[playerId];
        delete this.playerSettingsMap[playerId];
        delete this.remotePlayerMap[playerId];
    }

    // -----------------------------------------------------------------------
    // Spectator management
    // -----------------------------------------------------------------------

    addSpectator(spectatorId, ws, spectatorOpts = {}) {
        if (!this.spectatorsEnabled) return;

        this.spectators[spectatorId] = ws;
        if (spectatorOpts.isRemote) this.remotePlayerMap[spectatorId] = true;

        if (this.squisher.assetBundle) {
            this._send(ws, this.squisher.assetBundle);
        }

        try {
            if (this.frameHandler && this.frameHandler.handleNewSpectator) {
                this.frameHandler.handleNewSpectator({ id: spectatorId, ws });
            }
        } catch (e) {
            console.error('[GameSession] frameHandler.handleNewSpectator threw:', e);
        }

        this._sendPlayerFrame(spectatorId, ws);
    }

    removeSpectator(spectatorId) {
        try {
            if (this.frameHandler && this.frameHandler.handleSpectatorDisconnect) {
                this.frameHandler.handleSpectatorDisconnect(spectatorId);
            }
        } catch (e) {
            console.error('[GameSession] frameHandler.handleSpectatorDisconnect threw:', e);
        }
        delete this.spectators[spectatorId];
        delete this.remotePlayerMap[spectatorId];
    }

    // -----------------------------------------------------------------------
    // Player info updates (from homenames)
    // -----------------------------------------------------------------------

    handlePlayerUpdate(playerId, { info, settings }) {
        this.playerInfoMap[playerId] = info;
        this.playerSettingsMap[playerId] = settings;

        try {
            if (this.frameHandler && this.frameHandler.handlePlayerUpdate) {
                this.frameHandler.handlePlayerUpdate(playerId, { info, settings });
            }
        } catch (e) {
            console.error('[GameSession] frameHandler.handlePlayerUpdate threw:', e);
        }

        try {
            this.game.handlePlayerUpdate && this.game.handlePlayerUpdate(playerId, { info, settings });
        } catch (e) {
            console.error('[GameSession] game.handlePlayerUpdate threw:', e);
        }
    }

    // -----------------------------------------------------------------------
    // Input handling
    // -----------------------------------------------------------------------

    handleInput(playerId, input) {
        if (!input || typeof input !== 'object' || typeof input.type !== 'string') return;
        if (!this.players[playerId] && !this.spectators[playerId]) return;

        const pid = Number(playerId);

        try {
            if (input.type === 'click') {
                const data = input.data;
                if (!data || typeof data.x !== 'number' || typeof data.y !== 'number') return;
                this._handleClick(pid, data);
            } else if (input.type === 'keydown') {
                if (typeof input.key !== 'string' || input.key.length > 20) return;
                this.game.handleKeyDown && this.game.handleKeyDown(pid, input.key);
            } else if (input.type === 'keyup') {
                if (typeof input.key !== 'string' || input.key.length > 20) return;
                this.game.handleKeyUp && this.game.handleKeyUp(pid, input.key);
            } else if (input.type === 'mouseup') {
                this.game.handleMouseUp && this.game.handleMouseUp(pid, input.data);
            } else if (input.type === 'input') {
                if (input.gamepad) {
                    this.game.handleGamepadInput && this.game.handleGamepadInput(pid, input);
                } else {
                    const topLayer = this.frameEnabled ? this.frame.topLayerRoot : null;
                    const node = this.game.findNode(input.nodeId)
                        || (topLayer && topLayer.findChild(input.nodeId));
                    if (node && node.node && node.node.input) {
                        if (node.node.input.type === 'file') {
                            node.node.input.oninput(pid, Object.values(input.input || {}));
                        } else {
                            node.node.input.oninput(pid, input.input);
                        }
                    }
                }
            } else if (input.type === 'onhover') {
                const topLayer = this.frameEnabled ? this.frame.topLayerRoot : null;
                const node = this.game.findNode(input.nodeId)
                    || (topLayer && topLayer.findChild(input.nodeId));
                if (node && node.node?.onHover) node.node.onHover(pid);
            } else if (input.type === 'offhover') {
                const topLayer = this.frameEnabled ? this.frame.topLayerRoot : null;
                const node = this.game.findNode(input.nodeId)
                    || (topLayer && topLayer.findChild(input.nodeId));
                if (node && node.node?.offHover) node.node.offHover(pid);
            }
        } catch (e) {
            console.error(`[GameSession] Error handling input type="${input.type}" for player ${pid}:`, e);
        }
    }

    // -----------------------------------------------------------------------
    // Asset handling
    // -----------------------------------------------------------------------

    handleNewAsset(key, asset) {
        return this.squisher.handleNewAsset(key, asset).then(newBundle => {
            for (const pid in this.players) {
                this._send(this.players[pid], newBundle);
            }
            for (const sid in this.spectators) {
                this._send(this.spectators[sid], newBundle);
            }
        });
    }

    // -----------------------------------------------------------------------
    // Session navigation
    // -----------------------------------------------------------------------

    movePlayer(playerId, port) {
        const ws = this.players[playerId];
        if (ws) {
            this._send(ws, [5, Math.floor(port / 100), Math.floor(port % 100)]);
        }
    }

    spectateSession(playerId) {
        const ws = this.players[playerId];
        if (ws && this.port) {
            this._send(ws, [6, Math.floor(this.port / 100), Math.floor(this.port % 100)]);
        }
    }

    joinSession(spectatorId) {
        const ws = this.spectators[spectatorId];
        if (ws && this.port) {
            this._send(ws, [5, Math.floor(this.port / 100), Math.floor(this.port % 100)]);
        }
    }

    setServerCode(serverCode) {
        if (this.frameHandler && !this.frameHandler.isDashboard) {
            this.frameHandler.handleServerCode(serverCode);
        }
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    getPlayerCount() {
        return Object.keys(this.players).length;
    }

    destroy() {
        try { if (this.game.destroy) this.game.destroy(); } catch (e) {}
        try { if (this.game.clearAllTimers) this.game.clearAllTimers(); } catch (e) {}
        this.players = {};
        this.spectators = {};
        this.playerInfoMap = {};
        this.clientInfoMap = {};
        this.playerSettingsMap = {};
        this.remotePlayerMap = {};
    }

    // -----------------------------------------------------------------------
    // Private: broadcasting
    // -----------------------------------------------------------------------

    _scheduleBroadcast() {
        if (this._broadcastScheduled) return;
        this._broadcastScheduled = true;
        const schedule = (typeof setImmediate === 'function')
            ? setImmediate
            : (fn) => setTimeout(fn, 0);
        schedule(() => {
            this._broadcastScheduled = false;
            this._broadcastState();
        });
    }

    _broadcastState() {
        for (const pid in this.players) {
            try {
                this._sendPlayerFrame(pid, this.players[pid]);
            } catch (e) {
                console.error(`[GameSession] Broadcast failed for player ${pid}:`, e);
            }
        }
        for (const sid in this.spectators) {
            try {
                this._sendPlayerFrame(sid, this.spectators[sid]);
            } catch (e) {
                console.error(`[GameSession] Broadcast failed for spectator ${sid}:`, e);
            }
        }
    }

    _sendPlayerFrame(playerId, ws) {
        // Newer squishers defer squish/broadcast and coalesce per tick. The
        // direct-send paths (a player/spectator just joined) need the current
        // state, so flush any pending changes first. No-op when nothing pending
        // and on older squishers that don't implement flush().
        if (typeof this.squisher.flush === 'function') this.squisher.flush();
        let frame = this.squisher.getPlayerFrame(playerId);
        if (!frame) frame = this.squisher.state;
        if (frame) {
            const flat = Array.isArray(frame) ? frame.flat() : frame;
            this._send(ws, flat);
        }
    }

    _send(ws, data) {
        try {
            if (ws.readyState === WebSocket.OPEN || ws.readyState === 1) {
                ws.send(Buffer.from(data));
            }
        } catch (e) {
            // Swallow send errors — client likely disconnected
        }
    }

    // -----------------------------------------------------------------------
    // Private: click / hit-testing
    // -----------------------------------------------------------------------

    _handleClick(playerId, click) {
        if (!click || typeof click.x !== 'number' || typeof click.y !== 'number') return;
        if (click.x < 0 || click.y < 0 || click.x >= 100 || click.y >= 100) return;

        const spectating = this.spectatorsEnabled && !!this.spectators[playerId];
        const clickedNode = this._findClick(click.x, click.y, spectating, playerId);

        if (clickedNode) {
            const bottomLayer = this.frameEnabled ? this.frame.root : null;
            const topLayer = this.frameEnabled ? this.frame.topLayerRoot : null;

            const realNode = this.game.findNode(clickedNode.id)
                || (bottomLayer && bottomLayer.findChild(clickedNode.id))
                || (topLayer && topLayer.findChild(clickedNode.id));

            if (realNode && realNode.node && realNode.node.handleClick) {
                if (this.frameEnabled) {
                    if (click.x <= (this.bezelX / 2) || click.x >= (100 - this.bezelX / 2)
                        || click.y <= (this.bezelY / 2) || click.y >= (100 - this.bezelY / 2)) {
                        realNode.node.handleClick(playerId, click.x, click.y);
                    } else {
                        const shiftedX = click.x - (this.bezelX / 2);
                        const shiftedY = click.y - (this.bezelY / 2);
                        const scaledX = shiftedX * (1 / ((100 - this.bezelX) / 100));
                        const scaledY = shiftedY * (1 / ((100 - this.bezelY) / 100));
                        realNode.node.handleClick(playerId, scaledX, scaledY);
                    }
                } else {
                    realNode.node.handleClick(playerId, click.x, click.y);
                }
            }
        }
    }

    _findClick(x, y, spectating, playerId) {
        let clicked = null;

        if (this.frameEnabled && this.frame.root) {
            clicked = this._findClickHelper(x, y, spectating, playerId, this.frame.root.node, null, { x: 1, y: 1 }, false, 0) || clicked;
        }

        const layers = this.game.getLayers();
        for (let i = 0; i < layers.length; i++) {
            const layer = layers[i];
            const scale = layer.scale || this.scale;
            clicked = this._findClickHelper(x, y, spectating, playerId, layer.root.node, null, scale, true, 0) || clicked;
        }

        if (this.frameEnabled && this.frame.topLayerRoot) {
            clicked = this._findClickHelper(x, y, spectating, playerId, this.frame.topLayerRoot.node, null, { x: 1, y: 1 }, false, 0) || clicked;
        }

        return clicked;
    }

    _findClickHelper(x, y, spectating, playerId, node, clicked, scale, inGame, depth) {
        // Guard against deep/cyclic trees
        if (depth > 100) return clicked;

        if (node.playerIds && node.playerIds.length > 0 && !node.playerIds.find(p => p == playerId)) {
            return clicked;
        }

        if (node.coordinates2d && node.coordinates2d.length > 0) {
            const vertices = [];
            for (let i = 0; i < node.coordinates2d.length; i++) {
                const xOff = 100 - (scale.x * 100);
                const yOff = 100 - (scale.y * 100);
                const sx = node.coordinates2d[i][0] * ((100 - xOff) / 100) + (xOff / 2);
                const sy = node.coordinates2d[i][1] * ((100 - yOff) / 100) + (yOff / 2);
                vertices.push([sx, sy]);
            }

            if (vertices.length > 0) {
                let isInside = false;
                let minX = vertices[0][0], maxX = vertices[0][0];
                let minY = vertices[0][1], maxY = vertices[0][1];
                for (let i = 1; i < vertices.length; i++) {
                    minX = Math.min(vertices[i][0], minX);
                    maxX = Math.max(vertices[i][0], maxX);
                    minY = Math.min(vertices[i][1], minY);
                    maxY = Math.max(vertices[i][1], maxY);
                }

                if (!(x < minX || x > maxX || y < minY || y > maxY)) {
                    let ii = 0, jj = vertices.length - 1;
                    for (ii, jj; ii < vertices.length; jj = ii++) {
                        if ((vertices[ii][1] > y) !== (vertices[jj][1] > y) &&
                            x < (vertices[jj][0] - vertices[ii][0]) * (y - vertices[ii][1]) / (vertices[jj][1] - vertices[ii][1]) + vertices[ii][0]) {
                            isInside = !isInside;
                        }
                    }
                }

                if (isInside) {
                    if (!(spectating && inGame)) {
                        clicked = node;
                    }
                }
            }
        }

        if (node.children) {
            const childKeys = Object.keys(node.children);
            for (let i = 0; i < childKeys.length; i++) {
                const child = node.children[childKeys[i]];
                if (child && child.node) {
                    clicked = this._findClickHelper(x, y, spectating, playerId, child.node, clicked, scale, inGame, depth + 1);
                }
            }
        }

        return clicked;
    }
}

module.exports = GameSession;
