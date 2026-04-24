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
 *       onPlayerMove: (playerId, port) => { ... },
 *   });
 *
 * Consumers:
 *   - homegames-core/child_game_server.js   (no-frame OR full-frame, depending on mode)
 *   - homegames-common/game-session-manager.js
 */

const { squishMap, DEFAULT_SQUISH_VERSION } = require('./game-loader');

// Simple name generator for anonymous players (replaces homegames-core's dictionary-based one)
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
    /**
     * @param {object} game        - Game instance (must have getLayers(), findNode(), etc.)
     * @param {string} squishVersion - Squish version string (e.g. '135')
     * @param {object} [opts]      - Optional features
     * @param {object} [opts.frame]          - Frame/bezel config (enables bezel chrome)
     * @param {object} [opts.frame.root]     - HomegamesRoot bottom-layer root node
     * @param {object} [opts.frame.topLayerRoot] - HomegamesRoot top-layer root node
     * @param {object} [opts.frame.assets]   - HomegamesRoot assets
     * @param {number} [opts.frame.bezelX]   - Bezel X percentage (e.g. 10)
     * @param {number} [opts.frame.bezelY]   - Bezel Y percentage (e.g. 10)
     * @param {object} [opts.frame.handler]  - HomegamesRoot instance (for handleNewPlayer, etc.)
     * @param {boolean} [opts.spectators]    - Enable spectator support
     * @param {object} [opts.homenames]      - HomenamesHelper instance (or any adapter with same API)
     * @param {function} [opts.onPlayerMove] - Called when a player should be redirected: (playerId, port) => {}
     * @param {string} [opts.username]       - Username for homenames
     * @param {number} [opts.port]           - Port this session is running on
     */
    constructor(game, squishVersion, opts = {}) {
        // Prefer SQUISH_PATH env var (set by host server to a fully-resolved path)
        const squishPkg = process.env.SQUISH_PATH
            || squishMap[squishVersion]
            || squishMap[DEFAULT_SQUISH_VERSION];
        const { Squisher } = require(squishPkg);

        this.game = game;
        this.squishVersion = squishVersion;
        this.port = opts.port || null;
        this.username = opts.username || null;

        // Frame / bezel setup
        this.frameEnabled = !!opts.frame;
        this.frame = opts.frame || null;

        const bezelX = this.frameEnabled ? (this.frame.bezelX || 10) : 0;
        const bezelY = this.frameEnabled ? (this.frame.bezelY || 10) : 0;
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
        this.squisher.addListener(() => this._broadcastState());

        this.gameMetadata = game.constructor.metadata ? game.constructor.metadata() : {};
        this.aspectRatio = this.gameMetadata.aspectRatio || { x: 16, y: 9 };

        // Player / spectator maps  —  values are raw WebSocket objects
        this.players = {};
        this.spectators = {};
        this.playerInfoMap = {};
        this.clientInfoMap = {};
        this.playerSettingsMap = {};
        this.remotePlayerMap = {}; // tracks which player/spectator IDs connected via proxy

        // Optional subsystems
        this.spectatorsEnabled = !!opts.spectators;
        this.homenames = opts.homenames || null;
        this.onPlayerMove = opts.onPlayerMove || null;

        // Frame handler (HomegamesRoot instance)
        this.frameHandler = (this.frame && this.frame.handler) || null;
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    initialize() {
        if (this._initialized) return Promise.resolve();
        return this.squisher.initialize
            ? this.squisher.initialize().then(() => { this._initialized = true; })
            : Promise.resolve();
    }

    // -----------------------------------------------------------------------
    // Player management
    // -----------------------------------------------------------------------

    /**
     * Add a player to the session.
     *
     * @param {number} playerId
     * @param {WebSocket} ws
     * @param {object} [playerOpts]
     * @param {object} [playerOpts.clientInfo]    - Client device info
     * @param {object} [playerOpts.info]          - Player info (name, etc.) from homenames
     * @param {object} [playerOpts.settings]      - Player settings from homenames
     * @param {string} [playerOpts.requestedGame] - Game the player initially requested
     * @param {boolean} [playerOpts.isRemote]     - Whether the player connected via proxy
     */
    addPlayer(playerId, ws, playerOpts = {}) {
        this.players[playerId] = ws;
        this.playerInfoMap[playerId] = playerOpts.info || {};
        this.clientInfoMap[playerId] = playerOpts.clientInfo || {};
        this.playerSettingsMap[playerId] = playerOpts.settings || { SOUND: true };
        if (playerOpts.isRemote) this.remotePlayerMap[playerId] = true;

        // Send asset bundle if available
        if (this.squisher.assetBundle) {
            this._send(ws, this.squisher.assetBundle);
        }

        // If we have a Homenames adapter, do the full player setup flow:
        // generate a name for anonymous players, fetch settings, register listener.
        if (this.homenames) {
            const notifyPlayer = (extraInfo) => {
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

                try { this.homenames.addListener(playerId); } catch (e) {}

                if (this.frameHandler && this.frameHandler.handleNewPlayer) {
                    this.frameHandler.handleNewPlayer(playerPayload);
                }
                this.game.handleNewPlayer && this.game.handleNewPlayer(playerPayload);
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
                    console.error('[GameSession] Homenames fetch failed, proceeding without:', err);
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
                    .catch((err) => {
                        console.error('[GameSession] Homenames update failed, proceeding anyway:', err);
                        finishAdd();
                    });
            }
        } else {
            // No Homenames — simple path (no-frame / testing)
            const playerPayload = {
                playerId,
                settings: this.playerSettingsMap[playerId],
                info: this.playerInfoMap[playerId],
                clientInfo: this.clientInfoMap[playerId],
                requestedGame: playerOpts.requestedGame || null,
            };

            if (this.frameHandler && this.frameHandler.handleNewPlayer) {
                this.frameHandler.handleNewPlayer(playerPayload);
            }
            this.game.handleNewPlayer && this.game.handleNewPlayer(playerPayload);
            this._sendPlayerFrame(playerId, ws);
        }
    }

    removePlayer(playerId) {
        this.game.handlePlayerDisconnect && this.game.handlePlayerDisconnect(playerId);

        if (this.frameHandler && this.frameHandler.handlePlayerDisconnect) {
            this.frameHandler.handlePlayerDisconnect(playerId);
        }

        delete this.players[playerId];
        delete this.playerInfoMap[playerId];
        delete this.clientInfoMap[playerId];
        delete this.playerSettingsMap[playerId];
        delete this.remotePlayerMap[playerId];
    }

    // -----------------------------------------------------------------------
    // Spectator management (only active when spectatorsEnabled)
    // -----------------------------------------------------------------------

    addSpectator(spectatorId, ws, spectatorOpts = {}) {
        if (!this.spectatorsEnabled) return;

        this.spectators[spectatorId] = ws;
        if (spectatorOpts.isRemote) this.remotePlayerMap[spectatorId] = true;

        if (this.squisher.assetBundle) {
            this._send(ws, this.squisher.assetBundle);
        }

        if (this.frameHandler && this.frameHandler.handleNewSpectator) {
            this.frameHandler.handleNewSpectator({ id: spectatorId, ws });
        }

        this._sendPlayerFrame(spectatorId, ws);
    }

    removeSpectator(spectatorId) {
        if (this.frameHandler && this.frameHandler.handleSpectatorDisconnect) {
            this.frameHandler.handleSpectatorDisconnect(spectatorId);
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

        if (this.frameHandler && this.frameHandler.handlePlayerUpdate) {
            this.frameHandler.handlePlayerUpdate(playerId, { info, settings });
        }

        this.game.handlePlayerUpdate && this.game.handlePlayerUpdate(playerId, { info, settings });
    }

    // -----------------------------------------------------------------------
    // Input handling
    // -----------------------------------------------------------------------

    handleInput(playerId, input) {
        if (input.type === 'click') {
            this._handleClick(Number(playerId), input.data);
        } else if (input.type === 'keydown') {
            this.game.handleKeyDown && this.game.handleKeyDown(Number(playerId), input.key);
        } else if (input.type === 'keyup') {
            this.game.handleKeyUp && this.game.handleKeyUp(Number(playerId), input.key);
        } else if (input.type === 'mouseup') {
            this.game.handleMouseUp && this.game.handleMouseUp(playerId, input.data);
        } else if (input.type === 'input') {
            if (input.gamepad) {
                this.game.handleGamepadInput && this.game.handleGamepadInput(Number(playerId), input);
            } else {
                const topLayer = this.frameEnabled
                    ? this.frame.topLayerRoot
                    : null;
                const node = this.game.findNode(input.nodeId)
                    || (topLayer && topLayer.findChild(input.nodeId));
                if (node && node.node.input) {
                    if (node.node.input.type === 'file') {
                        node.node.input.oninput(playerId, Object.values(input.input));
                    } else {
                        node.node.input.oninput(playerId, input.input);
                    }
                }
            }
        } else if (input.type === 'onhover') {
            const topLayer = this.frameEnabled ? this.frame.topLayerRoot : null;
            const node = this.game.findNode(input.nodeId)
                || (topLayer && topLayer.findChild(input.nodeId));
            if (node && node.node?.onHover) node.node.onHover(playerId);
        } else if (input.type === 'offhover') {
            const topLayer = this.frameEnabled ? this.frame.topLayerRoot : null;
            const node = this.game.findNode(input.nodeId)
                || (topLayer && topLayer.findChild(input.nodeId));
            if (node && node.node?.offHover) node.node.offHover(playerId);
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
    // Session navigation (frame mode only)
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
        if (this.game.destroy) this.game.destroy();
        if (this.game.clearAllTimers) this.game.clearAllTimers();
    }

    // -----------------------------------------------------------------------
    // Private: broadcasting
    // -----------------------------------------------------------------------

    _broadcastState() {
        for (const pid in this.players) {
            this._sendPlayerFrame(pid, this.players[pid]);
        }
        for (const sid in this.spectators) {
            this._sendPlayerFrame(sid, this.spectators[sid]);
        }
    }

    _sendPlayerFrame(playerId, ws) {
        let frame = this.squisher.getPlayerFrame(playerId);
        if (!frame) {
            frame = this.squisher.state;
        }
        if (frame) {
            const flat = Array.isArray(frame) ? frame.flat() : frame;
            this._send(ws, flat);
        }
    }

    _send(ws, data) {
        const WebSocket = require('ws');
        if (ws.readyState === WebSocket.OPEN || ws.readyState === 1) {
            ws.send(Buffer.from(data));
        }
    }

    // -----------------------------------------------------------------------
    // Private: click / hit-testing
    // -----------------------------------------------------------------------

    _handleClick(playerId, click) {
        if (click.x >= 100 || click.y >= 100) return;

        const spectating = this.spectatorsEnabled && !!this.spectators[playerId];
        const clickedNode = this._findClick(click.x, click.y, spectating, playerId);

        if (clickedNode) {
            const bottomLayer = this.frameEnabled
                ? this.frame.root
                : null;
            const topLayer = this.frameEnabled
                ? this.frame.topLayerRoot
                : null;

            const realNode = this.game.findNode(clickedNode.id)
                || (bottomLayer && bottomLayer.findChild(clickedNode.id))
                || (topLayer && topLayer.findChild(clickedNode.id));

            if (realNode) {
                if (this.frameEnabled) {
                    // Check if click is in the bezel area
                    if (click.x <= (this.bezelX / 2) || click.x >= (100 - this.bezelX / 2)
                        || click.y <= (this.bezelY / 2) || click.y >= (100 - this.bezelY / 2)) {
                        realNode.node.handleClick && realNode.node.handleClick(playerId, click.x, click.y);
                    } else {
                        const shiftedX = click.x - (this.bezelX / 2);
                        const shiftedY = click.y - (this.bezelY / 2);
                        const scaledX = shiftedX * (1 / ((100 - this.bezelX) / 100));
                        const scaledY = shiftedY * (1 / ((100 - this.bezelY) / 100));
                        realNode.node.handleClick && realNode.node.handleClick(playerId, scaledX, scaledY);
                    }
                } else {
                    realNode.node.handleClick && realNode.node.handleClick(playerId, click.x, click.y);
                }
            }
        }
    }

    _findClick(x, y, spectating, playerId) {
        let clicked = null;

        // Bottom custom layer (frame)
        if (this.frameEnabled && this.frame.root) {
            const scale = { x: 1, y: 1 };
            clicked = this._findClickHelper(x, y, spectating, playerId, this.frame.root.node, null, scale, false) || clicked;
        }

        // Game layers
        for (const layerIndex in this.game.getLayers()) {
            const layer = this.game.getLayers()[layerIndex];
            const scale = layer.scale || this.scale;
            clicked = this._findClickHelper(x, y, spectating, playerId, layer.root.node, null, scale, true) || clicked;
        }

        // Top custom layer (frame)
        if (this.frameEnabled && this.frame.topLayerRoot) {
            const scale = { x: 1, y: 1 };
            clicked = this._findClickHelper(x, y, spectating, playerId, this.frame.topLayerRoot.node, null, scale, false) || clicked;
        }

        return clicked;
    }

    _findClickHelper(x, y, spectating, playerId, node, clicked, scale, inGame) {
        if (node.playerIds && node.playerIds.length > 0 && !node.playerIds.find(p => p === playerId)) {
            return clicked;
        }

        if (node.coordinates2d) {
            const vertices = [];
            for (const i in node.coordinates2d) {
                const xOff = 100 - (scale.x * 100);
                const yOff = 100 - (scale.y * 100);
                const sx = node.coordinates2d[i][0] * ((100 - xOff) / 100) + (xOff / 2);
                const sy = node.coordinates2d[i][1] * ((100 - yOff) / 100) + (yOff / 2);
                vertices.push([sx, sy]);
            }

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
                if (spectating && inGame) {
                    // Spectators can't click in-game nodes (only frame/bezel nodes)
                } else {
                    clicked = node;
                }
            }
        }

        for (const i in node.children) {
            clicked = this._findClickHelper(x, y, spectating, playerId, node.children[i].node, clicked, scale, inGame);
        }

        return clicked;
    }
}

module.exports = GameSession;
