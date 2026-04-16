/**
 * MiniGameSession — A lightweight game session without the Dashboard chrome.
 *
 * Extracted from homegames-core/lib-testing/server.js.
 *
 * Used by:
 *   - lib-testing (Studio preview)
 *   - container-entry.js (Docker game sessions)
 *   - game-session-manager.js (when running in-process for tests)
 *
 * Unlike the full GameSession in homegames-core, this has:
 *   - No HomegamesRoot / bezel / frame
 *   - No Homenames integration
 *   - No spectator support
 *   - No child process forking
 *
 * It's just: game + squisher + players + WebSocket broadcast.
 */

const { squishMap, DEFAULT_SQUISH_VERSION } = require('./game-loader');

class MiniGameSession {
    constructor(game, squishVersion) {
        // Prefer SQUISH_PATH (set by the host server to a fully-resolved path)
        // so that the squish package resolves from the *host's* node_modules,
        // not from homegames-common's directory.
        const squishPkg = process.env.SQUISH_PATH
            || squishMap[squishVersion]
            || squishMap[DEFAULT_SQUISH_VERSION];
        const { Squisher } = require(squishPkg);

        this.game = game;
        this.squishVersion = squishVersion;
        this.scale = { x: 1, y: 1 };

        this.squisher = new Squisher({
            game,
            scale: this.scale,
            onAssetUpdate: (newAssetBundle) => {
                for (const pid in this.players) {
                    this._send(this.players[pid], newAssetBundle);
                }
            },
        });

        this.squisher.addListener(() => this._broadcastState());

        this.gameMetadata = game.constructor.metadata ? game.constructor.metadata() : {};
        this.aspectRatio = this.gameMetadata.aspectRatio || { x: 16, y: 9 };
        this.players = {};
        this.playerInfoMap = {};
        this.clientInfoMap = {};
    }

    initialize() {
        return Promise.resolve();
    }

    addPlayer(playerId, ws, clientInfo, requestedGame) {
        this.players[playerId] = ws;
        this.clientInfoMap[playerId] = clientInfo || {};

        if (this.squisher.assetBundle) {
            this._send(ws, this.squisher.assetBundle);
        }

        const playerPayload = {
            playerId,
            settings: {},
            info: {},
            clientInfo: clientInfo || {},
            requestedGame,
        };

        this.game.handleNewPlayer && this.game.handleNewPlayer(playerPayload);

        // Send the initial game state frame to this player.
        // Without this, the player sees nothing until the game triggers
        // its next state change (which may never happen without interaction).
        let frame = this.squisher.getPlayerFrame(playerId);
        if (!frame) {
            frame = this.squisher.state;
        }
        if (frame) {
            const flat = Array.isArray(frame) ? frame.flat() : frame;
            this._send(ws, flat);
        }
    }

    removePlayer(playerId) {
        this.game.handlePlayerDisconnect && this.game.handlePlayerDisconnect(playerId);
        delete this.players[playerId];
        delete this.playerInfoMap[playerId];
        delete this.clientInfoMap[playerId];
    }

    getPlayerCount() {
        return Object.keys(this.players).length;
    }

    handleInput(playerId, input) {
        if (input.type === 'click') {
            this._handleClick(playerId, input.data);
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
                const node = this.game.findNode(input.nodeId);
                if (node && node.node.input) {
                    if (node.node.input.type === 'file') {
                        node.node.input.oninput(playerId, Object.values(input.input));
                    } else {
                        node.node.input.oninput(playerId, input.input);
                    }
                }
            }
        } else if (input.type === 'onhover') {
            const node = this.game.findNode(input.nodeId);
            if (node && node.node?.onHover) node.node.onHover(playerId);
        } else if (input.type === 'offhover') {
            const node = this.game.findNode(input.nodeId);
            if (node && node.node?.offHover) node.node.offHover(playerId);
        }
    }

    handleNewAsset(key, asset) {
        return this.squisher.handleNewAsset(key, asset).then(newBundle => {
            for (const pid in this.players) {
                this._send(this.players[pid], newBundle);
            }
        });
    }

    _handleClick(playerId, click) {
        if (click.x >= 100 || click.y >= 100) return;

        const clicked = this._findClick(click.x, click.y, playerId);
        if (clicked) {
            const realNode = this.game.findNode(clicked.id);
            if (realNode) {
                realNode.node.handleClick && realNode.node.handleClick(playerId, click.x, click.y);
            }
        }
    }

    _findClick(x, y, playerId) {
        let clicked = null;
        for (const layerIndex in this.game.getLayers()) {
            const layer = this.game.getLayers()[layerIndex];
            const scale = layer.scale || this.scale;
            clicked = this._findClickHelper(x, y, playerId, layer.root.node, null, scale) || clicked;
        }
        return clicked;
    }

    _findClickHelper(x, y, playerId, node, clicked, scale) {
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

            if (isInside) clicked = node;
        }

        for (const i in node.children) {
            clicked = this._findClickHelper(x, y, playerId, node.children[i].node, clicked, scale);
        }

        return clicked;
    }

    _broadcastState() {
        for (const pid in this.players) {
            let frame = this.squisher.getPlayerFrame(pid);
            if (!frame) {
                frame = this.squisher.state;
            }
            if (frame) {
                const flat = Array.isArray(frame) ? frame.flat() : frame;
                this._send(this.players[pid], flat);
            }
        }
    }

    _send(ws, data) {
        // Support both real WebSocket objects and fake ws objects (proxy)
        const WebSocket = require('ws');
        if (ws.readyState === WebSocket.OPEN || ws.readyState === 1) {
            ws.send(Buffer.from(data));
        }
    }

    destroy() {
        if (this.game.destroy) this.game.destroy();
        // Clean up setInterval/setTimeout if the game uses ViewableGame
        if (this.game.clearAllTimers) this.game.clearAllTimers();
    }
}

module.exports = MiniGameSession;
