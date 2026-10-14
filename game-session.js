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
const { ProjectTransferHost } = require('./project-transfer');
const GameDispatcher = require('./game-dispatch');
const { createSessionRuntime, playerFrame, collectGameAssets } = require('./session-runtime');
const { packAssetBundle, loadAssetBundle } = require('./local-play-shared');
const { squishMap, DEFAULT_SQUISH_VERSION } = require('./game-loader');
const { MAX_SAVE_DATA_BYTES, SAVE_PUSH_OPCODE, SAVE_REQUEST_OPCODE } = require('./save-games');
const { normalizeCursor, encodeCursor } = require('./cursor');

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
        if (!squishMap[squishVersion || DEFAULT_SQUISH_VERSION]) throw new Error(`Unsupported Squish version: ${squishVersion}`);
        const squishPkg = squishMap[squishVersion || DEFAULT_SQUISH_VERSION];
        if (!squishPkg) {
            throw new Error(`No squish package found for version "${squishVersion}"`);
        }
        const codec = require(squishPkg);

        this.game = game;
        this.media = opts.media || null;
        this.sessionAssets = new Map();
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
            userExportsStore: opts.userExportsStore,
            assetLoader: opts.assetLoader,
            scale: this.scale,

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

        this.runtime = createSessionRuntime(codec, game, squisherOpts);
        this.projectTransfers = new ProjectTransferHost({ exportProject: id => this.exportProject(id),
            listExports: () => this.runtime.listExports(), readExport: (_, name) => this.runtime.readExport(name) });
        this.squisher = this.runtime.squisher;
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
        this.playerCursors = new Map();
        this.remotePlayerMap = {};
        this.stateHistory = [];


        // Pending client-save requests (broadcast save backend): playerId ->
        // { gameKey, resolve, timer }. Resolved by a 'saveData' input from
        // that player, or null on timeout/disconnect.
        this._pendingSaveRequests = {};

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
        for (const packet of this.sessionAssets.values()) this._send(ws, packet);

        if (this.homenames) {
            const notifyPlayer = (extraInfo) => {
                if (!this.players[playerId]) return; // disconnected during async

                if (extraInfo) {
                    if (extraInfo.playerInfo) this.playerInfoMap[playerId] = extraInfo.playerInfo;
                    if (extraInfo.playerSettings) this.playerSettingsMap[playerId] = extraInfo.playerSettings;
                    if (extraInfo.clientInfo) this.clientInfoMap[playerId] = extraInfo.clientInfo;
                }

                // Homenames may be unreachable (or have no record yet) — never
                // hand the game a nameless player.
                if (!this.playerInfoMap[playerId].name) {
                    this.playerInfoMap[playerId].name = _generateName();
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
            if (!this.playerInfoMap[playerId].name) {
                this.playerInfoMap[playerId].name = _generateName();
            }

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
        this.projectTransfers.leave(Number(playerId));
        this.media?.leave(Number(playerId));
        try { this.gameInput?.removePlayer(Number(playerId)); }
        catch (error) { console.error('[GameSession] Error releasing input:', error); }
        // Disconnect mid-drag counts as releasing — games need the drag-end
        this._endPress(playerId, null);

        // A pending save request can't be answered anymore
        this._resolvePendingSave(playerId, null);

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
        this.playerCursors.delete(Number(playerId));
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
        for (const packet of this.sessionAssets.values()) this._send(ws, packet);

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

    exportProject(playerId) {
        if (!this.players[playerId]) return Promise.reject(new Error('Join the game before requesting a copy'));
        return this.runtime.exportProject(Number(playerId));
    }

    handleInput(playerId, input) {
        if (!input || typeof input !== 'object' || typeof input.type !== 'string') return;
        if (!this.players[playerId] && !this.spectators[playerId]) return;

        const pid = Number(playerId);

        try {
            if (input.type === 'media' && this.players[playerId] && this.media) {
                if (input.action === 'hello') {
                    this.media.join(pid, { live: false, recording: input.recording === 1 || input.recording === 2, audioRecording: input.recording === 2,
                        send: message => this._send(this.players[playerId], Buffer.concat([Buffer.from([16]), Buffer.from(JSON.stringify(message))])),
                        addMedia() {}, removeMedia() {} });
                } else this.media.handle(pid, input);
                return;
            }
            if (input.type === 'project-transfer') {
                if (this.players[playerId]) void this.projectTransfers.handle(pid, input, bytes => this._send(this.players[playerId], bytes));
                return;
            }
            if (input.type === 'saveData') {
                // Answer to a SAVE_REQUEST_OPCODE frame — platform plumbing,
                // never forwarded to the game. Content is validated again by
                // extractClientSaveData before any game sees it.
                const pending = this._pendingSaveRequests[pid];
                if (pending && input.gameKey === pending.gameKey) {
                    let save = (input.save && typeof input.save === 'object') ? input.save : null;
                    try {
                        if (save && Buffer.byteLength(JSON.stringify(save), 'utf8') > MAX_SAVE_DATA_BYTES + 1024) {
                            save = null;
                        }
                    } catch (e) {
                        save = null;
                    }
                    this._resolvePendingSave(pid, save);
                }
            } else {
                if (input.type === 'input' && input.gamepad && !this.players[playerId]) return;
                this._getInputDispatcher().handleInput(pid, input);
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

    // Platform-managed uploads use the common bundle encoder, including video,
    // without depending on an older Squish release's private asset type map.
    async registerSessionAsset(key, asset) {
        const packet = packAssetBundle([{ key, type: asset.info.type, data: asset.data }]);
        this.sessionAssets.set(key, packet);
        // Preserve Squish's per-player audio filtering for these assets too.
        if (this.squisher.gameAssets) this.squisher.gameAssets[key] = asset;
        for (const ws of [...Object.values(this.players), ...Object.values(this.spectators)]) this._send(ws, packet);
    }

    // -----------------------------------------------------------------------
    // Player cursor
    // -----------------------------------------------------------------------

    setCursor(playerId, cursor) {
        const id = Number(playerId);
        const ws = this.players[id];
        if (!ws || ws.readyState !== WebSocket.OPEN) return false;
        const normalized = normalizeCursor(cursor);
        this.playerCursors.set(id, normalized);
        this._send(ws, encodeCursor(normalized));
        return true;
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

    // Tell one player's client to leave this session and run a game
    // single-player in the browser (LocalSession fed by the server's
    // /games/:gameKey/local-manifest endpoint). Opcode 12: [12] + UTF-8 JSON.
    sendLocalPlayRedirect(playerId, { gameKey, versionId = null, invitation = null } = {}) {
        const ws = this.players[playerId];
        if (ws && (gameKey || invitation)) {
            const payload = Buffer.from(JSON.stringify({ gameKey, versionId, ...(invitation ? { invitation } : {}) }), 'utf8');
            this._send(ws, Buffer.concat([Buffer.from([12]), payload]));
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
    // Save games (broadcast backend)
    // -----------------------------------------------------------------------

    // Push a save envelope to every connected client. Used when server-side
    // save files are disabled — the clients are the persistence layer.
    broadcastSaveData(envelope) {
        let payload;
        try {
            payload = Buffer.concat([
                Buffer.from([SAVE_PUSH_OPCODE]),
                Buffer.from(JSON.stringify(envelope)),
            ]);
        } catch (e) {
            return;
        }
        for (const pid in this.players) {
            this._send(this.players[pid], payload);
        }
        for (const sid in this.spectators) {
            this._send(this.spectators[sid], payload);
        }
    }

    // Ask a connected player's client for its stored save of `gameKey`.
    // Resolves the envelope the client answers with (or null on timeout,
    // disconnect, or no save). Used at session creation so the new game can
    // be constructed with the creating player's saveData.
    requestClientSave(playerId, { gameKey } = {}, timeoutMs = 3000) {
        const ws = this.players[playerId];
        if (!ws || typeof gameKey !== 'string') return Promise.resolve(null);

        // A newer request supersedes any outstanding one for this player
        this._resolvePendingSave(playerId, null);

        return new Promise((resolve) => {
            const timer = setTimeout(() => this._resolvePendingSave(playerId, null), timeoutMs);
            this._pendingSaveRequests[playerId] = { gameKey, resolve, timer };
            this._send(ws, Buffer.concat([
                Buffer.from([SAVE_REQUEST_OPCODE]),
                Buffer.from(JSON.stringify({ gameKey })),
            ]));
        });
    }

    _resolvePendingSave(playerId, value) {
        const pending = this._pendingSaveRequests[playerId];
        if (!pending) return;
        delete this._pendingSaveRequests[playerId];
        clearTimeout(pending.timer);
        try { pending.resolve(value); } catch (e) {}
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    getPlayerCount() {
        return Object.keys(this.players).length;
    }

    destroy() {
        this.projectTransfers.close();
        this.media?.destroy();
        this.runtime.stop();
        this.sessionAssets.clear();
        for (const pid in this._pendingSaveRequests) {
            this._resolvePendingSave(pid, null);
        }
        try { if (this.game.destroy) this.game.destroy(); } catch (e) {}
        try { if (this.game.clearAllTimers) this.game.clearAllTimers(); } catch (e) {}
        this.players = {};
        this.spectators = {};
        this.playerCursors.clear();
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
            this._checkActivePresses();
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
        const frame = playerFrame(this.squisher, playerId);
        if (frame) this._send(ws, frame);
    }

    _send(ws, data) {
        try {
            if (ws.readyState === WebSocket.OPEN || ws.readyState === 1) {
                // ws never mutates outgoing buffers, so one Buffer (e.g. the
                // asset bundle) can be shared across every recipient instead
                // of copied per send.
                ws.send(Buffer.isBuffer(data) ? data : Buffer.from(data));
            }
        } catch (e) {
            // Swallow send errors — client likely disconnected
        }
    }

    // -----------------------------------------------------------------------
    // Private: click / hit-testing
    // -----------------------------------------------------------------------

    // Map raw client coordinates (0-100 canvas space) into game space,
    // undoing the frame bezel scaling. Points on the bezel itself pass
    // through unscaled — frame nodes live in raw space.
    _toGameCoords(x, y) {
        if (!this.frameEnabled) return { x, y };
        if (x <= (this.bezelX / 2) || x >= (100 - this.bezelX / 2)
            || y <= (this.bezelY / 2) || y >= (100 - this.bezelY / 2)) {
            return { x, y };
        }
        const shiftedX = x - (this.bezelX / 2);
        const shiftedY = y - (this.bezelY / 2);
        return {
            x: shiftedX * (1 / ((100 - this.bezelX) / 100)),
            y: shiftedY * (1 / ((100 - this.bezelY) / 100)),
        };
    }

    _getInputDispatcher() {
        if (!this._inputDispatcher) {
            this._inputDispatcher = new GameDispatcher(this.game, {
                fileBuffers: true,
                toGameCoords: (x, y) => this._toGameCoords(x, y),
                findNode: id => this.game.findNode(id)
                    || (this.frameEnabled && this.frame.topLayerRoot?.findChild(id)),
                findPointerNode: id => this.game.findNode(id)
                    || (this.frameEnabled && (this.frame.root?.findChild(id) || this.frame.topLayerRoot?.findChild(id))),
                getLayers: (x, y, playerId) => this._inputLayers(x, y, playerId),
            });
            this.gameInput = this._inputDispatcher.gameInput;
        }
        return this._inputDispatcher;
    }

    _endPress(playerId, release) { this._inputDispatcher?.endPress(playerId, release); }

    _checkActivePresses() {
        this._inputDispatcher?.checkActivePresses();
    }

    _inputLayers(x, y, playerId) {
        const layers = [];
        if (this.frameEnabled && this.frame.root) layers.push({ root: this.frame.root });
        // Overflowing game geometry must never shadow the bezel's controls.
        const inBezel = this.frameEnabled && (
            x <= this.bezelX / 2 || x >= 100 - this.bezelX / 2
            || y <= this.bezelY / 2 || y >= 100 - this.bezelY / 2
        );
        if (!inBezel) {
            for (const layer of this.game.getLayers()) layers.push({
                ...layer, scale: layer.scale || this.scale,
                interactive: !(this.spectatorsEnabled && this.spectators[playerId]),
            });
        }
        if (this.frameEnabled && this.frame.topLayerRoot) layers.push({ root: this.frame.topLayerRoot });
        return layers;
    }
}

module.exports = GameSession;
