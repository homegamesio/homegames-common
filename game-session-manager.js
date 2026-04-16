/**
 * GameSessionManager — Orchestrates game sessions.
 *
 * Takes a game (by versionId, raw code, or local path) and gives you a port
 * where a WebSocket game server is running.
 *
 * Uses Docker containers when available, falls back to fork() when not.
 *
 * Consumers:
 *   - homegames-core HomegamesDashboard (startSession when player picks a game)
 *   - lib-testing server (Studio preview)
 *   - homedome (could use for test-running a game, though it mainly uses validateGame)
 */

const { fork } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const { isDockerAvailable, ensureImage, runGameContainer, stopContainer, isContainerRunning } = require('./docker-helper');
const { squishMap, DEFAULT_SQUISH_VERSION, fetchGameFromForgejo, loadGameClassFromPath, detectSquishVersion } = require('./game-loader');

// ---------------------------------------------------------------------------
// Port pool
// ---------------------------------------------------------------------------
const DEFAULT_PORT_MIN = 7002;
const DEFAULT_PORT_MAX = 7099;

class PortPool {
    constructor(min, max) {
        this.ports = {};
        for (let i = min; i <= max; i++) {
            this.ports[i] = false;
        }
    }

    acquire() {
        for (const p in this.ports) {
            if (!this.ports[p]) {
                this.ports[p] = true;
                return Number(p);
            }
        }
        return null;
    }

    release(port) {
        if (this.ports[port] !== undefined) {
            this.ports[port] = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Session tracking
// ---------------------------------------------------------------------------
let sessionIdCounter = 0;

class GameSessionManager {
    /**
     * @param {object} opts
     * @param {number} [opts.portMin] — start of port range (default 7002)
     * @param {number} [opts.portMax] — end of port range (default 7099)
     * @param {string} [opts.dockerImageDir] — path to dir containing the Dockerfile for homegames-runner
     * @param {string} [opts.childServerPath] — path to child_game_server.js (for fork fallback)
     * @param {string} [opts.dockerImageName] — Docker image name (default 'homegames-runner')
     * @param {number} [opts.gracePeriodMs] — ms to wait with no players before killing (default 30000)
     * @param {number} [opts.lifecycleCheckMs] — ms between lifecycle checks (default 10000)
     * @param {object} [opts.forgejo] — { url, token } for Forgejo access
     * @param {string} [opts.saveDataRoot] — root directory for game save data
     * @param {string} [opts.username] — homegames username
     * @param {string} [opts.certPath] — path to TLS certs
     * @param {function} [opts.log] — logging function ({ info, error })
     * @param {number} [opts.bezelX] — bezel size X for init message (default 0)
     * @param {number} [opts.bezelY] — bezel size Y for init message (default 0)
     */
    constructor(opts = {}) {
        this.portPool = new PortPool(
            opts.portMin || DEFAULT_PORT_MIN,
            opts.portMax || DEFAULT_PORT_MAX
        );
        this.dockerImageDir = opts.dockerImageDir || null;
        this.dockerImageName = opts.dockerImageName || 'homegames-runner';
        this.childServerPath = opts.childServerPath || null;
        this.gracePeriodMs = opts.gracePeriodMs || 30000;
        this.lifecycleCheckMs = opts.lifecycleCheckMs || 10000;
        this.forgejo = opts.forgejo || {};
        this.saveDataRoot = opts.saveDataRoot || path.join(os.tmpdir(), 'hg-save-data');
        this.username = opts.username || null;
        this.certPath = opts.certPath || null;
        this.log = opts.log || { info: console.log, error: console.error };

        this.sessions = {};
        this._dockerChecked = false;
        this._dockerOk = false;
    }

    /**
     * Determine whether Docker is available and the image is ready.
     * Caches the result after first call.
     */
    async _ensureDockerReady() {
        if (this._dockerChecked) return this._dockerOk;
        this._dockerChecked = true;

        if (!isDockerAvailable()) {
            this.log.info('Docker not available — sessions will use fork()');
            this._dockerOk = false;
            return false;
        }

        if (this.dockerImageDir) {
            try {
                await ensureImage(this.dockerImageDir, this.dockerImageName);
                this._dockerOk = true;
                this.log.info('Docker available and homegames-runner image ready');
            } catch (err) {
                this.log.error('Failed to build Docker image: ' + err.message);
                this._dockerOk = false;
            }
        } else {
            // No Dockerfile dir specified — check if image already exists
            const { isImageBuilt } = require('./docker-helper');
            this._dockerOk = isImageBuilt(this.dockerImageName);
            if (this._dockerOk) {
                this.log.info('Docker available, existing homegames-runner image found');
            } else {
                this.log.info('Docker available but no homegames-runner image. Specify dockerImageDir to build it. Using fork().');
            }
        }

        return this._dockerOk;
    }

    /**
     * Start a game session.
     *
     * @param {object} input — one of:
     *   { versionId }   — fetch code from Forgejo and run it
     *   { code }        — run raw code (Studio preview)
     *   { gamePath }    — run from local file path
     * @param {object} [opts]
     *   { onReady }     — callback when session is ready and listening
     *   { env }         — extra env vars for child process / container
     *   { movePlayer }  — function({ playerId, port }) for Dashboard integration
     *   { playerId }    — initial player to notify on ready
     *
     * @returns {Promise<{ sessionId, port, type: 'docker'|'fork' }>}
     */
    async startSession(input, opts = {}) {
        const port = this.portPool.acquire();
        if (!port) {
            throw new Error('No available ports for new game session');
        }

        const sessionId = ++sessionIdCounter;
        const useDocker = await this._ensureDockerReady();

        try {
            if (useDocker) {
                return await this._startDockerSession(sessionId, port, input, opts);
            } else {
                return await this._startForkSession(sessionId, port, input, opts);
            }
        } catch (err) {
            this.portPool.release(port);
            throw err;
        }
    }

    // -----------------------------------------------------------------------
    // Docker path
    // -----------------------------------------------------------------------
    async _startDockerSession(sessionId, port, input, opts) {
        let codePath;
        let squishVersion;
        let cleanupFn = null;
        let gameEntryRelative = null;

        if (input.code) {
            // Raw code from Studio — write to temp dir
            codePath = path.join(os.tmpdir(), `hg-session-${sessionId}`);
            fs.mkdirSync(codePath, { recursive: true });
            fs.writeFileSync(path.join(codePath, 'index.js'), input.code);
            squishVersion = detectSquishVersion(input.code);
            cleanupFn = () => {
                try { fs.rmSync(codePath, { recursive: true, force: true }); } catch (e) {}
            };
        } else if (input.gamePath) {
            // Local file path — mount a broad enough ancestor so that
            // relative requires (e.g. ../../common/util) resolve correctly.
            // We walk up from the game file to find the project root
            // (directory containing node_modules or package.json).
            const resolved = path.resolve(input.gamePath);
            codePath = this._findProjectRoot(resolved) || path.dirname(resolved);
            // Tell the container where the entry point is relative to the mount
            gameEntryRelative = path.relative(codePath, resolved);
            try {
                const GameClass = loadGameClassFromPath(resolved);
                squishVersion = (GameClass.metadata && GameClass.metadata().squishVersion) || DEFAULT_SQUISH_VERSION;
            } catch (err) {
                squishVersion = DEFAULT_SQUISH_VERSION;
            }
        } else if (input.versionId) {
            // Fetch from Forgejo
            const result = await fetchGameFromForgejo({
                forgejoUrl: this.forgejo.url,
                forgejoToken: this.forgejo.token,
                owner: input.owner,
                repo: input.repo,
                ref: input.ref,
            });
            codePath = path.dirname(result.entryPath);
            squishVersion = result.squishVersion;
            cleanupFn = result.cleanup;
        } else {
            throw new Error('startSession requires one of: code, gamePath, or versionId');
        }

        // Save data directory for this game
        const saveDataPath = path.join(this.saveDataRoot, `session-${sessionId}`);

        const { containerId } = await runGameContainer({
            codePath,
            port,
            squishVersion,
            saveDataPath,
            imageName: this.dockerImageName,
            gameEntryRelative,
        });

        const session = {
            id: sessionId,
            port,
            type: 'docker',
            containerId,
            squishVersion,
            cleanup: cleanupFn,
            _emptyTicks: 0,
        };

        this.sessions[sessionId] = session;
        this._startLifecycleMonitor(sessionId);

        this.log.info(`Session ${sessionId} started via Docker on port ${port} (container ${containerId.slice(0, 12)})`);

        if (opts.onReady) {
            this.log.info(`Session ${sessionId} waiting for port ${port} to become reachable...`);
            this._waitForPort(port, 15000).then(() => {
                this.log.info(`Session ${sessionId} port ${port} is reachable, calling onReady`);
                // Additional delay for Docker Desktop on macOS — the port mapping
                // through the Linux VM can briefly refuse connections after the
                // TCP check passes. The WebSocket upgrade needs the full stack ready.
                return this._waitForWebSocket(port, 10000);
            }).then(() => {
                this.log.info(`Session ${sessionId} WebSocket confirmed, calling onReady`);
                opts.onReady(session);
            }).catch((err) => {
                this.log.error(`Session ${sessionId} container never became ready: ${err.message}`);
            });
        }

        return { sessionId, port, type: 'docker' };
    }

    // -----------------------------------------------------------------------
    // Fork path (fallback when Docker is not available)
    // -----------------------------------------------------------------------
    async _startForkSession(sessionId, port, input, opts) {
        if (!this.childServerPath) {
            throw new Error('No childServerPath configured and Docker is not available');
        }

        let gamePath;
        let squishVersion;
        let cleanupFn = null;

        if (input.code) {
            const tmpDir = path.join(os.tmpdir(), `hg-session-${sessionId}`);
            fs.mkdirSync(tmpDir, { recursive: true });
            gamePath = path.join(tmpDir, 'index.js');
            fs.writeFileSync(gamePath, input.code);
            squishVersion = detectSquishVersion(input.code);
            cleanupFn = () => {
                try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
            };
        } else if (input.gamePath) {
            gamePath = path.resolve(input.gamePath);
            try {
                const GameClass = loadGameClassFromPath(gamePath);
                squishVersion = (GameClass.metadata && GameClass.metadata().squishVersion) || DEFAULT_SQUISH_VERSION;
            } catch (err) {
                squishVersion = DEFAULT_SQUISH_VERSION;
            }
        } else if (input.versionId) {
            const result = await fetchGameFromForgejo({
                forgejoUrl: this.forgejo.url,
                forgejoToken: this.forgejo.token,
                owner: input.owner,
                repo: input.repo,
                ref: input.ref,
            });
            gamePath = result.entryPath;
            squishVersion = result.squishVersion;
            cleanupFn = result.cleanup;
        } else {
            throw new Error('startSession requires one of: code, gamePath, or versionId');
        }

        const squishPkg = squishMap[squishVersion] || squishMap[DEFAULT_SQUISH_VERSION];

        return new Promise((resolve, reject) => {
            const env = Object.assign({}, process.env, {
                NODE_PATH: `${process.cwd()}${path.sep}node_modules`,
                SQUISH_PATH: squishPkg,
            }, opts.env || {});

            const child = fork(this.childServerPath, [], { env });

            child.send(JSON.stringify({
                key: input.gameKey || path.basename(gamePath, '.js'),
                squishVersion,
                gamePath,
                port,
                player: opts.playerId ? { id: opts.playerId } : undefined,
                username: this.username,
                certPath: this.certPath,
            }));

            const session = {
                id: sessionId,
                port,
                type: 'fork',
                child,
                squishVersion,
                cleanup: cleanupFn,
                gameKey: input.gameKey || null,
                gamePath,
                _emptyTicks: 0,
                requestCallbacks: {},
                _requestIdCounter: 0,
            };

            child.on('message', (thang) => {
                const msg = JSON.parse(thang);
                if (msg.success) {
                    this.sessions[sessionId] = session;
                    this._startLifecycleMonitor(sessionId);
                    this.log.info(`Session ${sessionId} started via fork() on port ${port}`);
                    resolve({ sessionId, port, type: 'fork' });

                    if (opts.onReady) opts.onReady(session);
                } else if (msg.requestId && session.requestCallbacks[msg.requestId]) {
                    session.requestCallbacks[msg.requestId](msg.payload);
                    delete session.requestCallbacks[msg.requestId];
                }
            });

            child.on('error', (err) => {
                this.log.error(`Session ${sessionId} fork error: ${err.message}`);
                this._cleanupSession(sessionId);
                reject(err);
            });

            child.on('close', () => {
                this.log.info(`Session ${sessionId} fork closed`);
                this._cleanupSession(sessionId);
            });
        });
    }

    // -----------------------------------------------------------------------
    // Find the project root (nearest ancestor with node_modules or package.json)
    // so we mount enough of the tree for relative requires to work.
    // -----------------------------------------------------------------------
    _findProjectRoot(filePath) {
        let dir = path.dirname(filePath);
        const root = path.parse(dir).root;

        while (dir !== root) {
            if (fs.existsSync(path.join(dir, 'node_modules')) || fs.existsSync(path.join(dir, 'package.json'))) {
                return dir;
            }
            dir = path.dirname(dir);
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Wait for a port to become reachable (container startup)
    // -----------------------------------------------------------------------
    _waitForPort(port, timeoutMs = 15000) {
        const net = require('net');
        const start = Date.now();
        const interval = 500;

        return new Promise((resolve, reject) => {
            const check = () => {
                if (Date.now() - start > timeoutMs) {
                    return reject(new Error(`Port ${port} not reachable after ${timeoutMs}ms`));
                }

                const socket = new net.Socket();
                socket.setTimeout(1000);
                socket.once('connect', () => {
                    socket.destroy();
                    resolve();
                });
                socket.once('error', () => {
                    socket.destroy();
                    setTimeout(check, interval);
                });
                socket.once('timeout', () => {
                    socket.destroy();
                    setTimeout(check, interval);
                });
                socket.connect(port, '127.0.0.1');
            };
            check();
        });
    }

    _waitForWebSocket(port, timeoutMs = 10000) {
        const WebSocket = require('ws');
        const start = Date.now();
        const interval = 500;

        return new Promise((resolve, reject) => {
            const attempt = () => {
                if (Date.now() - start > timeoutMs) {
                    return reject(new Error(`WebSocket on port ${port} not ready after ${timeoutMs}ms`));
                }

                const ws = new WebSocket(`ws://127.0.0.1:${port}`);
                ws.once('open', () => {
                    ws.close();
                    resolve();
                });
                ws.once('error', () => {
                    ws.close();
                    setTimeout(attempt, interval);
                });
            };
            attempt();
        });
    }

    // -----------------------------------------------------------------------
    // Lifecycle monitor — kill sessions with no players after grace period
    // -----------------------------------------------------------------------
    _startLifecycleMonitor(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) return;

        session._lifecycleInterval = setInterval(() => {
            const s = this.sessions[sessionId];
            if (!s) {
                clearInterval(session._lifecycleInterval);
                return;
            }

            if (s.type === 'docker') {
                const running = isContainerRunning(s.containerId);
                this.log.info(`Session ${sessionId} lifecycle check: container running = ${running}`);
                if (!running) {
                    this.log.info(`Session ${sessionId} container exited`);
                    this._cleanupSession(sessionId);
                }
            } else if (s.type === 'fork') {
                // For fork sessions, send heartbeat. The child_game_server.js
                // already has its own checkPulse logic.
                try {
                    s.child.send(JSON.stringify({ type: 'heartbeat' }));
                } catch (err) {
                    // Child already dead
                    this._cleanupSession(sessionId);
                }
            }
        }, this.lifecycleCheckMs);
    }

    // -----------------------------------------------------------------------
    // Stop a session
    // -----------------------------------------------------------------------
    async stopSession(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) return;

        if (session.type === 'docker') {
            await stopContainer(session.containerId);
        } else if (session.type === 'fork') {
            try { session.child.kill(); } catch (e) {}
        }

        this._cleanupSession(sessionId);
    }

    _cleanupSession(sessionId) {
        const session = this.sessions[sessionId];
        if (!session) return;

        if (session._lifecycleInterval) {
            clearInterval(session._lifecycleInterval);
        }

        this.portPool.release(session.port);

        if (session.cleanup) {
            session.cleanup();
        }

        delete this.sessions[sessionId];
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    getSession(sessionId) {
        return this.sessions[sessionId] || null;
    }

    findSessionByPort(port) {
        for (const id in this.sessions) {
            if (this.sessions[id].port === port) return this.sessions[id];
        }
        return null;
    }

    findSessionsByGame(gameKey) {
        return Object.values(this.sessions).filter(s => s.gameKey === gameKey);
    }

    listSessions() {
        return Object.values(this.sessions).map(s => ({
            id: s.id,
            port: s.port,
            type: s.type,
            squishVersion: s.squishVersion,
            gameKey: s.gameKey || null,
        }));
    }

    /**
     * Send a message to a forked child session (no-op for Docker sessions).
     */
    sendToSession(sessionId, msg) {
        const session = this.sessions[sessionId];
        if (session && session.type === 'fork' && session.child) {
            session.child.send(JSON.stringify(msg));
        }
    }

    /**
     * Request data from a forked child session (e.g., getPlayers).
     */
    requestFromSession(sessionId, apiName) {
        return new Promise((resolve, reject) => {
            const session = this.sessions[sessionId];
            if (!session || session.type !== 'fork') {
                resolve(null);
                return;
            }
            const requestId = ++session._requestIdCounter;
            session.requestCallbacks[requestId] = resolve;
            session.child.send(JSON.stringify({ api: apiName, requestId }));

            // Timeout after 5 seconds
            setTimeout(() => {
                if (session.requestCallbacks[requestId]) {
                    delete session.requestCallbacks[requestId];
                    resolve(null);
                }
            }, 5000);
        });
    }
}

module.exports = GameSessionManager;
