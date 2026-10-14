// Game-facing input semantics shared by hosted and local sessions. Transport,
// membership checks and platform messages stay in the session adapters. Hooks
// supply framed layers, node lookup and coordinate transforms without DOM,
// WebSocket or home-server dependencies in this module.
const MAX_FILE_INPUT_BYTES = 8 * 1024 * 1024;
const GameInput = require('./game-input');

const decodeFileInput = (raw, useBuffer = false) => {
    if (typeof raw === 'string') {
        let binary;
        if (!useBuffer && typeof atob === 'function') {
            binary = atob(raw);
            if (binary.length === 0 || binary.length > MAX_FILE_INPUT_BYTES) return null;
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
            return bytes;
        }
        const buf = Buffer.from(raw, 'base64');
        if (buf.length === 0 || buf.length > MAX_FILE_INPUT_BYTES) return null;
        return buf;
    }
    if (raw && typeof raw === 'object') {
        const bytes = Object.values(raw);
        if (bytes.length === 0 || bytes.length > MAX_FILE_INPUT_BYTES) return null;
        return useBuffer ? Buffer.from(bytes) : Uint8Array.from(bytes);
    }
    return null;
};

const { describeMedia } = require('./media-upload');
const buildFileMeta = (bytes, input) => {
    const media = describeMedia(bytes, input);
    // Preserve the callback's reported MIME for existing games. Classification
    // recognizes container formats separately from their audio/video hints.
    const contentType = typeof input.contentType === 'string' && input.contentType.length <= 100 ? input.contentType : null;
    return { ...media, contentType };
};

class GameDispatcher {
    constructor(game, opts = {}) {
        this.game = game;
        this.gameInput = new GameInput(game);
        this._activePresses = {};
        this.getLayers = opts.getLayers || (() => game.getLayers());
        this.findNode = opts.findNode || (id => game.findNode(id));
        this.findPointerNode = opts.findPointerNode || this.findNode;
        this.toGameCoords = opts.toGameCoords || ((x, y) => ({ x, y }));
        this.fileBuffers = !!opts.fileBuffers;
    }

    handleInput(playerId, input) {
        if (!input || typeof input !== 'object' || typeof input.type !== 'string') return;

        const pid = Number(playerId);

        try {
            if (input.type === 'click') {
                const data = input.data;
                if (!data || typeof data.x !== 'number' || typeof data.y !== 'number') return;
                this._handleClick(pid, data);
            } else if (input.type === 'keydown') {
                if (typeof input.key !== 'string' || input.key.length > 20) return;
                this.gameInput.keyDown(pid, input.key);
            } else if (input.type === 'keyup') {
                if (typeof input.key !== 'string' || input.key.length > 20) return;
                this.gameInput.keyUp(pid, input.key);
            } else if (input.type === 'mouseup') {
                this.game.handleMouseUp && this.game.handleMouseUp(pid, input.data);
                this.endPress(pid, input.data);
            } else if (input.type === 'mousemove') {
                // Only sent while the pointer/finger is held down — drives
                // drag handlers (game.handleMouseMove + pressed node's onDrag)
                this._handleDragMove(pid, input.data);
            } else if (input.type === 'pointermove') {
                // Pointer Lock sends relative mouse motion without a held
                // button. Keep it separate from absolute, scaled drag input.
                const delta = input.data;
                if (!delta || !Number.isFinite(delta.dx) || !Number.isFinite(delta.dy)
                    || Math.abs(delta.dx) > 4096 || Math.abs(delta.dy) > 4096) return;
                this.game.handlePointerMove?.(pid, { dx: delta.dx, dy: delta.dy });
            } else if (input.type === 'input') {
                if (input.gamepad) {
                    this.gameInput.gamepad(pid, input);
                } else {
                    const node = this.findNode(input.nodeId);
                    if (node && node.node && node.node.input) {
                        if (node.node.input.type === 'file') {
                            const fileBytes = decodeFileInput(input.input, this.fileBuffers);
                            if (fileBytes) node.node.input.oninput(pid, fileBytes, buildFileMeta(fileBytes, input));
                        } else {
                            node.node.input.oninput(pid, input.input);
                        }
                    }
                }
            } else if (input.type === 'onhover') {
                const node = this.findNode(input.nodeId);
                if (node && node.node && node.node.onHover) node.node.onHover(pid);
            } else if (input.type === 'offhover') {
                const node = this.findNode(input.nodeId);
                if (node && node.node && node.node.offHover) node.node.offHover(pid);
            }
        } catch (e) {
            console.error(`[GameDispatcher] Error handling input type="${input.type}":`, e);
        }
    }

    // --- Private: click / hit-testing ---

    _handleClick(playerId, click) {
        if (!click || typeof click.x !== 'number' || typeof click.y !== 'number') return;
        if (click.x < 0 || click.y < 0 || click.x >= 100 || click.y >= 100) return;

        const existingPress = this._activePresses[playerId];
        // Current clients mark the first click of a physical press with
        // press: true and re-send plain clicks while held. Legacy clients
        // send no flag at all — for them, a click with no open press starts
        // one. Either way, held re-sends drive the drag handlers here while
        // handleClick below still re-fires under the pointer (the
        // repeated-click contract existing games are built on).
        const isNewPress = !existingPress || click.press === true;

        if (existingPress && click.press === true) {
            // The previous release never reached us (blur, off-canvas
            // release) — close the stale press out before starting this one.
            this.endPress(playerId, null);
        } else if (existingPress && !isNewPress) {
            this._handleDragMove(playerId, click);
        }

        const clickedNode = this._findClick(click.x, click.y, playerId);
        const realNode = clickedNode ? this.findPointerNode(clickedNode.id) : null;

        if (isNewPress) {
            this._activePresses[playerId] = {
                node: (realNode && realNode.node) || null,
                x: click.x,
                y: click.y,
            };
        }

        if (realNode && realNode.node && realNode.node.handleClick) {
            const { x, y } = this.toGameCoords(click.x, click.y);
            realNode.node.handleClick(playerId, x, y);
        }
    }

    // A held pointer moved (mousemove input, or a client's repeated click
    // while held). Updates the press position and fires the drag handlers.
    _handleDragMove(playerId, move) {
        if (!move || typeof move.x !== 'number' || typeof move.y !== 'number') return;
        if (move.x < 0 || move.y < 0 || move.x >= 100 || move.y >= 100) return;

        const press = this._activePresses[playerId];
        if (press) {
            press.x = move.x;
            press.y = move.y;
        }

        const { x, y } = this.toGameCoords(move.x, move.y);
        try {
            this.game.handleMouseMove && this.game.handleMouseMove(playerId, { x, y });
        } catch (e) {
            console.error('[GameDispatcher] game.handleMouseMove threw:', e);
        }

        if (press && press.node && typeof press.node.onDrag === 'function') {
            try {
                press.node.onDrag(playerId, x, y);
            } catch (e) {
                console.error('[GameDispatcher] node.onDrag threw:', e);
            }
        }
    }

    // End the active press, firing the pressed node's offClick with the
    // release point. release may be null (stale press, node removal) — the
    // last known drag position is used instead.
    endPress(playerId, release) {
        const press = this._activePresses[playerId];
        if (!press) return;
        delete this._activePresses[playerId];

        if (press.node && typeof press.node.offClick === 'function') {
            const hasCoords = release && typeof release.x === 'number' && typeof release.y === 'number';
            const raw = hasCoords ? release : { x: press.x, y: press.y };
            try {
                const { x, y } = this.toGameCoords(raw.x, raw.y);
                press.node.offClick(playerId, x, y);
            } catch (e) {
                console.error('[GameDispatcher] node.offClick threw:', e);
            }
        }
    }

    // Close a press if game logic removed its target from the scene.
    checkActivePresses(playerId) {
        if (playerId === undefined) {
            for (const id of Object.keys(this._activePresses)) this.checkActivePresses(id);
            return;
        }
        const press = this._activePresses[playerId];
        if (!press || !press.node) return;
        if (!this.findPointerNode(press.node.id)) this.endPress(playerId, null);
    }

    _findClick(x, y, playerId) {
        let clicked = null;
        for (const layer of this.getLayers(x, y, playerId)) {
            if (layer.interactive === false) continue;
            clicked = this._findClickHelper(x, y, playerId, layer.root.node, null,
                layer.scale || { x: 1, y: 1 }, 0) || clicked;
        }
        return clicked;
    }

    _findClickHelper(x, y, playerId, node, clicked, scale, depth) {
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
                    clicked = node;
                }
            }
        }

        if (node.children) {
            const childKeys = Object.keys(node.children);
            for (let i = 0; i < childKeys.length; i++) {
                const child = node.children[childKeys[i]];
                if (child && child.node) {
                    clicked = this._findClickHelper(x, y, playerId, child.node, clicked, scale, depth + 1);
                }
            }
        }

        return clicked;
    }
}

module.exports = GameDispatcher;
