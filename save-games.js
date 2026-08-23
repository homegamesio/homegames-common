/**
 * Save games — one game-facing contract, multiple platform backends.
 *
 * Games opt in by accepting `saveGame(data) => Promise` and `saveData`
 * (parsed JSON or undefined) in their constructor option bag. Games decide
 * WHEN to save; the platform decides WHERE the blob goes:
 *
 *   - File backend (SAVE_FILES_ENABLED, the default): the host persists one
 *     save per game+version under <saveDataRoot>/<gameKey>/<versionId>/save.json.
 *     At launch, the newest compatible save is resolved: the game's own
 *     version first, then each entry of metadata().saveCompatibility in order.
 *
 *   - Broadcast backend (SAVE_FILES_ENABLED=false, e.g. a public instance
 *     whose maintainer doesn't want player data on disk): the host persists
 *     nothing. Each save is pushed to every connected client as a binary
 *     frame (SAVE_PUSH_OPCODE) for the browser to keep. At session creation
 *     the platform asks the creating client for its copy (SAVE_REQUEST_OPCODE)
 *     and injects it as saveData — construction-time injection is what keeps
 *     mid-session joiners from replacing a running game's state.
 *
 * Every saveGame call is validated (JSON-serializable, size-capped) and
 * debounced: calls inside the interval coalesce, last write wins, and all
 * coalesced callers resolve when the batched write lands. This is the
 * platform's defense against a game calling saveGame every tick — critical
 * for the broadcast backend, where each flush hits every client's socket.
 *
 * Save files are envelopes, not bare blobs, so pickers/clients can show
 * something meaningful without understanding game data:
 *   { gameKey, versionId, savedAt, data }
 */

const fs = require('fs');
const path = require('path');

// Hard cap on JSON.stringify(data) — a save is game state, not an asset store.
const MAX_SAVE_DATA_BYTES = 1024 * 1024;

// Minimum ms between actual writes/broadcasts. Disk writes are cheap; client
// broadcasts fan out to every connected socket, so they get a longer floor.
const FILE_SAVE_INTERVAL_MS = 1000;
const BROADCAST_SAVE_INTERVAL_MS = 3000;

// Server -> client binary opcodes (first byte of the frame, payload is UTF-8
// JSON). Mirrored in homegames-client — keep them in sync.
const SAVE_PUSH_OPCODE = 10;    // payload: save envelope
const SAVE_REQUEST_OPCODE = 11; // payload: { gameKey }; client answers with
                                // a { type: 'saveData', gameKey, save } input

// Version id used for built-in/local games that have no published versions.
const DEFAULT_VERSION_ID = 'local-game-version';

const SAVE_FILE_NAME = 'save.json';

// ---------------------------------------------------------------------------
// Keys and validation
// ---------------------------------------------------------------------------

// Game keys and version ids come from metadata/catalog data and become
// directory names — restrict to a filesystem-safe charset and refuse
// anything that could escape the save root.
const sanitizeSaveKey = (key) => {
    const cleaned = String(key == null ? '' : key)
        .replace(/[^a-zA-Z0-9._-]/g, '_')
        .slice(0, 100);
    if (!cleaned || /^\.+$/.test(cleaned)) {
        return '_' + (cleaned || 'unknown');
    }
    return cleaned;
};

// JSON-round-trip the game's data (rejects circular structures and functions)
// and enforce the size cap. Returns the JSON string.
const serializeSaveData = (data) => {
    const json = JSON.stringify(data);
    if (json === undefined) {
        throw new Error('Save data must be JSON-serializable');
    }
    if (Buffer.byteLength(json, 'utf8') > MAX_SAVE_DATA_BYTES) {
        throw new Error(`Save data exceeds ${MAX_SAVE_DATA_BYTES} bytes`);
    }
    return json;
};

// Can a game at `versionId` (declaring `compatibility` with older versions)
// load this envelope?
const isCompatibleSave = (envelope, versionId, compatibility = []) => {
    if (!envelope || typeof envelope !== 'object' || envelope.data === undefined) return false;
    if (envelope.versionId === versionId) return true;
    return Array.isArray(compatibility) && compatibility.indexOf(envelope.versionId) !== -1;
};

// A client-supplied envelope is attacker-controlled: cap its size, require
// the envelope shape, and require version compatibility before the game
// ever sees it. Returns the inner data or undefined.
const extractClientSaveData = (envelope, { versionId, compatibility = [], log } = {}) => {
    if (!envelope || typeof envelope !== 'object') return undefined;
    try {
        serializeSaveData(envelope.data);
    } catch (err) {
        log && log.error && log.error(`Rejecting client save: ${err.message}`);
        return undefined;
    }
    if (!isCompatibleSave(envelope, versionId, compatibility)) {
        log && log.info && log.info(`Rejecting client save for version ${envelope.versionId} (running ${versionId})`);
        return undefined;
    }
    return envelope.data;
};

// ---------------------------------------------------------------------------
// Debounced writer
// ---------------------------------------------------------------------------

// Coalesce a burst of saves into one write: the first call after a quiet
// period flushes almost immediately; calls landing while a flush is pending
// (or inside the interval) replace the pending data and share its outcome.
const createDebouncedWriter = ({ intervalMs, write }) => {
    let lastWrite = 0;
    let pending = null;

    const flush = () => {
        const batch = pending;
        pending = null;
        lastWrite = Date.now();
        Promise.resolve()
            .then(() => write(batch.value))
            .then(() => batch.resolvers.forEach(resolve => resolve()))
            .catch(err => batch.rejecters.forEach(reject => reject(err)));
    };

    return (value) => new Promise((resolve, reject) => {
        if (pending) {
            pending.value = value;
            pending.resolvers.push(resolve);
            pending.rejecters.push(reject);
            return;
        }
        pending = { value, resolvers: [resolve], rejecters: [reject] };
        const delay = Math.max(0, intervalMs - (Date.now() - lastWrite));
        setTimeout(flush, delay);
    });
};

// ---------------------------------------------------------------------------
// saveGame factories
// ---------------------------------------------------------------------------

const createSaveGame = ({ gameKey, versionId, intervalMs, write }) => {
    const debounced = createDebouncedWriter({ intervalMs, write });
    return (data) => {
        let cleaned;
        try {
            cleaned = JSON.parse(serializeSaveData(data));
        } catch (err) {
            return Promise.reject(err);
        }
        return debounced({ gameKey, versionId, savedAt: Date.now(), data: cleaned });
    };
};

const saveFilePath = (gameDir, versionId) =>
    path.join(gameDir, sanitizeSaveKey(versionId), SAVE_FILE_NAME);

// File backend: atomic (tmp + rename) envelope writes under the game's dir.
const createFileSaveGame = ({ gameDir, gameKey, versionId, intervalMs = FILE_SAVE_INTERVAL_MS, log }) => {
    const write = (envelope) => {
        const file = saveFilePath(gameDir, versionId);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        const tmp = file + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(envelope));
        fs.renameSync(tmp, file);
        log && log.info && log.info(`Saved game data for ${gameKey}@${versionId}`);
    };
    return createSaveGame({ gameKey, versionId, intervalMs, write });
};

// Broadcast backend: nothing touches disk; the envelope goes to every
// connected client on flush. getSession is lazy because the game (and its
// first saveGame call) can exist before the GameSession does. The promise
// resolves on flush, not on per-client acks — delivery is best-effort by
// design, and with no clients connected the flush is a no-op.
const createBroadcastSaveGame = ({ getSession, gameKey, versionId, intervalMs = BROADCAST_SAVE_INTERVAL_MS, log }) => {
    const write = (envelope) => {
        const session = getSession && getSession();
        if (session && typeof session.broadcastSaveData === 'function') {
            session.broadcastSaveData(envelope);
            log && log.info && log.info(`Broadcast save data for ${gameKey}@${versionId}`);
        }
    };
    return createSaveGame({ gameKey, versionId, intervalMs, write });
};

// ---------------------------------------------------------------------------
// Load path
// ---------------------------------------------------------------------------

// Resolve the save a launching game should receive: its own version's save
// first, then each declared-compatible previous version in order. Returns
// the envelope's inner data, or undefined.
const resolveSaveData = ({ gameDir, versionId, compatibility = [], log }) => {
    const candidates = [versionId, ...compatibility].filter(
        (v, i, arr) => v && arr.indexOf(v) === i
    );
    for (const candidate of candidates) {
        const file = saveFilePath(gameDir, candidate);
        if (!fs.existsSync(file)) continue;
        try {
            const envelope = JSON.parse(fs.readFileSync(file, 'utf8'));
            if (envelope && envelope.data !== undefined) {
                log && log.info && log.info(`Loaded save data from ${file}`);
                return envelope.data;
            }
        } catch (err) {
            log && log.error && log.error(`Unreadable save file ${file}: ${err.message}`);
        }
    }
    return undefined;
};

module.exports = {
    MAX_SAVE_DATA_BYTES,
    FILE_SAVE_INTERVAL_MS,
    BROADCAST_SAVE_INTERVAL_MS,
    SAVE_PUSH_OPCODE,
    SAVE_REQUEST_OPCODE,
    DEFAULT_VERSION_ID,
    sanitizeSaveKey,
    serializeSaveData,
    isCompatibleSave,
    extractClientSaveData,
    createDebouncedWriter,
    createFileSaveGame,
    createBroadcastSaveGame,
    resolveSaveData,
    saveFilePath,
};
