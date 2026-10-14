/**
 * Local play shared primitives — dependency-free and browser-safe, so every
 * consumer runs the SAME implementation instead of a documented mirror:
 *
 *   - normalizePath / resolveInFiles: how a game's virtual file map is
 *     resolved. Used by homegames-client's game-loader (executing the map in
 *     the browser) and homegames-core's local-play (building the map from
 *     disk) — the builder and the executor must agree byte-for-byte.
 *   - packAssetBundle: the type-1 asset bundle format, byte-identical to
 *     squish's Squisher.initialize() packing. Used by the platform API and
 *     homegames-core (serving bundles) and homegames-client (Studio's
 *     in-browser preview).
 *
 * No Buffer, no fs, no acorn — this file is webpack-bundled into the browser
 * client as-is. Node consumers can pass Buffers anywhere a Uint8Array is
 * expected (Buffer is a Uint8Array).
 */

// Collapse '.' and '..' segments: 'minigames/../weapons' -> 'weapons'.
// '..' at the root is a no-op, so paths that escape the map root fold back
// into it — the builder ships escaped files under these collapsed keys.
const normalizePath = (p) => {
    const parts = [];
    for (const seg of p.split('/')) {
        if (!seg || seg === '.') continue;
        if (seg === '..') parts.pop();
        else parts.push(seg);
    }
    return parts.join('/');
};

// Candidate order for resolving a require against a virtual file map:
// exact, then '.js', then '/index.js'.
const resolutionCandidates = (fromDir, request) => {
    const base = normalizePath(fromDir ? fromDir + '/' + request : request);
    return [base, base + '.js', base + '/index.js'];
};

// Resolve a require request within a virtual file map. Returns the matching
// key or null.
const resolveInFiles = (files, fromDir, request) => {
    for (const candidate of resolutionCandidates(fromDir, request)) {
        if (Object.prototype.hasOwnProperty.call(files, candidate)) return candidate;
    }
    return null;
};

// ---------------------------------------------------------------------------
// Type-1 asset bundle packing — must stay byte-identical to
// Squisher.initialize() in squish (src/Squisher.js): per asset a 44-byte
// header [1, typeByte, 10-byte base36 length of (data+32), 32-byte key] + data.
// ---------------------------------------------------------------------------

const ASSET_TYPE_BYTES = { image: 1, audio: 2, font: 3, video: 4 };

// Preserve complete Squish asset records while keeping RTC packets bounded.
// Concatenating these slices produces the original, unchanged wire bytes.
const splitAssetBundle = (bundle, maxBytes = 10 * 1024 * 1024) => {
    const packets = []; let start = 0, offset = 0;
    while (offset < bundle.length) {
        const encoded = String.fromCharCode(...bundle.subarray(offset + 2, offset + 12));
        const length = parseInt(encoded, 36) + 12;
        if (bundle[offset] !== 1 || !/^[0-9a-z]{10}$/.test(encoded) || length < 44 || offset + length > bundle.length) throw new Error('Invalid asset bundle');
        if (length > maxBytes) throw new Error('An asset exceeds the RTC packet limit');
        if (offset + length - start > maxBytes) { packets.push(bundle.subarray(start, offset)); start = offset; }
        offset += length;
    }
    if (offset > start) packets.push(bundle.subarray(start, offset));
    return packets;
};

/**
 * @param {Array<{key: string, type: string, data: Uint8Array}>} entries
 * @returns {Uint8Array}
 */
const packAssetBundle = (entries) => {
    const parts = entries.map(({ key, type, data }) => {
        const assetKeyLength = 32;
        const encodedMaxLength = 10;
        const headerLength = 2 + encodedMaxLength + assetKeyLength;
        const buf = new Uint8Array(headerLength + data.length);

        buf[0] = 1;
        buf[1] = ASSET_TYPE_BYTES[type] || ASSET_TYPE_BYTES.image;

        const encodedLength = (data.length + assetKeyLength).toString(36);
        const padLen = encodedMaxLength - encodedLength.length;
        for (let i = 0; i < padLen; i++) {
            buf[2 + i] = 48; // '0'
        }
        for (let i = 0; i < encodedLength.length; i++) {
            buf[2 + padLen + i] = encodedLength.charCodeAt(i);
        }

        const keyWriteLen = Math.min(assetKeyLength, key.length);
        for (let i = 0; i < keyWriteLen; i++) {
            buf[2 + encodedMaxLength + i] = key.charCodeAt(i);
        }

        buf.set(data, headerLength);
        return buf;
    });

    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};

// Loading differs by host (project files, retained bytes or a legacy Asset),
// but the complete bundle and its per-key cache use this same encoder.
const assetReads = new WeakMap();
const loadAssetBundle = async (entries, readData, cache = Object.create(null)) => {
    if (!assetReads.has(cache)) assetReads.set(cache, new Map());
    const reads = assetReads.get(cache);
    const packets = await Promise.all(entries.map(async entry => {
        if (!Object.prototype.hasOwnProperty.call(cache, entry.key)) {
            const read = {};
            reads.set(entry.key, read);
            const data = await readData(entry);
            const packet = packAssetBundle([{ key: entry.key, type: entry.type, data }]);
            // A failed bundle may leave another file read in flight. A retry
            // can supersede it without letting its late result poison cache.
            if (reads.get(entry.key) === read) cache[entry.key] = packet;
            return packet;
        }
        return cache[entry.key];
    }));
    const bundle = new Uint8Array(packets.reduce((size, packet) => size + packet.length, 0));
    let offset = 0;
    for (const packet of packets) { bundle.set(packet, offset); offset += packet.length; }
    return bundle;
};

module.exports = { normalizePath, resolutionCandidates, resolveInFiles, packAssetBundle, splitAssetBundle, loadAssetBundle, ASSET_TYPE_BYTES };
