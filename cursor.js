// Per-player cursor control stays separate from replaceable scene frames.
// This module is shared by Core and the browser runtime.
const CURSOR_OPCODE = 13;
const MAX_CURSOR_BYTES = 256;

const normalizeCursor = cursor => {
    if (cursor === null) return null;
    if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)
        || typeof cursor.assetKey !== 'string' || !/^[\x20-\x7e]{1,32}$/.test(cursor.assetKey)
        || !cursor.assetKey.trim()) {
        throw new TypeError('Cursor must be null or contain an ASCII assetKey of 1–32 characters');
    }
    const hotspot = cursor.hotspot === undefined ? { x: 0, y: 0 } : cursor.hotspot;
    if (!hotspot || typeof hotspot !== 'object' || Array.isArray(hotspot)
        || !Number.isInteger(hotspot.x) || hotspot.x < 0
        || !Number.isInteger(hotspot.y) || hotspot.y < 0) {
        throw new TypeError('Cursor hotspot must contain nonnegative integer x and y coordinates');
    }
    const normalized = { assetKey: cursor.assetKey, hotspot: { x: hotspot.x || 0, y: hotspot.y || 0 } };
    if (cursor.pointerLock !== undefined) {
        if (typeof cursor.pointerLock !== 'boolean') throw new TypeError('Cursor pointerLock must be a boolean');
        normalized.pointerLock = cursor.pointerLock;
    }
    if (cursor.size !== undefined) {
        const size = cursor.size;
        if (!size || typeof size !== 'object' || Array.isArray(size)
            || !Number.isInteger(size.width) || size.width < 1 || size.width > 128
            || !Number.isInteger(size.height) || size.height < 1 || size.height > 128) {
            throw new TypeError('Cursor size must contain integer width and height from 1 to 128');
        }
        normalized.size = { width: size.width, height: size.height };
    }
    return normalized;
};

const encodeCursor = cursor => {
    const payload = new TextEncoder().encode(JSON.stringify(normalizeCursor(cursor)));
    const packet = new Uint8Array(payload.length + 1);
    packet[0] = CURSOR_OPCODE;
    packet.set(payload, 1);
    return packet;
};

const decodeCursor = packet => {
    const bytes = packet instanceof ArrayBuffer ? new Uint8Array(packet)
        : ArrayBuffer.isView(packet) ? new Uint8Array(packet.buffer, packet.byteOffset, packet.byteLength) : null;
    if (!bytes || bytes.length < 2 || bytes.length > MAX_CURSOR_BYTES || bytes[0] !== CURSOR_OPCODE) {
        throw new TypeError('Invalid cursor packet');
    }
    try {
        return normalizeCursor(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(1))));
    } catch (error) {
        throw new TypeError('Invalid cursor packet: ' + error.message);
    }
};

module.exports = { CURSOR_OPCODE, normalizeCursor, encodeCursor, decodeCursor };
