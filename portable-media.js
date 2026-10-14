'use strict';
const { describeMedia } = require('./media-upload');

// Authored game assets include fonts and static SVGs already understood by
// the Homegames renderer. This does not expand the player-upload API.
function describeAsset(bytes, path) {
    const media = describeMedia(bytes, { fileName: path });
    if (media.kind) return media;
    const signature = String.fromCharCode(...bytes.subarray(0, 4));
    const fonts = { wOFF: 'font/woff', wOF2: 'font/woff2', OTTO: 'font/otf', '\u0000\u0001\u0000\u0000': 'font/ttf' };
    if (bytes.length >= 12 && fonts[signature]) return { kind: 'font', contentType: fonts[signature] };
    const source = new TextDecoder().decode(bytes);
    if (/^\s*(?:<\?xml\b[^?]*\?>\s*)?<svg\b/i.test(source) && /<\/svg>\s*$/i.test(source)
        && !/<(?:[\w-]+:)?(?:script|foreignObject|style|animate\w*|set)\b|<!DOCTYPE|<!ENTITY|\bon[\w-]+\s*=/i.test(source)
        && !/\b(?:href|src)\s*=\s*(?!["']#)["']/i.test(source)
        && !/url\s*\(\s*(?!["']?#[\w-]+["']?\s*\))/i.test(source)) {
        return { kind: 'image', contentType: 'image/svg+xml' };
    }
    return media;
}

function validateAsset(info, data) {
    if (!info || !['image', 'audio', 'video', 'font'].includes(info.type)
        || !(data instanceof Uint8Array) || !data.length || data.length > 10 * 1024 * 1024 - 44
        || describeAsset(data, info.path).kind !== info.type) throw new Error('Unsupported, invalid or oversized game asset');
}
module.exports = { describeAsset, validateAsset };
