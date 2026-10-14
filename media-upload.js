// Browser-safe media classification and game-facing registration. Both session
// adapters supply the same helper; transport and file picking stay outside it.
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const ascii = (bytes, start, length) => String.fromCharCode(...bytes.subarray(start, start + length));
const describeMedia = (bytes, input = {}) => {
    const fileName = typeof input.fileName === 'string' ? input.fileName.slice(0, 128) : null;
    const hint = typeof input.contentType === 'string' ? input.contentType.toLowerCase().split(';')[0].slice(0, 100) : '';
    let kind = null, contentType = null;
    const set = (k, mime) => { kind = k; contentType = mime; };
    if (bytes.length >= 4 && bytes[0] === 0x89 && ascii(bytes, 1, 3) === 'PNG') set('image', 'image/png');
    else if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) set('image', 'image/jpeg');
    else if (ascii(bytes, 0, 3) === 'GIF') set('image', 'image/gif');
    else if (ascii(bytes, 0, 4) === 'RIFF') {
        const format = ascii(bytes, 8, 4);
        if (format === 'WEBP') set('image', 'image/webp');
        if (format === 'WAVE') set('audio', 'audio/wav');
        if (format === 'AVI ') set('video', 'video/x-msvideo');
    } else if (ascii(bytes, 0, 3) === 'ID3' || (bytes.length > 1 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0)) set('audio', 'audio/mpeg');
    else if (ascii(bytes, 0, 4) === 'fLaC') set('audio', 'audio/flac');
    else if (ascii(bytes, 0, 4) === 'OggS') {
        const video = hint === 'video/ogg' || /\.ogv$/i.test(fileName || '');
        set(video ? 'video' : 'audio', video ? 'video/ogg' : 'audio/ogg');
    } else if (bytes.length >= 4 && bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) {
        const audio = hint === 'audio/webm' || /\.weba$/i.test(fileName || '');
        set(audio ? 'audio' : 'video', audio ? 'audio/webm' : 'video/webm');
    } else if (bytes.length >= 12 && ascii(bytes, 4, 4) === 'ftyp') {
        const brand = ascii(bytes, 8, 4);
        if (['avif', 'avis'].includes(brand)) set('image', 'image/avif');
        else {
            // MP4/WebM/Ogg are containers: a MIME/name hint distinguishes
            // audio-only files. A shared container signature alone cannot.
            const audio = /^M4[ABP] /.test(brand) || hint.startsWith('audio/') || /\.(m4a|m4b)$/i.test(fileName || '');
            set(audio ? 'audio' : 'video', audio ? 'audio/mp4' : 'video/mp4');
        }
    }
    return { kind, contentType, fileName };
};

const createFileUploadHandler = ({ Asset, registerAsset, isPlayerActive }) => {
    let sequence = 0;
    const slots = new Map();
    return async (playerId, payload, metadata = {}, options = {}) => {
        if (!isPlayerActive(Number(playerId))) throw new Error('The uploading player has left the session');
        const data = payload instanceof ArrayBuffer ? new Uint8Array(payload)
            : ArrayBuffer.isView(payload) ? new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength) : null;
        if (!data?.length || data.length > MAX_UPLOAD_BYTES) throw new Error('Choose an image, audio file or video up to 5 MB');
        const media = describeMedia(data, metadata);
        if (!media.kind) throw new Error('That file is not a supported image, audio file or video');
        // Optional game-owned slots replace prior media for this player. Keep
        // options separate from file metadata supplied by a remote device.
        if (options.slot != null && (typeof options.slot !== 'string' || !/^[a-zA-Z0-9_-]{1,32}$/.test(options.slot))) {
            throw new Error('Invalid upload slot');
        }
        const slot = options.slot == null ? null : `${Number(playerId)}:${options.slot}`;
        const key = (slot && slots.get(slot)) || `upload-${++sequence}`;
        if (slot) slots.set(slot, key);
        const asset = new Asset({ id: key, type: media.kind, contentType: media.contentType, fileName: media.fileName }, data.slice());
        asset.key = key;
        await registerAsset(key, asset);
        return asset;
    };
};

module.exports = { MAX_UPLOAD_BYTES, describeMedia, createFileUploadHandler };
