// Game-facing control plane. Native streams and RTP transport belong to the
// browser adapters; this module only manages membership, handles and lifetime.
const { MAX_UPLOAD_BYTES, describeMedia } = require('./media-upload');
class MediaSession {
    constructor() { this.endpoints = new Map(); this.streams = new Map(); this.recordings = new Map(); this.listeners = new Set(); this.sequence = 0; }
    onChange(listener) { this.listeners.add(listener); return () => this.listeners.delete(listener); }
    notify(record, state) {
        const value = { ...record.info, state };
        for (const listener of this.listeners) { try { listener(value); } catch (err) { console.error(err); } }
    }
    join(playerId, endpoint) {
        this.endpoints.set(playerId, endpoint);
        for (const record of this.streams.values()) if (record.ready) this.deliver(record, playerId, endpoint);
    }
    request(playerId, options = {}) {
        const endpoint = this.endpoints.get(Number(playerId));
        if (!endpoint || this.closed || endpoint.live === false) return Promise.reject(new Error('This client connection does not support live media'));
        if (!options.audio && !options.video) return Promise.reject(new Error('Request audio or video'));
        if (this.recordings.has(Number(playerId)) || [...this.streams.values()].some(r => r.info.playerId === Number(playerId))) {
            return Promise.reject(new Error('Stop your current microphone/camera before enabling another'));
        }
        const id = `media-${++this.sequence}`;
        const info = { id, playerId: Number(playerId), audio: !!options.audio, video: !!options.video,
            transmitting: options.transmitting !== false, pushToTalk: !!options.pushToTalk };
        return new Promise((resolve, reject) => {
            const record = { info, resolve, reject };
            record.timer = setTimeout(() => this.stop(id, 'Microphone/camera permission timed out'), 60000);
            this.streams.set(id, record);
            endpoint.send({ type: 'media', action: 'request', stream: info });
        });
    }
    // Recorded clips use the reliable data channel, never live media tracks.
    // The game decides when to register the returned bytes as a shared asset.
    record(playerId, options = {}) {
        playerId = Number(playerId);
        const endpoint = this.endpoints.get(playerId);
        if (!endpoint || this.closed) return Promise.reject(new Error('This client connection does not support recording'));
        if (endpoint.recording === false) return Promise.reject(new Error('This player needs the updated Homegames client to record.'));
        if (this.recordings.has(playerId) || [...this.streams.values()].some(r => r.info.playerId === playerId)) {
            return Promise.reject(new Error('Stop your current microphone/camera before recording'));
        }
        const kind = options.kind === 'audio' ? 'audio' : 'video';
        if (kind === 'audio' && endpoint.audioRecording !== true) return Promise.reject(new Error('This client does not support audio recording. Choose an audio file instead.'));
        const durationSeconds = Math.min(30, Math.max(1, Number(options.durationSeconds) || 30));
        const maxBytes = Math.min(MAX_UPLOAD_BYTES, Math.max(128 * 1024, Math.floor(Number(options.maxBytes) || MAX_UPLOAD_BYTES)));
        const info = { id: `recording-${++this.sequence}`, kind, durationSeconds, maxBytes,
            prompt: String(options.prompt || '').slice(0, 120) };
        return new Promise((resolve, reject) => {
            const record = { info, resolve, reject };
            record.timer = setTimeout(() => this.cancelRecording(playerId, 'Recording timed out. Please try again.'), 180000);
            this.recordings.set(playerId, record);
            endpoint.send({ type: 'media', action: 'record', recording: info });
        });
    }
    cancelRecording(playerId, error = 'Recording cancelled') {
        const record = this.recordings.get(playerId);
        if (!record) return;
        this.recordings.delete(playerId); clearTimeout(record.timer);
        this.endpoints.get(playerId)?.send({ type: 'media', action: 'record-cancel', id: record.info.id });
        record.reject(new Error(error));
    }
    recordingResult(playerId, message) {
        const record = this.recordings.get(playerId);
        if (!record || record.info.id !== message.id) return;
        if (message.error) { this.cancelRecording(playerId, String(message.error).slice(0, 160)); return; }
        try {
            if (typeof message.data !== 'string' || !message.data.length
                || message.data.length > Math.ceil(record.info.maxBytes / 3) * 4
                || !/^[A-Za-z0-9+/]*={0,2}$/.test(message.data)) throw new Error('Invalid or oversized recording');
            const bytes = Buffer.from(message.data, 'base64');
            const meta = describeMedia(bytes, { contentType: message.contentType, fileName: message.fileName });
            if (!bytes.length || bytes.length > record.info.maxBytes || meta.kind !== record.info.kind) throw new Error('Recording must match the requested media kind and size limit');
            this.recordings.delete(playerId); clearTimeout(record.timer);
            record.resolve({ bytes, meta, durationSeconds: record.info.durationSeconds });
        } catch (error) { this.cancelRecording(playerId, error.message); }
    }
    handle(playerId, message) {
        if (message.action === 'record-result') { this.recordingResult(playerId, message); return; }
        const record = this.streams.get(message.id);
        if (!record || record.info.playerId !== playerId) return;
        if (message.action === 'result' && !record.ready) {
            if (message.error) { this.stop(message.id, String(message.error).slice(0, 160)); return; }
            if (typeof message.sourceId !== 'string' || message.sourceId.length > 128) return;
            clearTimeout(record.timer); record.ready = true; record.info.sourceId = message.sourceId;
            record.resolve({ ...record.info }); record.resolve = record.reject = null;
            for (const [id, endpoint] of this.endpoints) this.deliver(record, id, endpoint);
            this.notify(record, 'ready');
        } else if (message.action === 'stopped') this.stop(message.id);
        else if (message.action === 'released') this.setTransmitting(message.id, false);
    }
    attach(playerId, stream) {
        const record = [...this.streams.values()].find(r => r.ready && r.info.playerId === playerId && r.info.sourceId === stream.id);
        if (!record) return false;
        record.native = stream;
        for (const [id, endpoint] of this.endpoints) this.deliver(record, id, endpoint);
        return true;
    }
    deliver(record, id, endpoint) {
        endpoint.send({ type: 'media', action: 'available', stream: { ...record.info } });
        if (record.native && id !== record.info.playerId) endpoint.addMedia(record.info.id, record.native);
    }
    setTransmitting(id, transmitting) {
        const record = this.streams.get(id);
        if (!record?.ready || record.info.transmitting === !!transmitting) return;
        record.info.transmitting = !!transmitting;
        for (const endpoint of this.endpoints.values()) endpoint.send({ type: 'media', action: 'state', stream: { ...record.info } });
        this.notify(record, 'changed');
    }
    stop(id, error = 'Stream stopped') {
        const record = this.streams.get(id);
        if (!record) return;
        this.streams.delete(id); clearTimeout(record.timer); record.reject?.(new Error(error));
        for (const endpoint of this.endpoints.values()) {
            endpoint.send({ type: 'media', action: 'ended', id }); endpoint.removeMedia(id);
        }
        this.notify(record, 'ended');
    }
    leave(playerId) {
        this.cancelRecording(playerId, 'The player left');
        for (const [id, record] of this.streams) if (record.info.playerId === playerId) this.stop(id, 'The player left');
        this.endpoints.delete(playerId);
    }
    destroy() {
        if (this.closed) return;
        this.closed = true;
        for (const id of [...this.recordings.keys()]) this.cancelRecording(id, 'The session ended');
        for (const id of [...this.streams.keys()]) this.stop(id, 'The session ended');
        this.endpoints.clear(); this.listeners.clear();
    }
}
module.exports = MediaSession;
