'use strict';
// Homegames session protocol. No DOM, browser storage or RTC dependency.
// Client -> host: JSON {type:'project-transfer', action:'request'|'ack'|'cancel', id, offset?, kind?, name?}.
// Requests default to a project archive; export-list returns name/size metadata,
// while export returns the original bytes for one name, including empty files.
// Host -> client: opcode 14 + UTF-8 JSON control; opcode 15 + u32 id + u32 offset + bytes.
// One acknowledged 64 KiB chunk at a time, interleaved with normal Squish frames.
const { exportArchive, LIMITS } = require('./portable-project');
const { validateName, LIMITS: EXPORT_LIMITS } = require('./user-exports');
const CONTROL = 14, CHUNK = 15, CHUNK_BYTES = 64 * 1024;
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', { fatal: true });
const validId = id => Number.isInteger(id) && id > 0 && id <= 0xffffffff;
function control(value) { const json = encoder.encode(JSON.stringify(value)), packet = new Uint8Array(1 + json.length); packet[0] = CONTROL; packet.set(json, 1); return packet; }
class ProjectTransferHost {
    constructor({ exportProject, listExports, readExport, timeoutMs = 30000 }) { Object.assign(this, { exportProject, listExports, readExport, timeoutMs }); this.transfers = new Map(); this.closed = false; }
    async handle(playerId, message, send) {
        if (this.closed || message?.type !== 'project-transfer' || !validId(message.id)) return;
        const current = this.transfers.get(playerId);
        const error = text => send(control({ action: 'error', id: message.id, message: text }));
        if (message.action === 'cancel') { if (current?.id === message.id) this.leave(playerId); return; }
        if (message.action === 'request') {
            if (current || this.transfers.size >= 4) { error('A file transfer is already in progress. Try again shortly.'); return; }
            const transfer = { id: message.id, offset: 0, send }; this.transfers.set(playerId, transfer); this.touch(playerId, transfer);
            try {
                let bytes, metadata;
                const kind = message.kind || 'project';
                if (kind === 'export-list') {
                    if (!this.listExports) throw new Error('This host does not support viewing exports');
                    const files = await this.listExports(playerId);
                    if (this.closed || this.transfers.get(playerId) !== transfer) return;
                    this.leave(playerId); send(control({ action: 'exports', id: transfer.id, files })); return;
                } else if (kind === 'export') {
                    validateName(message.name);
                    if (!this.readExport) throw new Error('This host does not support viewing exports');
                    bytes = await this.readExport(playerId, message.name);
                    if (!(bytes instanceof Uint8Array) || bytes.length > EXPORT_LIMITS.fileBytes) throw new Error('Invalid export');
                    metadata = { kind, name: message.name };
                } else if (kind === 'project') {
                    const project = await this.exportProject(playerId); bytes = await exportArchive(project);
                    metadata = { gameId: project.manifest.gameId, revision: project.revision, name: String(project.metadata.name || 'Game').slice(0, 200) };
                } else throw new Error('Unknown file request');
                if (this.closed || this.transfers.get(playerId) !== transfer) return;
                transfer.bytes = bytes;
                send(control({ action: 'offer', id: transfer.id, bytes: bytes.length, ...metadata }));
            } catch (e) { if (this.transfers.get(playerId) === transfer) { this.leave(playerId); error(String(e.message).slice(0, 200)); } }
            return;
        }
        if (message.action !== 'ack' || !current || current.id !== message.id) return;
        if (!current.bytes || message.offset !== current.offset) { this.leave(playerId); error('Invalid game-copy acknowledgement'); return; }
        this.touch(playerId, current);
        if (current.offset === current.bytes.length) { this.leave(playerId); send(control({ action: 'complete', id: current.id })); return; }
        const end = Math.min(current.offset + CHUNK_BYTES, current.bytes.length), packet = new Uint8Array(9 + end - current.offset);
        packet[0] = CHUNK; const view = new DataView(packet.buffer); view.setUint32(1, current.id); view.setUint32(5, current.offset);
        packet.set(current.bytes.subarray(current.offset, end), 9); current.offset = end; send(packet);
    }
    touch(id, transfer) { clearTimeout(transfer.timer); transfer.timer = setTimeout(() => { if (this.transfers.get(id) === transfer) { this.leave(id); transfer.send(control({ action: 'error', id: transfer.id, message: 'Game-copy transfer timed out' })); } }, this.timeoutMs); }
    leave(id) { const value = this.transfers.get(id); if (value) clearTimeout(value.timer); this.transfers.delete(id); }
    close() { this.closed = true; for (const id of this.transfers.keys()) this.leave(id); }
}
class ProjectTransferClient {
    constructor({ send, importArchive, timeoutMs = 45000 }) { Object.assign(this, { send, importArchive, timeoutMs }); this.sequence = Math.floor(Math.random() * 0xffffff); }
    request({ kind = 'project', name } = {}) {
        if (this.closed) return Promise.reject(new Error('Session closed'));
        if (this.pending) return Promise.reject(new Error('A file transfer is already in progress'));
        if (!['project', 'export-list', 'export'].includes(kind)) return Promise.reject(new Error('Unknown file request'));
        if (kind === 'export') { try { validateName(name); } catch (error) { return Promise.reject(error); } }
        return new Promise((resolve, reject) => {
            const id = this.sequence = this.sequence % 0xffffffff + 1;
            this.pending = { id, resolve, reject, offset: 0, kind, name }; this.touch();
            try { this.send({ type: 'project-transfer', action: 'request', id, kind, name }); } catch (e) { this.fail(e); }
        });
    }
    touch() { const entry = this.pending; clearTimeout(entry.timer); entry.timer = setTimeout(() => this.fail(new Error('Game-copy request timed out. The host may not support exporting.')), this.timeoutMs); }
    async receive(value) {
        const entry = this.pending; if (!entry) return;
        const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        try {
            if (bytes[0] === CONTROL) {
                if (bytes.length > (entry.kind === 'export-list' ? 32768 : 4096)) throw new Error('Oversized file-transfer control');
                const message = JSON.parse(decoder.decode(bytes.subarray(1))); if (message.id !== entry.id) return;
                if (message.action === 'error') throw new Error(String(message.message).slice(0, 200));
                if (message.action === 'exports') {
                    if (entry.kind !== 'export-list' || !Array.isArray(message.files) || message.files.length > EXPORT_LIMITS.files) throw new Error('Invalid export list');
                    const seen = new Set(); let total = 0;
                    const files = message.files.map(file => {
                        validateName(file.name);
                        if (seen.has(file.name.toLowerCase()) || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > EXPORT_LIMITS.fileBytes || (total += file.size) > EXPORT_LIMITS.totalBytes) throw new Error('Invalid export list');
                        seen.add(file.name.toLowerCase()); return { name: file.name, size: file.size };
                    });
                    this.pending = null; clearTimeout(entry.timer); entry.resolve(files); return;
                }
                if (message.action === 'offer') {
                    const file = entry.kind === 'export';
                    if (entry.kind === 'export-list' || entry.bytes || !Number.isSafeInteger(message.bytes) || message.bytes < (file ? 0 : 1)
                        || message.bytes > (file ? EXPORT_LIMITS.fileBytes : LIMITS.archiveBytes)
                        || (file ? message.kind !== 'export' || message.name !== entry.name
                            : message.kind === 'export' || !/^[a-f0-9]{64}$/.test(message.revision) || typeof message.gameId !== 'string')) throw new Error('Invalid file-transfer offer');
                    entry.metadata = message; entry.bytes = new Uint8Array(message.bytes); this.touch();
                    this.send({ type: 'project-transfer', action: 'ack', id: entry.id, offset: 0 }); return;
                }
                if (message.action !== 'complete' || !entry.bytes || entry.offset !== entry.bytes.length || entry.validating) throw new Error('Incomplete game copy');
                entry.validating = true; this.touch();
                if (entry.kind === 'export') { this.pending = null; clearTimeout(entry.timer); entry.resolve({ name: entry.name, bytes: entry.bytes }); return; }
                const project = await this.importArchive(entry.bytes);
                if (this.pending !== entry) return;
                if (project.revision !== entry.metadata.revision || project.manifest.gameId !== entry.metadata.gameId) throw new Error('Game-copy identity changed');
                this.pending = null; clearTimeout(entry.timer); entry.resolve({ bytes: entry.bytes, project }); return;
            }
            if (bytes[0] !== CHUNK || bytes.length < 10) throw new Error('Invalid game-copy packet');
            const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); if (view.getUint32(1) !== entry.id) return;
            if (!entry.bytes || entry.validating || view.getUint32(5) !== entry.offset || bytes.length - 9 !== Math.min(CHUNK_BYTES, entry.bytes.length - entry.offset)) throw new Error('Invalid game-copy offset');
            entry.bytes.set(bytes.subarray(9), entry.offset); entry.offset += bytes.length - 9; this.touch();
            this.send({ type: 'project-transfer', action: 'ack', id: entry.id, offset: entry.offset });
        } catch (e) { if (this.pending === entry) this.fail(e); }
    }
    fail(error) { const entry = this.pending; if (!entry) return; this.pending = null; clearTimeout(entry.timer); try { this.send({ type: 'project-transfer', action: 'cancel', id: entry.id }); } catch (_) {} entry.reject(error); }
    close() { this.fail(new Error('Session closed')); this.closed = true; }
}
module.exports = { ProjectTransferHost, ProjectTransferClient, CONTROL, CHUNK, CHUNK_BYTES };
