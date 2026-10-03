// Private invitations only. The browser owns the game; this service relays
// SDP/ICE and ties room lifetime to its host's signaling socket.
const crypto = require('crypto');
const WebSocket = require('ws');
const { isIP } = require('net');

const id = () => crypto.randomBytes(18).toString('base64url');
const urls = value => (value || '').split(',').map(s => s.trim()).filter(Boolean);
const iceFromEnv = (env = process.env) => {
    const servers = [];
    // A STUN default also avoids relying exclusively on mDNS host candidates
    // on LANs where multicast is filtered. Override with your own service;
    // an explicitly empty value opts into direct candidates only.
    const stun = urls(env.RTC_STUN_URLS === undefined ? 'stun:stun.l.google.com:19302' : env.RTC_STUN_URLS);
    const turn = urls(env.RTC_TURN_URLS);
    if (stun.length) servers.push({ urls: stun });
    if (turn.length && env.RTC_TURN_SECRET) {
        const username = `${Math.floor(Date.now() / 1000) + 3600}:${id()}`;
        const credential = crypto.createHmac('sha1', env.RTC_TURN_SECRET).update(username).digest('base64');
        servers.push({ urls: turn, username, credential });
    }
    return servers;
};

const attachRtcSignaling = (server, { path = '/rtc', getIceServers = iceFromEnv,
    maxRooms = 1000, maxConnections = 4096, heartbeatMs = 15000, trustLoopbackProxy = false } = {}) => {
    const rooms = new Map();
    const wss = new WebSocket.Server({ noServer: true, maxPayload: 64 * 1024 });
    const send = (ws, data) => {
        if (ws.readyState !== WebSocket.OPEN) return;
        if (ws.bufferedAmount > 256 * 1024) { ws.terminate(); return; }
        ws.send(JSON.stringify(data));
    };
    const fail = (ws, message) => { send(ws, { type: 'error', message }); ws.close(1008); };
    const upgrade = (req, socket, head) => {
        if (req.url !== path) { socket.destroy(); return; }
        if (wss.clients.size >= maxConnections) { socket.destroy(); return; }
        wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
    };
    server.on('upgrade', upgrade);
    wss.on('connection', (ws, req) => {
        ws.alive = true;
        ws.ip = req.socket.remoteAddress;
        // The local nginx must overwrite X-Real-IP. Never trust this header
        // from a directly connected Internet client (or a non-loopback proxy).
        if (trustLoopbackProxy && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(ws.ip)
            && typeof req.headers['x-real-ip'] === 'string' && isIP(req.headers['x-real-ip'])) {
            ws.ip = req.headers['x-real-ip'];
        }
        ws.on('pong', () => { ws.alive = true; });
        ws.on('error', () => {});
        const registration = setTimeout(() => { if (!ws.room) ws.close(1008); }, 10000);
        registration.unref?.();
        let windowAt = Date.now(), count = 0;
        ws.on('message', raw => {
            if (Date.now() - windowAt > 1000) { windowAt = Date.now(); count = 0; }
            if (++count > 100) return fail(ws, 'Too many signaling messages');
            let msg;
            try { msg = JSON.parse(raw); } catch (_) { return fail(ws, 'Invalid signaling message'); }
            if (!msg || typeof msg !== 'object') return fail(ws, 'Invalid signaling message');
            if (!ws.room) {
                if (msg.type === 'create') {
                    const owned = [...rooms.values()].filter(r => r.host.ip === ws.ip).length;
                    if (rooms.size >= maxRooms || owned >= 20) return fail(ws, 'Room limit reached');
                    const room = { id: id(), invite: id(), host: ws, peers: new Map() };
                    rooms.set(room.id, room); ws.room = room;
                    send(ws, { type: 'created', roomId: room.id, invite: room.invite, iceServers: getIceServers() });
                } else if (msg.type === 'join') {
                    const room = rooms.get(msg.roomId);
                    if (!room || room.invite !== msg.invite || room.host.readyState !== WebSocket.OPEN) {
                        return fail(ws, 'This invitation has ended or is invalid');
                    }
                    if (room.peers.size >= 16) return fail(ws, 'This room is full');
                    ws.room = room; ws.peerId = id(); room.peers.set(ws.peerId, ws);
                    const iceServers = getIceServers();
                    send(ws, { type: 'joined', peerId: ws.peerId, iceServers });
                    send(room.host, { type: 'peer-joined', peerId: ws.peerId, iceServers });
                } else return fail(ws, 'Create or join a room first');
                clearTimeout(registration);
                return;
            }
            const room = ws.room;
            if (msg.type === 'remove' && ws === room.host) {
                const peer = room.peers.get(msg.peerId);
                if (peer) fail(peer, 'The host ended this connection');
                return;
            }
            if (msg.type !== 'signal') return fail(ws, 'Only connection signaling is accepted');
            const description = msg.description;
            const candidate = msg.candidate;
            if (description && (!['offer', 'answer'].includes(description.type) || typeof description.sdp !== 'string')) {
                return fail(ws, 'Invalid session description');
            }
            if (!description && (!candidate || typeof candidate.candidate !== 'string')) {
                return fail(ws, 'Invalid ICE candidate');
            }
            const target = ws === room.host ? room.peers.get(msg.peerId) : room.host;
            if (target) send(target, { type: 'signal', peerId: ws.peerId || msg.peerId, description, candidate });
        });
        ws.on('close', () => {
            clearTimeout(registration);
            const room = ws.room;
            if (!room) return;
            ws.room = null;
            if (room.host === ws) {
                rooms.delete(room.id);
                for (const peer of room.peers.values()) {
                    send(peer, { type: 'ended' }); peer.close(1000);
                }
            } else {
                room.peers.delete(ws.peerId);
                send(room.host, { type: 'peer-left', peerId: ws.peerId });
            }
        });
    });
    const timer = setInterval(() => {
        for (const ws of wss.clients) {
            if (!ws.alive) { ws.terminate(); continue; }
            ws.alive = false; ws.ping();
        }
    }, heartbeatMs);
    timer.unref?.();
    let disposed = false;
    const close = () => {
        if (disposed) return;
        disposed = true;
        clearInterval(timer);
        server.removeListener('upgrade', upgrade);
        for (const ws of wss.clients) ws.terminate();
        rooms.clear(); wss.close();
    };
    server.once('close', close);
    return { rooms, close };
};

module.exports = { attachRtcSignaling, iceFromEnv };
