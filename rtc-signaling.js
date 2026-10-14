// The browser owns the game. This service owns SDP/ICE relay and host leases.
// Catalog discovery is available only to explicitly configured legacy hosts.
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
    maxRooms = 1000, maxConnections = 4096, heartbeatMs = 15000, trustLoopbackProxy = false,
    resolveGame = null, onRoomCreated = null, leaseMs = 90000, now = Date.now, allowOtherUpgrades = false } = {}) => {
    const rooms = new Map();
    const wss = new WebSocket.Server({ noServer: true, maxPayload: 64 * 1024 });
    const send = (ws, data) => {
        if (ws.readyState !== WebSocket.OPEN) return;
        if (ws.bufferedAmount > 256 * 1024) { ws.terminate(); return; }
        ws.send(JSON.stringify(data));
    };
    const fail = (ws, message) => { send(ws, { type: 'error', message }); ws.close(1008); };
    const live = room => room.host.readyState === WebSocket.OPEN
        && now() - room.updatedAt < leaseMs;
    const full = room => Math.max(room.playerCount, room.peers.size + 1) >= room.maxPlayers;
    const publicRoom = room => ({ roomId: room.id, ...room.game,
        playerCount: room.playerCount, maxPlayers: room.maxPlayers,
        createdAt: room.createdAt, joinable: !full(room) });
    const handleRequest = (req, res) => {
        if (!resolveGame) return false;
        const url = new URL(req.url, 'http://localhost');
        if (url.pathname !== '/rooms' && !/^\/rooms\/[^/]+$/.test(url.pathname)) return false;
        const respond = (status, body) => {
            res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
                'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, OPTIONS' });
            res.end(JSON.stringify(body));
        };
        if (req.method === 'OPTIONS') { respond(200, {}); return true; }
        if (req.method !== 'GET') { respond(405, { error: 'Method not allowed' }); return true; }
        const visible = room => room && room.game && room.visibility === 'public' && live(room);
        if (url.pathname !== '/rooms') {
            const room = rooms.get(url.pathname.slice('/rooms/'.length));
            if (visible(room)) respond(200, publicRoom(room));
            else respond(404, { error: 'Room unavailable' });
        } else {
            const limit = Number(url.searchParams.get('limit') || 50);
            const offset = Number(url.searchParams.get('offset') || 0);
            if (!Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isInteger(offset) || offset < 0) {
                respond(400, { error: 'Invalid pagination' }); return true;
            }
            const gameId = url.searchParams.get('gameId');
            const available = [...rooms.values()].filter(room => visible(room) && (!gameId || room.game.gameId === gameId))
                .sort((a, b) => b.playerCount - a.playerCount || b.createdAt - a.createdAt);
            respond(200, { rooms: available.slice(offset, offset + limit).map(publicRoom), total: available.length });
        }
        return true;
    };
    const upgrade = (req, socket, head) => {
        if (req.url !== path) { if (!allowOtherUpgrades) socket.destroy(); return; }
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
        ws.on('message', async raw => {
            if (Date.now() - windowAt > 1000) { windowAt = Date.now(); count = 0; }
            if (++count > 100) return fail(ws, 'Too many signaling messages');
            let msg;
            try { msg = JSON.parse(raw); } catch (_) { return fail(ws, 'Invalid signaling message'); }
            if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return fail(ws, 'Invalid signaling message');
            const fields = {
                create: ['type', 'visibility', 'game', 'maxPlayers'], join: ['type', 'roomId', 'invite'],
                heartbeat: ['type', 'playerCount'], visibility: ['type', 'visibility'],
                remove: ['type', 'peerId'], signal: ['type', 'peerId', 'description', 'candidate'],
            };
            if (!Object.hasOwn(fields, msg.type) || Object.keys(msg).some(key => !fields[msg.type].includes(key))) {
                return fail(ws, 'Only connection signaling fields are accepted');
            }
            if (!ws.room) {
                if (ws.registering) return fail(ws, 'Room registration is still in progress');
                if (msg.type === 'create') {
                    const hasCapacity = () => rooms.size < maxRooms && [...rooms.values()].filter(r => r.host.ip === ws.ip).length < 20;
                    if (!hasCapacity()) return fail(ws, 'Room limit reached');
                    const visibility = msg.visibility || 'private';
                    if (!['public', 'private'].includes(visibility)) return fail(ws, 'Invalid room visibility');
                    let game = null;
                    if (msg.game) {
                        if (!resolveGame || typeof msg.game.gameId !== 'string' || !msg.game.gameId.length
                            || msg.game.gameId.length > 128 || typeof msg.game.versionId !== 'string'
                            || !msg.game.versionId.length || msg.game.versionId.length > 128) return fail(ws, 'Invalid catalog game');
                        ws.registering = true;
                        try {
                            const canonical = await resolveGame(msg.game.gameId, msg.game.versionId);
                            if (!canonical || canonical.multiplayer !== true) throw new Error();
                            game = { gameId: msg.game.gameId, versionId: msg.game.versionId,
                                name: String(canonical.name).slice(0, 200), maxPlayers: canonical.maxPlayers };
                        } catch (_) { return fail(ws, 'This published game is not available for multiplayer'); }
                        finally { ws.registering = false; }
                        if (ws.readyState !== WebSocket.OPEN) return;
                        if (!hasCapacity()) return fail(ws, 'Room limit reached');
                    }
                    if (visibility === 'public' && !game) return fail(ws, 'Public rooms require a published game');
                    const capacity = Math.min(17, Number.isInteger(game?.maxPlayers) && game.maxPlayers > 0 ? game.maxPlayers : 17,
                        Number.isInteger(msg.maxPlayers) && msg.maxPlayers > 0 ? msg.maxPlayers : 17);
                    const room = { id: id(), invite: id(), host: ws, peers: new Map(), game, visibility,
                        maxPlayers: capacity, playerCount: 1, createdAt: now(), updatedAt: now() };
                    rooms.set(room.id, room); ws.room = room;
                    if (game && onRoomCreated) Promise.resolve().then(() => onRoomCreated({ ...game, visibility })).catch(() => {});
                    send(ws, { type: 'created', protocol: 2, roomId: room.id, invite: room.invite, visibility,
                        heartbeatIntervalMs: Math.min(15000, Math.floor(leaseMs / 3)), iceServers: getIceServers() });
                } else if (msg.type === 'join') {
                    const room = rooms.get(msg.roomId);
                    if (!room || !live(room) || (room.invite !== msg.invite && room.visibility !== 'public')) {
                        return fail(ws, 'This invitation has ended or is invalid');
                    }
                    if (full(room)) return fail(ws, 'This room is full');
                    ws.room = room; ws.peerId = id(); room.peers.set(ws.peerId, ws);
                    const iceServers = getIceServers();
                    send(ws, { type: 'joined', peerId: ws.peerId, iceServers });
                    send(room.host, { type: 'peer-joined', peerId: ws.peerId, iceServers });
                } else return fail(ws, 'Create or join a room first');
                clearTimeout(registration);
                return;
            }
            const room = ws.room;
            if (!live(room)) return fail(ws, 'The host is no longer available');
            if (msg.type === 'heartbeat' && ws === room.host) {
                if (!Number.isInteger(msg.playerCount) || msg.playerCount < 1 || msg.playerCount > room.maxPlayers) {
                    return fail(ws, 'Invalid player count');
                }
                room.playerCount = msg.playerCount; room.updatedAt = now();
                return;
            }
            if (msg.type === 'visibility' && ws === room.host && room.game && ['public', 'private'].includes(msg.visibility)) {
                room.visibility = msg.visibility;
                send(ws, { type: 'visibility', visibility: room.visibility }); return;
            }
            if (msg.type === 'remove' && ws === room.host) {
                const peer = room.peers.get(msg.peerId);
                if (peer) fail(peer, 'The host ended this connection');
                return;
            }
            if (msg.type !== 'signal') return fail(ws, 'Only connection signaling is accepted');
            const description = msg.description;
            const candidate = msg.candidate;
            const objectWithKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
                && Object.keys(value).every(key => keys.includes(key));
            if (description != null && candidate != null) return fail(ws, 'Send one connection signal at a time');
            if (description != null && (!objectWithKeys(description, ['type', 'sdp'])
                || !['offer', 'answer'].includes(description.type) || typeof description.sdp !== 'string'
                || !description.sdp.length || Buffer.byteLength(description.sdp) > 48 * 1024)) {
                return fail(ws, 'Invalid session description');
            }
            if (!description && (!objectWithKeys(candidate, ['candidate', 'sdpMid', 'sdpMLineIndex', 'usernameFragment'])
                || typeof candidate.candidate !== 'string' || Buffer.byteLength(candidate.candidate) > 4096
                || (candidate.sdpMid != null && (typeof candidate.sdpMid !== 'string' || candidate.sdpMid.length > 256))
                || (candidate.sdpMLineIndex != null && (!Number.isInteger(candidate.sdpMLineIndex) || candidate.sdpMLineIndex < 0 || candidate.sdpMLineIndex > 65535))
                || (candidate.usernameFragment != null && (typeof candidate.usernameFragment !== 'string' || candidate.usernameFragment.length > 256)))) {
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
        for (const room of rooms.values()) {
            if (!live(room)) { rooms.delete(room.id); fail(room.host, 'The host heartbeat expired'); }
        }
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
    return { rooms, close, handleRequest };
};

module.exports = { attachRtcSignaling, iceFromEnv };
