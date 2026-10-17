'use strict';
const { isIP } = require('node:net');
function canonicalIp(value) {
    if (typeof value !== 'string' || value.length > 128 || value.includes('%')) return '';
    if (value.startsWith('::ffff:') && isIP(value.slice(7)) === 4) return value.slice(7);
    if (isIP(value) === 4) return value;
    if (isIP(value) === 6) {
        const normalized = new URL(`http://[${value}]/`).hostname.slice(1, -1);
        const mapped = /^::ffff:([a-f0-9]+):([a-f0-9]+)$/.exec(normalized);
        if (mapped) { const n = parseInt(mapped[1] + mapped[2].padStart(4, '0'), 16); return [n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255].join('.'); }
        return normalized;
    }
    return '';
}
function clientIp(req, trustProxy = false, header = 'x-real-ip') {
    const remote = canonicalIp(req.socket?.remoteAddress);
    const candidate = String(req.headers?.[header] || '').split(',').at(-1).trim();
    return trustProxy && ['127.0.0.1', '::1'].includes(remote) ? canonicalIp(candidate) || remote : remote;
}
// Fixed-size, fixed-window admission budgets survive individual socket closes.
// Once the table is full, unknown addresses fail closed until a window expires.
function budget({ limit, windowMs = 60000, maxKeys = 10000, now = Date.now }) {
    if (![limit, windowMs, maxKeys].every(n => Number.isSafeInteger(n) && n > 0)) throw new Error('Invalid admission budget');
    const entries = new Map(); let sweepAt = 0;
    return key => {
        const at = now();
        if (at >= sweepAt) { for (const [ip, entry] of entries) if (entry.until <= at) entries.delete(ip); sweepAt = at + Math.min(windowMs, 1000); }
        let entry = entries.get(key);
        if (entry?.until <= at) { entries.delete(key); entry = null; }
        if (!entry) {
            if (entries.size >= maxKeys) return false;
            entries.set(key, entry = { count: 0, until: at + windowMs });
        }
        return ++entry.count <= limit;
    };
}
module.exports = { budget, canonicalIp, clientIp };
