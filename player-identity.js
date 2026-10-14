'use strict';

// Self-contained: the trusted wrapper also embeds this in downloaded HTML.
function createPlayerIdentity() {
    const normalizeName = value => {
        if (typeof value !== 'string' || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(value)) throw new Error('Use a name without control characters.');
        const name = value.normalize('NFC').trim().replace(/\s+/gu, ' ');
        if (!name || name.length > 32) throw new Error('Choose a name between 1 and 32 characters.');
        return name;
    };
    const words = ['chocolate', 'iguana', 'cardigan', 'enormous', 'gargantuan', 'orangutan',
        'cookies', 'monstera', 'daisy', 'grapefruit', 'blueberry', 'mango', 'elephant', 'bamboo',
        'sapphire', 'papaya', 'waffle', 'turquoise', 'aquatic', 'goblin', 'funky', 'hotdog', 'elegant', 'cascade', 'euphoria'];
    const generateName = () => Array.from({length: 2}, () => words[Math.floor(Math.random() * words.length)]).join(' ');
    const initialName = value => { try { return normalizeName(value); } catch (_) { return generateName(); } };
    function profile(window) {
        const key = 'homegames-player-name';
        let name;
        try { name = normalizeName(window.localStorage.getItem(key)); } catch (_) { name = generateName(); }
        const set = value => {
            name = normalizeName(value);
            // Names still work when storage is disabled or the frame is opaque.
            try { window.localStorage.setItem(key, name); } catch (_) {}
            return name;
        };
        set(name);
        return { get: () => name, set };
    }
    return { normalizeName, generateName, initialName, profile };
}
module.exports = { createPlayerIdentity, ...createPlayerIdentity() };
