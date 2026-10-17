'use strict';

// Self-contained: the sender is also embedded in standalone HTML. Project
// bytes travel between these two windows, never in a URL or server request.
function openGameInStudio(window, getArchive, studioUrl = 'https://homegames.io/studio.html') {
    const url = new URL(studioUrl);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw new Error('Invalid Studio address');
    const token = window.crypto.randomUUID(), origin = url.origin;
    // Browsers serialize file message origins as either "null" or "file://".
    url.hash = new URLSearchParams({ edit: token, from: window.location.protocol === 'file:' ? 'file://' : window.location.origin }).toString();
    return new Promise((resolve, reject) => {
        let target, archive, sending = false, finished = false;
        const finish = error => {
            if (finished) return; finished = true;
            clearTimeout(timer); clearInterval(closed);
            window.removeEventListener('message', receive); window.removeEventListener('pagehide', leaving);
            error ? reject(error) : resolve();
        };
        const leaving = () => finish(new Error('Keep the game open until Studio receives it.'));
        const receive = event => {
            if (finished || !target || event.source !== target || event.origin !== origin || event.data?.token !== token) return;
            if (event.data.type === 'homegames-studio-saved') return finish();
            if (event.data.type === 'homegames-studio-error') return finish(new Error(String(event.data.error).slice(0, 300)));
            if (event.data.type !== 'homegames-studio-ready' || sending) return;
            sending = true;
            archive ||= Promise.resolve().then(getArchive).then(bytes => {
                if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 65 * 1024 * 1024) throw new Error('Invalid game archive');
                return bytes;
            });
            archive.then(bytes => {
                if (!finished) target.postMessage({ type: 'homegames-studio-game', token, bytes }, origin);
                sending = false;
            }).catch(finish);
        };
        const timer = setTimeout(() => finish(new Error('Studio did not receive the game. Open Studio online once, or import the game HTML or ZIP there.')), 90000);
        const closed = setInterval(() => { if (target?.closed) finish(new Error('Studio was closed before saving the copy.')); }, 500);
        window.addEventListener('message', receive); window.addEventListener('pagehide', leaving);
        try {
            target = window.open(url.href, '_blank');
            if (!target) finish(new Error('Allow this game to open a Studio tab, or import its HTML or ZIP in Studio.'));
        } catch (error) { finish(error); }
    });
}

function receiveGameInStudio(window, saveArchive) {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get('edit'), origin = params.get('from'), source = window.opener;
    const localFile = origin === 'file://';
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token || '') || !source) return Promise.reject(new Error('Reopen Edit this game from the player, or import its HTML or ZIP.'));
    try {
        if (origin !== 'null' && !localFile && (!['http:', 'https:'].includes(new URL(origin).protocol) || new URL(origin).origin !== origin)) throw new Error();
    } catch (_) { return Promise.reject(new Error('Invalid game sender')); }
    return new Promise((resolve, reject) => {
        let receiving = false, finished = false;
        const send = data => { try { source.postMessage({ ...data, token }, origin === 'null' || localFile ? '*' : origin); } catch (_) { /* Sender may have closed. */ } };
        const finish = (error, value) => {
            if (finished) return; finished = true;
            clearTimeout(timer); clearInterval(ping); window.removeEventListener('message', receive); window.removeEventListener('pagehide', leaving);
            if (error) { send({ type: 'homegames-studio-error', error: error.message }); reject(error); }
            else { send({ type: 'homegames-studio-saved' }); resolve(value); }
        };
        const leaving = () => finish(new Error('Studio closed before receiving the game.'));
        const receive = event => {
            if (finished || receiving || event.source !== source || (localFile ? !['null', 'file://'].includes(event.origin) : event.origin !== origin)
                || event.data?.token !== token || event.data.type !== 'homegames-studio-game') return;
            const bytes = event.data.bytes;
            if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 65 * 1024 * 1024) return finish(new Error('Invalid game archive'));
            receiving = true; clearInterval(ping); clearTimeout(timer);
            // The caller validates and persists the archive as data before ACK.
            Promise.resolve().then(() => saveArchive(bytes)).then(value => finish(null, value), finish);
        };
        const ready = () => send({ type: 'homegames-studio-ready' });
        const timer = setTimeout(() => finish(new Error('The game did not arrive. Keep its tab open and try Edit this game again.')), 90000);
        const ping = setInterval(ready, 500);
        window.addEventListener('message', receive); window.addEventListener('pagehide', leaving); ready();
    });
}

module.exports = { openGameInStudio, receiveGameInStudio };
