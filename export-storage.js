'use strict';

// Browser host storage. Embedded in standalone HTML as a self-contained adapter.
function createExportStorage(window, { installationId, gameId, packageRevision = 'local', database: sharedDatabase, transaction }) {
    if (typeof installationId !== 'string' || !installationId || typeof gameId !== 'string' || !gameId) throw new Error('Export storage requires a host-selected game identity');
    const key = [installationId, gameId, packageRevision]; let database;
    const open = () => sharedDatabase ? Promise.resolve(sharedDatabase) : database ||= new Promise((resolve, reject) => {
        const request = window.indexedDB.open('homegames-user-exports', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('exports');
        request.onerror = () => reject(request.error);
        request.onsuccess = () => { request.result.onversionchange = () => request.result.close(); resolve(request.result); };
    });
    function validate(files) {
        const names = Object.keys(files), seen = new Set(); let total = 0;
        if (names.length > 128) throw new Error('Too many exports');
        for (const name of names) {
            if (!/^[A-Za-z0-9_][A-Za-z0-9_. -]{0,119}$/.test(name) || /[ .]$/.test(name)
                || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name)
                || ['__proto__','constructor','prototype'].includes(name) || seen.has(name.toLowerCase())) throw new Error('Invalid export name');
            seen.add(name.toLowerCase());
            const bytes = files[name];
            if (!(bytes instanceof Uint8Array) || bytes.length > 16 * 1024 * 1024 || (total += bytes.length) > 64 * 1024 * 1024) throw new Error('Export size limit exceeded');
        }
    }
    return {
        async getExports() {
            const db = await open();
            return new Promise((resolve, reject) => {
                const tx = db.transaction('exports', 'readonly'), request = tx.objectStore('exports').get(key);
                tx.oncomplete = () => { try { const files = request.result || {}; validate(files); resolve(files); } catch (e) { reject(e); } };
                tx.onabort = () => reject(tx.error || new Error('Unable to read exports'));
            });
        },
        async putExport(name, bytes) {
            validate({ [name]: bytes }); bytes = bytes.slice();
            const db = await open();
            return new Promise((resolve, reject) => {
                const tx = transaction ? transaction(['exports']) : db.transaction('exports', 'readwrite'), store = tx.objectStore('exports'), request = store.get(key); let error;
                request.onsuccess = () => { try { const files = { ...request.result, [name]: bytes }; validate(files); store.put(files, key); } catch (e) { error = e; tx.abort(); } };
                tx.oncomplete = () => resolve();
                tx.onabort = () => reject(error || tx.error || new Error('Unable to save export'));
            });
        },
    };
}
module.exports = { createExportStorage };
