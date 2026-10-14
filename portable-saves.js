'use strict';

// These two functions are also embedded verbatim in standalone HTML. Keep them
// self-contained: no game source or parent storage object crosses the boundary.
function attachSaveHost(window, frame, settings) {
    const { installationId, gameId, versionId, compatibility = [], onStatus = () => {} } = settings;
    if (!/^[a-zA-Z0-9-]{16,80}$/.test(installationId) || typeof gameId !== 'string' || !/^save-schema:\d+$/.test(versionId)) throw new Error('Invalid save identity');
    const gameKey = 'project:' + installationId;
    const versions = [versionId, ...compatibility.filter(v => /^save-schema:\d+$/.test(v)).slice(0, 32)].filter((v,i,a) => a.indexOf(v) === i);
    const maxBytes = 1024 * 1024;
    let dbPromise, port, disposed = false, stopping, closing, closeResolve, closeTimer;
    let generation = 0, initialized = false, storageFailure, latest = null, pending = 0, tail = Promise.resolve();
    const report = (state, message) => { try { onStatus({state, message}); } catch (_) {} };
    const fail = error => report('error', 'Progress not saved: ' + error.message + ' Download a save backup before closing.');
    const clean = data => {
        const json = JSON.stringify(data);
        if (json === undefined || new TextEncoder().encode(json).length > maxBytes) throw new Error('Save data must be JSON and at most 1 MiB');
        return JSON.parse(json);
    };
    const envelope = (data, schema = versionId) => ({ gameKey, gameId, versionId: schema, savedAt: Date.now(), data: clean(data) });
    function database() {
        if (!dbPromise) dbPromise = new Promise((resolve, reject) => {
            let blocked = false;
            const request = window.indexedDB.open('homegames-portable-saves', 1);
            request.onupgradeneeded = () => request.result.createObjectStore('saves', {keyPath:['installationId','versionId']});
            request.onerror = () => reject(request.error);
            request.onblocked = () => { blocked = true; reject(new Error('Close other game tabs and reload to update save storage.')); };
            request.onsuccess = () => {
                if (blocked) { request.result.close(); return; }
                request.result.onversionchange = () => request.result.close(); resolve(request.result);
            };
        });
        return dbPromise;
    }
    function queue(task) {
        pending++;
        const result = tail.then(task);
        tail = result.catch(() => {}).finally(() => { pending--; });
        return result;
    }
    async function read() {
        try {
            const db = await database();
            const rows = await new Promise((resolve,reject) => {
                const tx = db.transaction('saves','readonly'), rows = [];
                versions.forEach((v,i) => { const r=tx.objectStore('saves').get([installationId,v]);r.onsuccess=()=>{rows[i]=r.result;}; });
                tx.oncomplete=()=>resolve(rows);tx.onabort=()=>reject(tx.error || new Error('Could not read game save'));
            });
            generation = rows[0]?.generation || 0;
            const found = rows.find(Boolean);
            if (found) {
                if (found.envelope.gameId !== gameId || !versions.includes(found.envelope.versionId)) throw new Error('Saved game identity does not match this game');
                latest = { ...found.envelope, data: clean(found.envelope.data) };
            }
            initialized = true;
            report('ready', latest ? 'Game progress restored from this browser' : 'Game saves stay in this browser');
            return latest;
        } catch (error) {
            // Explicit session fallback: gameplay and manual backups still work,
            // but writes reject and the UI never claims persistence succeeded.
            initialized = true;storageFailure = error;fail(error);return null;
        }
    }
    async function write(data, schema = versionId) {
        if (!initialized) throw new Error('Load this game before saving');
        latest = envelope(data,schema); // Keep a downloadable backup even on quota/conflict failure.
        if (storageFailure) throw storageFailure;
        const db=await database(), next=latest;
        await new Promise((resolve,reject) => {
            const tx=db.transaction('saves','readwrite'),store=tx.objectStore('saves');let error;
            const request=store.get([installationId,versionId]);
            request.onsuccess=()=>{
                try {
                    if ((request.result?.generation || 0) !== generation) throw new Error('Another tab saved newer progress. Reload to use it, or download this session’s save.');
                    store.put({installationId,versionId,generation:generation+1,envelope:next});
                } catch(e){error=e;tx.abort();}
            };
            tx.oncomplete=()=>{generation++;resolve();};
            tx.onabort=()=>reject(error||tx.error||new Error('Browser storage could not save progress'));
        });
        report('saved','Game progress saved in this browser');
    }
    const send = message => { if(port&&!disposed)port.postMessage(message); };
    function connect(event) {
        if (disposed || port || event.source !== frame.contentWindow || event.origin !== 'null' || event.data?.type !== 'homegames-save-connect-v1') return;
        const channel = new window.MessageChannel();port=channel.port1;
        port.onmessage = event => {
            const message=event.data;
            if (disposed || !message || typeof message !== 'object') return;
            if (message.type==='closed') { closeResolve?.(); return; }
            const {id,op}=message;
            if (!Number.isSafeInteger(id) || id<1 || !['get','put'].includes(op)) return;
            if (pending>=64) { send({id,error:'Too many pending save requests'});return; }
            // The parent chooses the identity and schema. No caller-controlled
            // key, file path, source, arbitrary read or delete operation exists.
            if (Object.keys(message).some(k=>!['id','op','data'].includes(k))) {send({id,error:'Invalid save request'});return;}
            let data;
            try {if(op==='put')data=clean(message.data);}catch(error){send({id,error:error.message});fail(error);return;}
            queue(async()=>{
                if(disposed)throw new Error('Game session closed');
                if(op==='get')return initialized?latest:read();
                return write(data);
            }).then(value=>send({id,value}),error=>{fail(error);send({id,error:error.message});});
        };
        frame.contentWindow.postMessage({type:'homegames-save-port-v1'},'*',[channel.port2]);
    }
    window.addEventListener('message',connect);
    const beforeUnload=event=>{if(pending){event.preventDefault();event.returnValue='';}};
    window.addEventListener('beforeunload',beforeUnload);
    function dispose() {
        disposed=true;clearTimeout(closeTimer);port?.close();window.removeEventListener('message',connect);window.removeEventListener('beforeunload',beforeUnload);
        dbPromise?.then(db=>db.close(),()=>{});
    }
    function stopRuntime() {
        if(!stopping)stopping=(async()=>{
            if(port&&!disposed)await new Promise(resolve=>{closeResolve=resolve;closeTimer=setTimeout(resolve,3000);send({type:'close'});});
            await tail;
        })();
        return stopping;
    }
    return {
        get pending(){return pending>0;},
        get stopped(){return Boolean(stopping);},
        async close() {
            if(closing)return closing;
            closing=(async()=>{
                await stopRuntime();dispose();
            })();return closing;
        },
        dispose,
        async exportSave() {
            await tail;if(!latest)throw new Error('This game has not saved any progress yet');
            // Compact JSON keeps every valid 1 MiB save within the import cap.
            // return JSON.stringify({...latest,data:clean(latest.data)},null,2);
            return JSON.stringify({...latest,data:clean(latest.data)});
        },
        async importSave(text) {
            if(typeof text!=='string'||new TextEncoder().encode(text).length>maxBytes+4096)throw new Error('Save file is too large');
            const incoming=JSON.parse(text);
            if(incoming?.gameId!==gameId||!versions.includes(incoming.versionId))throw new Error('This save is for a different game or an incompatible save version');
            // Import is a parent UI action. Older compatible data retains its
            // original schema until the game migrates it through saveGame.
            const data=clean(incoming.data);
            await stopRuntime();
            await queue(async()=>{if(!initialized)await read();await write(data,incoming.versionId);});
        },
        downloadSave(name='game-save.json') {
            return this.exportSave().then(text=>{
                const url=window.URL.createObjectURL(new Blob([text],{type:'application/json'})),link=window.document.createElement('a');
                link.href=url;link.download=name;link.click();setTimeout(()=>window.URL.revokeObjectURL(url),30000);
            });
        }
    };
}

function connectSaveStore(window, {gameKey, versionId, onError = () => {}, stop = () => {}}) {
    return new Promise((resolve,reject)=>{
        let port,seq=0,closed=false;const pending=new Map();
        const timer=setTimeout(()=>{window.removeEventListener('message',receive);reject(new Error('Game save storage did not connect. Reload to try again.'));},10000);
        function receive(event) {
            if(event.source!==window.parent||event.data?.type!=='homegames-save-port-v1'||!event.ports[0])return;
            clearTimeout(timer);window.removeEventListener('message',receive);port=event.ports[0];
            function request(op,data) {
                if(closed)return Promise.reject(new Error('Game session closed'));
                if(pending.size>=64)return Promise.reject(new Error('Too many pending save requests'));
                return new Promise((resolve,reject)=>{
                    const id=++seq;const timeout=setTimeout(()=>{pending.delete(id);const error=new Error('Game save timed out');onError(error);reject(error);},10000);
                    pending.set(id,{resolve,reject,timeout});
                    try{port.postMessage(data===undefined?{id,op}:{id,op,data});}catch(e){clearTimeout(timeout);pending.delete(id);reject(e);}
                });
            }
            port.onmessage=event=>{
                const response=event.data;
                if(response?.type==='close') {
                    stop();closed=true;
                    const finish=()=>{if(pending.size){setTimeout(finish,10);return;}port.postMessage({type:'closed'});port.close();};finish();return;
                }
                const call=pending.get(response?.id);if(!call)return;
                pending.delete(response.id);clearTimeout(call.timeout);
                if(response.error){const error=new Error(response.error);onError(error);call.reject(error);}else call.resolve(response.value);
            };
            resolve({
                // Portable saves cross the boundary immediately; the parent's
                // transaction is the acknowledgement. No iframe debounce can
                // be destroyed by Stop before sending its last save.
                eager:true,strict:true,
                getSave:key=>key==='local:'+gameKey?request('get'):Promise.reject(new Error('Wrong game save key')),
                putSave:(key,value)=>{
                    if(key!=='local:'+gameKey||value?.gameKey!==gameKey||value.versionId!==versionId)return Promise.reject(new Error('Wrong game save identity'));
                    return request('put',value.data);
                }
            });
        }
        window.addEventListener('message',receive);window.parent.postMessage({type:'homegames-save-connect-v1'},'*');
    });
}
module.exports={attachSaveHost,connectSaveStore};
