'use strict';
const { createLiveMediaBridge } = require('./live-media-bridge');
// Browser client adapter for opaque players. Commands operate on the public
// Homegames client API; neither side reads game metadata or a game instance.
function attachClientHost(window, frame, recordAudio, exportStorage, createExportsViewer, recordVideo, createPlayerToolbar, options = {}) {
    const document = window.document;
    let port, sequence = 0, closed = false, toolbar = options.toolbar, ownToolbar = false, recording, viewer, sharing;
    let gameTitle = options.title;
    const liveMedia = options.createLiveMediaBridge?.(window, message => port?.postMessage(message), {
        host: true, busy: () => !!recording, focusPlayer: () => frame.focus(),
    });
    const pending = new Map(), shareRequests = new Map();
    function request(format, name) {
        if (!port || closed) return Promise.reject(new Error('The player is not ready'));
        return new Promise((resolve, reject) => {
            const id = ++sequence, timer = setTimeout(() => { pending.delete(id); reject(new Error('Game download timed out')); }, 60000);
            pending.set(id, { resolve, reject, timer, format }); port.postMessage({ type: 'download-game', id, format, name });
        });
    }
    const status = (text, details = {}) => { if (options.onPlayerStatus) options.onPlayerStatus(text, details); else toolbar?.setStatus(text, details); };
    function command(action, value) { if (port && !closed) port.postMessage({ type: 'player-control', action, value }); }
    function sharingLink(mode) {
        if (!port || closed) return Promise.reject(new Error('The player is not ready'));
        if (!['session', 'copy'].includes(mode)) return Promise.reject(new Error('Unknown sharing option'));
        if (shareRequests.has(mode)) return shareRequests.get(mode);
        const result = new Promise((resolve, reject) => {
            const id = ++sequence;
            const timer = setTimeout(() => { pending.delete(id); reject(new Error('Creating an invitation timed out. Try again.')); }, 35000);
            pending.set(id, { resolve, reject, timer, sharing: true });
            port.postMessage({ type: 'player-share', id, mode });
        });
        shareRequests.set(mode, result);
        result.finally(() => { if (shareRequests.get(mode) === result) shareRequests.delete(mode); }).catch(() => {});
        return result;
    }
    async function download(format) {
        try {
            // The host can supply a recovered catalog name for older packs.
            // Otherwise use the title announced by the current game. Keep this
            // self-contained: this adapter is also embedded in downloaded HTML.
            const name = typeof options.downloadName === 'function' ? options.downloadName() : options.downloadName;
            let stem = String(name || gameTitle || 'game').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'game';
            if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/.test(stem)) stem += '-game';
            status('Preparing game download…');
            const bytes = await request(format), url = window.URL.createObjectURL(new Blob([bytes], { type: format === 'html' ? 'text/html' : 'application/zip' }));
            const link = document.createElement('a'); link.href = url; link.download = stem + '.' + format; link.click();
            setTimeout(() => window.URL.revokeObjectURL(url), 30000); status('Game copy downloaded');
        } catch (e) { status(e.message, { attention: true }); }
    }
    function connect(event) {
        if (closed || port || event.source !== frame.contentWindow || event.origin !== 'null' || event.data?.type !== 'homegames-client-connect-v1') return;
        const channel = new window.MessageChannel(); port = channel.port1;
        port.onmessage = event => {
            const message = event.data;
            if (!closed && liveMedia?.handle(message)) return;
            if (!closed && message?.type === 'player-state') {
                if (typeof message.title === 'string') { gameTitle = message.title.slice(0, 200); toolbar?.setTitle(gameTitle); }
                if (typeof message.author === 'string') toolbar?.setAuthor?.(message.author.slice(0, 200));
                const ratio = message.aspectRatio;
                if (ratio && Number.isFinite(ratio.x) && Number.isFinite(ratio.y) && ratio.x > 0 && ratio.y > 0) {
                    toolbar?.setAspectRatio?.({ x: ratio.x, y: ratio.y });
                }
                if (typeof message.status === 'string') status(message.status.slice(0, 300), { attention: message.statusAttention === true });
                if (message.ready) {
                    toolbar?.setPlayerName(options.profile?.get() || '', message.playerNames && options.profile ? value => {
                        if (closed) throw new Error('This player has closed. Reopen the game to change your name.');
                        const name = options.profile.set(value); command('player-name', name); return name;
                    } : null);
                    for (const [key, label] of [['share', 'Invite'], ['copy-share', 'Share a copy'], ['manual-connect', 'Manual connection'], ['exports', 'View exports']]) {
                        const soloInvite = key === 'share' && message.multiplayer === false;
                        toolbar?.setAction(key, (message.inlineSharing && ['share', 'copy-share'].includes(key)) || key !== 'exports' && !message.sharing ? null : {
                            label: soloInvite ? 'Invite (solo)' : label, disabled: soloInvite,
                            title: soloInvite ? 'This is a solo game. Use Share a copy to send it to a friend.' : '', run: () => command(key),
                        });
                    }
                    if (message.sharing && message.inlineSharing) {
                        if (!sharing || sharing.multiplayer !== (message.multiplayer !== false)) {
                            sharing = { multiplayer: message.multiplayer !== false, getLink: sharingLink, dispose: () => command('dispose-sharing') };
                            toolbar?.setSharing?.(sharing);
                        }
                    } else if (sharing) { toolbar?.setSharing?.(null); sharing = null; }
                    toolbar?.setAction('download-html', { label: 'Download game HTML', id: options.htmlId, run: () => download('html') });
                    toolbar?.setAction('download-zip', { label: 'Download game ZIP', id: options.zipId, run: () => download('zip') });
                    if (options.editGame) toolbar?.setAction('edit-game', { label: 'Edit this game', id: 'edit-game',
                        run: () => options.editGame(() => request('zip')) });
                }
                return;
            }
            if (!closed && message?.type === 'player-share-status' && typeof message.status === 'string'
                && ['session', 'copy'].includes(message.mode)) {
                toolbar?.setSharingStatus?.(message.status.slice(0, 300), message.mode); return;
            }
            if (!closed && message?.type === 'player-share-result') {
                const entry = pending.get(message.id);
                if (!entry?.sharing) return;
                pending.delete(message.id); clearTimeout(entry.timer);
                if (message.error) entry.reject(new Error(String(message.error).slice(0, 300)));
                else {
                    const { url, qr } = message;
                    if (typeof url !== 'string' || url.length > 4096 || !/^https?:\/\//.test(url)
                        || !Array.isArray(qr) || qr.length < 21 || qr.length > 177 || (qr.length - 21) % 4 !== 0
                        || qr.some(row => typeof row !== 'string' || row.length !== qr.length || !/^[01]+$/.test(row))) {
                        entry.reject(new Error('Invalid invitation received from the player'));
                    } else entry.resolve({ url, qr });
                }
                return;
            }
            if (!closed && message?.type === 'close-exports') { viewer?.close(); return; }
            if (!closed && message?.type === 'view-exports' && Number.isSafeInteger(message.id)) {
                if (viewer || !createExportsViewer) { port.postMessage({ type:'export-result', id:message.id, error:'Export viewer is unavailable or already open' }); return; }
                viewer = createExportsViewer(window, { list: () => request('export-list'), read: name => request('export-file', name) });
                viewer.result.finally(() => { viewer = null; if (!closed) port.postMessage({ type:'export-result', id:message.id }); });
                return;
            }
            if (!closed && ['get-exports','put-export'].includes(message?.type) && Number.isSafeInteger(message.id)) {
                Promise.resolve().then(() => {
                    if (!exportStorage) throw new Error('Export storage is unavailable');
                    return message.type === 'get-exports' ? exportStorage.getExports() : exportStorage.putExport(message.name, message.bytes);
                }).then(value => { if (!closed) port.postMessage({type:'export-result',id:message.id,value}); }, error => { if (!closed) port.postMessage({type:'export-result',id:message.id,error:error.message}); });
                return;
            }
            if (!closed && message?.type === 'cancel-audio') { if (recording?.requestId === message.id) recording.close(); return; }
            if (!closed && ['record-audio','record-video'].includes(message?.type) && Number.isSafeInteger(message.id)) {
                if (recording || liveMedia?.busy) { port.postMessage({type:'audio-result', id:message.id, error:'A microphone/camera is already active'}); return; }
                const record = message.type === 'record-audio' ? recordAudio : recordVideo;
                if (!record) { port.postMessage({type:'audio-result',id:message.id,error:'Recording is unavailable'}); return; }
                recording = record(window, message.recording || {});
                recording.requestId = message.id;
                recording.result.then(value => { recording = null; if (!closed) port.postMessage({type:'audio-result', id:message.id, value}); }, error => { recording = null; if (!closed) port.postMessage({type:'audio-result', id:message.id, error:error.message}); });
                return;
            }
            const entry = pending.get(message?.id);
            if (closed || message?.type !== 'game-download' || !entry || entry.sharing) return;
            pending.delete(message.id); clearTimeout(entry.timer);
            if (message.error) entry.reject(new Error(String(message.error).slice(0, 300)));
            else if (entry.format === 'export-list' || entry.format === 'export-file') entry.resolve(message.value);
            else if (!(message.bytes instanceof Uint8Array) || !message.bytes.length || message.bytes.length > (entry.format === 'html' ? 220 : 65) * 1024 * 1024) entry.reject(new Error('Invalid game download'));
            else entry.resolve(message.bytes);
        };
        frame.contentWindow.postMessage({ type: 'homegames-client-port-v1', playerName: options.profile?.get() }, '*', [channel.port2]);
        if (!toolbar && createPlayerToolbar) {
            toolbar = createPlayerToolbar(window, { title: options.title, author: options.author, home: options.home, status: 'Starting game…',
                onOpen: () => command('pause-input'), onClose: () => command('resume-input') });
            ownToolbar = true; frame.before(toolbar.bar);
        }
        toolbar?.setGameArea?.(frame, frame.parentElement);
    }
    window.addEventListener('message', connect);
    return { request, command, download, close() { command('dispose-sharing'); liveMedia?.close(); closed = true; if (sharing) { toolbar?.setSharing?.(null); sharing = null; } window.removeEventListener('message', connect); port?.close(); if (ownToolbar) toolbar?.dispose(); recording?.close(); viewer?.close();
        for (const entry of pending.values()) { clearTimeout(entry.timer); entry.reject(new Error('Player closed')); } pending.clear(); shareRequests.clear(); } };
}
function connectClientSource(window, download, exports = {}, controls = {}) {
    let port, closed = false, sequence = 0, resolveConnect, state, playerName;
    const recordings = new Map();
    const connected = new Promise(resolve => { resolveConnect = resolve; });
    const liveMedia = createLiveMediaBridge(window, message => {
        if (port) port.postMessage(message);
        else connected.then(() => { if (!closed) port?.postMessage(message); });
    });
    const connectTimer = setTimeout(resolveConnect, 15000);
    const listener = event => {
        if (closed || event.source !== window.parent || event.data?.type !== 'homegames-client-port-v1' || !event.ports[0]) return;
        window.removeEventListener('message', listener); port = event.ports[0]; playerName = event.data.playerName; clearTimeout(connectTimer); resolveConnect();
        if (state) port.postMessage({ type: 'player-state', ...state });
        port.onmessage = async event => {
            const message = event.data;
            if (liveMedia.handle(message)) return;
            if (!closed && message?.type === 'player-share' && Number.isSafeInteger(message.id)
                && ['session', 'copy'].includes(message.mode)) {
                try {
                    if (typeof controls['sharing-link'] !== 'function') throw new Error('Inline sharing is unavailable');
                    const value = await controls['sharing-link'](message.mode);
                    if (!closed) port.postMessage({ type: 'player-share-result', id: message.id, ...value });
                } catch (error) {
                    if (!closed) port.postMessage({ type: 'player-share-result', id: message.id, error: error.message });
                }
                return;
            }
            if (!closed && message?.type === 'player-control' && Object.hasOwn(controls, message.action)) {
                try {
                    if (message.action === 'player-name') playerName = message.value;
                    await controls[message.action](message.value);
                } catch (error) { port.postMessage({type:'player-state', status:error.message, statusAttention:true}); }
                return;
            }
            if (message?.type === 'audio-result' || message?.type === 'export-result') { const entry = recordings.get(message.id); if (!entry) return; recordings.delete(message.id); clearTimeout(entry.timer); message.error ? entry.reject(new Error(message.error)) : entry.resolve(message.value); return; }
            if (closed || message?.type !== 'download-game' || !Number.isSafeInteger(message.id) || !['html','zip','export-list','export-file'].includes(message.format)) return;
            try {
                const value = message.format === 'export-list' ? { value: await exports.list() }
                    : message.format === 'export-file' ? { value: await exports.read(message.name) }
                    : { bytes: await download(message.format) };
                if (!closed) port.postMessage({ type: 'game-download', id: message.id, ...value });
            }
            catch (e) { if (!closed) port.postMessage({ type: 'game-download', id: message.id, error: e.message }); }
        };
    };
    window.addEventListener('message', listener); window.parent.postMessage({ type: 'homegames-client-connect-v1' }, '*');
    const request = (type, data = {}) => new Promise((resolve, reject) => {
        if (closed || recordings.size >= 128) { reject(new Error('Client adapter unavailable or busy')); return; }
        const id = ++sequence, entry = {resolve, reject, recordingId:data.recording?.id, type};
        entry.timer = type === 'view-exports' ? null : setTimeout(() => {
            recordings.delete(id);
            if (type === 'record-audio' || type === 'record-video') port?.postMessage({type:'cancel-audio',id});
            reject(new Error('Client request timed out'));
        }, 90000);
        recordings.set(id, entry);
        connected.then(() => {
            if (!recordings.has(id)) return;
            if (closed || !port) { clearTimeout(entry.timer); recordings.delete(id); reject(new Error('Client adapter is unavailable')); return; }
            port.postMessage({type,id,...data});
        });
    });
    return { setState(value) { state = { ...state, ...value }; if (!closed) port?.postMessage({ type:'player-state', ...state }); },
        setSharingStatus(status, mode = 'copy') { if (!closed) port?.postMessage({ type:'player-share-status', status, mode }); },
        getPlayerName: async () => { await connected; return playerName; },
        recordAudio: info => request('record-audio', {recording:info}),
        recordVideo: info => request('record-video', {recording:info}),
        captureLive: info => liveMedia.request(info),
        viewExports: () => request('view-exports'),
        closeExports() { port?.postMessage({type:'close-exports'}); },
        cancelRecording(recordingId) { for (const [id, entry] of recordings) if (['record-audio','record-video'].includes(entry.type) && entry.recordingId === recordingId) { port?.postMessage({type:'cancel-audio',id}); clearTimeout(entry.timer); recordings.delete(id); entry.reject(new Error('Recording cancelled')); } },
        getExports: () => request('get-exports'), putExport: (name,bytes) => request('put-export',{name,bytes}),
        close() { liveMedia.close(); closed = true; clearTimeout(connectTimer); resolveConnect(); window.removeEventListener('message', listener); for (const [id,entry] of recordings) { if(entry.recordingId)port?.postMessage({type:'cancel-audio',id}); clearTimeout(entry.timer); entry.reject(new Error('Player closed')); } recordings.clear(); port?.close(); } };
}


// A generic Homegames client capability. Games supply a prompt and duration;
// clients own device access and consent and return a standard audio file.
// Self-contained so the trusted adapter can be embedded in standalone HTML.
function recordAudio(window, info) {
    const document = window.document;
    let finish, stream, recorder, timer, closed = false;
    const duration = Math.min(30, Math.max(1, Number(info.durationSeconds) || 3));
    const maxBytes = Math.min(5 * 1024 * 1024, Math.max(128 * 1024, Number(info.maxBytes) || 5 * 1024 * 1024));
    const overlay = document.createElement('dialog'); overlay.setAttribute('aria-label', 'Record audio');
    overlay.style.cssText = 'max-width:360px;padding:24px;border-radius:12px;background:#101820;color:white;font:16px/1.5 system-ui';
    const text = document.createElement('p'); text.textContent = String(info.prompt || 'Record audio for this game. The host receives the recording.').slice(0,120);
    const status = document.createElement('p'); status.textContent = `Your microphone will record for ${duration} seconds.`;
    const start = document.createElement('button'), cancel = document.createElement('button'); start.textContent = 'Record audio'; cancel.textContent = 'Cancel';
    for (const button of [start, cancel]) button.style.cssText = 'padding:10px;margin:4px;font:inherit';
    const result = new Promise((resolve, reject) => { finish = (error, value) => {
        if (closed) return; closed = true; clearTimeout(timer); if (recorder?.state === 'recording') recorder.stop();
        stream?.getTracks().forEach(t => t.stop()); document.removeEventListener('visibilitychange', hidden); overlay.close(); overlay.remove(); error ? reject(error) : resolve(value);
    }; });
    cancel.onclick = () => finish(new Error('Recording cancelled'));
    const hidden = () => { if (document.hidden) finish(new Error('Recording cancelled because the page was hidden')); };
    document.addEventListener('visibilitychange', hidden);
    overlay.oncancel = event => { event.preventDefault(); cancel.onclick(); };
    start.onclick = async () => {
        start.disabled = true;
        try {
            if (!window.navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) throw new Error('This client cannot record here. Choose an audio file instead.');
            const capture = await window.navigator.mediaDevices.getUserMedia({audio:true,video:false});
            if (closed) { capture.getTracks().forEach(t => t.stop()); return; }
            stream = capture; recorder = new window.MediaRecorder(stream); const chunks = []; let bytesRecorded = 0;
            recorder.ondataavailable = event => { if (event.data.size) { bytesRecorded += event.data.size; if (bytesRecorded > 5 * 1024 * 1024) finish(new Error('Recording is too large')); else chunks.push(event.data); } };
            recorder.onstop = async () => {
                if (closed) return; let audio;
                try {
                    audio = new (window.AudioContext || window.webkitAudioContext)();
                    const input = await audio.decodeAudioData(await new Blob(chunks).arrayBuffer());
                    const rate = 22050, count = Math.min(Math.floor(input.duration * rate), duration * rate), bytes = new Uint8Array(44 + count * 2);
                    if (!count || bytes.length > maxBytes) throw new Error('Recording is empty or too large');
                    const view = new DataView(bytes.buffer), word = (at,s) => { for(let i=0;i<s.length;i++)bytes[at+i]=s.charCodeAt(i); };
                    word(0,'RIFF');view.setUint32(4,bytes.length-8,true);word(8,'WAVEfmt ');view.setUint32(16,16,true);view.setUint16(20,1,true);view.setUint16(22,1,true);
                    view.setUint32(24,rate,true);view.setUint32(28,rate*2,true);view.setUint16(32,2,true);view.setUint16(34,16,true);word(36,'data');view.setUint32(40,count*2,true);
                    const samples = input.getChannelData(0);
                    for(let i=0;i<count;i++)view.setInt16(44+i*2,Math.round(Math.max(-1,Math.min(1,samples[Math.min(samples.length-1,Math.floor(i*input.sampleRate/rate))]))*32767),true);
                    let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
                    finish(null,{type:'media',action:'record-result',id:info.id,data:window.btoa(binary),contentType:'audio/wav',fileName:'recording.wav'});
                } catch(e) { finish(e); } finally { await audio?.close(); }
            };
            recorder.onerror = () => finish(new Error('Recording failed'));
            recorder.start(250); status.textContent = 'Recording…';
            timer = setTimeout(() => { recorder.stop(); stream.getTracks().forEach(t=>t.stop()); }, duration * 1000);
        } catch(e) { finish(e); }
    };
    overlay.append(text,status,start,cancel);document.body.append(overlay);overlay.showModal();start.focus();
    return {result,close:()=>finish(new Error('Recording cancelled'))};
}
module.exports = { attachClientHost, connectClientSource, recordAudio };
