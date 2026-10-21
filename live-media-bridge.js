'use strict';

// MediaStream cannot cross the opaque player's MessagePort. A local WebRTC
// connection carries approved tracks; permission and hardware stay in the
// surrounding page. No signaling service or STUN/TURN server is involved.
// Self-contained because exported HTML embeds this function verbatim.
function createLiveMediaBridge(window, send, { host = false, busy = () => false } = {}) {
    let active, sequence = 0, closed = false;
    const document = window.document || {};
    const post = (entry, action, value = {}) => {
        if (!closed) send({ type: 'live-media', id: entry.id, action, ...value });
    };
    function finish(entry, error = 'Microphone/camera disconnected', notify = true) {
        if (entry.closed) return;
        entry.closed = true;
        clearTimeout(entry.timer); clearTimeout(entry.disconnectTimer);
        entry.dialog?.close(); entry.dialog?.remove(); entry.button?.remove();
        entry.pc?.close();
        entry.stream?.getTracks().forEach(track => { track.onended = null; track.stop(); });
        if (active === entry) active = null;
        if (notify) post(entry, 'stop', { error });
        entry.reject?.(new Error(error)); entry.onended?.();
    }
    function peer(entry) {
        const pc = entry.pc = new window.RTCPeerConnection({ iceServers: [] });
        pc.onicecandidate = event => { if (event.candidate && !entry.closed) post(entry, 'candidate', { candidate: event.candidate.toJSON() }); };
        pc.onconnectionstatechange = () => {
            clearTimeout(entry.disconnectTimer);
            if (pc.connectionState === 'failed') finish(entry, 'Microphone/camera connection failed');
            if (pc.connectionState === 'disconnected') entry.disconnectTimer = setTimeout(() => finish(entry), 5000);
            if (pc.connectionState === 'connected') { clearTimeout(entry.timer); ready(entry); }
        };
        return pc;
    }
    function ready(entry) {
        if (host || entry.closed || !entry.resolve || entry.pc?.connectionState !== 'connected' || !entry.stream) return;
        if (entry.info.audio && !entry.stream.getAudioTracks().length || entry.info.video && !entry.stream.getVideoTracks().length) return;
        const resolve = entry.resolve; entry.resolve = null; entry.reject = null;
        resolve(entry.stream);
    }
    function createEntry(id, info) {
        const entry = { id, info, candidates: [], work: Promise.resolve() };
        entry.timer = setTimeout(() => finish(entry, 'Microphone/camera request timed out'), 60000);
        active = entry;
        return entry;
    }
    function consent(entry) {
        const dialog = entry.dialog = document.createElement('dialog');
        dialog.setAttribute('aria-label', 'Enable live media');
        dialog.style.cssText = 'margin:auto;padding:24px;max-width:360px;border:1px solid #666;border-radius:16px;background:#202321;color:white;font:16px system-ui';
        const label = document.createElement('p');
        label.textContent = entry.info.video ? `Share your camera${entry.info.audio ? ' and microphone' : ''} with this session?` : 'Enable your microphone for this session?';
        const start = document.createElement('button'); start.textContent = entry.info.video ? 'Enable camera' : 'Enable microphone';
        const cancel = document.createElement('button'); cancel.textContent = 'Cancel';
        for (const button of [start, cancel]) button.style.cssText = 'padding:12px;margin:16px 8px 0 0;font:inherit';
        dialog.append(label, start, cancel); document.body.appendChild(dialog);
        const cancelled = () => finish(entry, 'Microphone/camera permission cancelled');
        dialog.oncancel = event => { event.preventDefault(); cancelled(); };
        cancel.onclick = cancelled;
        start.onclick = async () => {
            if (entry.closed || start.disabled) return;
            start.disabled = true;
            try {
                if (!window.navigator.mediaDevices?.getUserMedia) throw new Error('Microphone/camera requires HTTPS or localhost');
                const stream = await window.navigator.mediaDevices.getUserMedia({
                    audio: entry.info.audio ? { echoCancellation: true, noiseSuppression: true } : false,
                    video: entry.info.video ? { width: { ideal: 640 }, height: { ideal: 360 }, frameRate: { ideal: 20, max: 30 } } : false,
                });
                if (entry.closed) { stream.getTracks().forEach(track => track.stop()); return; }
                entry.stream = stream;
                // Start silent, including during negotiation. Only a subsequent
                // transmit command can enable the actual capture tracks.
                const pc = peer(entry);
                for (const track of stream.getTracks()) {
                    track.enabled = false; track.onended = () => finish(entry);
                    pc.addTrack(track, stream);
                }
                dialog.close(); dialog.remove();
                const button = entry.button = document.createElement('button');
                button.textContent = 'Disconnect microphone / camera';
                button.style.cssText = 'position:fixed;right:12px;bottom:12px;padding:10px;border:1px solid #fff;border-radius:8px;background:#8b2525;color:white;z-index:2147483647;font:13px system-ui';
                button.onclick = () => finish(entry); document.body.appendChild(button);
                await pc.setLocalDescription(await pc.createOffer());
                if (!entry.closed) post(entry, 'description', { description: pc.localDescription.toJSON() });
            } catch (error) { finish(entry, error.message || 'Unable to access microphone/camera'); }
        };
        dialog.showModal(); start.focus();
    }
    function handle(message) {
        if (closed || message?.type !== 'live-media' || !Number.isSafeInteger(message.id)) return false;
        if (host && message.action === 'request') {
            if (active || busy()) { post(message, 'stop', { error: 'A microphone/camera is already active or awaiting permission' }); return true; }
            const info = message.info || {};
            if (info.audio !== true && info.video !== true) { post(message, 'stop', { error: 'No microphone/camera requested' }); return true; }
            const entry = createEntry(message.id, { audio: info.audio === true, video: info.video === true, pushToTalk: info.pushToTalk === true });
            try { consent(entry); } catch (error) { finish(entry, error.message); }
            return true;
        }
        const entry = active;
        if (!entry || entry.id !== message.id) return true;
        if (message.action === 'stop') { finish(entry, String(message.error || 'Microphone/camera disconnected').slice(0, 300), false); return true; }
        if (host && message.action === 'transmit') {
            const enabled = message.enabled === true && (!entry.info.pushToTalk || !document.hidden);
            entry.stream?.getTracks().forEach(track => { track.enabled = enabled; });
            return true;
        }
        if (!host && message.action === 'released') { entry.onrelease?.(); return true; }
        // Serialize SDP and ICE, including candidates arriving before SDP.
        entry.work = entry.work.then(async () => {
            if (entry.closed) return;
            if (message.action === 'candidate' && message.candidate) {
                if (entry.pc?.remoteDescription) await entry.pc.addIceCandidate(message.candidate);
                else if (entry.candidates.length < 64) entry.candidates.push(message.candidate);
            } else if (message.action === 'description') {
                const description = message.description;
                if (description?.type !== (host ? 'answer' : 'offer') || typeof description.sdp !== 'string' || description.sdp.length > 100000) throw new Error('Invalid media connection');
                const pc = entry.pc || peer(entry);
                if (!host) pc.ontrack = event => {
                    if (entry.closed) return;
                    entry.stream = event.streams[0]; ready(entry);
                };
                await pc.setRemoteDescription(description);
                if (entry.closed) return;
                for (const candidate of entry.candidates.splice(0)) await pc.addIceCandidate(candidate);
                if (!host) {
                    await pc.setLocalDescription(await pc.createAnswer());
                    if (!entry.closed) post(entry, 'description', { description: pc.localDescription.toJSON() });
                }
            }
        }).catch(error => finish(entry, error.message));
        return true;
    }
    const release = () => {
        if (!host || !active?.info.pushToTalk) return;
        active.stream?.getTracks().forEach(track => { track.enabled = false; });
        post(active, 'released');
    };
    const visibility = () => { if (document.hidden) release(); };
    const close = () => { if (active) finish(active); closed = true;
        window.removeEventListener('pagehide', close); window.removeEventListener('blur', release); document.removeEventListener?.('visibilitychange', visibility); };
    window.addEventListener('pagehide', close);
    if (host) { window.addEventListener('blur', release); document.addEventListener?.('visibilitychange', visibility); }
    return { handle, close, get busy() { return !!active; },
        request(info) {
            if (host || closed || active) throw new Error('Microphone/camera is unavailable or already active');
            const entry = createEntry(++sequence, info);
            const result = new Promise((resolve, reject) => { entry.resolve = resolve; entry.reject = reject; });
            post(entry, 'request', { info: { audio: !!info.audio, video: !!info.video, pushToTalk: !!info.pushToTalk } });
            return { result, close: () => finish(entry),
                setTransmitting(enabled) { if (!entry.closed) post(entry, 'transmit', { enabled: !!enabled }); },
                set onended(callback) { entry.onended = callback; },
                set onrelease(callback) { entry.onrelease = callback; },
            };
        },
    };
}

module.exports = { createLiveMediaBridge };
