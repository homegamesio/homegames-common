'use strict';
// Shared camera consent/recording UI, embedded unchanged in the trusted parent
// of isolated games. The result travels through the ordinary media protocol.
function recordVideo(window, info) {
    const { document, navigator, MediaRecorder, performance, Blob } = window;
    const btoa = value => window.btoa(value);
    const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
    class VideoRecorder {
        constructor(send) {
            this.send = send; this.container = document.body;
            this.hidden = () => { if (document.hidden) this.fail('Recording cancelled because the page was hidden. Try again.'); };
            document.addEventListener('visibilitychange', this.hidden);
        }
        request(info) {
            const duration = Math.min(30, Math.max(1, Number(info.durationSeconds) || 30));
            const dialog = document.createElement('dialog');
            dialog.setAttribute('aria-label', 'Record video');
            dialog.style.cssText = 'box-sizing:border-box;margin:auto;padding:20px;width:min(440px,94vw);max-height:94vh;overflow:auto;border:2px solid #30213e;border-radius:20px;background:#fff8eb;color:#30213e;font:16px system-ui;text-align:center';
            const title = document.createElement('h2'); title.textContent = 'Record video'; title.style.cssText = 'margin:0 0 8px';
            const prompt = document.createElement('p'); prompt.textContent = String(info.prompt || '').slice(0, 120);
            prompt.style.cssText = 'font-size:24px;font-weight:800;overflow-wrap:anywhere;margin:8px 0 16px';
            const preview = document.createElement('video'); preview.muted = true; preview.autoplay = true; preview.playsInline = true;
            preview.style.cssText = 'display:none;width:100%;max-height:30vh;object-fit:contain;background:#30213e;border-radius:12px;transform:scaleX(-1)';
            const status = document.createElement('p');
            status.textContent = `Enable your camera and microphone. Your ${duration}-second video will be shared with everyone in this game after recording.`;
            status.setAttribute('aria-live', 'polite');
            const start = document.createElement('button'); start.textContent = 'Enable camera & microphone';
            const cancel = document.createElement('button'); cancel.textContent = 'Cancel';
            for (const button of [start, cancel]) button.style.cssText = 'padding:13px 16px;margin:5px;border:0;border-radius:10px;background:#30213e;color:#fff8eb;font:600 15px system-ui;cursor:pointer';
            cancel.style.background = '#e8dfd2'; cancel.style.color = '#30213e';
            dialog.append(title, prompt, preview, status, start, cancel); this.container.appendChild(dialog);
            const maxBytes = Math.min(MAX_UPLOAD_BYTES, Math.max(128 * 1024, Math.floor(Number(info.maxBytes) || MAX_UPLOAD_BYTES)));
            const current = this.active = { id: info.id, duration, maxBytes, dialog, preview, status, start, cancel, chunks: [], size: 0 };
            cancel.onclick = () => this.fail('Recording cancelled. You can try again.');
            dialog.oncancel = event => { event.preventDefault(); cancel.onclick(); };
            start.onclick = async () => {
                start.disabled = true;
                try {
                    if (typeof MediaRecorder === 'undefined') throw new Error('This browser cannot record video. Try a current browser.');
                    if (!navigator.mediaDevices?.getUserMedia) throw new Error('Camera recording needs HTTPS or localhost.');
                    const stream = await navigator.mediaDevices.getUserMedia({
                        audio: { echoCancellation: true, noiseSuppression: true },
                        video: { width: { ideal: 640 }, height: { ideal: 360 }, frameRate: { ideal: 20, max: 24 }, facingMode: 'user' },
                    });
                    if (this.active !== current) { stream.getTracks().forEach(track => track.stop()); return; }
                    current.stream = stream;
                    for (const track of stream.getTracks()) track.onended = () => this.fail('Camera or microphone disconnected. Please try again.');
                    preview.srcObject = stream; preview.style.display = 'block'; await preview.play();
                    if (this.active !== current) return;
                    status.textContent = 'Check your framing, then start recording.';
                    start.textContent = `Record ${duration} seconds`; start.disabled = false;
                    start.onclick = () => this.countdown(current);
                } catch (error) { if (this.active === current) this.fail(error.message || 'Unable to access camera and microphone'); }
            };
            dialog.showModal(); start.focus();
        }
        countdown(current) {
            if (this.active !== current) return;
            current.start.disabled = true;
            let count = 3; current.status.textContent = `Get ready… ${count}`;
            current.countdown = setInterval(() => {
                count--;
                if (count) current.status.textContent = `Get ready… ${count}`;
                else { clearInterval(current.countdown); this.start(current); }
            }, 1000);
        }
        start(current) {
            if (this.active !== current) return;
            try {
                const mimeType = ['video/webm;codecs=vp8,opus', 'video/mp4', 'video/webm']
                    .find(type => MediaRecorder.isTypeSupported(type));
                const recorder = current.recorder = new MediaRecorder(current.stream, {
                    ...(mimeType ? { mimeType } : {}),
                    videoBitsPerSecond: Math.min(650000, Math.max(100000, Math.floor(current.maxBytes * 8 / current.duration * 0.75) - 64000)),
                    audioBitsPerSecond: 64000,
                });
                recorder.ondataavailable = event => {
                    if (this.active !== current || !event.data.size) return;
                    current.size += event.data.size;
                    if (current.size > current.maxBytes) { this.fail('This recording is too large. Please try again.'); return; }
                    current.chunks.push(event.data);
                };
                recorder.onerror = () => { if (this.active === current) this.fail('The camera could not finish recording. Please try again.'); };
                recorder.onstop = () => this.finish(current);
                recorder.start(1000);
                const deadline = performance.now() + current.duration * 1000;
                const update = () => { current.status.textContent = `RECORDING · ${Math.max(0, Math.ceil((deadline - performance.now()) / 1000))} seconds left`; };
                update(); current.clock = setInterval(update, 200);
                current.timer = setTimeout(() => {
                    clearInterval(current.clock);
                    current.status.textContent = 'Sending recording…';
                    recorder.stop(); this.stopTracks(current);
                }, current.duration * 1000);
            } catch (error) { this.fail(error.message || 'Unable to start recording'); }
        }
        async finish(current) {
            if (this.active !== current) return;
            try {
                const contentType = current.recorder.mimeType || current.chunks[0]?.type || 'video/webm';
                const blob = new Blob(current.chunks, { type: contentType });
                if (!blob.size || blob.size > current.maxBytes) throw new Error('Recording was empty or too large. Please try again.');
                const bytes = new Uint8Array(await blob.arrayBuffer());
                if (this.active !== current) return;
                let binary = '';
                for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
                const message = { type: 'media', action: 'record-result', id: current.id, data: btoa(binary), contentType,
                    fileName: contentType.includes('mp4') ? 'recording.mp4' : 'recording.webm' };
                this.cancel(current.id); this.send(message);
            } catch (error) { if (this.active === current) this.fail(error.message || 'Unable to send recording'); }
        }
        stopTracks(current) {
            current.stream?.getTracks().forEach(track => { track.onended = null; track.stop(); });
            current.preview.srcObject = null;
        }
        cancel(id) {
            const current = this.active;
            if (!current || current.id !== id) return;
            this.active = null;
            clearTimeout(current.timer); clearInterval(current.clock); clearInterval(current.countdown);
            if (current.recorder?.state !== 'inactive' && current.recorder) current.recorder.stop();
            this.stopTracks(current); current.dialog.close(); current.dialog.remove(); current.chunks = [];
        }
        fail(error) {
            const id = this.active?.id;
            if (!id) return;
            this.cancel(id); this.send({ type: 'media', action: 'record-result', id, error });
        }
        destroy() { this.cancel(this.active?.id); document.removeEventListener('visibilitychange', this.hidden); }
    }
    let capture, finish;
    const result = new Promise((resolve, reject) => { finish = message => {
        capture.destroy(); message.error ? reject(new Error(message.error)) : resolve(message);
    }; });
    capture = new VideoRecorder(finish); capture.request(info);
    return { result, close() { capture.fail('Recording cancelled'); } };
}
module.exports = { recordVideo };
