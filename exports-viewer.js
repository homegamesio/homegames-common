'use strict';

// Client UI only. Self-contained so standalone HTML can embed the same viewer
// in its trusted parent; games never receive DOM or download capabilities.
function createExportsViewer(window, { list, read }) {
    const document = window.document;
    const el = (tag, text, parent) => { const node = document.createElement(tag); if (text) node.textContent = text; parent?.append(node); return node; };
    const dialog = el('dialog'); dialog.className = 'hg-exports'; dialog.setAttribute('aria-label', 'Game exports');
    const style = el('style', null, dialog);
    style.textContent = `.hg-exports{box-sizing:border-box;width:min(760px,calc(100vw - 24px));max-height:calc(100dvh - 24px);margin:auto;padding:20px;border:1px solid #4a5049;border-radius:16px;background:#202321;color:#f6f6ee;font:14px/1.5 system-ui,sans-serif;text-align:left;overflow:auto;box-shadow:0 24px 80px #0009}
        .hg-exports::backdrop{background:#080c0ac9}.hg-exports *{box-sizing:border-box}.hg-exports h2{font-size:22px;margin:0}.hg-exports p{margin:10px 0;color:#b7bfb5}.hg-exports button{min-height:44px;padding:8px 12px;border:1px solid #596157;border-radius:8px;background:#30372e;color:#f6f6ee;font:inherit;cursor:pointer;text-align:left}.hg-exports button:disabled{opacity:.5;cursor:wait}.hg-exports :focus-visible{outline:2px solid #fff78e;outline-offset:3px}.hg-exports-head{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.hg-exports-head h2{flex:1}.hg-exports-body{display:grid;grid-template-columns:minmax(140px,1fr) minmax(0,2fr);gap:16px}.hg-exports-files{display:flex;flex-direction:column;gap:6px;max-height:55dvh;overflow:auto}.hg-exports-files button{overflow-wrap:anywhere}.hg-exports-files button[aria-pressed=true]{border-color:#fff78e;background:#414530}.hg-exports-preview{min-width:0;overflow-wrap:anywhere}.hg-exports-preview h3{font-size:15px;margin:0 0 12px}.hg-exports-preview img,.hg-exports-preview video{display:block;max-width:100%;max-height:42dvh;background:#101211;margin:0 auto 12px}.hg-exports-preview audio{width:100%;margin-bottom:12px}.hg-exports-preview pre{white-space:pre-wrap;max-height:38dvh;overflow:auto;background:#101211;padding:12px;font:12px/1.5 monospace}.hg-exports-preview .hg-exports-save{background:#fff78e;color:#22261e;border-color:#fff78e}@media(max-width:520px){.hg-exports{padding:16px}.hg-exports-body{grid-template-columns:1fr}.hg-exports-files{max-height:150px}.hg-exports-preview img,.hg-exports-preview video{max-height:30dvh}}`;
    const head = el('div', null, dialog); head.className = 'hg-exports-head'; el('h2', 'Game exports', head);
    const refresh = el('button', 'Refresh', head), closeButton = el('button', 'Close', head);
    const status = el('p', 'Loading exports…', dialog); status.setAttribute('role', 'status');
    const body = el('div', null, dialog); body.className = 'hg-exports-body';
    const files = el('div', null, body); files.className = 'hg-exports-files'; files.setAttribute('aria-label', 'Export files');
    const preview = el('div', null, body); preview.className = 'hg-exports-preview';
    let closed = false, busy = false, previewUrl, finish;
    const result = new Promise(resolve => { finish = resolve; });
    function clearPreview() { preview.querySelectorAll('video,audio').forEach(media => { media.pause(); media.removeAttribute('src'); media.load(); }); preview.replaceChildren(); if (previewUrl) window.URL.revokeObjectURL(previewUrl); previewUrl = null; }
    function close() { if (closed) return; closed = true; clearPreview(); dialog.close(); dialog.remove(); finish(); }
    const validName = name => typeof name === 'string' && /^[A-Za-z0-9_][A-Za-z0-9_. -]{0,119}$/.test(name) && !/[ .]$/.test(name);
    const sizeText = size => size < 1024 ? `${size} B` : size < 1048576 ? `${(size / 1024).toFixed(1)} KB` : `${(size / 1048576).toFixed(1)} MB`;
    function setBusy(value) { busy = value; refresh.disabled = value; files.querySelectorAll('button').forEach(button => { button.disabled = value; }); }
    function contentType(name, bytes) {
        const at = (offset, text) => [...text].every((ch, i) => bytes[offset + i] === ch.charCodeAt(0));
        if (at(0, '\x89PNG\r\n\x1a\n')) return 'image/png';
        if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return 'image/jpeg';
        if (at(0, 'GIF87a') || at(0, 'GIF89a')) return 'image/gif';
        if (at(0, 'RIFF') && at(8, 'WEBP')) return 'image/webp';
        if (at(0, 'RIFF') && at(8, 'WAVE')) return 'audio/wav';
        if (at(0, '\x1a\x45\xdf\xa3')) return /\.(weba|opus)$/i.test(name) ? 'audio/webm' : 'video/webm';
        if (at(4, 'ftyp')) return /\.(m4a|aac)$/i.test(name) ? 'audio/mp4' : 'video/mp4';
        if (at(0, 'OggS')) return /\.ogv$/i.test(name) ? 'video/ogg' : 'audio/ogg';
        if (at(0, 'ID3') || (bytes[0] === 255 && (bytes[1] & 224) === 224)) return 'audio/mpeg';
        return 'application/octet-stream';
    }
    async function select(file, button) {
        if (closed || busy) return;
        setBusy(true); clearPreview(); status.textContent = `Loading ${file.name}…`;
        files.querySelectorAll('button').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
        try {
            const value = await read(file.name);
            if (closed) return;
            if (value.name !== file.name || !(value.bytes instanceof Uint8Array) || value.bytes.length > 16 * 1024 * 1024) throw new Error('Invalid export file');
            const { name, bytes } = value, type = contentType(name, bytes);
            el('h3', name, preview); status.textContent = `${sizeText(bytes.length)} · Shared with everyone in this game`;
            previewUrl = window.URL.createObjectURL(new window.Blob([bytes], { type }));
            if (/^(image|audio|video)\//.test(type)) {
                const media = el(type.startsWith('image/') ? 'img' : type.split('/')[0], null, preview);
                if (media.tagName === 'IMG') media.alt = name;
                else { media.controls = true; media.preload = 'metadata'; media.setAttribute('playsinline', ''); }
                media.src = previewUrl;
                media.onerror = () => { if (!closed && media.isConnected) status.textContent = 'This browser cannot preview this file. You can still save it.'; };
            } else if (/\.(json|txt|csv|md|js|html|css|xml|svg|yaml|yml)$/i.test(name)) {
                const text = new window.TextDecoder().decode(bytes.subarray(0, 65536));
                el('pre', text || '(Empty file)', preview);
                if (bytes.length > 65536) el('p', 'Preview shows the first 64 KB. Save file includes all bytes.', preview);
            } else el('p', 'No preview for this format. Save it to open in another app.', preview);
            const save = el('button', 'Save file', preview); save.className = 'hg-exports-save';
            save.onclick = () => { const url = window.URL.createObjectURL(new window.Blob([bytes], { type })); const link = el('a', null, document.body); link.href = url; link.download = name; link.click(); link.remove(); window.setTimeout(() => window.URL.revokeObjectURL(url), 30000); };
        } catch (error) { if (!closed) status.textContent = error.message; }
        finally { if (!closed) setBusy(false); }
    }
    async function load() {
        if (closed || busy) return;
        setBusy(true); clearPreview(); files.replaceChildren(); status.textContent = 'Loading exports…';
        try {
            const entries = await list();
            if (closed) return;
            if (!Array.isArray(entries) || entries.length > 128 || entries.some(file => !validName(file.name) || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > 16 * 1024 * 1024)) throw new Error('Invalid export list');
            status.textContent = entries.length ? 'Choose a file to preview and save. These files are shared with everyone in this game.' : 'No exports yet. Files saved by this game will appear here.';
            for (const file of entries) { const button = el('button', `${file.name} · ${sizeText(file.size)}`, files); button.setAttribute('aria-pressed', 'false'); button.onclick = () => select(file, button); }
        } catch (error) { if (!closed) status.textContent = error.message; }
        finally { if (!closed) setBusy(false); }
    }
    refresh.onclick = load; closeButton.onclick = close; dialog.oncancel = event => { event.preventDefault(); close(); };
    document.body.append(dialog); dialog.showModal(); closeButton.focus(); void load();
    return { result, close };
}
module.exports = { createExportsViewer };
