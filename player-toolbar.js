'use strict';

// Self-contained: downloaded games embed this function without website assets.
function createPlayerToolbar(window, options = {}) {
    const document = window.document, actions = new Map(), running = new Set();
    const element = (tag, className, text) => {
        const node = document.createElement(tag); node.className = className;
        if (text) node.textContent = text; return node;
    };
    const button = (className, text) => { const node = element('button', className, text); node.type = 'button'; return node; };
    const bar = element('header', 'hg-player-bar'); bar.setAttribute('aria-label', 'Game controls');
    const style = element('style', '');
    style.textContent = `
.hg-player-bar,.hg-player-menu{box-sizing:border-box;color:#f6f6ee;font:14px/1.4 system-ui,sans-serif}
.hg-player-bar *,.hg-player-menu *{box-sizing:border-box}
.hg-player-bar{position:absolute;inset:0 0 auto;z-index:10;width:100%;height:0;pointer-events:none;--hg-safe-top:env(safe-area-inset-top,0px);--hg-safe-left:env(safe-area-inset-left,0px);--hg-safe-right:env(safe-area-inset-right,0px);--hg-safe-bottom:env(safe-area-inset-bottom,0px)}
.hg-player-bar button,.hg-player-menu button,.hg-player-menu a{font:inherit;color:inherit;border:1px solid #4a5049;border-radius:12px;background:#252b25;cursor:pointer;text-decoration:none}
.hg-player-bar button,.hg-player-menu button{min-height:44px;padding:10px 14px}
.hg-player-bar .hg-player-home{position:absolute;top:calc(8px + var(--hg-safe-top));left:calc(8px + var(--hg-safe-left));width:44px;height:44px;padding:6px;background:#202820;pointer-events:auto;display:grid;place-items:center}
.hg-player-home img{display:block;width:30px;height:30px;object-fit:contain}
.hg-player-bar button:hover,.hg-player-menu button:hover,.hg-player-menu a:hover{background:#394036}
.hg-player-bar :focus-visible,.hg-player-menu :focus-visible{outline:2px solid #fff78e;outline-offset:3px}
.hg-player-bar [hidden],.hg-player-menu [hidden]{display:none!important}
.hg-player-bar button:disabled,.hg-player-menu button:disabled{opacity:.45;cursor:default}
.hg-player-menu{position:fixed;inset:0;margin:0;width:100%;height:100%;height:100dvh;max-width:none;max-height:none;overflow:auto;padding:max(24px,env(safe-area-inset-top)) max(20px,env(safe-area-inset-right)) max(24px,env(safe-area-inset-bottom)) max(20px,env(safe-area-inset-left));border:0;border-radius:0;background:#141b16}
.hg-player-menu::backdrop{background:#080c0a}
.hg-player-menu-content{width:100%;max-width:960px;margin:0 auto}
.hg-player-menu-header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:24px}
.hg-player-menu-brand{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600}
.hg-player-menu-brand img{width:28px;height:28px}
.hg-player-menu .hg-player-menu-close{background:#fff78e;color:#22261e;border-color:#fff78e;flex:none}
.hg-player-heading{margin:0 0 24px;text-align:center}.hg-player-title{margin:0;font-size:clamp(24px,4vw,36px);line-height:1.2;overflow-wrap:anywhere;font-weight:600}
.hg-player-author{display:block;font-size:14px;font-weight:400;color:#b7bfb5;margin-top:8px}
.hg-player-sharing{max-width:420px;margin:0 auto 32px;text-align:center}
.hg-player-share-qr{width:min(224px,100%);aspect-ratio:1;margin:0 auto 16px;background:#fff;padding:8px;border-radius:8px}
.hg-player-share-qr svg{display:block;width:100%;height:100%}
.hg-player-share-caption{margin:0 0 12px;font-size:15px}
.hg-player-share-status{margin:12px 0;color:#c4cec0;overflow-wrap:anywhere;min-height:20px}
.hg-player-share-note{margin:12px 0 0;color:#b7bfb5;font-size:12px}
.hg-player-share-actions{display:flex;justify-content:center;flex-wrap:wrap;gap:8px}
.hg-player-menu .hg-player-share-toggle{background:#fff78e;color:#22261e;border-color:#fff78e}
.hg-player-share-link{width:100%;min-height:44px;margin-top:12px;border:1px solid #4a5049;border-radius:8px;padding:10px;background:#0c110e;color:#f6f6ee;font:12px system-ui,sans-serif}
.hg-player-sections{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:24px;padding-top:24px;border-top:1px solid #354235}
.hg-player-section h2{margin:0 0 12px;font-size:15px;font-weight:500;color:#c4cec0}
.hg-player-menu-actions{display:flex;flex-direction:column;gap:8px}
.hg-player-menu-actions>button{width:100%;min-height:44px;text-align:left}
.hg-player-action-help{display:block;color:#b7bfb5;font-size:12px;margin-top:4px}
.hg-player-menu-footer{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-top:24px;padding-top:20px;border-top:1px solid #354235}
.hg-player-menu .hg-player-leave{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:10px 18px}
.hg-player-status{color:#b7bfb5;white-space:pre-wrap;overflow-wrap:anywhere;margin:24px 0 0;font-size:12px}
.hg-player-brand{display:inline-flex;align-items:center;min-height:44px;padding:10px 14px}
.hg-player-name{max-width:420px;margin:0 auto 24px;display:flex;align-items:end;flex-wrap:wrap;gap:8px}.hg-player-name label{display:block;flex:1;min-width:160px}
.hg-player-name input{display:block;width:100%;min-height:44px;margin-top:8px;padding:10px;font:inherit;font-size:16px;color:inherit;background:#0c110e;border:1px solid #4a5049;border-radius:10px}
.hg-player-name p{width:100%;color:#c4cec0;margin:0;overflow-wrap:anywhere;font-size:12px}
.hg-player-attention{position:absolute;top:calc(60px + var(--hg-safe-top));left:calc(8px + var(--hg-safe-left));max-width:min(420px,calc(100% - 16px - var(--hg-safe-left)));padding:14px;background:#352c20;border:1px solid #8a7855;border-radius:12px;pointer-events:auto;box-shadow:0 8px 32px #0006}
.hg-player-attention p{margin:0 0 10px;overflow-wrap:anywhere}
@media(max-width:640px){.hg-player-sections{grid-template-columns:1fr;gap:20px}.hg-player-menu-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:480px){.hg-player-menu{padding: max(16px,env(safe-area-inset-top)) max(16px,env(safe-area-inset-right)) max(16px,env(safe-area-inset-bottom)) max(16px,env(safe-area-inset-left))}.hg-player-menu-header{gap:8px;margin-bottom:24px}.hg-player-menu-brand{font-size:14px}.hg-player-menu-brand img{width:24px;height:24px}.hg-player-menu .hg-player-menu-close{padding:10px}.hg-player-share-qr{width:208px}.hg-player-share-link{font-size:16px}}
`;
    const home = button('hg-player-home', '');
    home.setAttribute('aria-label', 'Open Homegames menu'); home.setAttribute('aria-haspopup', 'dialog');
    home.setAttribute('aria-expanded', 'false'); home.title = 'Homegames menu';
    const logo = element('img', ''); logo.alt = ''; logo.width = logo.height = 32;
    logo.src = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAIbElEQVRYR7WXC1BU5xmGn7M3rgICYRHjBQSiBUIUTQQ0oEZTIRdTihcy04xO22mbSWKTTDQql2jNbdKk06S2TdqmaWrspMk0tHViiEpqEEyCGmhEq0gEXS4r7HJZll2WPX/nnLO7LEhsOp3+Mwxw9j//9/7v973v9620cOHCpKSkab9blJ2wSq/XGfh/LwFjsjx2usl6pLt7eLNUXHz7oTde/eadcbFhWmgBQgIJgUBC+h8BKacop00+p882wgPfPfSBVL7j257d5fkGbdv4EsL/qvbc/7ny++ssBTyyjKSTkKSpr1Gx57hHqiovFZU7V4EY8Z2rhdrwncMMDnlU7BPeVz+eDNdHne8KQoAsBCGhISSazdya7GTL1iWBC/rfrnq6HqmqfIOo3HUXyL2BFKCDbRXtHDt2gp6eHvUWCgVRRiODHo9GiSwIIAtiy/9MYVB5J2dxDsuT3Dy8twAM+gnk+QBsFJW77gbZOs6AJLH3BTvV1e9jsVjUgMqlf7W+kG3V9USajLy+ppDdJ0+xaFossyIjOdLdyS1JZowmwe6PTvpyJpGVmcnam0w8sud2MAXVuIDKZwIMKACuTgCwvaKdo7XHsXRatMIE9m8p5u0Pm1m5dC4mg57pYdEkRZuYPiDhjoYuvZ5+ay8PvFmDEFruMzMzKUo38dDeAiTjJAb2qgDWi8qd6xCiFwmvBkKCR7e3Unf8U40B5ZEkcfgHmxh1OegQLvqdHgpnmOmQBPMU9U4LZ8zl5d32L3j+T59qRStJ5Ofnk2t2snVvIUwGEKiB8m+B3AfCPQWAzgAzBx7cxO9rT3JHlpmspFTkkV4coZGkm4wMhoXy5fmLtPQN81zNiQDodevWMU9q58dPXw9ARSl4e8eVIMHWJ85T39AYYEA58b6FqbT09HJf3gJiB3X8yzRIavh02vtspMyMp/3MVdLzZvHIy4cCAMrKykh0tvDosyvAoAuIXRH5U083+FRQvkFTgRj2MSAovf8j2ju6AgDmL78DecyN5exZbi3ZQP3+18guXo+to5VLTadYtmkzXxyuJnPlvTTX/AVbj1VNgQLA7GzhsWdXIAx6TYo+HY7LsLxMCy73+KQouGd9Dd09fQEA237+E/qGvDSfOM3tKzKw2Vyk3LYMEZqArbmWcJMbXUQiMfE30FhTzYFX3lIVWVRURLrRwuPPrQySoWZnVeMM3A+yHYTN58aCH25t4dSppoAKVtxTTEFpCQdf+xlL79tE5k3zuNjayoz5GcToZa5YrZyr/RsRC4o4+FIllo6rKgNZWVmsSJZ44vlV1/hA5bgRlYKwBopQMZEdu7s5cuQoFkuXylnmslzyVq0m/Rtx1LxXy90bS+jquEzs/ExMDhtNdR9yutmKY2CYgrtW8VrFHhVARkYGBXP17PipBiDYQ30ANoqKnfciie5AcpQCeWzHJerq6rFYFBVI3PXQI+TnzuPsyVZuSE2lp7mO6NlpzLoplQt1h4nLXov70se445aQEnqZbd+rUoNlZWZRmKxju8LA1DJUnPCe8fz7klC2pZ6LFzvo6uxSfcFo1GFOiKCr28HcOTFcbLMTHx/OwIALvV5iekwo1t5hEm6IYNTt5WqvE51OR3Z2NoVzBI8pVhxi/CorngwASspqcDjGUD19ihWg0t8qfQam9nL17lqrSElOITO8iwefKmDEK2g+04t9SPF2He++06TIcFIv8J3c39iBo92O1yuPN2qdRN+QB48smBFtCjQvrXH7BeT/2wdEQHiogVr9bM5dTSI5bzV2lwe3vZeGd94cByBk64S+779F8OWVoxtOdJG3dMaUrEz10OsVvHjATbc8l9mLcjGGhuAntfbXLwa1Y8UJ/Wvy/OBj5czZPszmcOJ901PwXScH96fo8HE7ZxzL0CdnBAYTJTXKvFDzygu+ZrSrGGQbQ0OjnD9uBYNEzh1J14xkxxs6yc9N+tq3VzbuPxLDYEI+clikSqrX6cAQEYnD5eHYqy8pAJSJqAhEP22XBhj8bT8WSaZ499wJALyyzJkWGzdnxk0e3ib9r+Hr7RuhqcXBwaY4ZubfTWhkJMLj4kLDx8y8eTF2YeKff/yFH8BKhHDR0T5I2x/aabMNsOWlZRNmxI4rQ0RNCyHGX3xBnj6ZEoXJl2tuxDw3A5cxgguN9aQtX62qYqTfjtMQxpBrjJa39iFV7VIYyFPP8Hi8nG/t59x5GyX3pgWahpLPzxq7uXVx4qRYU82GcPQfl3mvczlExasF57S0kbHkNgwR0+hzuHF6xtTLqQB2bC8Rjz+8GJ1Oi6f8DDs8NJ62snhhAgajnk8/62bBgjgiwrWRSis+4avmoLFb0sbvY5/YsaQ8RPfwqDrKDVst6OUxwhLnqDYhZBnvqItzb/8G6dE1a8T3k5PVU9Vu7RuBlWPtzmGcHg8zY2PBaFDNwy9+oexTNikDq06nTs+qaY2OcmJ4BPuDFVgGXGpA2TNKV937xMxOQa/TodfriYoMp/nv7yDtLCoST6T56A64mS+OP4bJhBQZca01KCAUAJJOBS68MmLUTd2VK3yy+UmcsqZnr2cU0dbMjWnzYagfp1fGiJcTf/1zEIDrimvqXOuio8HpRFZG9aD1pWOIN1aXYTDPVp86Oi8h6fREJM6asO/sgV9OBHBtmKkDX98IBF4BVRHxuNJziJqTykD1G0TeWYo+LEJ9VTNpQcv+fUjb1671PJmWbvDPSl/3+6CS70C9BH1H8YPrGxjg4zFlBNCTO2Sn1RCCNSwcvceDwe0mZHSEalufR1qbl3do3y233BlrnNgq/5Pd/XfcjO/WvtkJbGNj/Ojzzz+QcnJyZiSEhLyeHRW1UidJX4kiuOteD5yfXlUVX7FRFsLTNDh41Op2b/43wV/aTZKTkWoAAAAASUVORK5CYII='; home.append(logo);
    const attention = element('div', 'hg-player-attention'); attention.hidden = true;
    const attentionText = element('p', ''); attentionText.setAttribute('role', 'alert');
    const attentionAction = button('', 'Open menu');
    attention.append(attentionText, attentionAction); bar.append(style, home, attention);

    const menu = element('dialog', 'hg-player-menu'); menu.setAttribute('aria-label', 'Homegames menu');
    const content = element('div', 'hg-player-menu-content');
    const header = element('div', 'hg-player-menu-header'), brand = element('div', 'hg-player-menu-brand');
    const brandLogo = element('img', ''); brandLogo.src = logo.src; brandLogo.alt = '';
    brand.append(brandLogo, element('span', '', 'Homegames'));
    const done = button('hg-player-menu-close', 'Back to game');
    header.append(brand, done);
    const heading = element('div', 'hg-player-heading'), title = element('h1', 'hg-player-title');
    const titleName = element('span', ''), author = element('span', 'hg-player-author');
    title.append(titleName, author); heading.append(title);
    const sections = element('div', 'hg-player-sections');
    const groups = new Map();
    let menuActive = false, disposed = false;
    const groupDefinitions = [['together', 'Session'], ['downloads', 'Downloads'], ['tools', 'Game tools']];
    for (const [key, label] of groupDefinitions) {
        const panel = element('section', 'hg-player-section'); panel.setAttribute('aria-label', label);
        const panelTitle = element('h2', '', label);
        const list = element('div', 'hg-player-menu-actions');
        panel.append(panelTitle, list); sections.append(panel);
        groups.set(key, { panel, list });
    }
    const leave = element(typeof options.home === 'string' ? 'a' : 'button', 'hg-player-leave', 'Leave game');
    leave.hidden = !options.home;
    if (typeof options.home === 'string') leave.href = options.home;
    else { leave.type = 'button'; leave.onclick = () => { closeMenu(); options.home?.(); }; }
    const status = element('p', 'hg-player-status'); status.setAttribute('role', 'status'); status.setAttribute('aria-atomic', 'true');
    const website = element('a', 'hg-player-brand', 'homegames.io');
    website.href = 'https://homegames.io/'; website.target = '_blank'; website.rel = 'noopener noreferrer';
    const footer = element('div', 'hg-player-menu-footer'); footer.append(website, leave);
    const nameForm = element('form', 'hg-player-name'); nameForm.hidden = true;
    const nameLabel = element('label', '', 'Your name'), nameInput = element('input', '');
    nameInput.type = 'text'; nameInput.maxLength = 32; nameInput.required = true; nameInput.autocomplete = 'nickname';
    nameInput.setAttribute('aria-label', 'Your name'); nameLabel.append(nameInput);
    const nameSave = button('', 'Save name'); nameSave.type = 'submit';
    const nameStatus = element('p', ''); nameStatus.setAttribute('role', 'status');
    nameForm.append(nameLabel, nameSave, nameStatus);
    let playerName = '', changeName, nameDirty = false;
    nameInput.oninput = () => { nameDirty = true; };
    nameForm.onsubmit = async event => {
        event.preventDefault(); if (!changeName || nameSave.disabled) return;
        nameSave.disabled = true;
        try { playerName = await changeName(nameInput.value); nameInput.value = playerName; nameDirty = false; nameStatus.textContent = 'Name updated for this session.'; }
        catch (error) { nameStatus.textContent = error.message || String(error); }
        finally { nameSave.disabled = false; }
    };
    const sharingSection = element('section', 'hg-player-sharing'); sharingSection.hidden = true;
    sharingSection.setAttribute('aria-label', 'Invite and share');
    const qr = element('div', 'hg-player-share-qr'); qr.hidden = true;
    const shareCaption = element('p', 'hg-player-share-caption');
    const shareStatus = element('p', 'hg-player-share-status'); shareStatus.setAttribute('role', 'status');
    const shareActions = element('div', 'hg-player-share-actions');
    const shareToggle = button('hg-player-share-toggle', 'Share with friends');
    const shareCopy = button('', 'Copy link'), shareRetry = button('', 'Try again');
    const shareLink = element('input', 'hg-player-share-link'); shareLink.readOnly = true; shareLink.hidden = true;
    const shareNote = element('p', 'hg-player-share-note');
    shareActions.append(shareToggle, shareCopy, shareRetry);
    sharingSection.append(qr, shareCaption, shareStatus, shareActions, shareLink, shareNote);
    content.append(header, heading, sharingSection, nameForm, sections, status, footer);
    menu.append(content); document.body.append(menu);
    let sharing, shareMode = 'session', shareGeneration = 0, shareUrl = '', copyRequested = false;
    const sharingStatus = { session: '', copy: '' };
    function paintQr(rows, mode) {
        const size = rows?.length;
        if (!Array.isArray(rows) || size < 21 || size > 177 || (size - 21) % 4
            || rows.some(row => typeof row !== 'string' || row.length !== size || !/^[01]+$/.test(row))) throw new Error('Could not create the QR code. Try again.');
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', `0 0 ${size + 8} ${size + 8}`); svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', mode === 'session' ? 'Join session QR code' : 'Share game copy QR code');
        svg.setAttribute('shape-rendering', 'crispEdges');
        const background = document.createElementNS(svg.namespaceURI, 'rect');
        background.setAttribute('width', size + 8); background.setAttribute('height', size + 8); background.setAttribute('fill', '#fff');
        const path = document.createElementNS(svg.namespaceURI, 'path'); path.setAttribute('fill', '#000');
        let data = '';
        rows.forEach((row, y) => {
            for (let x = 0; x < size; x++) if (row[x] === '1') {
                const start = x; while (x + 1 < size && row[x + 1] === '1') x++;
                const length = x - start + 1; data += `M${start + 4} ${y + 4}h${length}v1h-${length}z`;
            }
        });
        path.setAttribute('d', data); svg.append(background, path); qr.replaceChildren(svg); qr.hidden = false;
    }
    function sharingLabels() {
        const solo = sharing?.multiplayer === false, waiting = solo && !copyRequested;
        shareCaption.textContent = waiting ? 'Share a playable copy of this game with your friends.' : shareMode === 'session'
            ? 'Use the QR code to invite a friend to your multiplayer session'
            : 'Use the QR code to share a playable copy of this game with your friends.';
        shareToggle.textContent = solo || shareMode === 'session' ? 'Share with friends' : 'Invite to session';
        shareToggle.hidden = sharing?.copy === false || (solo && copyRequested);
        shareCopy.hidden = waiting;
        shareLink.setAttribute('aria-label', shareMode === 'session' ? 'Invitation link' : 'Game copy link');
        shareNote.textContent = waiting ? '' : shareMode === 'session' ? 'Keep this game open while you play together.' : 'Keep this game open while they download.';
    }
    async function refreshSharing() {
        if (!sharing || !menu.open || disposed) return;
        const generation = ++shareGeneration, provider = sharing, mode = shareMode;
        shareUrl = ''; qr.hidden = true; qr.replaceChildren(); shareLink.value = ''; shareLink.hidden = true;
        shareCopy.disabled = true; shareRetry.hidden = true; sharingLabels();
        if (sharing.multiplayer === false && !copyRequested) { shareStatus.textContent = ''; return; }
        shareStatus.textContent = mode === 'session' ? 'Creating invitation…' : 'Preparing game copy…';
        try {
            const value = await provider.getLink(mode);
            if (generation !== shareGeneration || !menu.open || disposed) return;
            if (typeof value?.url !== 'string' || value.url.length > 8192 || !['http:', 'https:'].includes(new URL(value.url).protocol)) throw new Error('Could not create a sharing link. Try again.');
            paintQr(value.qr, mode);
            shareUrl = value.url; shareLink.value = shareUrl; shareLink.hidden = false; shareCopy.disabled = false;
            shareStatus.textContent = sharingStatus[mode] || '';
        } catch (error) {
            if (generation !== shareGeneration || !menu.open || disposed) return;
            shareStatus.textContent = error.message || String(error); shareRetry.hidden = false;
        }
    }
    shareToggle.onclick = () => {
        shareMode = sharing?.multiplayer === false || shareMode === 'session' ? 'copy' : 'session';
        if (shareMode === 'copy') copyRequested = true;
        refreshSharing();
    };
    shareRetry.onclick = () => refreshSharing();
    shareCopy.onclick = async () => {
        if (!shareUrl) return;
        const generation = shareGeneration, url = shareUrl;
        try {
            await window.navigator.clipboard.writeText(url);
            if (generation === shareGeneration && menu.open) shareStatus.textContent = 'Link copied';
        } catch (_) {
            if (generation !== shareGeneration || !menu.open) return;
            shareLink.focus(); shareLink.select(); shareStatus.textContent = 'Copy the selected link';
        }
    };
    const resume = () => { if (menuActive) { menuActive = false; shareGeneration++; home.setAttribute('aria-expanded', 'false'); options.onClose?.(); } };
    function closeMenu() { if (menu.open) menu.close(); resume(); }
    function openMenu(mode) {
        if (disposed) return;
        if (!menu.open) {
            nameInput.value = playerName; nameDirty = false; nameStatus.textContent = ''; menuActive = true;
            shareMode = sharing?.multiplayer === false ? 'copy' : 'session';
            home.setAttribute('aria-expanded', 'true'); options.onOpen?.();
            try { menu.showModal(); } catch (error) { resume(); throw error; }
        }
        if ((mode === 'copy' && sharing?.copy !== false) || (mode === 'session' && sharing?.multiplayer !== false)) {
            shareMode = mode;
            if (mode === 'copy') copyRequested = true;
        }
        refreshSharing(); done.focus();
    }
    home.onclick = () => openMenu();
    done.onclick = closeMenu;
    menu.addEventListener('close', () => { if (!menu.open) resume(); });
    attentionAction.onclick = () => actions.has('retry') ? api.runAction('retry') : openMenu();
    const actionGroup = key => ['share', 'copy-share', 'manual-connect', 'privacy'].includes(key) ? 'together'
        : ['install', 'download-html', 'download-zip'].includes(key) ? 'downloads'
        : key === 'retry' ? 'together' : 'tools';
    function updateGroups() {
        for (const [key, action] of actions) action.button.hidden = !!action.value.hidden || (!!sharing && ['share', 'copy-share'].includes(key));
        for (const [key, group] of groups) {
            group.panel.hidden = !Array.from(actions.values()).some(action => action.group === key && !action.button.hidden);
        }
        sections.hidden = Array.from(groups.values()).every(group => group.panel.hidden);
    }
    function updateAttention(show) {
        attention.hidden = !show || !status.textContent;
        attentionText.textContent = attention.hidden ? '' : status.textContent;
        attentionAction.textContent = actions.has('retry') ? actions.get('retry').value.label : 'Open menu';
    }

    // Measure the complete client, before reserving space, so resizing cannot
    // oscillate between top/side layouts. The button sits in existing bars first.
    let gameArea, frame, observer, aspectRatio, binding;
    const fit = (width, height, ratio) => {
        const gameWidth = Math.min(width, height * ratio);
        return gameWidth * (gameWidth / ratio);
    };
    function layout() {
        if (!gameArea || !frame || disposed) return;
        const width = frame.clientWidth, height = frame.clientHeight;
        if (!(width > 0 && height > 0)) return;
        const css = window.getComputedStyle?.(bar);
        const inset = edge => Math.max(0, parseFloat(css?.getPropertyValue('--hg-safe-' + edge)) || 0);
        const left = inset('left'), top = inset('top'), right = inset('right'), bottom = inset('bottom');
        const w = Math.max(1, width - left - right), h = Math.max(1, height - top - bottom);
        const ratio = aspectRatio ? aspectRatio.x / aspectRatio.y : w / h;
        const naturalW = Math.min(w, h * ratio), naturalH = naturalW / ratio;
        let x = left, y = top, areaW = w, areaH = h, mode;
        if ((w - naturalW) / 2 >= 60) mode = 'left-bar';
        else if ((h - naturalH) / 2 >= 60) mode = 'top-bar';
        else if (fit(Math.max(1, w - 60), h, ratio) >= fit(w, Math.max(1, h - 60), ratio)) {
            x += Math.min(60, w - 1); areaW = Math.max(1, w - 60); mode = 'left-strip';
        } else {
            y += Math.min(60, h - 1); areaH = Math.max(1, h - 60); mode = 'top-strip';
        }
        const bounds = { position: 'absolute', left: x + 'px', top: y + 'px', width: areaW + 'px', height: areaH + 'px', minHeight: '0', minWidth: '0' };
        for (const [key, value] of Object.entries(bounds)) if (gameArea.style[key] !== value) gameArea.style[key] = value;
        bar.setAttribute('data-layout', mode);
    }
    function unbind() {
        observer?.disconnect(); observer = null;
        window.removeEventListener?.('resize', layout);
        window.visualViewport?.removeEventListener('resize', layout);
        if (binding) {
            for (const [key, value] of Object.entries(binding.areaStyle)) gameArea.style[key] = value;
            frame.style.position = binding.position;
        }
        binding = null; gameArea = frame = null;
    }
    const api = {
        bar, menu, statusElement: status,
        setGameArea(area, owner = area?.parentElement) {
            if (area === gameArea && owner === frame) { layout(); return; }
            unbind(); if (!area || !owner || disposed) return;
            gameArea = area; frame = owner;
            binding = { position: frame.style.position, areaStyle: {} };
            for (const key of ['position', 'left', 'top', 'width', 'height', 'minHeight', 'minWidth']) binding.areaStyle[key] = area.style[key];
            if (!['relative', 'absolute', 'fixed'].includes(window.getComputedStyle?.(frame)?.position)) frame.style.position = 'relative';
            if (bar.parentElement !== frame) frame.append(bar);
            if (window.ResizeObserver) { observer = new window.ResizeObserver(layout); observer.observe(frame); }
            window.addEventListener?.('resize', layout); window.visualViewport?.addEventListener('resize', layout);
            layout();
        },
        setAspectRatio(value) {
            if (!value || !Number.isFinite(value.x) || !Number.isFinite(value.y) || value.x <= 0 || value.y <= 0
                || !Number.isFinite(value.x / value.y) || value.x / value.y <= 0) return;
            if (aspectRatio?.x === value.x && aspectRatio?.y === value.y) return;
            aspectRatio = { x: value.x, y: value.y }; layout();
        },
        setTitle(value) { titleName.textContent = titleName.title = value || 'Homegames'; },
        setAuthor(value) {
            author.textContent = typeof value === 'string' && value.trim() ? ' by ' + value.trim().slice(0, 200) : '';
            author.title = author.textContent.trim(); author.hidden = !author.textContent;
        },
        setStatus(value, state = {}) { status.textContent = value || ''; updateAttention(state.attention ?? actions.has('retry')); },
        setPlayerName(value, onChange) {
            playerName = value; changeName = onChange; nameForm.hidden = !onChange;
            if (!menu.open || !nameDirty) nameInput.value = value;
        },
        setSharing(value) {
            const next = value && typeof value.getLink === 'function' && !(value.multiplayer === false && value.copy === false) ? value : null;
            const same = sharing?.getLink === next?.getLink;
            const wasSolo = sharing?.multiplayer === false;
            const couldCopy = sharing?.copy !== false;
            if (!same) {
                shareGeneration++; sharing?.dispose?.();
                copyRequested = false;
                sharingStatus.session = sharingStatus.copy = '';
                qr.hidden = true; shareLink.hidden = true; shareUrl = '';
            }
            sharing = next; sharingSection.hidden = !sharing;
            updateGroups();
            if (!sharing) return;
            if (!same || (shareMode === 'session' && sharing.multiplayer === false) || (shareMode === 'copy' && sharing.copy === false)) shareMode = sharing.multiplayer === false ? 'copy' : 'session';
            sharingLabels();
            if (menu.open && (!same || wasSolo !== (sharing.multiplayer === false) || couldCopy !== (sharing.copy !== false))) refreshSharing();
            if (sharing.multiplayer !== false) options.onActionReady?.('share');
            if (sharing.copy !== false) options.onActionReady?.('copy-share');
        },
        setSharingStatus(text, mode = 'copy') {
            if (!['session', 'copy'].includes(mode)) return;
            sharingStatus[mode] = typeof text === 'string' ? text.slice(0, 300) : '';
            if (menu.open && shareMode === mode && shareUrl) shareStatus.textContent = sharingStatus[mode];
        },
        setAction(key, value) {
            if (!value) {
                const old = actions.get(key); if (old) { old.button.hidden = true; old.button.remove(); actions.delete(key); }
                updateGroups(); if (key === 'retry') updateAttention(false); return;
            }
            let action = actions.get(key);
            if (!action) { action = { button: button('', value.label) }; actions.set(key, action); }
            const node = action.button;
            action.value = value; action.group = groups.has(value.group) ? value.group : actionGroup(key);
            groups.get(action.group).list.append(node);
            node.textContent = value.label; node.title = value.title || '';
            if (value.id) node.id = value.id;
            node.hidden = !!value.hidden; node.disabled = !!value.disabled || running.has(key);
            node.setAttribute('data-action', key);
            if (value.title) node.append(element('span', 'hg-player-action-help', value.title));
            node.onclick = () => {
                if (running.has(key) || node.disabled || disposed) return;
                if (sharing && ['share', 'copy-share'].includes(key)) { openMenu(key === 'share' ? 'session' : 'copy'); return; }
                if (menu.open) closeMenu();
                running.add(key); node.disabled = true;
                const finish = () => { running.delete(key); node.disabled = !!actions.get(key)?.value.disabled; };
                // Keep synchronous invocation for popup and native install gestures.
                try { Promise.resolve(value.run()).catch(error => api.setStatus(error.message || String(error), { attention: true })).finally(finish); }
                catch (error) { finish(); api.setStatus(error.message || String(error), { attention: true }); }
            };
            updateGroups(); if (key === 'retry') updateAttention(true);
            options.onActionReady?.(key);
        },
        runAction(key) {
            if (disposed) return false;
            if (sharing && ['share', 'copy-share'].includes(key)) {
                if ((key === 'share' && sharing.multiplayer === false) || (key === 'copy-share' && sharing.copy === false)) return false;
                openMenu(key === 'share' ? 'session' : 'copy'); return true;
            }
            const action = actions.get(key); if (!action || action.button.disabled) return false;
            action.button.click(); return true;
        },
        openMenu() { openMenu(); },
        dispose() { if (disposed) return; closeMenu(); unbind(); disposed = true; shareGeneration++; sharing?.dispose?.(); menu.remove(); bar.remove(); },
    };
    bar.homegamesToolbar = api;
    api.setTitle(options.title); api.setAuthor(options.author); api.setStatus(options.status);
    for (const [key, value] of Object.entries(options.actions || {})) api.setAction(key, value);
    updateGroups();
    return api;
}
module.exports = { createPlayerToolbar };
