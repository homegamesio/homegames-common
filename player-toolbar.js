'use strict';

// Client UI only. Self-contained so the same toolbar can be embedded in a
// downloaded HTML without loading scripts or styles from a website.
function createPlayerToolbar(window, options = {}) {
    const document = window.document, actions = new Map(), running = new Set();
    const element = (tag, className, text) => {
        const node = document.createElement(tag); node.className = className;
        if (text) node.textContent = text; return node;
    };
    const bar = element('header', 'hg-player-bar'); bar.setAttribute('aria-label', 'Game controls');
    const style = element('style', '');
    style.textContent = `
.hg-player-bar,.hg-player-menu{box-sizing:border-box;color:#f6f6ee;background:#202321;font:14px/1.4 system-ui,sans-serif}
.hg-player-bar *,.hg-player-menu *{box-sizing:border-box}
.hg-player-bar{display:flex;flex:none;align-items:center;gap:6px;width:100%;height:calc(58px + env(safe-area-inset-top));padding:calc(6px + env(safe-area-inset-top)) max(10px,env(safe-area-inset-right)) 6px max(10px,env(safe-area-inset-left));border-bottom:1px solid #363b36}
.hg-player-heading{flex:1;min-width:0}.hg-player-title{margin:0;font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hg-player-identity{display:flex;align-items:baseline;gap:10px;min-width:0}.hg-player-author{font-size:12px;font-weight:400;color:#b7bfb5;margin-left:6px}
.hg-player-status{margin:0;color:#b7bfb5;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hg-player-bar button,.hg-player-bar a,.hg-player-menu button{font:inherit;color:inherit;border:1px solid #4a5049;border-radius:8px;background:transparent;cursor:pointer;text-decoration:none}
.hg-player-bar button,.hg-player-bar a{display:inline-flex;align-items:center;justify-content:center;flex:none;min-width:40px;height:44px;padding:0 10px;white-space:nowrap}
.hg-player-bar .hg-player-icon{font-size:21px;padding:0;width:40px}
.hg-player-home img{display:block;width:32px;height:32px;object-fit:contain}
.hg-player-bar .hg-player-brand{height:auto;min-height:24px;min-width:0;padding:0;border:0;border-radius:3px;color:#94d2e5;font-size:12px;text-decoration:underline;text-underline-offset:3px}
.hg-player-bar .hg-player-brand:hover{background:transparent;color:#b9e5f1}
.hg-player-bar .hg-player-share{background:#fff78e;color:#22261e;border-color:#fff78e;font-weight:600}
.hg-player-bar button:hover,.hg-player-bar a:hover,.hg-player-menu button:hover{background:#394036}
.hg-player-bar .hg-player-share:hover{background:#fffbb5}
.hg-player-bar .hg-player-install{background:#a8edc9;color:#17271e;border-color:#a8edc9;font-weight:600}.hg-player-bar .hg-player-install:hover{background:#c4f5dc}
.hg-player-bar :focus-visible,.hg-player-menu :focus-visible{outline:2px solid #fff78e;outline-offset:2px}
.hg-player-bar [hidden],.hg-player-menu [hidden]{display:none!important}
.hg-player-bar button:disabled,.hg-player-menu button:disabled{opacity:.45;cursor:default}
.hg-player-edit-short{display:none}
@media(max-width:600px){.hg-player-edit-long{display:none}.hg-player-edit-short{display:inline}.hg-player-bar{gap:4px;flex-wrap:wrap;height:auto}.hg-player-home{order:-2}.hg-player-heading{order:-1;flex-basis:calc(100% - 48px)}.hg-player-share{margin-left:auto}.hg-player-bar button:not(.hg-player-icon){padding:0 8px}}
.hg-player-menu{position:fixed;inset:max(68px,env(safe-area-inset-top)) 12px auto auto;margin:0;width:min(320px,calc(100vw - 24px));max-height:calc(100dvh - 90px);overflow:auto;padding:16px;border:1px solid #4a5049;border-radius:12px;box-shadow:0 16px 50px #0008}
.hg-player-menu::backdrop{background:#080c0a99}.hg-player-menu h2{margin:0 0 12px;font-size:16px}
.hg-player-menu-actions{display:flex;flex-direction:column;gap:6px}.hg-player-menu button{width:100%;min-height:44px;padding:10px 12px;text-align:left}
.hg-player-menu .hg-player-menu-status{font-size:12px;color:#b7bfb5;overflow-wrap:anywhere;margin:12px 0}
.hg-player-menu .hg-player-menu-close{text-align:center;margin-top:10px}
.hg-player-name{margin:0 0 16px;padding-bottom:16px;border-bottom:1px solid #4a5049}
.hg-player-name label{display:block;margin-bottom:6px}.hg-player-name input{width:100%;min-height:44px;padding:10px;font:inherit;color:inherit;background:#141815;border:1px solid #4a5049;border-radius:8px}
.hg-player-name button{margin-top:8px}.hg-player-name p{font-size:12px;color:#b7bfb5;margin:8px 0 0;overflow-wrap:anywhere}
`;
    bar.append(style);
    const home = element(typeof options.home === 'string' ? 'a' : 'button', 'hg-player-icon hg-player-home');
    home.setAttribute('aria-label', 'Home'); home.title = 'Home'; home.hidden = !options.home;
    // Embedded copy of homegamesio/favicon-32x32.png; no network request in downloaded games.
    const logo = element('img', ''); logo.alt = ''; logo.width = logo.height = 32;
    logo.src = 'data:image/png;base64,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'; home.append(logo);
    if (typeof options.home === 'string') home.href = options.home;
    else { home.type = 'button'; home.onclick = options.home; }
    const heading = element('div', 'hg-player-heading');
    const identity = element('div', 'hg-player-identity'), title = element('h1', 'hg-player-title'), titleName = element('span', ''), author = element('span', 'hg-player-author'), status = element('p', 'hg-player-status');
    title.append(titleName, author);
    const website = element('a', 'hg-player-brand', 'homegames.io');
    website.href = 'https://homegames.io/'; website.target = '_blank'; website.rel = 'noopener noreferrer'; website.title = 'Open homegames.io in a new tab';
    identity.append(title, website);
    status.setAttribute('role', 'status'); status.setAttribute('aria-atomic', 'true'); heading.append(identity, status);
    const share = element('button', 'hg-player-share', 'Share'); share.type = 'button'; share.hidden = true;
    const more = element('button', 'hg-player-icon', '⋯'); more.type = 'button'; more.title = 'More';
    more.setAttribute('aria-label', 'More'); more.setAttribute('aria-haspopup', 'dialog');
    const downloadButton = element('button', '', 'Download file'); downloadButton.type = 'button'; downloadButton.hidden = true;
    const installButton = element('button', 'hg-player-install', 'Download app'); installButton.type = 'button'; installButton.hidden = true;
    const editButton = element('button', 'hg-player-edit'); editButton.type = 'button'; editButton.hidden = true;
    editButton.title = 'Open your own editable copy in Studio'; editButton.setAttribute('aria-label', 'Edit this game');
    editButton.append(element('span', 'hg-player-edit-long', 'Edit this game'), element('span', 'hg-player-edit-short', 'Edit'));
    const primary = new Set([share, installButton, downloadButton, editButton]);
    bar.append(home, heading, share, installButton, downloadButton, editButton, more);
    const menu = element('dialog', 'hg-player-menu'); menu.setAttribute('aria-label', 'Game options');
    const menuTitle = element('h2', '', 'Game options'), list = element('div', 'hg-player-menu-actions');
    const placeDownload = () => {
        // Installable players get one primary download action; their portable
        // file remains available in More. File-only players keep it in the bar.
        if (actions.has('install') && !installButton.hidden) { list.prepend(downloadButton); downloadButton.textContent = 'Download game file (HTML)'; }
        else { bar.insertBefore(downloadButton, editButton); downloadButton.textContent = 'Download file'; }
    };
    const menuStatus = element('p', 'hg-player-menu-status');
    const nameForm = element('form', 'hg-player-name'); nameForm.hidden = true;
    const nameLabel = element('label', '', 'Your name'), nameInput = element('input', '');
    nameInput.type = 'text'; nameInput.maxLength = 32; nameInput.required = true; nameInput.autocomplete = 'nickname';
    nameInput.setAttribute('aria-label', 'Your name'); nameLabel.append(nameInput);
    const nameSave = element('button', '', 'Save name'); nameSave.type = 'submit';
    const nameStatus = element('p', ''); nameStatus.setAttribute('role', 'status');
    nameForm.append(nameLabel, nameSave, nameStatus);
    let playerName = '', changeName;
    nameForm.onsubmit = async event => {
        event.preventDefault(); if (!changeName || nameSave.disabled) return;
        nameSave.disabled = true;
        try { playerName = await changeName(nameInput.value); nameInput.value = playerName; nameStatus.textContent = 'Name updated for this session.'; }
        catch (error) { nameStatus.textContent = error.message || String(error); }
        finally { nameSave.disabled = false; }
    };
    const done = element('button', 'hg-player-menu-close', 'Done'); done.type = 'button'; done.onclick = () => menu.close();
    menu.append(menuTitle, nameForm, list, menuStatus, done); document.body.append(menu);
    let menuActive = false;
    const resume = () => { if (menuActive) { menuActive = false; options.onClose?.(); } };
    more.onclick = () => { if (!menu.open) { nameInput.value = playerName; nameStatus.textContent = ''; menuActive = true; options.onOpen?.(); menu.showModal(); } };
    menu.addEventListener('close', resume);
    menu.addEventListener('click', event => { if (event.target === menu) { const r = menu.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) menu.close(); } });
    let disposed = false;
    const api = {
        bar, menu, statusElement: status,
        setTitle(value) { titleName.textContent = titleName.title = value || 'Homegames'; },
        setAuthor(value) { author.textContent = typeof value === 'string' && value.trim() ? ' by ' + value.trim().slice(0, 200) : ''; author.title = author.textContent.trim(); author.hidden = !author.textContent; },
        setStatus(value) { status.textContent = status.title = menuStatus.textContent = value || ''; },
        setPlayerName(value, onChange) {
            playerName = value; changeName = onChange; nameForm.hidden = !onChange;
            if (!menu.open) nameInput.value = value;
            if (onChange) more.hidden = false;
        },
        setAction(key, value) {
            if (!value) { const old = actions.get(key); if (old) { old.hidden = true; if (!primary.has(old)) old.remove(); actions.delete(key); } if (key === 'install') placeDownload(); return; }
            let button = actions.get(key);
            if (!button) { button = key === 'share' ? share : key === 'edit-game' ? editButton
                : key === 'install' ? installButton : key === 'download-html' ? downloadButton : element('button', '', value.label);
                button.type = 'button'; actions.set(key, button); if (!primary.has(button)) list.append(button); }
            if (value.id) button.id = value.id;
            if (button !== editButton) button.textContent = value.label;
            button.hidden = !!value.hidden; button.disabled = !!value.disabled || running.has(key);
            if (key === 'install' || key === 'download-html') placeDownload();
            button.onclick = () => {
                if (running.has(key)) return;
                if (menu.open) { menu.close(); resume(); }
                running.add(key); button.disabled = true;
                // Invoke synchronously: opening Studio needs the click gesture.
                try { Promise.resolve(value.run()).catch(error => api.setStatus(error.message || String(error)))
                    .finally(() => { running.delete(key); button.disabled = !!value.disabled; }); }
                catch (error) { running.delete(key); button.disabled = !!value.disabled; api.setStatus(error.message || String(error)); }
            };
            options.onActionReady?.(key);
        },
        runAction(key) { const button = actions.get(key); if (!button || button.disabled) return false; button.click(); return true; },
        openMenu() { more.click(); },
        dispose() { if (disposed) return; disposed = true; if (menu.open) menu.close(); menu.remove(); bar.remove(); },
    };
    bar.homegamesToolbar = api;
    api.setTitle(options.title); api.setAuthor(options.author); api.setStatus(options.status);
    for (const [key, value] of Object.entries(options.actions || {})) api.setAction(key, value);
    return api;
}
module.exports = { createPlayerToolbar };
