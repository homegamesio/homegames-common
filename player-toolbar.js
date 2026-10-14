'use strict';

// Client UI only. Self-contained so the same toolbar can be embedded in a
// downloaded HTML without loading scripts or styles from a website.
function createPlayerToolbar(window, options = {}) {
    const document = window.document, actions = new Map();
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
.hg-player-status{margin:0;color:#b7bfb5;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hg-player-bar button,.hg-player-bar a,.hg-player-menu button{font:inherit;color:inherit;border:1px solid #4a5049;border-radius:8px;background:transparent;cursor:pointer;text-decoration:none}
.hg-player-bar button,.hg-player-bar a{display:inline-flex;align-items:center;justify-content:center;flex:none;min-width:40px;height:44px;padding:0 10px;white-space:nowrap}
.hg-player-bar .hg-player-icon{font-size:21px;padding:0;width:40px}
.hg-player-bar .hg-player-share{background:#fff78e;color:#22261e;border-color:#fff78e;font-weight:600}
.hg-player-bar button:hover,.hg-player-bar a:hover,.hg-player-menu button:hover{background:#394036}
.hg-player-bar .hg-player-share:hover{background:#fffbb5}
.hg-player-bar :focus-visible,.hg-player-menu :focus-visible{outline:2px solid #fff78e;outline-offset:2px}
.hg-player-bar [hidden],.hg-player-menu [hidden]{display:none!important}
.hg-player-bar button:disabled,.hg-player-menu button:disabled{opacity:.45;cursor:default}
.hg-player-bar.hg-player-simple .hg-player-status{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%)}
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
    const home = element(typeof options.home === 'string' ? 'a' : 'button', 'hg-player-icon', '⌂');
    home.setAttribute('aria-label', 'Home'); home.title = 'Home'; home.hidden = !options.home;
    if (typeof options.home === 'string') home.href = options.home;
    else { home.type = 'button'; home.onclick = options.home; }
    const heading = element('div', 'hg-player-heading');
    const title = element('h1', 'hg-player-title'), status = element('p', 'hg-player-status');
    status.setAttribute('role', 'status'); status.setAttribute('aria-atomic', 'true'); heading.append(title, status);
    const exportsButton = element('button', 'hg-player-icon', '⇩');
    exportsButton.type = 'button'; exportsButton.title = 'View exports'; exportsButton.setAttribute('aria-label', 'View exports'); exportsButton.hidden = true;
    const share = element('button', 'hg-player-share', 'Share'); share.type = 'button'; share.hidden = true;
    const more = element('button', 'hg-player-icon', '⋯'); more.type = 'button'; more.title = 'More';
    more.setAttribute('aria-label', 'More'); more.setAttribute('aria-haspopup', 'dialog');
    const downloadButton = element('button', '', 'Download'); downloadButton.type = 'button'; downloadButton.hidden = true;
    if (options.simple) { bar.classList.add('hg-player-simple'); more.hidden = true; }
    bar.append(home, heading, exportsButton, share, downloadButton, more);
    const menu = element('dialog', 'hg-player-menu'); menu.setAttribute('aria-label', 'Game options');
    const menuTitle = element('h2', '', 'Game options'), list = element('div', 'hg-player-menu-actions');
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
        setTitle(value) { title.textContent = title.title = value || 'Homegames'; },
        setStatus(value) { status.textContent = status.title = menuStatus.textContent = value || ''; },
        setPlayerName(value, onChange) {
            playerName = value; changeName = onChange; nameForm.hidden = !onChange;
            if (!menu.open) nameInput.value = value;
            if (onChange) more.hidden = false;
        },
        setAction(key, value) {
            if (!value) { const old = actions.get(key); if (old) { old.hidden = true; if (old !== share && old !== exportsButton && old !== downloadButton) old.remove(); actions.delete(key); } return; }
            let button = actions.get(key);
            if (!button) { button = key === 'share' ? share : key === 'exports' ? exportsButton
                : options.simple && key === 'download-html' ? downloadButton : element('button', '', value.label);
                button.type = 'button'; actions.set(key, button); if (button !== share && button !== exportsButton && button !== downloadButton) list.append(button); }
            if (value.id) button.id = value.id;
            if (button !== exportsButton) button.textContent = button === downloadButton ? 'Download' : value.label;
            button.hidden = !!value.hidden || (options.simple && button === exportsButton); button.disabled = !!value.disabled;
            button.onclick = () => {
                if (menu.open) { menu.close(); resume(); }
                try { Promise.resolve(value.run()).catch(error => api.setStatus(error.message || String(error))); }
                catch (error) { api.setStatus(error.message || String(error)); }
            };
            options.onActionReady?.(key);
        },
        runAction(key) { const button = actions.get(key); if (!button || button.disabled) return false; button.click(); return true; },
        openMenu() { more.click(); },
        dispose() { if (disposed) return; disposed = true; if (menu.open) menu.close(); menu.remove(); bar.remove(); },
    };
    bar.homegamesToolbar = api;
    api.setTitle(options.title); api.setStatus(options.status);
    for (const [key, value] of Object.entries(options.actions || {})) api.setAction(key, value);
    return api;
}
module.exports = { createPlayerToolbar };
