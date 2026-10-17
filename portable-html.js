'use strict';

// Shared by browser Studio and Node tooling. Project source is always data in
// the parent. Only mount runtimeDocument inside an opaque-origin sandbox.
const { exportArchive, LIMITS } = require('./portable-project');
const { attachSaveHost } = require('./portable-saves');
const { attachClientHost, recordAudio } = require('./portable-client');
const { createExportsViewer } = require('./exports-viewer');
const { recordVideo } = require('./video-recording');
const { createExportStorage } = require('./export-storage');
const { createPlayerToolbar } = require('./player-toolbar');
const { createPlayerIdentity } = require('./player-identity');
const { openGameInStudio } = require('./studio-handoff');
const inline = value => JSON.stringify(value).replace(/</g, '\\u003c');
const escapeHtml = value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const filename = name => {
    let slug = String(name || 'game').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'game';
    if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/.test(slug)) slug += '-game';
    return `${slug}.zip`;
};
const htmlBytesLimit = LIMITS.archiveBytes * 3 + 8 * 1024 * 1024;
// Extract data only. Never evaluate a received HTML wrapper or reuse its runtime
// in the trusted page. Call importArchive on these bytes before rebuilding it.
function readHtmlArchive(source) {
    if (typeof source !== 'string' || source.length > htmlBytesLimit) throw new Error('Game HTML is too large');
    const marker = '<script id="homegames-project" type="application/json">';
    const start = source.indexOf(marker), end = source.indexOf('</script>', start + marker.length);
    if (start < 0 || end < 0) throw new Error('Choose a Homegames HTML bundle or project ZIP');
    const payload = JSON.parse(source.slice(start + marker.length, end));
    if (payload.formatVersion !== 1 || typeof payload.archive !== 'string'
        || payload.archive.length > Math.ceil(LIMITS.archiveBytes / 3) * 4
        || /[^A-Za-z0-9+/=]/.test(payload.archive)) throw new Error('Invalid game HTML archive');
    const bytes = Uint8Array.from(atob(payload.archive), c => c.charCodeAt(0));
    if (bytes.length > LIMITS.archiveBytes) throw new Error('Game archive is too large');
    return bytes;
}
function base64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(binary);
}

async function runtimeDocument(project, { clientBundleSource, installationId, sharing = {}, studioUrl, studioDebug = false } = {}) {
    if (!clientBundleSource?.includes('PortableProject')) throw new Error('Rebuild the Homegames client before playing portable projects');
    if (!/^[a-zA-Z0-9-]{16,80}$/.test(installationId || '')) throw new Error('Missing local installation ID');
    const signal = new URL(sharing.signalingUrl || 'wss://api.homegames.io/rtc');
    if (!['ws:', 'wss:', 'http:', 'https:'].includes(signal.protocol) || signal.username || signal.password) throw new Error('Invalid signaling URL');
    signal.protocol = signal.protocol === 'https:' ? 'wss:' : signal.protocol === 'http:' ? 'ws:' : signal.protocol;
    const join = new URL(sharing.joinUrl || 'https://homegames.io/play.html');
    if (!['http:', 'https:'].includes(join.protocol)) throw new Error('Invalid invitation URL');
    const studio = new URL(studioUrl || '/studio.html', join);
    if (!['http:', 'https:'].includes(studio.protocol) || studio.username || studio.password) throw new Error('Invalid Studio URL');
    const receive = new URL(sharing.receiveUrl || '/game-app.html', join);
    if (!['http:', 'https:'].includes(receive.protocol)) throw new Error('Invalid copy receiver URL');
    const payload = { archive: base64(await exportArchive(project)), installationId, studioUrl: studio.href, studioDebug: studioDebug === true,
        sharing: sharing === false ? false : { signalingUrl: signal.href, joinUrl: join.href, receiveUrl: receive.href } };
    // No cookies, storage, parent DOM, navigation, popup or download permission.
    // Network access is limited by CSP to the signaling endpoint; RTC itself is
    // allowed for multiplayer. This is an origin boundary, not a CPU sandbox.
    const csp = `default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'; img-src data: blob:; media-src data: blob:; font-src data: blob:; worker-src blob:; connect-src ${sharing === false ? "'none'" : signal.origin + signal.pathname}; base-uri 'none'; form-action 'none'; frame-src 'none'`;
    return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${escapeHtml(csp)}"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
html,body{margin:0;height:100%;background:#101820;color:#f7fafc;font:14px system-ui}body{display:flex;flex-direction:column}#game{flex:1;min-height:0;display:flex;align-items:center;justify-content:center;overflow:hidden}#error{padding:16px;color:#ffbaba;white-space:pre-wrap}
</style></head><body><div id="game"></div><div id="error" hidden></div>
<script>${clientBundleSource.replace(/<\/script/gi, '<\\/script')}</script><script>
(async()=>{
const payload=${inline(payload)};
let client,clientSource,copyShare,pairing,debug;
const state=status=>clientSource?.setState({status});
const fail=error=>{document.getElementById('error').hidden=false;document.getElementById('error').textContent=error.message||String(error);state('Unable to play: '+(error.message||String(error)));};
try {
const project=await HomegamesClient.PortableProject.importArchive(Uint8Array.from(atob(payload.archive),ch=>ch.charCodeAt(0)));
const saveError=error=>{state('Progress not saved: '+error.message);};
const saveStore=await HomegamesClient.PortableProject.connectSaveStore(window,{gameKey:'project:'+payload.installationId,versionId:'save-schema:'+project.manifest.saveSchemaVersion,onError:saveError,stop:()=>client?.stop()});
const shareCopy=async()=>{const copy=await client.requestGameCopy();copyShare?.close();copyShare=HomegamesClient.GameCopies.showCopyShare(copy.project,{signalingUrl:payload.sharing.signalingUrl,receiveUrl:payload.sharing.receiveUrl,onOpen:()=>client.setInputEnabled(false),onClose:()=>client.setInputEnabled(true)});};
clientSource=HomegamesClient.PortableProject.connectClientSource(window,async format=>{
const copy=await client.requestGameCopy();
if(format==='zip')return copy.bytes;
return new TextEncoder().encode(await HomegamesClient.PortableProject.buildIsolatedHtml(copy.project,{clientBundleSource:document.scripts[0].textContent,installationId:crypto.randomUUID(),sharing:payload.sharing,studioUrl:payload.studioUrl}));
},{list:()=>client.listExports(),read:name=>client.readExport(name)}, {
share:()=>client.showShare(),exports:()=>client.viewExports(),'copy-share':shareCopy,'manual-connect':()=>pairing?.show(),
'pause-input':()=>client.setInputEnabled(false),'resume-input':()=>{client.setInputEnabled(true);if(payload.studioDebug)client._localSession?._updateInputAttachment();},'player-name':name=>client.setPlayerName(name)
});
const ready=status=>clientSource.setState({title:project.metadata.name||'Homegame',author:project.metadata.author||project.metadata.createdBy||'',status,ready:true,sharing:!!payload.sharing,multiplayer:client._localSession?client._localSession.maxPlayers>1:true,playerNames:typeof client.setPlayerName==='function'});
client=new HomegamesClient({containerId:'game',chrome:false,localHome:false,share:payload.sharing,saveStore,platform:clientSource,playerName:await clientSource.getPlayerName?.(),
loadLocalGame:async()=>HomegamesClient.PortableProject.prepareTrustedLocalGame(project,{trusted:true,installationId:payload.installationId}),
onReady:()=>{ready('Playing locally');debug?.ready();},onSessionStatus:state,onError:fail});
pairing=payload.sharing?HomegamesClient.createManualPairing({container:document.body,getSession:()=>client._localSession,
onOpen:()=>client.setInputEnabled(false),onClose:()=>client.setInputEnabled(true),
join:async transport=>{client.stop();client=new HomegamesClient({containerId:'game',chrome:false,transport,platform:clientSource,playerName:await clientSource.getPlayerName?.(),onReady:()=>{ready('Connected manually to host');debug?.ready();},onClose:()=>state('Host disconnected'),onError:fail});client.start();}}):null;
if(payload.studioDebug)debug=HomegamesClient.PortableProject.connectStudioDebugSource(window,()=>client._localSession);
window.addEventListener('pagehide',()=>{debug?.close();copyShare?.close();pairing?.dispose();client.stop();clientSource.close();});client.startLocalGame({});
}catch(error){fail(error);}
})();
</script></body></html>`;
}

function createFrame(document, source) {
    const frame = document.createElement('iframe');
    frame.title = 'Game preview';
    // Pointer Lock still requires a canvas gesture. Keep the opaque origin:
    // enabling mouse capture does not grant parent/storage access.
    frame.setAttribute('sandbox', 'allow-scripts allow-pointer-lock');
    // Explicit delegation also covers browsers that restrict gamepads in
    // cross-origin frames. '*' is needed for this frame's opaque origin.
    frame.setAttribute('allow', "autoplay *; fullscreen *; gamepad *; camera 'none'; microphone 'none'; geolocation 'none'");
    frame.referrerPolicy = 'no-referrer';
    frame.srcdoc = source;
    return frame;
}

async function buildIsolatedHtml(project, options) {
    const document = await runtimeDocument(project, options);
    const studioUrl = new URL(options.studioUrl || '/studio.html', options.sharing?.joinUrl || 'https://homegames.io/play.html').href;
    const payload = inline({ formatVersion: 1, document, archive: base64(await exportArchive(project)), name: filename(project.metadata.name), title:project.metadata.name||'Homegame', author:project.metadata.author||project.metadata.createdBy||'',
        studioUrl, homeUrl: new URL('/catalog.html', studioUrl).href,
        saves:{packageRevision:project.revision,installationId:options.installationId,gameId:project.manifest.gameId,versionId:'save-schema:'+project.manifest.saveSchemaVersion,compatibility:project.metadata.saveCompatibility || []} });
    return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>${escapeHtml(project.metadata.name || 'Homegame')}</title>
<style>html,body{margin:0;height:100%;background:#101820;color:#f7fafc;font:14px system-ui}body{display:flex;flex-direction:column}iframe{flex:1;width:100%;border:0;min-height:0}[hidden]{display:none!important}</style></head><body>
<input id="portable-save-file" type="file" accept=".json,application/json" hidden>
<script id="homegames-project" type="application/json">${payload}</script>
<script>const payload=JSON.parse(document.getElementById('homegames-project').textContent);
const originalHtml='<!doctype html>\\n'+document.documentElement.outerHTML;
let frame,saveHost,clientHost;
const toolbar=(${createPlayerToolbar.toString()})(window,{title:payload.title,author:payload.author,home:payload.homeUrl,status:'Starting game…',onOpen:()=>clientHost?.command('pause-input'),onClose:()=>clientHost?.command('resume-input')});document.body.prepend(toolbar.bar);
const showSaveStatus=message=>toolbar.setStatus(message);
const editGame=getArchive=>{showSaveStatus('Opening Studio…');return (${openGameInStudio.toString()})(window,getArchive,payload.studioUrl).then(()=>showSaveStatus('Editable copy saved in Studio'));};
async function mount(){clientHost?.close();if(saveHost)await saveHost.close();frame?.remove();frame=(${createFrame.toString()})(document,payload.document);saveHost=(${attachSaveHost.toString()})(window,frame,{...payload.saves,onStatus:value=>showSaveStatus(value.message)});clientHost=(${attachClientHost.toString()})(window,frame,(${recordAudio.toString()}),(${createExportStorage.toString()})(window,payload.saves),(${createExportsViewer.toString()}),(${recordVideo.toString()}),(${createPlayerToolbar.toString()}),{toolbar,editGame,htmlId:'portable-html-copy',zipId:'portable-copy',profile:(${createPlayerIdentity.toString()})().profile(window)});document.body.appendChild(frame);}
const fallback=(bytes,type,name)=>{const url=URL.createObjectURL(new Blob([bytes],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),30000);};
toolbar.setAction('download-html',{label:'Download game HTML',id:'portable-html-copy',run:()=>fallback(originalHtml,'text/html',payload.name.replace(/\\.zip$/,'.html'))});
toolbar.setAction('download-zip',{label:'Download game ZIP',id:'portable-copy',run:()=>fallback(Uint8Array.from(atob(payload.archive),c=>c.charCodeAt(0)),'application/zip',payload.name)});
toolbar.setAction('edit-game',{label:'Edit this game',id:'edit-game',run:()=>editGame(()=>Uint8Array.from(atob(payload.archive),c=>c.charCodeAt(0)))});
toolbar.setAction('save-download',{label:'Download save',id:'portable-save-download',run:()=>saveHost.downloadSave(payload.name.replace(/\\.zip$/,'-save.json'))});
toolbar.setAction('save-import',{label:'Load save',id:'portable-save-import',run:()=>document.getElementById('portable-save-file').click()});
mount();
document.getElementById('portable-save-file').onchange=async event=>{const file=event.target.files[0];event.target.value='';if(!file)return;try{if(file.size>1024*1024+4096)throw Error('Save file is too large');const text=await file.text();if(!confirm('Load this save and replace the current progress for this game?'))return;await saveHost.importSave(text);await mount();}catch(error){if(saveHost.stopped)await mount();showSaveStatus(error.message);}};
</script></body></html>`;
}

module.exports = { runtimeDocument, createFrame, buildIsolatedHtml, filename, readHtmlArchive, htmlBytesLimit };
