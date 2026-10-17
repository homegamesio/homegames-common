'use strict';
// Studio-only debugging across the opaque player boundary. The game never gets
// access to the editor, its storage, or executable callbacks in the parent.
function inspectorTree(value) {
    let count = 0;
    const number = value => Number.isFinite(value) ? value : 0;
    const point = value => ({x:number(value?.x), y:number(value?.y)});
    function walk(node, depth) {
        if (!node || typeof node !== 'object' || depth > 48 || ++count > 4000) return null;
        const result = {id:typeof node.id === 'number' ? node.id : String(node.id).slice(0,100), children:[]};
        if (Array.isArray(node.coordinates2d)) result.coordinates2d = node.coordinates2d.slice(0,512).filter(p=>Array.isArray(p)&&p.length>=2).map(p=>[number(p[0]),number(p[1])]);
        if (Array.isArray(node.fill)) result.fill = node.fill.slice(0,4).map(number);
        if (node.text) result.text = {...point(node.text),text:String(node.text.text||'').slice(0,2000),size:number(node.text.size),align:String(node.text.align||'').slice(0,20)};
        if (node.asset) result.asset = {key:String(node.asset.key||'').slice(0,200),pos:point(node.asset.pos),size:point(node.asset.size)};
        if (Array.isArray(node.playerIds)) result.playerIds = node.playerIds.slice(0,64).filter(Number.isFinite);
        if (node.clickable) result.clickable = true;
        if (node.input) result.input = String(node.input).slice(0,100);
        if (Array.isArray(node.children)) for (const child of node.children) { if(count>=4000)break;const next=walk(child,depth+1);if(next)result.children.push(next); }
        return result;
    }
    return Array.isArray(value) ? value.slice(0,128).map(node=>walk(node,0)).filter(Boolean) : [];
}
function attachStudioDebugHost(window, frame, {onReady=()=>{},onError=()=>{},onLog=()=>{}} = {}) {
    let port, closed=false, sequence=0, playerId=1, snapshot, input, pick;
    const pending=new Map();
    function request(action,value) {
        if(!port||closed)return Promise.reject(new Error('Preview debugger is not ready'));
        return new Promise((resolve,reject)=>{
            const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(new Error('Preview debugger timed out'));},5000);
            pending.set(id,{resolve,reject,timer});port.postMessage({id,action,value});
        });
    }
    const command=(action,value)=>{request(action,value).catch(error=>{if(!closed)onError(error);});};
    function connect(event) {
        if(closed||port||event.source!==frame.contentWindow||event.origin!=='null'||event.data?.type!=='homegames-studio-debug-v1')return;
        const channel=new window.MessageChannel();port=channel.port1;
        port.onmessage=({data})=>{
            if(closed||!data)return;
            if(data.event==='ready'){playerId=Number.isFinite(data.playerId)?data.playerId:1;onReady(data.available===true);}
            else if(data.event==='snapshot'&&snapshot&&Number.isFinite(data.time)&&Number.isSafeInteger(data.frame))snapshot({time:data.time,buf:data.frame,tree:inspectorTree(data.tree)});
            else if(data.event==='input'&&input&&Number.isFinite(data.value?.time))input({time:data.value.time,type:String(data.value.type||'').slice(0,40),key:String(data.value.key||'').slice(0,80)});
            else if(data.event==='pick'&&pick){const x=data.x===null?null:Number(data.x),y=data.y===null?null:Number(data.y);if((x===null||Number.isFinite(x))&&(y===null||Number.isFinite(y))){if(data.kind==='select'){const callback=pick.onPick;pick=null;callback?.(x,y);}else pick.onMove?.(x,y);}}
            else if(data.event==='log'&&['log','warn','error'].includes(data.level))onLog(data.level,String(data.message).slice(0,4000));
            else if(data.event==='result'){const entry=pending.get(data.id);if(!entry)return;pending.delete(data.id);clearTimeout(entry.timer);data.error?entry.reject(new Error(String(data.error).slice(0,500))):entry.resolve(data.value);}
        };
        frame.contentWindow.postMessage({type:'homegames-studio-debug-port-v1'},'*',[channel.port2]);
    }
    window.addEventListener('message',connect);
    return {
        embedded:true,get playerId(){return playerId;},
        enableInspector(onSnapshot,onInput){snapshot=onSnapshot;input=onInput;command('inspect',true);},
        disableInspector(){snapshot=input=pick=null;command('inspect',false);},
        showFrame:id=>command('frame',id),resumeLive:()=>command('live'),setHighlight:points=>command('highlight',points),
        enablePick(callbacks){pick=callbacks;command('pick',true);},disablePick(){pick=null;command('pick',false);},
        addPlayer:()=>request('add-player'),removePlayer:id=>command('remove-player',id),freeze:()=>command('freeze'),
        stop(){if(closed)return;closed=true;window.removeEventListener('message',connect);port?.close();snapshot=input=pick=null;for(const entry of pending.values()){clearTimeout(entry.timer);entry.reject(new Error('Preview closed'));}pending.clear();}
    };
}
function connectStudioDebugSource(window, getSession) {
    const document=window.document,frames=new Map();
    let port,closed=false,available=false,frameId=0,frameBytes=0,secondId=null,secondView,firstLabel;
    const send=data=>{if(!closed&&port)port.postMessage(data);};
    const resize=()=>window.dispatchEvent(new window.Event('resize'));
    function removePlayer(session) {if(secondId!==null)session?.removePlayer(secondId);secondId=null;secondView?.remove();secondView=null;firstLabel?.remove();firstLabel=null;resize();}
    const label=(container,text)=>{const el=document.createElement('span');el.textContent=text;el.style.cssText='position:absolute;left:8px;top:6px;z-index:2;background:#101820cc;color:#fff;padding:3px 6px;border-radius:4px;font:12px system-ui;pointer-events:none';container.style.position='relative';container.append(el);return el;};
    const commands={
        inspect(session,enabled){frames.clear();frameBytes=0;if(!enabled){session.disableInspector();return;}
            session.enableInspector(snap=>{if(!snap.buf?.byteLength||snap.buf.byteLength>8*1024*1024)return;const id=++frameId;frames.set(id,snap.buf.slice());frameBytes+=snap.buf.byteLength;while(frames.size>600||frameBytes>64*1024*1024){const oldest=frames.keys().next().value;frameBytes-=frames.get(oldest).byteLength;frames.delete(oldest);}send({event:'snapshot',frame:id,time:snap.time,tree:inspectorTree(snap.tree)});},value=>send({event:'input',value}));},
        frame(session,id){const buf=frames.get(id);if(!buf)throw new Error('This recorded frame is no longer available');session.showFrame(buf);},
        live:session=>session.resumeLive(),highlight:(session,value)=>session.setHighlight(value),
        pick(session,enabled){if(!enabled){session.disablePick();return;}session.enablePick({onMove:(x,y)=>send({event:'pick',kind:'move',x,y}),onPick:(x,y)=>send({event:'pick',kind:'select',x,y})});},
        'add-player'(session){if(secondId!==null)return secondId;if(session.frozen)throw new Error('Restart the game before adding a player');
            const game=document.getElementById('game');secondView=document.createElement('div');secondView.id='studio-debug-player-2';secondView.style.cssText='flex:1;min-height:0;display:flex;align-items:center;justify-content:center;overflow:hidden;border-top:1px solid #45546a';game.after(secondView);resize();
            secondId=session.addPlayer(secondView.id);if(secondId===null){removePlayer(session);throw new Error('Could not add a player');}
            firstLabel=label(game,'Player '+session.playerId);label(secondView,'Player '+secondId);resize();return secondId;},
        'remove-player':session=>removePlayer(session),freeze(session){removePlayer(session);session.freeze();}
    };
    function connect(event){
        if(closed||port||event.source!==window.parent||event.data?.type!=='homegames-studio-debug-port-v1'||!event.ports[0])return;
        window.removeEventListener('message',connect);port=event.ports[0];
        port.onmessage=({data})=>{if(closed||!data||!Number.isSafeInteger(data.id))return;
            try {const session=getSession();if(!session)throw new Error('Debug tools require a local game');if(!Object.hasOwn(commands,data.action))throw new Error('Unknown debug action');const value=commands[data.action](session,data.value);send({event:'result',id:data.id,value});}
            catch(error){send({event:'result',id:data.id,error:error.message});}
        };send({event:'ready',available,playerId:getSession()?.playerId});
    }
    window.addEventListener('message',connect);window.parent.postMessage({type:'homegames-studio-debug-v1'},'*');
    const originals={},wrappers={};let logWindow=0,logs=0;
    for(const level of ['log','warn','error']){originals[level]=window.console[level];wrappers[level]=(...args)=>{originals[level].apply(window.console,args);const now=Date.now();if(now-logWindow>1000){logs=0;logWindow=now;}if(++logs>25)return;const message=args.map(value=>{try{return typeof value==='string'?value:JSON.stringify(value);}catch(_){return String(value);}}).join(' ').slice(0,4000);send({event:'log',level,message});};window.console[level]=wrappers[level];}
    return {ready(){available=!!getSession();send({event:'ready',available,playerId:getSession()?.playerId});},close(){if(closed)return;closed=true;window.removeEventListener('message',connect);getSession()?.disableInspector();removePlayer(getSession());frames.clear();port?.close();for(const level of Object.keys(originals))if(window.console[level]===wrappers[level])window.console[level]=originals[level];}};
}
module.exports={inspectorTree,attachStudioDebugHost,connectStudioDebugSource};
