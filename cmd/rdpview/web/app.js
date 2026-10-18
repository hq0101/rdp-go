'use strict';
const token=location.hash.slice(1), canvas=document.getElementById('desktop'), ctx=canvas.getContext('2d',{alpha:false});
const status=document.getElementById('status'), waiting=document.getElementById('waiting'), hint=document.getElementById('hint');
const headers={'X-OpenRDP-Token':token};
const textValue=document.getElementById('text-value'),textMessage=document.getElementById('text-message');
let unicodeAvailable=false,clipboardInfo={},textBusy=false,clipboardBusy=false,connectionInfo={},remoteActive=false;
let displayInfo={},resizeInfo={},resizeSending=false,resizeSeen=-1;
const resizeMessage=document.getElementById('resize-message'),resolution=document.getElementById('resolution');
const desktop=document.createElement('canvas'), desktopCtx=desktop.getContext('2d',{alpha:false});
let appRevision="",appControl=false,appMoveToken="",appFocusToken="";
let stopped=false, etag='', queue=[], sending=false, ready=false, generation=0;
let pointer={Kind:0,Shape:null}, pointerVersion=-1, positionVersion=0, cursorX=0,cursorY=0,inside=false,previousCursor=null;
const audioPlayer=typeof OpenRDPAudio==='function'?new OpenRDPAudio({request:api,button:document.getElementById('audio-toggle'),message:document.getElementById('audio-message'),volume:document.getElementById('audio-volume')}):null;
const microphone=typeof OpenRDPCapture==='function'?new OpenRDPCapture({request:api,button:document.getElementById('microphone-toggle'),message:document.getElementById('microphone-message')}):null;
const richClipboard=typeof OpenRDPClipboard==='function'?new OpenRDPClipboard({request:api,onBusy:busy=>{clipboardBusy=busy;updateTextButtons();}}):null;
const uploadClipboard=typeof OpenRDPUpload==='function'?new OpenRDPUpload({request:api}):null;
const notifyUI=typeof OpenRDPNotifications==='function'?new OpenRDPNotifications({request:api,generation:()=>generation,before:beforeAppControl,after:()=>{appControl=false;}}):null;
const appUI=typeof OpenRDPRemoteApp==='function'?new OpenRDPRemoteApp({request:api,generation:()=>generation,focus:()=>canvas.focus({preventScroll:true}),before:beforeAppControl,after:()=>{appControl=false;etag='';}}):null;
const fileClipboard=typeof OpenRDPFiles==='function'?new OpenRDPFiles({request:api}):null;
function end(message){notifyUI?.end();document.getElementById('drive-message').textContent='连接已结束，共享已关闭';uploadClipboard?.end();fileClipboard?.end();richClipboard?.end();microphone?.end();audioPlayer?.end();stopped=true;ready=false;queue=[];drawPointer();updateTextButtons();updateResizeButtons();status.textContent=message;document.getElementById('disconnect').disabled=true;hint.textContent='连接已结束';}
async function api(path,options={}){const r=await fetch(path,{...options,headers:{...headers,...options.headers},cache:'no-store'});if(!r.ok && r.status!==304){const e=new Error('request failed');e.status=r.status;if(path.startsWith('/clipboard/upload')&&r.headers.get('Content-Type')==='application/json'){try{e.transferError=(await r.json()).error;}catch{}}e.inputPartial=r.headers?.get('X-OpenRDP-Input-Partial')==='1';throw e;}return r;}
function enqueue(e){if(stopped||!ready||appControl)return;if(appMoveToken)e.app_move=appMoveToken;if(appFocusToken)e.app_focus=appFocusToken;if(queue.length>=256){disconnect();return;}if(e.kind==='move'&&queue.at(-1)?.kind==='move')queue[queue.length-1]=e;else queue.push(e);}
async function flush(){
 if(sending||!queue.length||stopped)return;sending=true;const batch=queue.splice(0,64),hasText=batch.some(e=>e.kind==='text'),batchGeneration=generation;
 try{await api('/input',{method:'POST',headers:{'Content-Type':'application/json','X-OpenRDP-Generation':String(generation),'X-OpenRDP-App-Revision':appRevision},body:JSON.stringify(batch)});if(generation!==batchGeneration)return;if(hasText)textMessage.textContent='文本已发送到远程当前输入位置';}
 catch(e){if(generation!==batchGeneration)return;if(e.inputPartial){queue=[];enqueue({kind:'release'});if(hasText)textMessage.textContent='输入已中止，部分文本可能已输入；请先检查远程内容';else hint.textContent='输入已中止，请检查远程状态后重试';}else if(e.status===409){queue=[];ready=false;etag='';status.textContent='正在恢复会话…';if(hasText)textMessage.textContent='会话正在恢复，本次文本未确认，请恢复后检查再发送';}else if(e.status===422||e.status===400){textMessage.textContent='文本输入未被接受，请使用剪贴板发送';}else end('连接已断开');}
 finally{sending=false;if(hasText&&generation===batchGeneration)textBusy=false;updateTextButtons();}
}
setInterval(flush,30);
function drawPointer(){
 if(previousCursor){const r=previousCursor;ctx.drawImage(desktop,r.x,r.y,r.w,r.h,r.x,r.y,r.w,r.h);previousCursor=null;}
 canvas.classList.toggle('remote-cursor',ready&&pointer.Kind!==0);
 if(!ready||!inside||pointer.Kind!==2||!pointer.Shape)return;
 const s=pointer.Shape,ox=cursorX-s.Hotspot.X,oy=cursorY-s.Hotspot.Y;
 const x=Math.max(0,ox),y=Math.max(0,oy),w=Math.min(canvas.width,ox+s.Width)-x,h=Math.min(canvas.height,oy+s.Height)-y;
 if(w<=0||h<=0)return;
 const patch=desktopCtx.getImageData(x,y,w,h),p=patch.data;
 for(let row=0;row<h;row++)for(let col=0;col<w;col++){const i=(y+row-oy)*s.Width+x+col-ox,k=(row*w+col)*4;for(let c=0;c<3;c++)p[k+c]=s.alpha.length?Math.min(255,Math.floor(s.xor[i*3+c]*s.alpha[i]/255)+Math.floor((p[k+c]*(255-s.alpha[i])+127)/255)):(p[k+c]&s.and[i])^s.xor[i*3+c];}
 ctx.putImageData(patch,x,y);previousCursor={x,y,w,h};
}
function updateDrive(d,phase){
 const panel=document.getElementById('drive-panel'),message=document.getElementById('drive-message'),path=document.getElementById('drive-path');
 panel.hidden=!d?.enabled;
 if(!d?.enabled){message.textContent='';path.textContent='';return;}
 const descriptions={ready:'已连接',negotiating:'正在连接',rejected:'服务器未接受共享',failed:'共享已停止',closed:'共享已关闭',disconnected:'共享已断开'};
 message.textContent=d.name+' · '+(d.writable?'可读写':'只读')+' · '+(phase==='redirecting'?'正在切换服务器':phase==='reconnecting'?'等待重新连接':descriptions[d.phase]||'等待连接');
 path.textContent='\\\\tsclient\\'+d.name;
}
function updateState(state){
 appMoveToken=state.remoteapp?.move?.token||"";appFocusToken=state.remoteapp?.focus_token||"";
 appUI?.update(state.remoteapp,state.active,state.generation);
 notifyUI?.update(state.remoteapp,state.active,state.generation);
 updateDrive(state.drive,state.reconnect?.phase);
 audioPlayer?.update(state.audio,state.reconnect?.phase??'connected');
 microphone?.update(state.microphone,state.reconnect?.phase??'connected');
 unicodeAvailable=!!state.unicode_input;clipboardInfo=state.clipboard||{};connectionInfo=state.reconnect||{};remoteActive=!!state.active;
 displayInfo=state.display||{};resizeInfo=state.resize||{};
 if(state.generation!==generation){generation=state.generation;queue=[];ready=false;etag='';textBusy=false;}
 if(!state.active){ready=false;queue=[];etag='';textBusy=false;status.textContent='正在恢复会话…';waiting.textContent='服务器正在重新激活桌面…';waiting.classList.remove('hidden');}
 if(connectionInfo.phase==='reconnecting'||connectionInfo.phase==='redirecting'||connectionInfo.phase==='restoring'){ready=false;queue=[];etag='';textBusy=false;status.textContent=connectionInfo.phase==='redirecting'?'正在切换服务器…':connectionInfo.phase==='reconnecting'?'连接中断，正在重新连接…':'连接已建立，等待新画面…';waiting.textContent=connectionInfo.phase==='redirecting'?'正在连接本地配置允许的目标服务器…':connectionInfo.phase==='reconnecting'?'正在恢复原来的远程会话，请稍候…':'正在重新接收桌面画面…';waiting.classList.remove('hidden');}
 if(resizeInfo.pending){ready=false;queue=[];etag='';textBusy=false;status.textContent='正在调整分辨率…';waiting.textContent='正在等待远程桌面切换尺寸…';waiting.classList.remove('hidden');}
 if(!resizeSending){
  if(resizeInfo.pending)resizeMessage.textContent='已发送请求，正在等待服务器切换桌面…';
  else if(resizeInfo.result==='applied')resizeMessage.textContent='服务器已切换至 '+state.width+' × '+state.height;
  else if(resizeInfo.result==='adjusted')resizeMessage.textContent='服务器采用了 '+state.width+' × '+state.height+'，与请求尺寸不同';
  else if(resizeInfo.result==='unconfirmed')resizeMessage.textContent='尚未确认尺寸变化；请检查当前尺寸后再决定是否重试';
  else if(resizeInfo.result==='closed'||resizeInfo.result==='failed'||resizeInfo.result==='interrupted')resizeMessage.textContent='本次调整未完成，显示控制通道不可用';
  else resizeMessage.textContent=displayInfo.ready?'选择分辨率后点击应用，无需重新登录':displayInfo.enabled?'等待服务器提供分辨率调整能力…':'当前连接未启用动态分辨率';
 }
 if(resizeSeen!==generation){resizeSeen=generation;const actual=state.width+'x'+state.height;if(['1280x720','1600x900','1920x1080','2560x1440'].includes(actual))resolution.value=actual;}
 if(state.pointer_version!==pointerVersion){
  pointer=state.pointer;pointerVersion=state.pointer_version;
  if(pointer.Shape){pointer.Shape.xor=Uint8Array.from(atob(pointer.Shape.XOR),c=>c.charCodeAt(0));pointer.Shape.and=Uint8Array.from(atob(pointer.Shape.AND),c=>c.charCodeAt(0));pointer.Shape.alpha=Uint8Array.from(atob(pointer.Shape.Alpha||''),c=>c.charCodeAt(0));}
 }
 if(state.position_version!==positionVersion){positionVersion=state.position_version;cursorX=pointer.Position.X;cursorY=pointer.Position.Y;}
 cursorX=Math.max(0,Math.min(state.width-1,cursorX));cursorY=Math.max(0,Math.min(state.height-1,cursorY));
 drawPointer();updateTextButtons();updateResizeButtons();
}
async function frames(){
 if(stopped)return;
 try{
  const state=await (await api('/status?pointer_version='+pointerVersion)).json();updateState(state);
  const r=await api('/frame',{headers:etag?{'If-None-Match':etag}:{}});
  if(state.active&&!resizeInfo.pending&&!resizeSending&&r.status===200&&Number(r.headers.get('X-OpenRDP-Generation'))===generation){
   const frameGeneration=generation,bitmap=await createImageBitmap(await r.blob());
   if(stopped||generation!==frameGeneration||!remoteActive||connectionInfo.phase==='reconnecting'||connectionInfo.phase==='redirecting'||resizeInfo.pending||resizeSending){bitmap.close();return scheduleFrames();}
   if(canvas.width!==bitmap.width||canvas.height!==bitmap.height){canvas.width=bitmap.width;canvas.height=bitmap.height;}
   if(desktop.width!==bitmap.width||desktop.height!==bitmap.height){desktop.width=bitmap.width;desktop.height=bitmap.height;}
   desktopCtx.drawImage(bitmap,0,0);ctx.drawImage(bitmap,0,0);bitmap.close();previousCursor=null;
   etag=r.headers.get('ETag');appRevision=r.headers.get('X-OpenRDP-App-Revision')||'';ready=!appControl;drawPointer();updateTextButtons();updateResizeButtons();waiting.classList.add('hidden');status.textContent='已连接 · '+canvas.width+' × '+canvas.height;
  }
 }catch{end('连接已断开');waiting.textContent='连接已结束，请重新启动测试客户端';}
 scheduleFrames();
}
function scheduleFrames(){if(!stopped)setTimeout(frames,100);}
async function beforeAppControl(){
 appControl=true;ready=false;queue=[];
 while(sending&&!stopped)await new Promise(resolve=>setTimeout(resolve,10));
 if(stopped)throw new Error('connection ended');
 await api('/input',{method:'POST',headers:{'Content-Type':'application/json','X-OpenRDP-Generation':String(generation),'X-OpenRDP-App-Revision':appRevision},body:JSON.stringify([{kind:'release'}])});
}
function position(e){const r=canvas.getBoundingClientRect();return{x:Math.max(0,Math.min(canvas.width-1,Math.floor((e.clientX-r.left)*canvas.width/r.width))),y:Math.max(0,Math.min(canvas.height-1,Math.floor((e.clientY-r.top)*canvas.height/r.height)))};}
canvas.addEventListener('pointermove',e=>{if(e.pointerType==='mouse'){const p=position(e);inside=true;cursorX=p.x;cursorY=p.y;drawPointer();enqueue({kind:'move',...p});}});
canvas.addEventListener('pointerenter',e=>{const p=position(e);inside=true;cursorX=p.x;cursorY=p.y;drawPointer();});
canvas.addEventListener('pointerleave',()=>{inside=false;drawPointer();});
canvas.addEventListener('pointerdown',e=>{if(!ready||e.button>2)return;e.preventDefault();canvas.focus({preventScroll:true});canvas.setPointerCapture(e.pointerId);enqueue({kind:'button',button:[1,3,2][e.button],down:true,...position(e)});});
canvas.addEventListener('pointerup',e=>{if(e.button>2)return;e.preventDefault();enqueue({kind:'button',button:[1,3,2][e.button],down:false,...position(e)});if(canvas.hasPointerCapture(e.pointerId))canvas.releasePointerCapture(e.pointerId);});
canvas.addEventListener('pointercancel',()=>enqueue({kind:'release'}));
canvas.addEventListener('contextmenu',e=>e.preventDefault());
canvas.addEventListener('wheel',e=>{e.preventDefault();if(e.deltaY)enqueue({kind:'wheel',units:e.deltaY<0?120:-120});},{passive:false});
const keys={Escape:1,Digit1:2,Digit2:3,Digit3:4,Digit4:5,Digit5:6,Digit6:7,Digit7:8,Digit8:9,Digit9:10,Digit0:11,Minus:12,Equal:13,Backspace:14,Tab:15,KeyQ:16,KeyW:17,KeyE:18,KeyR:19,KeyT:20,KeyY:21,KeyU:22,KeyI:23,KeyO:24,KeyP:25,BracketLeft:26,BracketRight:27,Enter:28,ControlLeft:29,KeyA:30,KeyS:31,KeyD:32,KeyF:33,KeyG:34,KeyH:35,KeyJ:36,KeyK:37,KeyL:38,Semicolon:39,Quote:40,Backquote:41,ShiftLeft:42,Backslash:43,KeyZ:44,KeyX:45,KeyC:46,KeyV:47,KeyB:48,KeyN:49,KeyM:50,Comma:51,Period:52,Slash:53,ShiftRight:54,NumpadMultiply:55,AltLeft:56,Space:57,CapsLock:58,F1:59,F2:60,F3:61,F4:62,F5:63,F6:64,F7:65,F8:66,F9:67,F10:68,NumLock:69,ScrollLock:70,Numpad7:71,Numpad8:72,Numpad9:73,NumpadSubtract:74,Numpad4:75,Numpad5:76,Numpad6:77,NumpadAdd:78,Numpad1:79,Numpad2:80,Numpad3:81,Numpad0:82,NumpadDecimal:83,IntlBackslash:86,F11:87,F12:88};
const extended={NumpadEnter:28,ControlRight:29,NumpadDivide:53,AltRight:56,Home:71,ArrowUp:72,PageUp:73,ArrowLeft:75,ArrowRight:77,End:79,ArrowDown:80,PageDown:81,Insert:82,Delete:83,MetaLeft:91,MetaRight:92,ContextMenu:93};
for(const name of ['keydown','keyup'])canvas.addEventListener(name,e=>{if(!ready)return;if(e.isComposing||e.keyCode===229){hint.textContent='请展开上方「中文输入与文本剪贴板」面板输入中文';return;}const ext=Object.hasOwn(extended,e.code),code=ext?extended[e.code]:keys[e.code];if(!code)return;e.preventDefault();e.stopPropagation();enqueue({kind:'key',code,extended:ext,down:name==='keydown'});});
canvas.addEventListener('focus',()=>{hint.textContent='正在控制远程桌面 · 点击画面外可退出键盘控制';});
canvas.addEventListener('blur',()=>{enqueue({kind:'blur'});hint.textContent='点击画面开始操作 · 移出焦点会释放按键';});
window.addEventListener('blur',()=>enqueue({kind:'blur'}));
document.addEventListener('visibilitychange',()=>{if(document.hidden)enqueue({kind:'blur'});});
async function disconnect(){if(stopped)return;try{await api('/disconnect',{method:'POST',keepalive:true});}catch{}end('已断开');}
document.getElementById('disconnect').addEventListener('click',disconnect);
document.getElementById('fullscreen').addEventListener('click',()=>{const screen=document.querySelector('.screen');(document.fullscreenElement?document.exitFullscreen():screen.requestFullscreen()).catch(()=>{});});
// Navigation also includes reload. Release input, but leave the session alive
// for the next document; the server expires abandoned pages separately.
window.addEventListener('pagehide',()=>{uploadClipboard?.end();fileClipboard?.end();richClipboard?.end();microphone?.end();audioPlayer?.end();if(!stopped&&ready)fetch('/input',{method:'POST',headers:{...headers,'Content-Type':'application/json','X-OpenRDP-Generation':String(generation),'X-OpenRDP-App-Revision':appRevision},body:JSON.stringify([{kind:'blur'}]),keepalive:true}).catch(()=>{});});
function updateTextButtons(){
 richClipboard?.update({generation,ready:ready&&!stopped,active:remoteActive,phase:connectionInfo.phase??'connected',clipboard:clipboardInfo});
 fileClipboard?.update({generation,ready:ready&&!stopped,active:remoteActive,phase:connectionInfo.phase??'connected',clipboard:clipboardInfo});
 uploadClipboard?.update({generation,ready:ready&&!stopped,active:remoteActive,phase:connectionInfo.phase??'connected',clipboard:clipboardInfo});
 document.getElementById('send-text').disabled=stopped||!ready||!unicodeAvailable||textBusy;
 document.getElementById('send-clipboard').disabled=stopped||!ready||!clipboardInfo.enabled||!clipboardInfo.ready||clipboardInfo.busy||clipboardInfo.file_busy||clipboardBusy;
 document.getElementById('get-clipboard').disabled=stopped||!ready||!clipboardInfo.enabled||!clipboardInfo.ready||!clipboardInfo.remote_text||clipboardInfo.busy||clipboardInfo.file_busy||clipboardBusy;
}
function sendText(){
 if(stopped||!ready||!unicodeAvailable||textBusy)return;
 if(!textValue.value.length||textValue.value.length>512){textMessage.textContent='请输入短文本；较长内容请通过剪贴板发送';return;}
 textBusy=true;enqueue({kind:'text',text:textValue.value});textMessage.textContent='正在发送文本…';updateTextButtons();flush();
}
async function clipboardAction(action){
 if(richClipboard)return richClipboard.textAction(action);
 if(stopped||!ready||clipboardBusy)return;const actionGeneration=generation;clipboardBusy=true;updateTextButtons();textMessage.textContent='正在传输文本…';
 try{
  const r=await api('/clipboard',{method:'POST',headers:{'Content-Type':'application/json','X-OpenRDP-Generation':String(actionGeneration)},body:JSON.stringify(action==='set'?{action,text:textValue.value}:{action})});
  if(generation!==actionGeneration)return;
  if(action==='get'){const result=await r.json();if(generation!==actionGeneration)return;textValue.value=result.text;textMessage.textContent='已读取远程文本，可编辑或复制到本机';}
  else textMessage.textContent='远程已接受文本，可切回远程窗口粘贴';
 }catch(e){if(generation!==actionGeneration)return;textMessage.textContent=e.status===504?'远程回复超时，请稍后重试':e.status===409?'剪贴板忙或内容已改变；读取前请先在远程复制文本':e.status===422?'远程拒绝了剪贴板请求':'文本传输失败，请检查内容大小与连接';}
 finally{clipboardBusy=false;updateTextButtons();}
}
document.getElementById('send-text').addEventListener('click',sendText);
document.getElementById('send-clipboard').addEventListener('click',()=>clipboardAction('set'));
document.getElementById('get-clipboard').addEventListener('click',()=>clipboardAction('get'));
document.getElementById('copy-text').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(textValue.value);textMessage.textContent='已复制到本机剪贴板';}catch{textMessage.textContent='浏览器未允许复制，请在文本框中手动选择并复制';}});
function updateResizeButtons(){const disabled=stopped||!ready||!displayInfo.ready||resizeSending||resizeInfo.pending||sending;resolution.disabled=disabled;document.getElementById('apply-resolution').disabled=disabled;}
async function resizeDesktop(){
 if(stopped||!ready||!displayInfo.ready||resizeSending||resizeInfo.pending||sending)return;
 const match=/^(\d+)x(\d+)$/.exec(resolution.value);if(!match)return;
 const width=Number(match[1]),height=Number(match[2]),actionGeneration=generation;
 if(width<200||width>8192||width%2||height<200||height>8192||width*height>16777216||width*height>displayInfo.max_area){resizeMessage.textContent='所选分辨率超过当前服务器支持范围';return;}
 resizeSending=true;ready=false;queue=[];etag='';textBusy=false;updateTextButtons();updateResizeButtons();resizeMessage.textContent='正在申请调整分辨率…';
 try{const r=await api('/resize',{method:'POST',headers:{'Content-Type':'application/json','X-OpenRDP-Generation':String(generation),'X-OpenRDP-App-Revision':appRevision},body:JSON.stringify({width,height})});if(generation!==actionGeneration)return;resizeMessage.textContent=r.status===204?'当前已是所选分辨率':'请求已发送，等待服务器实际切换…';}
 catch(e){if(generation!==actionGeneration)return;resizeMessage.textContent=e.status===409?'当前暂时无法调整，请等待桌面恢复后重试':e.status===400?'服务器不支持所选尺寸':'分辨率请求未完成，请检查连接';}
 finally{resizeSending=false;updateResizeButtons();}
}
document.getElementById('apply-resolution').addEventListener('click',resizeDesktop);
if(token.length<40){end('缺少连接凭据，请使用启动时生成的地址');waiting.textContent='请使用完整的本地测试地址打开';}else frames();
