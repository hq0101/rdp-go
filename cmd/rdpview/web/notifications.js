'use strict';
// This panel represents remote icons in the page, not OS notifications. Server
// text is assigned only as text; icon URLs are generated from our decoded PNGs.
class OpenRDPNotifications {
 constructor({request,generation,before,after}) {
  Object.assign(this,{request,generation,before,after});this.page=0;this.urls=[];this.entries=[];this.serial=0;this.lifecycle=0;this.pending=0;this.chain=Promise.resolve();this.last='';
  for(const [name,id] of Object.entries({root:'notify-tools',icons:'notify-icons',message:'notify-message',pageLabel:'notify-page',prev:'notify-prev',next:'notify-next',bubble:'notify-balloon',title:'notify-title',text:'notify-text',open:'notify-open',dismiss:'notify-dismiss'}))this[name]=document.getElementById(id);
  this.prev.addEventListener('click',()=>this.changePage(-1));this.next.addEventListener('click',()=>this.changePage(1));
  this.open.addEventListener('click',()=>this.closeBalloon('balloon_click'));this.dismiss.addEventListener('click',()=>this.closeBalloon('balloon_hide'));
  document.addEventListener('visibilitychange',()=>{if(document.hidden)this.closeBalloon('balloon_hide');});
  document.addEventListener('keydown',e=>{if(e.key==='Tab')this.pointerKey='';});
  window.addEventListener('blur',()=>this.closeBalloon('balloon_hide'));
 }
 key(n){return n.window+':'+n.id+':'+n.lifetime;}
 end(){this.enabled=false;this.suspended=false;this.serial++;this.lifecycle++;this.pointerKey='';this.last='';this.clearBalloon();this.clearIcons();this.root.hidden=true;}
 clearIcons(){for(const url of this.urls)URL.revokeObjectURL(url);this.urls=[];this.icons.replaceChildren();this.entries=[];}
 clearBalloon(){clearTimeout(this.timer);this.shown=null;this.bubble.hidden=true;}
 update(state,active,epoch){
  const enabled=!!(state?.enabled&&state.ready&&active&&!state.syncing);
  if(!enabled){if(this.enabled)this.end();return;}
  if(this.epoch!==epoch){this.end();this.epoch=epoch;this.page=0;}
  this.enabled=true;
  if(state.move?.phase){if(!this.suspended){this.closeBalloon('balloon_hide');this.suspended=true;this.serial++;this.last='';this.root.hidden=true;}return;}
  this.suspended=false;const key=epoch+':'+state.notification_revision+':'+this.page;
  if(key===this.last)return;this.last=key;this.load();
 }
 changePage(delta){this.closeBalloon('balloon_hide');this.page=Math.max(0,this.page+delta);this.last='';this.load();}
 async load(){
  if(!this.enabled||this.suspended)return;const serial=++this.serial,epoch=this.epoch;
  try{
   const response=await this.request('/remoteapp/notifications?page='+this.page,{headers:{'X-OpenRDP-Generation':String(epoch)}});const data=await response.json();
   if(serial!==this.serial||epoch!==this.epoch||!this.enabled||data.generation!==epoch)return;
   this.page=data.Page;this.last=epoch+':'+data.revision+':'+this.page;
   if(this.shown&&!data.entries.some(n=>this.key(n)===this.key(this.shown)&&n.info_serial===this.shown.info_serial))this.closeBalloon('balloon_hide');
   this.render(data);
  }catch{if(serial===this.serial&&this.enabled){this.last='';this.message.textContent='通知区域暂不可用';}}
 }
 render(data){
  const focused=document.activeElement?.dataset?.notifyKey;
  this.clearIcons();this.entries=data.entries;this.root.hidden=data.Total===0;
  this.pageLabel.textContent=data.Total+' 个图标 · 第 '+(this.page+1)+' 页';this.prev.disabled=this.page===0;this.next.disabled=(this.page+1)*32>=data.Total;
  this.message.textContent='点击或右键操作 · Tab、Enter 与菜单键可用';
  for(const n of data.entries){
   const button=document.createElement('button');button.type='button';button.className='notify-icon';button.dataset.notifyKey=this.key(n);
   const label=n.tooltip||'远程图标 '+n.id;button.title=label;button.setAttribute('aria-label',label);
   if(n.icon){const bytes=Uint8Array.from(atob(n.icon),c=>c.charCodeAt(0));const url=URL.createObjectURL(new Blob([bytes],{type:'image/png'}));this.urls.push(url);const img=document.createElement('img');img.src=url;img.alt='';button.append(img);}else{button.textContent='●';button.title=label+'（图像暂不可用）';}
   button.addEventListener('mousedown',e=>{if(e.button!==0&&e.button!==2)return;this.pointerKey=this.key(n);const side=e.button===0?'left':'right';this.send(n,side+(e.detail===2?'_double':'_down'));});
   button.addEventListener('mouseup',e=>{if(e.button===0||e.button===2)this.send(n,e.button===0?'left_up':'right_up');});
   button.addEventListener('contextmenu',e=>e.preventDefault());
   button.addEventListener('keydown',e=>{if(['Enter',' ','ContextMenu'].includes(e.key)||e.key==='F10'&&e.shiftKey){e.preventDefault();if(e.repeat)return;this.send(n,e.key==='ContextMenu'||e.key==='F10'?'key_context':e.key==='Enter'&&this.pointerKey===this.key(n)?'select':'key_select');}});
   button.addEventListener('click',e=>{if(e.detail===0)this.send(n,'key_select');});
   button.addEventListener('mouseenter',()=>this.showBalloon(n));button.addEventListener('focus',()=>{if(!this.restoringFocus)this.showBalloon(n);});
   this.icons.append(button);if(focused===this.key(n)){this.restoringFocus=true;try{button.focus({preventScroll:true});}finally{this.restoringFocus=false;}}
  }
 }
 send(n,action,cycle=null){
  const ending=action==='balloon_hide'||action==='balloon_timeout'||action==='balloon_click';
  // Keep one bounded slot for the visible balloon's terminal callback even
  // when normal icon input has filled its 64-entry queue.
  if(!this.enabled||this.pending>=(ending?65:64))return Promise.resolve(false);
  const epoch=this.epoch,lifecycle=this.lifecycle,entry={...n};this.pending++;
  const work=this.chain.then(async()=>{
   const passive=action.startsWith('balloon_')&&action!=='balloon_click';
   if(!this.enabled||lifecycle!==this.lifecycle||epoch!==this.epoch||epoch!==this.generation())return false;
   if(this.suspended&&!passive)return false;
   const dismiss=action.startsWith('balloon_')&&action!=='balloon_show';
   if(dismiss&&!cycle?.token)return false;
   try{
    if(!passive)await this.before?.();
    if(!this.enabled||lifecycle!==this.lifecycle||epoch!==this.epoch||epoch!==this.generation())return false;
    const response=await this.request('/remoteapp/notify',{method:'POST',headers:{'Content-Type':'application/json','X-OpenRDP-Generation':String(epoch)},body:JSON.stringify({window:entry.window,id:entry.id,lifetime:entry.lifetime,revision:entry.revision,info_serial:entry.info_serial,action,balloon:dismiss?cycle.token:''})});
    if(action==='balloon_show'){
     const token=response.headers.get('X-OpenRDP-Balloon');
     if(!cycle||!token||!/^[1-9][0-9]{0,19}$/.test(token))throw new Error('missing balloon token');
     cycle.token=token;
    }
    return true;
   }catch(error){if(!(action==='balloon_hide'&&error.status===409)&&epoch===this.epoch&&lifecycle===this.lifecycle)this.message.textContent='图标已变化或请求未确认；不会重复发送';return false;}
   finally{if(!passive)this.after?.();}
  });
  this.chain=work.then(()=>{this.pending--;},()=>{this.pending--;});return work;
 }
 showBalloon(n){
  if(!this.enabled||this.suspended||!n.version||!n.balloon?.Text||document.hidden)return;
  if(this.shown&&this.key(this.shown)===this.key(n)&&this.shown.info_serial===n.info_serial)return;
  this.closeBalloon('balloon_hide');const cycle={...n,token:''};this.shown=cycle;this.title.textContent=n.balloon.Title||'远程通知';this.text.textContent=n.balloon.Text;this.bubble.hidden=false;
  const lifecycle=this.lifecycle;
  this.send(n,'balloon_show',cycle).then(ok=>{if(!ok&&lifecycle===this.lifecycle&&this.shown===cycle)this.clearBalloon();});
  this.timer=setTimeout(()=>this.closeBalloon('balloon_timeout'),Math.max(10000,Math.min(30000,n.balloon.Timeout||10000)));
 }
 closeBalloon(action){const n=this.shown;if(!n)return;this.clearBalloon();this.send(n,action,n);}
}
