'use strict';
// Server-provided titles are plain text. No server executable, arguments or
// title is ever interpreted as HTML, JavaScript or a local command.
class OpenRDPRemoteApp {
 constructor({request,generation,focus,before,after}) {
  Object.assign(this,{request,generation,focus,before,after});this.busy=false;
  this.root=document.getElementById('remoteapp-tools');this.select=document.getElementById('app-windows');this.message=document.getElementById('app-message');
  this.select.addEventListener('change',()=>this.update(this.state,this.active,this.epoch));
  this.launch=document.getElementById('app-launch');this.launch.addEventListener('click',()=>this.action('launch'));
  this.root.querySelectorAll('[data-app-action]').forEach(button=>button.addEventListener('click',()=>this.action(button.dataset.appAction)));
 }
 update(state,active,generation) {
  this.state=state;this.active=active;this.epoch=generation;this.root.hidden=!state?.enabled;
  if(!state?.enabled)return;
  const old=this.select.value,entries=state.windows||[];
  const signature=JSON.stringify(entries);
  if(signature!==this.signature){
   this.signature=signature;this.select.replaceChildren();
   for(const entry of entries){const option=document.createElement('option');option.value=entry.id+':'+entry.lifetime;option.textContent=(entry.title||'窗口 '+entry.id)+(entry.cloaked?'（已隐藏）':'');this.select.append(option);}
   if([...this.select.options].some(option=>option.value===old))this.select.value=old;
  }
  const selection=state.selected_lifetime?state.selected+':'+state.selected_lifetime:'';
  if(selection!==this.selection||generation!==this.selectionEpoch){
   this.selection=selection;this.selectionEpoch=generation;
   if(selection&&[...this.select.options].some(option=>option.value===selection))this.select.value=selection;
  }
  const enabled=active&&state.ready&&!this.busy&&!state.move?.phase;
  this.launch.disabled=!enabled||state.launch==='pending';
  this.launch.textContent=state.launch==='launched'?'再次启动应用':'启动应用';
  this.select.disabled=!enabled||!entries.length;
  const selected=entries.find(entry=>entry.id+':'+entry.lifetime===this.select.value);
  this.root.querySelectorAll('[data-app-action]').forEach(button=>{
   const action=button.dataset.appAction;
   button.disabled=!enabled||!selected||state.syncing||(['cloak','uncloak'].includes(action)&&(!state.cloaking||(action==='cloak')===!!selected.cloaked))||(selected?.cloaked&&!['uncloak','close'].includes(action));
  });
  if(!this.busy&&state.move?.phase){
   this.message.textContent=state.move.phase==='moving'?'正在调整窗口 · 方向键移动/缩放，Ctrl 精细调整，Enter 完成，Esc 取消':'等待服务器完成窗口调整…';
  }else if(!this.busy){
   const labels={waiting:'等待应用通道…',ready:'可启动应用',pending:'正在启动应用…',launched:'应用启动成功',failed:'应用启动失败（'+state.result+' / '+state.raw_result+'）'};
   this.message.textContent=state.syncing?'正在同步远程窗口…':(labels[state.launch]||'等待远程窗口')+(state.pending?' · 等待 '+state.pending+' 项窗口图像或几何信息':' · '+entries.length+' 个窗口');
  }
 }
 async action(action){
  if(this.busy||!this.active||!this.state?.ready)return;
  const epoch=this.epoch,[id,lifetime]=this.select.value.split(':');
  if(action!=='launch'&&(!id||!lifetime))return;
  this.busy=true;this.update(this.state,this.active,this.epoch);this.message.textContent='正在提交…';
  try{
   await this.before?.();
   if(epoch!==this.generation())throw new Error('connection changed');
   await this.request('/remoteapp',{method:'POST',headers:{'Content-Type':'application/json','X-OpenRDP-Generation':String(epoch)},body:JSON.stringify(action==='launch'?{action}:{action,window:Number(id),lifetime})});
   this.message.textContent=['cloak','uncloak'].includes(action)?'窗口显示状态已更新':'请求已发送，等待服务器更新';
   if(['activate','move','size'].includes(action))this.focus();
  }catch{this.message.textContent='请求未确认，请刷新窗口状态后重试；不会自动重复提交';}
  finally{this.busy=false;this.after?.();}
 }
}
