'use strict';
globalThis.OpenRDPFiles=class {
 constructor({request,document:doc=globalThis.document}) {
  this.request=request;this.state={};this.seq=0;this.pending=null;this.url=null;this.dead=false;
  this.e={};for(const id of ['files-get','files-cancel','files-save','files-message','files-progress'])this.e[id]=doc.getElementById(id);
  this.e['files-get'].addEventListener('click',()=>this.start());this.e['files-cancel'].addEventListener('click',()=>this.clear());this.render();
 }
 update(state) {
  const previous=this.state;this.state=state;
  if(previous.generation!==undefined&&(previous.generation!==state.generation||!state.active||state.phase!=='connected')) {
   if(this.pending||this.url){this.invalidate();this.message('连接已变化，旧下载已清除；恢复后请重新读取');}
  }
  if(!previous.clipboard?.file_download&&state.clipboard?.file_download&&!this.pending&&!this.dead)this.message('先在远端复制文件或文件夹，再点击“读取远端文件”');
  this.render();
 }
 available(){const s=this.state;return !this.dead&&s.ready&&s.active&&s.phase==='connected'&&s.clipboard?.file_download;}
 render(){
  const c=this.state.clipboard||{};
  this.e['files-get'].disabled=!this.available()||!!this.pending||c.busy||c.file_busy||!c.remote_files;
  this.e['files-cancel'].disabled=!this.pending&&!this.url;this.e['files-save'].hidden=!this.url;
  if(!this.pending&&!this.url&&!c.file_download)this.message('启动时启用文件下载后可使用此功能');
 }
 message(s){this.e['files-message'].textContent=s;}
 current(op){return !this.dead&&this.pending===op&&op.seq===this.seq&&op.generation===this.state.generation&&this.state.active&&this.state.phase==='connected';}
 async call(op,path,options={}) {
  const r=await this.request(path,{...options,signal:op.controller.signal,headers:{...options.headers,'X-OpenRDP-Generation':String(op.generation)}});
  if(r.headers.get('X-OpenRDP-Generation')!==String(op.generation))throw Object.assign(new Error('connection changed'),{status:409});return r;
 }
 cancelRemote(op){
  if(!op?.id)return;
  this.request('/clipboard/files',{method:'POST',keepalive:true,headers:{'Content-Type':'application/json','X-OpenRDP-Generation':String(op.generation)},body:JSON.stringify({action:'cancel',id:op.id})}).catch(()=>{});
 }
 invalidate(){
  const op=this.pending;++this.seq;this.pending=null;
  if(op){op.controller.abort();clearTimeout(op.timer);this.cancelRemote(op);}
  if(this.url){URL.revokeObjectURL(this.url);this.url=null;}
  this.e['files-save'].removeAttribute('href');this.e['files-save'].hidden=true;this.e['files-progress'].value=0;this.e['files-progress'].max=1;
 }
 clear(){this.invalidate();this.message('下载已取消或清除；远端原文件保持不变');this.render();}
 end(){if(this.dead)return;this.invalidate();this.dead=true;this.render();this.message('连接已结束，下载已清除');}
 async start(){
  if(!this.available()||this.pending||this.state.clipboard.busy||this.state.clipboard.file_busy)return;
  this.invalidate();const op={seq:++this.seq,generation:this.state.generation,controller:new AbortController(),id:null};
  this.pending=op;this.message('正在读取远端文件列表…');this.render();
  try {
   const r=await this.call(op,'/clipboard/files',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'download'})});
   const job=await r.json();if(typeof job.id!=='string'||!/^[0-9a-f]{32}$/.test(job.id))throw new Error('invalid transfer');
   op.id=job.id;if(!this.current(op)){this.cancelRemote(op);return;}await this.poll(op);
  }catch(e){this.failure(op,e);}
 }
 async poll(op){
  if(!this.current(op))return;
  try {
   const r=await this.call(op,'/clipboard/files?id='+encodeURIComponent(op.id));const s=await r.json();if(!this.current(op))return;
   if(s.id!==op.id||!Number.isSafeInteger(s.total)||s.total<0||s.total>64*1024*1024||!Number.isSafeInteger(s.received)||s.received<0||s.received>s.total)throw new Error('invalid progress');
   this.e['files-progress'].max=Math.max(s.total,1);this.e['files-progress'].value=s.received;
   if(s.state==='finished')throw Object.assign(new Error('transfer ended'),{transferError:s.error});
   if(s.state==='ready'){await this.prepare(op);return;}
   const labels={listing:'正在读取文件列表…',packing:'文件已接收，正在打包…',receiving:`已接收 ${(s.received/1048576).toFixed(2)} / ${(s.total/1048576).toFixed(2)} MB（${s.completed}/${s.files} 项）`};
   if(!labels[s.state])throw new Error('invalid state');this.message(labels[s.state]);op.timer=setTimeout(()=>this.poll(op),500);
  }catch(e){this.failure(op,e);}
 }
 async prepare(op){
  this.message('正在准备 ZIP 下载…');const r=await this.call(op,'/clipboard/files/archive?id='+encodeURIComponent(op.id));const size=Number(r.headers.get('Content-Length'));
  if(!Number.isSafeInteger(size)||size<22||size>68*1024*1024||r.headers.get('Content-Type')!=='application/zip')throw new Error('invalid archive');
  const blob=await r.blob();if(!this.current(op))return;if(blob.size!==size)throw new Error('truncated archive');
  this.url=URL.createObjectURL(blob);this.e['files-save'].href=this.url;this.e['files-save'].download='rdp-go-files.zip';this.e['files-save'].hidden=false;
  this.message('文件已完整接收，点击“保存 ZIP”交给浏览器保存');this.cancelRemote(op);op.id=null;this.render();
 }
 failure(op,e){
  if(!this.current(op))return;
  const messages={limit:'文件超出上限：最多 128 项、合计 64 MB',names:'文件名或目录结构存在冲突，未生成下载',changed:'连接或剪贴板已变化，请重新读取',rejected:'远端拒绝读取文件，请重新复制后再试',timeout:'读取超时，请重新复制后再试',cancelled:'下载已取消',cleanup_failed:'临时文件清理失败，请关闭查看器后检查本机临时目录'};
  this.invalidate();this.message(messages[e.transferError]||(e.status===409?'当前正在处理其他操作，稍后重试':'下载未完成，请检查连接后重试'));this.render();
 }
};
