'use strict';
globalThis.RdpGoUpload=class {
 constructor({request,document:doc=globalThis.document}) {
  this.request=request;this.state={};this.seq=0;this.pending=null;this.files=[];this.dead=false;this.published=false;
  this.e={};for(const id of ['upload-files','upload-folder','upload-send','upload-clear','upload-list','upload-progress','upload-message'])this.e[id]=doc.getElementById(id);
  for(const id of ['upload-files','upload-folder'])this.e[id].addEventListener('change',()=>this.select(this.e[id].files));
  this.e['upload-send'].addEventListener('click',()=>this.start());this.e['upload-clear'].addEventListener('click',()=>this.clear());this.render();
 }
 available(){const s=this.state;return !this.dead&&s.ready&&s.active&&s.phase==='connected'&&s.clipboard?.file_upload;}
 update(state){const prev=this.state;this.state=state;if(prev.generation!==undefined&&(prev.generation!==state.generation||!state.active||state.phase!=='connected')){this.invalidate();this.message('连接已变化，文件选择已清除；恢复后请重新选择');}this.render();}
 message(s){this.e['upload-message'].textContent=s;}
 render(){const busy=!!this.pending;for(const id of ['upload-files','upload-folder'])this.e[id].disabled=!this.available()||busy;
  this.e['upload-send'].disabled=!this.available()||busy||!this.files.length||this.state.clipboard?.busy||this.state.clipboard?.file_busy;
  this.e['upload-clear'].disabled=!busy&&!this.files.length&&!this.published;
 }
 select(list){if(!this.available()||this.pending)return;
  // Native FileList is live: clearing the input can empty the same object.
  // Retain the selected File references before resetting either chooser.
  const files=Array.from(list||[]);this.invalidate();let total=0;
  if(!files.length){this.message('未选择文件');this.render();return;}
  if(files.length>128||files.some(f=>!Number.isSafeInteger(f.size)||f.size<0||(total+=f.size)>64*1048576)){this.message('最多选择 128 项，文件合计不超过 64 MB');this.render();return;}
  this.files=files;this.e['upload-list'].textContent=files.map(f=>f.webkitRelativePath||f.name).join('\n');this.message(`已选择 ${files.length} 个文件，合计 ${(total/1048576).toFixed(2)} MB；点击发送后再到远端粘贴`);this.render();
 }
 current(op){return !this.dead&&this.pending===op&&op.seq===this.seq&&op.generation===this.state.generation&&this.state.active&&this.state.phase==='connected';}
 cancelRemote(op){if(!op?.id)return;this.request('/clipboard/upload',{method:'POST',keepalive:true,headers:{'Content-Type':'application/json','X-RdpGo-Generation':String(op.generation)},body:JSON.stringify({action:'cancel',id:op.id})}).catch(()=>{});}
 invalidate(){const op=this.pending;++this.seq;this.pending=null;if(op){op.controller.abort();this.cancelRemote(op);}this.files=[];this.published=false;for(const id of ['upload-files','upload-folder'])this.e[id].value='';this.e['upload-list'].textContent='';this.e['upload-progress'].value=0;this.e['upload-progress'].max=1;}
 clear(){const sent=this.published||this.pending?.publishing;this.invalidate();this.message(sent?'已清除本页选择；远端已接受的文件仍可能被粘贴':'已取消上传并清除选择');this.render();}
 end(){if(this.dead)return;this.invalidate();this.dead=true;this.render();this.message('连接已结束，文件选择已清除');}
 async call(op,path,options){const timer=setTimeout(()=>op.controller.abort(),30000);try {
  const r=await this.request(path,{...options,signal:op.controller.signal,headers:{...options.headers,'X-RdpGo-Generation':String(op.generation)}});
  if(r.headers.get('X-RdpGo-Generation')!==String(op.generation))throw Object.assign(new Error('connection changed'),{transferError:'changed'});return r;
 }finally{clearTimeout(timer);}}
 async start(){
  if(!this.available()||this.pending||!this.files.length||this.state.clipboard.busy||this.state.clipboard.file_busy)return;
  const files=this.files.slice(),op={seq:++this.seq,generation:this.state.generation,controller:new AbortController(),id:null,publishing:false};this.pending=op;this.published=false;this.render();this.message('正在准备上传…');
  try {
   const r=await this.call(op,'/clipboard/upload',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'create',files:files.map(f=>({name:f.webkitRelativePath||f.name,size:f.size}))})});
   const job=await r.json();if(typeof job.id!=='string'||!/^[0-9a-f]{32}$/.test(job.id))throw new Error('invalid upload');op.id=job.id;if(!this.current(op)){this.cancelRemote(op);return;}
   const total=files.reduce((sum,f)=>sum+f.size,0);let sent=0;this.e['upload-progress'].max=Math.max(total,1);
   for(let i=0;i<files.length;i++){
    let offset=0;do {
     if(!this.current(op))return;const end=Math.min(offset+256*1024,files[i].size),chunk=files[i].slice(offset,end);
     await this.call(op,`/clipboard/upload/data?id=${op.id}&index=${i}&offset=${offset}`,{method:'PUT',headers:{'Content-Type':'application/octet-stream'},body:chunk});
     if(!this.current(op))return;sent+=end-offset;offset=end;this.e['upload-progress'].value=sent;
     this.message(`已上传 ${(sent/1048576).toFixed(2)} / ${(total/1048576).toFixed(2)} MB（${i+1}/${files.length} 个文件）`);
    }while(offset<files[i].size);
   }
   if(!this.current(op))return;op.publishing=true;this.message('文件已上传，正在等待远端接受…');
   await this.call(op,'/clipboard/upload',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'publish',id:op.id})});
   if(!this.current(op))return;this.pending=null;this.files=[];this.published=true;
   for(const id of ['upload-files','upload-folder'])this.e[id].value='';
   this.e['upload-progress'].value=Math.max(total,1);this.message('远端已接受文件，请在远端目标文件夹按 Ctrl+V。是否完成粘贴以远端窗口为准。');this.render();
  }catch(e){
   if(!this.current(op))return;const publishing=op.publishing;
   const messages={names:'文件名或目录结构存在冲突，请重新选择',limit:'文件或保留来源达到上限，请减少文件或等待远端释放后重试',changed:'连接或剪贴板已变化，请重新选择',rejected:'远端拒绝接受文件',timeout:'上传等待超时'};
   this.invalidate();this.message(messages[e.transferError]||(publishing?'未确认远端是否接受，请先检查远端再决定是否重新发送':e.status===409?'正在处理其他剪贴板操作，请稍后重试':'上传未完成，请检查连接后重新选择'));this.render();
  }
 }
};
