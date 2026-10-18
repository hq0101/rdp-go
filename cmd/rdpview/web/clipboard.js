'use strict';
// Explicit clipboard actions, with one page operation and one owned preview.
// Markup is data only: no innerHTML, DOM parsing, source URLs or remote assets.
globalThis.OpenRDPClipboard=class OpenRDPClipboard {
 constructor({request,document:doc=globalThis.document,onBusy=()=>{},clipboard=globalThis.navigator?.clipboard}) {
  this.request=request;this.doc=doc;this.onBusy=onBusy;this.clipboard=clipboard;
  this.seq=0;this.pending=null;this.draft=null;this.url=null;this.dead=false;this.state={};
  this.e={};for(const name of ['rich-format','rich-import','rich-file','rich-send','rich-get','rich-copy','rich-clear','rich-image','rich-source','rich-plain','rich-preview','rich-message','text-value','text-message'])this.e[name]=doc.getElementById(name);
  this.e['rich-import'].addEventListener('click',()=>this.importLocal());
  this.e['rich-send'].addEventListener('click',()=>this.send());
  this.e['rich-get'].addEventListener('click',()=>this.get());
  this.e['rich-copy'].addEventListener('click',()=>this.copyLocal());
  this.e['rich-clear'].addEventListener('click',()=>this.clear());
  this.e['rich-format'].addEventListener('change',()=>this.clear());
  this.e['rich-file'].addEventListener('change',()=>{const file=this.e['rich-file'].files?.[0];this.e['rich-file'].value='';if(file)this.importImage(file);});
  this.render();
 }
 update(state) {
  const old=this.state;this.state=state;
  const lost=!state.active||state.phase!=='connected';
  if((old.generation!==undefined&&old.generation!==state.generation)||(!old.lost&&lost)) {
   this.state.lost=lost;this.invalidate();this.message('连接已变化，预览已清除；恢复后请重新读取');
  }
  else if(!old.clipboard?.enabled&&state.clipboard?.enabled&&!this.pending&&!this.dead){
   this.message('选择内容类型后读取到预览，再决定发送或复制');
  }
  this.state.lost=lost;this.render();
 }
 available(){const s=this.state,c=s.clipboard||{};return !this.dead&&s.ready&&!s.lost&&c.enabled&&c.ready;}
 idle(){return this.available()&&!this.pending&&!this.state.clipboard.busy;}
 render(){
  const idle=this.idle(),format=this.e['rich-format'].value,c=this.state.clipboard||{},draft=this.draft;
  this.e['rich-import'].disabled=!idle||!this.clipboard?.read;
  this.e['rich-file'].disabled=!idle;
  this.e['rich-send'].disabled=!idle||!draft||draft.format!==format;
  this.e['rich-get'].disabled=!idle||!(format==='html'?c.remote_html:c.remote_image);
  this.e['rich-copy'].disabled=!idle||!draft||!this.clipboard?.write||typeof ClipboardItem!=='function';
  this.e['rich-clear'].disabled=!draft&&!this.pending;
  this.e['rich-preview'].hidden=!draft;
  if(this.state.clipboard&&!c.enabled&&!this.pending&&!this.dead)this.message('本次连接未启用剪贴板');
 }
 message(text){this.e['rich-message'].textContent=text;}
 clearDraft(){
  if(this.url){URL.revokeObjectURL(this.url);this.url=null;}
  this.draft=null;this.e['rich-image'].removeAttribute('src');this.e['rich-image'].hidden=true;
  this.e['rich-source'].value='';this.e['rich-plain'].textContent='';
 }
 invalidate(){
  ++this.seq;this.pending?.controller.abort();this.pending=null;this.clearDraft();this.onBusy(false);
 }
 clear(){this.invalidate();this.message('预览已清除；远端剪贴板保持原有内容');this.render();}
 end(){if(this.dead)return;this.dead=true;this.invalidate();this.message('连接已结束，预览已清除');this.render();}
 begin(){
  if(!this.idle())return null;
  const op={id:++this.seq,generation:this.state.generation,controller:new AbortController()};
  this.pending=op;this.onBusy(true);this.render();return op;
 }
 current(op){return !this.dead&&!this.state.lost&&this.pending===op&&op.id===this.seq&&op.generation===this.state.generation;}
 finish(op){if(this.pending!==op)return;this.pending=null;this.onBusy(false);this.render();}
 failure(e,op,text=false){
  if(!this.current(op))return;
  const message=e.name==='NotAllowedError'?'浏览器未允许访问本机剪贴板；可选择 PNG 图片或使用上方纯文本操作':e.status===504?'远端回复超时；等待通道完成后再试':e.status===409?'连接或剪贴板已变化，请重新读取':e.status===422?'远端拒绝了剪贴板请求':e.userMessage||'剪贴板操作失败；请检查内容格式、大小或浏览器权限';
  if(text)this.e['text-message'].textContent=message;else this.message(message);
 }
 reject(message){const e=new Error(message);e.userMessage=message;throw e;}
 checkHTML(html,text){
  const enc=new TextEncoder();
  if(typeof html!=='string'||enc.encode(html).length>4*1024*1024-512||html.includes('\0'))this.reject('富文本过大或格式无效（上限约 4 MB）');
  if(text!==null&&(typeof text!=='string'||enc.encode(text).length>256*1024||text.includes('\0')))this.reject('纯文本表示过大或格式无效（上限 256 KB）');
 }
 async checkedImage(blob){
  if(!blob||blob.type!=='image/png'||blob.size>32*1024*1024-8||blob.size<33)this.reject('请选择有效 PNG 图片，文件不能超过 32 MB');
  const b=new Uint8Array(await blob.slice(0,33).arrayBuffer()),v=new DataView(b.buffer,b.byteOffset,b.byteLength);
  if(![137,80,78,71,13,10,26,10].every((n,i)=>b[i]===n)||v.getUint32(8)!==13||v.getUint32(12)!==0x49484452)this.reject('PNG 文件头无效');
  const w=v.getUint32(16),h=v.getUint32(20);
  if(!w||!h||w>16384||h>16384||w*h>16777216||w*h*4+124>32*1024*1024-8)this.reject('图片尺寸超过当前剪贴板传输上限');
  const image=await createImageBitmap(blob);
  try{if(image.width!==w||image.height!==h)this.reject('PNG 尺寸无效');}finally{image.close();}
  return {format:'image',blob,width:w,height:h};
 }
 install(draft,op){
  if(!this.current(op))return false;
  this.clearDraft();this.draft=draft;this.e['rich-format'].value=draft.format;
  if(draft.format==='image'){
   this.url=URL.createObjectURL(draft.blob);this.e['rich-image'].src=this.url;this.e['rich-image'].hidden=false;
   this.e['rich-plain'].textContent=`${draft.width} × ${draft.height} · PNG`;
  }else{
   this.e['rich-source'].value=draft.html;this.e['rich-plain'].textContent=draft.text===null?'该内容没有纯文本表示；可查看 HTML 源内容':draft.text;
  }
  this.e['rich-source'].closest('details').hidden=draft.format!=='html';this.render();return true;
 }
 async importImage(blob){
  const op=this.begin();if(!op)return;
  try{const draft=await this.checkedImage(blob);if(this.install(draft,op))this.message('图片已载入预览，尚未发送；点击“发送到远端”后在远端粘贴');}
  catch(e){this.failure(e,op);}finally{this.finish(op);}
 }
 async importLocal(){
  const op=this.begin();if(!op)return;const format=this.e['rich-format'].value;
  this.message('等待浏览器读取本机剪贴板…');
  try{
   const items=await this.clipboard.read();if(!this.current(op))return;
   const type=format==='html'?'text/html':'image/png',item=items.find(i=>i.types.includes(type));
   if(!item)this.reject(format==='html'?'本机剪贴板没有富文本，请先在文档中复制带格式内容':'本机剪贴板没有 PNG 图片，请先复制图片或选择 PNG 文件');
   const blob=await item.getType(type);if(!this.current(op))return;
   let draft;
   if(format==='image')draft=await this.checkedImage(blob);
   else{
    if(blob.size>4*1024*1024-512)this.reject('富文本超过 4 MB 上限');
    const html=await blob.text();let text=null;
    if(item.types.includes('text/plain')){const plain=await item.getType('text/plain');if(!this.current(op))return;if(plain.size>256*1024)this.reject('纯文本表示超过 256 KB 上限');text=await plain.text();}
    this.checkHTML(html,text);draft={format,html,text};
   }
   if(this.install(draft,op))this.message('已从本机读取到预览，尚未发送；确认后点击“发送到远端”');
  }catch(e){this.failure(e,op);}finally{this.finish(op);}
 }
 async call(op,path,options){
  const response=await this.request(path,{...options,signal:op.controller.signal,headers:{...options.headers,'X-OpenRDP-Generation':String(op.generation)}});
  if(response.headers.get('X-OpenRDP-Generation')!==String(op.generation)){const e=new Error('connection changed');e.status=409;throw e;}
  return response;
 }
 async send(){
  if(!this.draft)return;const op=this.begin();if(!op)return;const draft=this.draft;
  this.message('正在发送到远端剪贴板…');
  try{
   if(draft.format==='image')await this.call(op,'/clipboard/image',{method:'POST',headers:{'Content-Type':'image/png'},body:draft.blob});
   else{const body={action:'set',format:'html',html:draft.html};if(draft.text!==null)body.text=draft.text;await this.call(op,'/clipboard',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});}
   if(this.current(op))this.message('远端已接受，请切换到远端应用粘贴');
  }catch(e){this.failure(e,op);}finally{this.finish(op);}
 }
 async get(){
  const op=this.begin();if(!op)return;const format=this.e['rich-format'].value;
  this.message('正在读取远端剪贴板…');
  try{
   const r=await this.call(op,'/clipboard',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'get',format})});
   if(!this.current(op))return;
   let draft;
   if(format==='image')draft=await this.checkedImage(await r.blob());
   else{const result=await r.json();const text=result.has_text?result.text:null;this.checkHTML(result.html,text);draft={format,html:result.html,text};}
   if(this.install(draft,op))this.message('已读取到预览，尚未改动本机剪贴板；点击“复制到本机”后粘贴');
  }catch(e){this.failure(e,op);}finally{this.finish(op);}
 }
 async copyLocal(){
  if(!this.draft)return;const op=this.begin();if(!op)return;const d=this.draft;
  try{
   const data=d.format==='image'?{'image/png':d.blob}:{'text/html':new Blob([d.html],{type:'text/html'})};
   if(d.format==='html'&&d.text!==null)data['text/plain']=new Blob([d.text],{type:'text/plain'});
   // Invoke during the user's click, with already downloaded and validated data.
   await this.clipboard.write([new ClipboardItem(data)]);
   if(this.current(op))this.message('已复制到本机剪贴板，可以粘贴到本机应用');
  }catch(e){this.failure(e,op);}finally{this.finish(op);}
 }
 async textAction(action){
  const op=this.begin();if(!op)return;
  const message=this.e['text-message'];message.textContent='正在处理文本…';
  try{
   const body=action==='set'?{action,text:this.e['text-value'].value}:{action};
   const r=await this.call(op,'/clipboard',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   if(!this.current(op))return;
   if(action==='get'){const result=await r.json();if(!this.current(op))return;this.e['text-value'].value=result.text;message.textContent='已读取远端文本，可编辑或复制到本机';}
   else message.textContent='远端已接受文本，请切换远端窗口粘贴';
  }catch(e){this.failure(e,op,true);}finally{this.finish(op);}
 }
};
