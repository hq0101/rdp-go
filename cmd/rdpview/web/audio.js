'use strict';

// One bounded playback owner per remote session. This module never reads a
// microphone or records audio. Web Audio resamples source PCM for the output.
globalThis.OpenRDPAudio = class {
 constructor({request,button,message,volume,AudioContext=globalThis.AudioContext,random=globalThis.crypto}) {
  Object.assign(this,{request,button,message,volume,AudioContext,random});
  this.info={enabled:false,epoch:'0',playing:false};this.phase='connected';
  this.want=false;this.ended=false;this.serial=0;this.starting=false;this.lease=null;
  this.context=null;this.gain=null;this.nodes=new Set();this.requests=new Set();
  this.nextTime=0;this.completed=0;this.note='';this.retryEpoch=null;
  button.addEventListener('click',()=>{if(this.want||this.lease||this.starting)this.stop(true,false);else{this.want=true;void this.start(true);}});
  volume.addEventListener('input',()=>{if(this.gain)this.gain.gain.value=this.level();});
  this.draw();
 }
 level(){const n=Number(this.volume.value);return Number.isFinite(n)?Math.max(0,Math.min(1,n/100)):0.5;}
 validEpoch(value){return typeof value==='string'&&/^[1-9][0-9]{0,19}$/.test(value);}
 update(info={},phase='connected') {
  if(this.ended)return;
  if(!this.validEpoch(info.epoch))info={enabled:false,epoch:this.info.epoch};
  // A status response issued before Start must not invalidate its newer lease.
  if(BigInt(info.epoch)<BigInt(this.info.epoch))return;
  this.info=info;this.phase=phase;
  if(phase!=='connected'){this.stop(false,true);this.draw();return;}
  if(!info.enabled){this.stop(false,false);return;}
  if(this.retryEpoch){
   if(BigInt(info.epoch)<=BigInt(this.retryEpoch)){this.draw();return;}
   this.retryEpoch=null;
   if(info.playing)this.stop(false,false);
  }
  if(this.lease&&info.epoch!==this.lease.epoch){this.stop(false,false);this.note='声音已暂停，点击重新开启';}
  if(this.want&&!this.lease&&!this.starting&&!info.playing)void this.start(false);
  this.draw();
 }
 draw(){
  const available=this.info.enabled&&!this.ended;
  this.button.disabled=!available||this.phase!=='connected'||(!this.lease&&!this.starting&&this.info.playing);
  this.button.textContent=this.want||this.starting?'关闭声音':'开启声音';
  this.button.setAttribute('aria-pressed',String(!!this.lease));
  this.volume.disabled=!available;
  let state='off',text='此连接未启用声音';
  if(available){
   if(this.phase!=='connected'){state='recovering';text='连接恢复后继续声音';}
   else if(this.note)text=this.note;
   else if(this.starting){state='starting';text='正在开启声音…';}
   else if(this.lease){state=this.nodes.size?'playing':'ready';text=this.nodes.size?'正在播放远程声音':'声音已开启';}
   else if(this.info.playing)text='声音正在另一页面播放';
   else text='点击开启远程声音';
  }
  this.message.textContent=text;this.message.dataset.state=state;
  this.message.dataset.completed=String(this.completed);
 }
 async call(action,lease,tokens,keepalive=false){
  const controller=new AbortController();this.requests.add(controller);
  const timer=setTimeout(()=>controller.abort(),4000);
  try{
   const response=await this.request('/audio',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,client:lease.client,epoch:lease.epoch,...(tokens?{tokens}:{})}),signal:controller.signal,keepalive});
   return action==='start'||action==='poll'?await response.json():null;
  }finally{clearTimeout(timer);this.requests.delete(controller);}
 }
 async start(gesture){
  if(this.ended||!this.want||this.starting||this.lease||!this.info.enabled||this.phase!=='connected')return;
  this.starting=true;this.note='';const op=++this.serial;
  let attempt;
  try{
   if(!this.AudioContext||!this.random?.getRandomValues)throw Error('audio unavailable');
   if(!this.context){
    if(!gesture)throw Error('gesture required');
    this.context=new this.AudioContext({latencyHint:'interactive'});
    this.gain=this.context.createGain();this.gain.gain.value=this.level();this.gain.connect(this.context.destination);
    this.context.onstatechange=()=>{if(this.context.state!=='running'&&this.lease){this.stop(true,false);this.note='浏览器暂停了声音，点击重新开启';this.draw();}};
   }
   if(this.context.state!=='running')await this.context.resume();
   if(this.context.state!=='running')throw Error('audio suspended');
   if(op!==this.serial||!this.want)return;
   attempt={client:Array.from(this.random.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join(''),epoch:this.info.epoch};
   this.draw();const result=await this.call('start',attempt);
   if(!this.validEpoch(result.epoch))throw Error('invalid audio lease');
   attempt.epoch=result.epoch;
   if(op!==this.serial||!this.want||this.ended){void this.call('stop',attempt).catch(()=>{});return;}
   const lease={...attempt,op,acks:[],acking:false};this.lease=lease;
   this.info={...this.info,epoch:result.epoch,playing:true};this.nextTime=0;
   void this.pump(lease);
  }catch{
   // The unique client nonce allows cleanup even if the Start response was lost.
   if(attempt)void this.call('stop',attempt).catch(()=>{});
   if(op===this.serial){this.want=false;this.note='无法开启声音，请点击重试';}
  }finally{if(op===this.serial)this.starting=false;this.draw();}
 }
 current(lease){return !this.ended&&this.want&&this.lease===lease&&this.serial===lease.op;}
 async pump(lease){
  try{
   while(this.current(lease)){
    const result=await this.call('poll',lease);
    if(!this.current(lease))return;
    if(result.epoch!==lease.epoch||!Array.isArray(result.blocks??[])||(result.blocks??[]).length>32)throw Error('audio changed');
    for(const block of result.blocks??[])this.schedule(lease,block);
   }
  }catch(error){this.failed(lease,error);}
 }
 failed(lease,error){
  if(!this.current(lease))return;
  // Poll/ACK may observe transport replacement before the status loop does.
  // Wait for a strictly newer epoch; never replay old samples or completions.
  const recovering=error?.status===409||error?.status===502;
  this.stop(!recovering,recovering);
  if(recovering){this.retryEpoch=lease.epoch;this.note='正在恢复声音连接…';}
  else this.note='声音已暂停，点击重新开启';
  this.draw();
 }
 schedule(lease,block){
  if(!this.current(lease))return;
  const channels=block.channels,rate=block.sample_rate;
  if(!/^[1-9][0-9]{0,19}$/.test(block.token)||!Number.isInteger(rate)||rate<8000||rate>96000||(channels!==1&&channels!==2)||typeof block.data!=='string'||block.data.length>349480||this.nodes.size>=32)throw Error('invalid PCM metadata');
  const raw=atob(block.data),n=raw.length/(4*channels);
  if(!Number.isInteger(n)||n<1||raw.length>262108)throw Error('invalid PCM size');
  const data=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)data[i]=raw.charCodeAt(i);
  const view=new DataView(data.buffer),buffer=this.context.createBuffer(channels,n,rate);
  for(let c=0;c<channels;c++){
   const output=buffer.getChannelData(c);
   for(let i=0;i<n;i++){const sample=view.getFloat32((i*channels+c)*4,true);if(!Number.isFinite(sample)||sample < -1||sample>1)throw Error('invalid PCM sample');output[i]=sample;}
  }
  data.fill(0);
  const now=this.context.currentTime,start=Math.max(this.nextTime,now+(this.nodes.size?0.005:0.03));
  if(this.nodes.size&&start+buffer.duration-now>2)throw Error('audio queue too long');
  const source=this.context.createBufferSource();source.buffer=buffer;source.connect(this.gain);
  this.nodes.add(source);this.nextTime=start+buffer.duration;
  source.onended=()=>{
   source.disconnect();source.buffer=null;this.nodes.delete(source);
   if(this.current(lease)){this.completed++;lease.acks.push(block.token);void this.flushAcks(lease);}
   this.draw();
  };
  try{source.start(start);}catch{source.onended=null;source.disconnect();source.buffer=null;this.nodes.delete(source);throw Error('audio start failed');}
  this.draw();
 }
 async flushAcks(lease){
  if(lease.acking||!this.current(lease))return;lease.acking=true;
  try{while(lease.acks.length&&this.current(lease)){const tokens=lease.acks.splice(0,32);await this.call('ack',lease,tokens);}}
  catch(error){this.failed(lease,error);}
  finally{lease.acking=false;}
 }
 stop(notify,keepWanted,keepalive=false){
  const lease=this.lease;this.lease=null;this.serial++;this.starting=false;
  const op=this.serial;
  if(!keepWanted)this.want=false;
  for(const controller of this.requests)controller.abort();this.requests.clear();
  for(const source of this.nodes){source.onended=null;try{source.stop();}catch{}source.disconnect();source.buffer=null;}
  this.nodes.clear();this.nextTime=0;this.note='';this.retryEpoch=null;
  if(lease&&notify)void this.call('stop',lease,undefined,keepalive).then(()=>{if(this.serial===op){this.info={...this.info,playing:false};this.draw();}}).catch(()=>{});
  this.draw();
 }
 end(){if(this.ended)return;this.stop(true,false,true);this.ended=true;if(this.context){this.context.onstatechange=null;void this.context.close().catch(()=>{});}this.draw();}
};
