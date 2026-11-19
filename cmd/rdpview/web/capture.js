'use strict';

globalThis.RdpGoCapture=class {
 constructor({request,button,message,AudioContext=globalThis.AudioContext,AudioWorkletNode=globalThis.AudioWorkletNode,getUserMedia=c=>navigator.mediaDevices.getUserMedia(c),random=globalThis.crypto}){
  Object.assign(this,{request,button,message,AudioContext,AudioWorkletNode,getUserMedia,random});
  this.info={enabled:false,epoch:'1',recording:false};this.phase='connected';this.want=false;this.ended=false;this.serial=0;this.starting=false;this.acquiring=false;
  this.context=null;this.stream=null;this.node=null;this.source=null;this.mute=null;this.lease=null;this.upload=null;this.configured='';this.requests=new Set();this.note='';this.sent=0;this.retryEpoch=null;this.retryStart=false;this.stoppedEpoch=null;this.leaseSerial=0;
  button.addEventListener('click',()=>{if(this.want)this.stop(true,false);else{this.want=true;void this.startMedia();}});this.draw();
 }
 validEpoch(s){return typeof s==='string'&&/^[1-9][0-9]{0,19}$/.test(s);}
 current(lease){return !this.ended&&this.want&&this.lease===lease;}
 draw(){
  this.button.disabled=this.ended||(!this.want&&(!this.info.enabled||this.phase!=='connected'||this.info.recording));
  this.button.textContent=this.want?'关闭麦克风':'开启麦克风';this.button.setAttribute('aria-pressed',String(!!this.stream&&this.want));
  let state='off',text='此连接未启用麦克风';
  if(this.info.enabled||this.want){
   if(this.note)text=this.note;
   else if(this.starting){state='permission';text='请在浏览器中允许使用麦克风';}
   else if(this.want&&this.phase!=='connected'){state='recovering';text='连接恢复中，麦克风发送已暂停';}
   else if(this.want&&this.lease){state=this.info.ready?'recording':'waiting';text=this.info.ready?'麦克风已开启，正在发送到远程':'麦克风已开启，等待远程应用';}
   else if(this.info.recording)text=this.stoppedEpoch===this.info.epoch?'麦克风已关闭，正在清理连接':'另一页面正在使用麦克风';
   else text='麦克风已关闭，远端接收静音';
  }
  this.message.textContent=text;this.message.dataset.state=state;this.message.dataset.sent=String(this.sent);
 }
 async call(action,lease,extra={},keepalive=false){
  const controller=new AbortController();this.requests.add(controller);const timer=setTimeout(()=>controller.abort(),3000);
  try{const response=await this.request('/capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,client:lease.client,epoch:lease.epoch,...extra}),signal:controller.signal,keepalive});return action==='stop'?null:await response.json();}
  finally{clearTimeout(timer);this.requests.delete(controller);}
 }
 async startMedia(){
  if(this.ended||!this.want||this.starting||this.stream)return;
  this.starting=true;this.note='';this.stoppedEpoch=null;const op=++this.serial;this.draw();
  let context,stream;
  try{
   if(!this.AudioContext||!this.AudioWorkletNode||!this.random?.getRandomValues)throw Error('capture unavailable');
   context=new this.AudioContext({latencyHint:'interactive'});this.context=context;
   await context.resume();
   if(op!==this.serial||!this.want)return;
   await context.audioWorklet.addModule('/capture-worklet.js');
   if(op!==this.serial||!this.want)return;
   // Permission is requested only by this click path, never status/recovery.
   stream=await this.getUserMedia({audio:{channelCount:{ideal:2},echoCancellation:true,noiseSuppression:true,autoGainControl:true},video:false});
   if(op!==this.serial||!this.want){for(const t of stream.getTracks())t.stop();return;}
   this.stream=stream;
   for(const track of stream.getAudioTracks())track.onended=()=>{if(this.stream===stream){this.stop(true,false);this.note='麦克风已断开，请重新开启';this.draw();}};
   if(op!==this.serial||!this.want)return;
   if(context.state!=='running'||stream.getAudioTracks().length===0)throw Error('capture unavailable');
   this.source=context.createMediaStreamSource(stream);
   this.node=new this.AudioWorkletNode(context,'rdpgo-capture',{numberOfInputs:1,numberOfOutputs:1,outputChannelCount:[1],channelCountMode:'max',channelInterpretation:'discrete'});
   this.node.port.onmessage=e=>this.samples(e.data);
   this.node.onprocessorerror=()=>{this.stop(true,false);this.note='音频处理已停止，请重新开启';this.draw();};
   this.mute=context.createGain();this.mute.gain.value=0;
   this.source.connect(this.node);this.node.connect(this.mute);this.mute.connect(context.destination);
   context.onstatechange=()=>{if(this.context===context&&context.state!=='running'&&this.want){this.stop(true,false);this.note='浏览器暂停了麦克风，请重新开启';this.draw();}};
   await this.ensureLease();
  }catch{if(op===this.serial){this.stop(true,false);this.note='无法开启麦克风，请检查浏览器权限或设备';}}
  finally{if(op===this.serial)this.starting=false;if(context&&context!==this.context)void context.close().catch(()=>{});this.draw();}
 }
 async ensureLease(){
  if(this.ended||!this.want||!this.node||this.lease||this.acquiring||this.phase!=='connected'||!this.info.enabled||this.retryEpoch)return;
  this.acquiring=true;const op=this.serial,attemptSerial=this.leaseSerial;
  const attempt={client:Array.from(this.random.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join(''),epoch:this.info.epoch,sequence:0};
  try{
   const result=await this.call('start',attempt);
   if(!this.validEpoch(result.epoch))throw Error('invalid lease');attempt.epoch=result.epoch;
   if(op!==this.serial||attemptSerial!==this.leaseSerial||!this.want||this.phase!=='connected'){void this.call('stop',attempt).catch(()=>{});return;}
   this.lease=attempt;this.update(result,this.phase);this.configure();void this.poll(attempt);
  }catch(error){
   void this.call('stop',attempt).catch(()=>{});
   if(op===this.serial&&attemptSerial===this.leaseSerial){if(error?.status===409){this.retryEpoch=attempt.epoch;this.retryStart=true;this.note='正在等待麦克风连接';}else{this.stop(false,false);this.note='麦克风连接失败，请重新开启';}}
  }finally{if(op===this.serial&&attemptSerial===this.leaseSerial)this.acquiring=false;this.draw();}
 }
 update(info={},phase='connected'){
  if(this.ended||!this.validEpoch(info.epoch))return;
  if(BigInt(info.epoch)<BigInt(this.info.epoch))return;
  this.info=info;this.phase=phase;
  if(phase!=='connected'){this.pauseLease(false);this.draw();return;}
  if(!info.enabled){this.stop(true,false);return;}
  if(this.retryEpoch){
   // A competing page can own the same epoch that rejected this Start. Do not
   // retain a physical microphone indefinitely while waiting for it to change.
   if(this.retryStart&&info.recording){this.stop(false,false);this.stoppedEpoch=null;this.note='另一页面正在使用麦克风';this.draw();return;}
   if(BigInt(info.epoch)<=BigInt(this.retryEpoch)){this.draw();return;}this.retryEpoch=null;this.retryStart=false;this.note='';
  }
  if(this.lease){this.configure();}
  else if(this.want&&!this.acquiring){if(info.recording){this.stop(false,false);this.note='另一页面正在使用麦克风';}else void this.ensureLease();}
  this.draw();
 }
 configure(){
  if(!this.node||!this.lease)return;
  const s=this.info,valid=s.ready&&Number.isInteger(s.sample_rate)&&s.sample_rate>=8000&&s.sample_rate<=96000&&(s.channels===1||s.channels===2);
  const key=this.lease.client+':'+s.epoch+':'+(valid?s.sample_rate+':'+s.channels:'waiting');
  if(key===this.configured)return;
  this.configured=key;this.lease.epoch=s.epoch;this.lease.sequence=0;this.upload=null;
  this.node.port.postMessage({kind:'configure',epoch:s.epoch,rate:valid?s.sample_rate:0,channels:s.channels});
 }
 async poll(lease){
  while(this.current(lease)){
   try{const result=await this.call('poll',lease);if(this.current(lease))this.update(result,this.phase);}
   catch(error){if(this.current(lease))this.failed(lease,error);return;}
   await new Promise(resolve=>setTimeout(resolve,800));
  }
 }
 async samples(message){
  if(message?.error){this.stop(true,false);this.note='音频处理已停止，请重新开启';this.draw();return;}
  if(!message?.pcm)return;
  const lease=this.lease,bytes=new Uint8Array(message.pcm),epoch=message.epoch;
  const credit=()=>{if(this.node&&this.current(lease)&&lease.epoch===epoch)this.node.port.postMessage({kind:'credit',epoch});};
  if(!lease||!this.current(lease)||this.phase!=='connected'||lease.epoch!==epoch||this.upload||bytes.length>19200){bytes.fill(0);credit();return;}
  const upload={lease,epoch};this.upload=upload;
  try{
   let raw='';for(const b of bytes)raw+=String.fromCharCode(b);bytes.fill(0);
   const result=await this.call('data',lease,{sequence:lease.sequence+1,data:btoa(raw)});
   if(this.current(lease)&&lease.epoch===epoch&&this.upload===upload){lease.sequence++;this.sent++;this.update(result,this.phase);}
  }catch(error){if(this.current(lease)&&lease.epoch===epoch&&this.upload===upload&&error?.status!==429)this.failed(lease,error);}
  finally{bytes.fill(0);if(this.upload===upload)this.upload=null;credit();this.draw();}
 }
 failed(lease,error){
  if(!this.current(lease))return;
  const old=lease.epoch;this.pauseLease(true);
  if(error?.status===409||error?.status===502){this.retryEpoch=old;this.retryStart=false;this.note='麦克风发送暂停，正在恢复连接';}
  else{this.stop(false,false);this.note='麦克风发送失败，请重新开启';}
  this.draw();
 }
 pauseLease(notify,keepalive=false){
  this.leaseSerial++;this.acquiring=false;
  const old=this.lease;this.lease=null;this.upload=null;this.configured='';
  for(const controller of this.requests)controller.abort();this.requests.clear();
  if(this.node)this.node.port.postMessage({kind:'configure',epoch:this.info.epoch,rate:0});
  if(old&&notify)void this.call('stop',old,{},keepalive).catch(()=>{});
 }
 stop(notify,keepWanted=false,keepalive=false){
  if(this.want)this.stoppedEpoch=this.info.epoch;
  this.pauseLease(notify,keepalive);this.serial++;this.acquiring=false;this.starting=false;this.retryEpoch=null;this.retryStart=false;this.note='';if(!keepWanted)this.want=false;
  if(this.node){this.node.port.onmessage=null;this.node.onprocessorerror=null;this.node.port.postMessage({kind:'stop'});this.node.disconnect();this.node=null;}
  this.source?.disconnect();this.source=null;this.mute?.disconnect();this.mute=null;
  if(this.stream){for(const t of this.stream.getTracks()){t.onended=null;t.stop();}this.stream=null;}
  if(this.context){const old=this.context;this.context=null;old.onstatechange=null;void old.close().catch(()=>{});}
  this.draw();
 }
 end(){if(this.ended)return;this.stop(true,false,true);this.ended=true;this.draw();}
};
