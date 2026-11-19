import './capture-pcm.js';

class RdpGoCaptureProcessor extends AudioWorkletProcessor {
 constructor(){
  super();this.converter=null;this.epoch='0';this.credit=false;this.alive=true;
  this.port.onmessage=({data})=>{
   if(data?.kind==='configure'){
    this.converter?.clear();this.converter=null;this.epoch=data.epoch;this.credit=true;
    if(data.rate){try{this.converter=new globalThis.RdpGoCapturePCM(sampleRate,data.rate,data.channels,pcm=>{
     if(this.credit){this.credit=false;this.port.postMessage({epoch:this.epoch,pcm},[pcm]);}else new Uint8Array(pcm).fill(0);
    });}catch{this.port.postMessage({error:true});}}
   }else if(data?.kind==='credit'&&data.epoch===this.epoch)this.credit=true;
   else if(data?.kind==='stop'){this.converter?.clear();this.converter=null;this.alive=false;}
  };
 }
 process(inputs){if(this.converter){try{this.converter.push(inputs[0]||[]);}catch{this.converter.clear();this.converter=null;this.port.postMessage({error:true});}}return this.alive;}
}
registerProcessor('rdpgo-capture',RdpGoCaptureProcessor);
