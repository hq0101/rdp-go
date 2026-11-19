'use strict';
const cleanCaptureSample=x=>Number.isFinite(x)?Math.max(-1,Math.min(1,x)):0;

// Streaming, bounded PCM conversion for the audio rendering thread. Fractional
// position survives render quantum boundaries; reset means discard all history.
// A phase table avoids transcendental functions in the per-sample audio loop.
globalThis.RdpGoCapturePCM=class {
 constructor(inputRate,outputRate,channels,emit){
  if(!Number.isInteger(inputRate)||inputRate<8000||inputRate>192000||!Number.isInteger(outputRate)||outputRate<8000||outputRate>96000||(channels!==1&&channels!==2))throw Error('invalid capture format');
  Object.assign(this,{inputRate,outputRate,channels,emit});this.frames=Math.round(outputRate/50);
  this.packet=new ArrayBuffer(this.frames*channels*2);this.view=new DataView(this.packet);this.used=0;
  this.total=0;this.position=0;this.step=inputRate/outputRate;this.rebased=false;this.ring=[new Float32Array(256),new Float32Array(256)];
  this.half=48;this.phases=512;this.table=new Float32Array(this.phases*96);
  const cutoff=0.45*Math.min(1,outputRate/inputRate);
  if(inputRate!==outputRate)for(let phase=0;phase<this.phases;phase++){
   let sum=0;for(let j=0;j<96;j++){
    const x=j-(this.half-1)-phase/this.phases,z=2*cutoff*x;
    const sinc=z===0?1:Math.sin(Math.PI*z)/(Math.PI*z);
    const window=0.42+0.5*Math.cos(Math.PI*x/this.half)+0.08*Math.cos(2*Math.PI*x/this.half);
    const coefficient=2*cutoff*sinc*window;this.table[phase*96+j]=coefficient;sum+=coefficient;
   }
   for(let j=0;j<96;j++)this.table[phase*96+j]/=sum;
  }
 }
 write(left,right){
  for(let ch=0;ch<this.channels;ch++){
   const x=ch===0?left:right;
   this.view.setInt16((this.used*this.channels+ch)*2,Math.max(-32768,Math.min(32767,Math.round(x*32768))),true);
  }
  if(++this.used===this.frames){const ready=this.packet;this.packet=new ArrayBuffer(this.frames*this.channels*2);this.view=new DataView(this.packet);this.used=0;this.emit(ready);}
 }
 push(input){
  if(!Array.isArray(input)||input.length===0)return;
  const frames=input[0].length;if(frames>16384||input.some(ch=>ch.length!==frames))throw Error('invalid render quantum');
  for(let i=0;i<frames;i++){
   let left=cleanCaptureSample(input[0][i]),right=cleanCaptureSample((input[1]||input[0])[i]);
   if(this.channels===1)left=right=(left+right)/2;
   if(this.inputRate===this.outputRate){this.write(left,right);continue;}
   const index=this.total&255;this.ring[0][index]=left;this.ring[1][index]=right;this.total++;
   while(Math.floor(this.position)+this.half<this.total){
    const center=Math.floor(this.position),phase=Math.min(this.phases-1,Math.floor((this.position-center)*this.phases));
    let a=0,b=0;
    for(let j=0;j<96;j++){const n=center-(this.half-1)+j;if(n<0&&!this.rebased)continue;const w=this.table[phase*96+j];a+=this.ring[0][n&255]*w;b+=this.ring[1][n&255]*w;}
    this.write(a,b);this.position+=this.step;
   }
   // Preserve sub-sample phase while avoiding long-session integer growth.
   if(this.total>1048576){this.total-=1048576;this.position-=1048576;this.rebased=true;}
  }
 }
 clear(){for(const b of this.ring)b.fill(0);new Uint8Array(this.packet).fill(0);this.table.fill(0);this.used=0;}
};
