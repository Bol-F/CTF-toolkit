"use strict";
(() => {
  const host = window.StegoLab;
  const node = (tag, text, cls) => { const n=document.createElement(tag); if(text!==undefined)n.textContent=text; if(cls)n.className=cls; return n; };
  const put = (root,...children) => {root.append(...children);return root;};
  const button = (text, action, cls='button secondary small') => {const b=node('button',text,cls);b.type='button';b.addEventListener('click',action);return b;};
  const heading=(root,text)=>root.append(node('h3',text,'lab-heading'));
  const help=(root,text)=>root.append(node('p',text,'lab-help'));
  const code=(value)=>node('pre',typeof value==='string'?value:JSON.stringify(value,null,2),'code-block');
  const status=(root)=>{const x=node('div','','lab-status');x.setAttribute('role','status');root.append(x);return x;};
  const select=(values,initial)=>{const el=node('select');values.forEach(value=>{const [id,title]=Array.isArray(value)?value:[value,value];const o=node('option',title);o.value=id;el.append(o);});el.value=initial??el.options[0]?.value;return el;};
  const input=(value,type='text')=>{const el=node('input');el.type=type;el.value=value;return el;};
  const field=(parent,title,control)=>{const label=node('label',title);control.setAttribute('aria-label',title);label.append(control);parent.append(label);return control;};
  const controls=root=>{const n=node('div',undefined,'lab-controls');root.append(n);return n;};
  const getStage=(report,name)=>report?.analyzers?.find(a=>a.name===name)?.data;
  const preview=(job,id)=>`/api/jobs/${job.id}/preview/${encodeURIComponent(id)}`;
  const artifactURL=(job,id)=>`/api/jobs/${job.id}/artifacts/${encodeURIComponent(id)}`;
  const download=(root,title,url)=>{const a=node('a',title,'lab-download');a.href=url;a.download='';root.append(a);return a;};
  const saveBlob=(blob,name)=>{const u=URL.createObjectURL(blob);const a=node('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);};
  const loadImage=url=>new Promise((resolve,reject)=>{const img=new Image();img.onload=()=>resolve(img);img.onerror=()=>reject(new Error('Sanitized image preview could not be loaded'));img.src=url;});
  function canvasPixels(img){const c=node('canvas');c.width=img.naturalWidth;c.height=img.naturalHeight;const ctx=c.getContext('2d',{willReadFrequently:true});ctx.drawImage(img,0,0);return {canvas:c,data:ctx.getImageData(0,0,c.width,c.height)};}
  async function task(context,payload,out,{open=false}={}){
    out.textContent='Queueing restricted worker task…';
    const job=await host.api(`/api/jobs/${context.job.id}/actions`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    return watch(job,out,open);
  }
  async function watch(job,out,open=false){
    const started=Date.now();
    while(Date.now()-started<330000){
      const current=await host.api(`/api/jobs/${job.id}`);
      out.textContent=`${current.status} · ${current.stage} · ${Math.round(current.progress)}%`;
      if(['completed','failed','timeout','cancelled'].includes(current.status)){
        let report;try{report=await host.api(`/api/jobs/${job.id}/report`);}catch{throw new Error(current.error||'No action report available');}
        if(current.status!=='completed')throw new Error((report.errors||[current.error||current.status]).join('\n'));
        out.replaceChildren(node('span','Worker task completed. '),button('Open action report',()=>host.selectJob(current)));
        if(open)await host.selectJob(current);
        return {job:current,report};
      }
      if(!out.isConnected)return null;
      await new Promise(resolve=>setTimeout(resolve,600));
    }
    throw new Error('UI polling deadline reached; follow the job in Jobs');
  }
  function catchError(out,action){return async()=>{try{await action();}catch(error){out.textContent=error.message;out.classList.add('lab-error');}};}
  function preparation(root,context,operation,title){const out=status(root);root.append(button(title,catchError(out,()=>task(context,{operation},out,{open:true}))));}

  async function imageLab(root,context){
    const data=getStage(context.report,'image_lab');
    if(!data?.preview_artifact_id){help(root,'Prepare a raster preview in the restricted worker. PNG, BMP, JPEG, GIF, TIFF and WebP are supported.');preparation(root,context,'image_prepare','Prepare image inspection');return;}
    help(root,`${data.width} × ${data.height} ${data.mode} · ${data.frame_count} frame(s). RGB preview is opaque to preserve colors beneath alpha; inspect Alpha separately.${data.preview_resized?' Preview resized to 1024px; LSB extraction uses full original pixels.':''}`);
    const bar=controls(root);
    const channel=field(bar,'Channel',select([['RGB','RGB composite'],['R','Red'],['G','Green'],['B','Blue'],['A','Alpha']],'RGB'));
    const plane=field(bar,'Bit plane',select([['all','All bits'],...Array.from({length:8},(_,i)=>[String(i),`Bit ${i}`])],'all'));
    const brightness=field(bar,'Brightness',input(0,'range'));brightness.min=-128;brightness.max=128;
    const contrast=field(bar,'Contrast',input(1,'range'));contrast.min=0;contrast.max=4;contrast.step=.05;
    const gamma=field(bar,'Gamma',input(1,'range'));gamma.min=.1;gamma.max=4;gamma.step=.05;
    const imageZoom=field(bar,'Preview zoom',select([['1','1×'],['2','2×'],['4','4×'],['8','8×']],'1'));
    const invert=field(bar,'Invert',input('','checkbox'));invert.parentElement.className='check';
    const panels=node('div',undefined,'lab-panels');root.append(panels);
    const originalFigure=node('figure',undefined,'lab-figure'),processedFigure=node('figure',undefined,'lab-figure');
    originalFigure.append(node('figcaption','Original RGB preview'));processedFigure.append(node('figcaption','Processed preview'));
    panels.append(originalFigure,processedFigure);
    const img=await loadImage(preview(context.job,data.preview_artifact_id));if(!root.isConnected)return;
    let base=canvasPixels(img);originalFigure.append(base.canvas);
    const output=node('canvas');processedFigure.append(output);output.width=base.canvas.width;output.height=base.canvas.height;
    const difference=node('canvas'),diffFigure=node('figure',undefined,'lab-figure lab-full');
    diffFigure.append(node('figcaption','Absolute RGB difference from original'),difference);panels.append(diffFigure);
    difference.width=output.width;difference.height=output.height;
    imageZoom.value=output.width<256?'4':'1';
    const resizePreview=()=>{[base.canvas,output,difference].forEach(c=>{c.style.width=`${c.width*Number(imageZoom.value)}px`;});};
    imageZoom.onchange=resizePreview;resizePreview();
    let alphaPixels=null;
    if(data.alpha_artifact_id){alphaPixels=canvasPixels(await loadImage(preview(context.job,data.alpha_artifact_id))).data.data;}
    const metrics=status(root);
    function draw(){
      const source=base.data.data,dest=new Uint8ClampedArray(source.length),delta=new Uint8ClampedArray(source.length);
      let changed=0,sum=0;
      for(let p=0;p<source.length;p+=4){let different=false;
        for(let c=0;c<3;c++){
          const index=channel.value==='RGB'?c:'RGBA'.indexOf(channel.value);
          let value=index===3?(alphaPixels?.[p]??255):source[p+index];
          if(plane.value!=='all')value=((value>>Number(plane.value))&1)*255;
          if(invert.checked)value=255-value;
          value=((value-127.5)*Number(contrast.value)+127.5)+Number(brightness.value);
          value=255*Math.pow(Math.max(0,Math.min(255,value))/255,1/Number(gamma.value));
          dest[p+c]=value;delta[p+c]=Math.abs(dest[p+c]-source[p+c]);sum+=delta[p+c];different||=delta[p+c]>0;
        }
        dest[p+3]=255;delta[p+3]=255;if(different)changed++;
      }
      output.getContext('2d').putImageData(new ImageData(dest,output.width,output.height),0,0);
      difference.getContext('2d').putImageData(new ImageData(delta,output.width,output.height),0,0);
      metrics.textContent=`${channel.value} · plane ${plane.value} · brightness ${brightness.value} · contrast ${contrast.value} · gamma ${gamma.value}\nChanged preview pixels ${(100*changed/(source.length/4)).toFixed(2)}% · mean absolute RGB difference ${(sum/(source.length*.75)).toFixed(3)}`;
    }
    [channel,plane,brightness,contrast,gamma,invert].forEach(el=>el.addEventListener('input',draw));draw();
    root.append(button('Export processed PNG',()=>output.toBlob(blob=>saveBlob(blob,'stegolab-processed.png'))));
    if(data.frames?.length){heading(root,'GIF frames');const frames=node('div',undefined,'lab-frame-list');root.append(frames);
      data.frames.forEach(frame=>{const b=button(`Frame ${frame.index} · ${frame.duration_ms} ms`,async()=>{
        const picture=await loadImage(preview(context.job,frame.artifact_id));base=canvasPixels(picture);alphaPixels=new Uint8ClampedArray(base.data.data.length);for(let p=0;p<alphaPixels.length;p+=4)alphaPixels[p]=base.data.data[p+3];originalFigure.replaceChildren(node('figcaption',`GIF frame ${frame.index}`),base.canvas);output.width=difference.width=base.canvas.width;output.height=difference.height=base.canvas.height;resizePreview();draw();
      },'');const thumbnail=node('img');thumbnail.alt=`GIF frame ${frame.index}`;thumbnail.src=preview(context.job,frame.artifact_id);b.prepend(thumbnail);frames.append(b);});
      help(root,`Extracted ${data.frames.length} frames; ${data.frames_truncated?'remaining frames exceed limits.':'all frames inspected.'} Frame downloads are available in Artifacts.`);
    }
    heading(root,'Extract pixel bits');help(root,'Plane list order is significant. Channels are interleaved per pixel; selected bits are emitted per channel in the order listed. Packed byte order selects the first bit as MSB or LSB.');
    const lsb=controls(root),order=field(lsb,'Channel order',input('RGB')),bits=field(lsb,'Bits (0–7)',input('0')),
      byteOrder=field(lsb,'Pack bytes',select([['msb','First bit is MSB'],['lsb','First bit is LSB']])),direction=field(lsb,'Traversal',select([['row','Rows (left → right)'],['column','Columns (top → bottom)']])),
      frame=field(lsb,'Frame index',input(0,'number')),skip=field(lsb,'Skip bits',input(0,'number')),limit=field(lsb,'Output byte limit',input(65536,'number')),
      reverse=field(lsb,'Reverse pixel traversal',input('','checkbox'));reverse.parentElement.className='check';
    const lsbOut=status(root);root.append(button('Extract LSB data',catchError(lsbOut,async()=>{
      const result=await task(context,{operation:'image_lsb',channels:order.value.toUpperCase(),bits:bits.value.split(/[,\s]+/).filter(Boolean).map(Number),bit_order:byteOrder.value,direction:direction.value,reverse:reverse.checked,frame:Number(frame.value),skip_bits:Number(skip.value),max_bytes:Number(limit.value)},lsbOut);
      if(result){const detail=getStage(result.report,'image_lsb');root.append(code(detail));result.report.artifacts.forEach(a=>download(root,`Download ${a.name}`,artifactURL(result.job,a.id)));}
    })));
    heading(root,'Channel statistics and metadata');root.append(code({channels:data.channels,metadata:data.metadata}));
  }

  async function forensicsLab(root,context){
    const data=getStage(context.report,'file_forensics')||{};
    const bar=controls(root),source=field(bar,'Source bytes',select([['','Original evidence'],...context.report.artifacts.map(a=>[a.id,a.name])])),offset=field(bar,'Offset (decimal or 0x)',input('0'));
    const out=status(root),rows=node('div',undefined,'hex-rows'),scroll=node('div',undefined,'lab-scroll');scroll.append(rows);root.append(scroll);
    let cursor=0,size=context.report.file.size;
    async function fetchBytes(position){
      cursor=Math.max(0,position);offset.value=`0x${cursor.toString(16)}`;
      const query=new URLSearchParams({offset:cursor,length:512});if(source.value)query.set('artifact_id',source.value);
      const data=await host.api(`/api/jobs/${context.job.id}/bytes?${query}`);size=data.size;rows.replaceChildren();
      for(let i=0;i<data.bytes.length;i+=16){const line=node('div',undefined,'hex-row');line.append(node('span',`0x${(cursor+i).toString(16).padStart(8,'0')}\n${cursor+i}`,'hex-offset'));
        for(let j=0;j<16;j++){const value=data.bytes[i+j];const b=button(value===undefined?'  ':value.toString(16).padStart(2,'0'),()=>{
          rows.querySelectorAll('.selected').forEach(el=>el.classList.remove('selected'));b.classList.add('selected');out.textContent=`Offset ${cursor+i+j} / 0x${(cursor+i+j).toString(16)} · byte ${value} / 0x${value.toString(16).padStart(2,'0')} · ASCII ${value>=32&&value<127?String.fromCharCode(value):'non-printable'}`;
        },'hex-byte');b.disabled=value===undefined;b.title=`Byte ${cursor+i+j}`;line.append(b);}
        line.append(node('span',data.ascii.slice(i,i+16),'hex-ascii'));rows.append(line);
      }
      out.textContent=`${data.source} · ${data.size} bytes · showing ${cursor}–${Math.max(cursor,cursor+data.bytes.length-1)}`;
    }
    bar.append(button('Go',catchError(out,()=>fetchBytes(Number(offset.value)))),button('Previous',catchError(out,()=>fetchBytes(cursor-512))),button('Next',catchError(out,()=>fetchBytes(Math.min(Math.max(0,size-1),cursor+512)))));
    source.addEventListener('change',catchError(out,()=>fetchBytes(0)));await fetchBytes(0);
    heading(root,'Structure and embedded regions');help(root,'Click a region to jump to its bytes. Confirmed labels require container validation; signature candidates remain unconfirmed.');
    const structure=node('canvas',undefined,'entropy-canvas');structure.width=1000;structure.height=50;structure.style.height='50px';structure.setAttribute('aria-label','File structure byte regions');root.append(structure);
    const structureContext=structure.getContext('2d');const mapped=[...(data.regions||[]),...(data.embedded||[])];
    mapped.forEach((region,index)=>{structureContext.fillStyle=['#65d6b7','#c5f17c','#799dcb','#b69bd1'][index%4];structureContext.fillRect(region.offset/context.report.file.size*1000,4,Math.max(2,region.size/context.report.file.size*1000),40);});
    structure.onclick=event=>{source.value='';fetchBytes(Math.floor((event.clientX-structure.getBoundingClientRect().left)/structure.clientWidth*context.report.file.size)).catch(error=>{out.textContent=error.message;});};
    const regions=node('div',undefined,'region-list');root.append(regions);
    [...(data.regions||[]),...(data.embedded||[])].slice(0,150).forEach(region=>{
      const b=button(`${region.name} · 0x${region.offset.toString(16)} · ${region.size} B · ${region.classification}`,catchError(out,()=>{source.value='';return fetchBytes(region.offset);}),`region-button ${region.classification?.startsWith('confirmed')?'confirmed':''}`);
      b.title=region.evidence||`CRC: ${region.crc_valid}`;regions.append(b);
    });
    heading(root,'Entropy by byte region');const entropy=node('canvas',undefined,'entropy-canvas');entropy.width=1000;entropy.height=140;root.append(entropy);const ctx=entropy.getContext('2d');
    (data.entropy||[]).forEach((point,i,array)=>{ctx.fillStyle='#65d6b7';ctx.fillRect(i*1000/array.length,140-point.entropy/8*130,Math.max(1,1000/array.length-1),point.entropy/8*130);});
    entropy.onclick=event=>{const points=data.entropy||[];const item=points[Math.min(points.length-1,Math.floor((event.clientX-entropy.getBoundingClientRect().left)/entropy.clientWidth*points.length))];if(item){source.value='';fetchBytes(item.offset).then(()=>{out.textContent+=` · entropy ${item.entropy} bits/byte`;}).catch(error=>{out.textContent=error.message;});}};
    heading(root,'Archive and extracted artifacts');
    const table=node('table',undefined,'lab-table');const head=node('tr');['Member','Size','Offset / depth','Inspect'].forEach(x=>head.append(node('th',x)));table.append(head);
    const records=(data.archive_members?.length?data.archive_members:context.report.artifacts.filter(a=>['extracted','carved','tool_extracted','pdf_attachment'].includes(a.kind)));
    records.forEach(member=>{const tr=node('tr');tr.append(node('td',member.name),node('td',String(member.size)),node('td',member.offset??`depth ${member.depth??'—'}`));const td=node('td');
      const artifact=context.report.artifacts.find(a=>a.id===member.artifact_id||a.name===member.name&&a.kind==='extracted');
      if(artifact){td.append(button('Bytes',catchError(out,()=>{source.value=artifact.id;return fetchBytes(0);})),button('Recursive scan',catchError(out,()=>task(context,{operation:'inspect',artifact_id:artifact.id},out,{open:true}))));}
      else if(member.offset!==undefined)td.append(button('Header bytes',catchError(out,()=>{source.value='';return fetchBytes(member.offset);})));tr.append(td);table.append(tr);
    });root.append(put(node('div',undefined,'lab-table-wrap'),table));
  }

  async function audioLab(root,context){
    const data=getStage(context.report,'audio_lab');if(!data?.channel_data){help(root,'Generate a bounded PCM preview and time-frequency analysis in the restricted worker.');preparation(root,context,'audio_analyze','Analyze audio');return;}
    help(root,`${data.duration}s decoded preview · ${data.sample_rate} Hz · ${data.channels} channels · first ${data.max_seconds}s maximum. ${data.explanation}`);
    const bar=controls(root),channel=field(bar,'Channel',select(data.channel_data.map(c=>[String(c.channel),`Channel ${c.channel}`]))),zoom=field(bar,'Spectrogram zoom',select([['1','1×'],['2','2×'],['4','4×']]));
    const player=node('audio',undefined,'lab-audio-player');player.controls=true;player.preload='metadata';root.append(player);
    const wave=node('canvas',undefined,'waveform-canvas');wave.width=1000;wave.height=150;root.append(wave);
    const spectroWrap=node('div',undefined,'spectrogram-wrap'),spectro=node('canvas');spectroWrap.append(spectro);root.append(spectroWrap);
    const out=status(root),frequency=node('canvas',undefined,'spectrum-canvas');frequency.width=1000;frequency.height=150;root.append(frequency);
    let image;
    async function draw(){const selected=data.channel_data.find(c=>String(c.channel)===channel.value);player.src=preview(context.job,selected.playback_artifact_id);image=await loadImage(preview(context.job,selected.spectrogram_artifact_id));
      const wctx=wave.getContext('2d');wctx.clearRect(0,0,1000,150);wctx.strokeStyle='#c5f17c';wctx.beginPath();selected.waveform.forEach(([low,high],i,array)=>{const x=i*1000/array.length;wctx.moveTo(x,75-low*70);wctx.lineTo(x,75-high*70);});wctx.stroke();
      spectro.width=Math.max(image.naturalWidth,spectroWrap.clientWidth)*Number(zoom.value);spectro.height=300;spectro.getContext('2d').drawImage(image,0,0,spectro.width,300);
      const fctx=frequency.getContext('2d');fctx.clearRect(0,0,1000,150);fctx.strokeStyle='#65d6b7';fctx.beginPath();const max=Math.max(...selected.mean_magnitude,1e-8);selected.mean_magnitude.forEach((value,i,array)=>{const x=i*1000/array.length,y=145-value/max*140;i?fctx.lineTo(x,y):fctx.moveTo(x,y);});fctx.stroke();
      out.textContent=`Mean frequency spectrum · 0–${data.sample_rate/2} Hz · peak ${selected.peak_frequency_hz} Hz · RMS ${selected.rms}\nClick waveform/spectrogram to seek. Hover spectrogram for time/frequency.`;
    }
    channel.onchange=()=>draw().catch(error=>{out.textContent=error.message;});zoom.onchange=()=>{if(image){spectro.width=Math.max(image.naturalWidth,spectroWrap.clientWidth)*Number(zoom.value);spectro.getContext('2d').drawImage(image,0,0,spectro.width,300);}};
    wave.onclick=event=>{player.currentTime=Math.max(0,(event.clientX-wave.getBoundingClientRect().left)/wave.clientWidth*data.duration);};
    spectro.onmousemove=event=>{const box=spectro.getBoundingClientRect();out.textContent=`Time ${((event.clientX-box.left)/box.width*data.duration).toFixed(3)}s · frequency ${((1-(event.clientY-box.top)/box.height)*data.sample_rate/2).toFixed(1)} Hz`;};
    spectro.onclick=event=>{player.currentTime=(event.clientX-spectro.getBoundingClientRect().left)/spectro.width*data.duration;};
    await draw();root.append(button('Export spectrogram PNG',()=>spectro.toBlob(blob=>saveBlob(blob,`spectrogram-channel-${channel.value}.png`))));
    context.report.artifacts.filter(a=>a.name.startsWith('channel-')).forEach(a=>download(root,`Download ${a.name} `,artifactURL(context.job,a.id)));
    heading(root,'Audio metadata');root.append(code(context.report.analyzers.find(a=>a.name==='ffprobe')?.data||data));
  }

  function flagLab(root,context){
    help(root,'Confirmed pattern match means exact format agreement; it does not confirm the accepted challenge answer. Decoding and OCR can produce heuristic candidates. Custom regex runs with deadlines inside the worker.');
    const bar=controls(root),prefixes=field(bar,'Prefixes (comma separated)',input('flag,CTF,picoCTF,HTB,THM')),expression=field(bar,'Custom regex (optional)',input(''));
    const out=status(root),results=node('div');root.append(results);
    function show(report){results.replaceChildren();const entries=report.flag_candidates||report.analyzers.find(a=>a.name==='central_flags')?.findings||[];
      if(!entries.length)results.append(node('p','No configured pattern matches in the bounded scan.'));
      entries.forEach(candidate=>{const card=node('article',undefined,'lab-card');const top=node('strong',candidate.value||candidate.candidate_value||candidate.detail);top.append(node('span',candidate.classification||'candidate',`flag-badge ${candidate.classification?.includes('heuristic')?'heuristic':''}`));
        card.append(top,code({source_file:candidate.source_file||candidate.source,offset:candidate.offset,method:candidate.method,history:candidate.history,evidence:candidate.evidence}));results.append(card);
      });
    }
    bar.append(button('Scan all retained sources',catchError(out,async()=>{const result=await task(context,{operation:'flag_scan',prefixes:prefixes.value.split(',').map(x=>x.trim()).filter(Boolean),expression:expression.value},out);if(result)show(result.report);})));show(context.report);
    heading(root,'Recommended operations');(context.report.recommended_operations||[]).forEach(item=>{const card=node('article',undefined,'lab-card');card.append(node('strong',item.title),node('p',item.why),node('p',`Evidence: ${item.evidence}`));root.append(card);});
  }

  async function specializedLab(root,context){
    const registry=(await host.api('/api/tools')).tools;
    const names=['zsteg','steghide','stegseek','stegoveritas','outguess','openstego','stegsnow','stegdetect'];
    help(root,'Explicit tasks operate only on this uploaded artifact. Password tests require your own list (maximum 1,000 candidates), one thread and a 20-second tool deadline. Passwords are removed when the task finishes; diagnostics are redacted.');
    const bar=controls(root),tool=field(bar,'Adapter',select(names.map(name=>{const entry=registry.find(t=>t.name===name);return[name,`${name} · ${entry?.available?'installed':'unavailable'}`];}))),password=field(bar,'Password',input('','password'));
    const dictionary=node('textarea');dictionary.rows=4;dictionary.placeholder='StegSeek only: one supplied password candidate per line (at most 1,000).';dictionary.setAttribute('aria-label','Supplied password candidates');root.append(dictionary);
    const details=node('div'),out=status(root);root.append(details);
    function describe(){const info=registry.find(x=>x.name===tool.value);details.replaceChildren(code({name:info?.name,available:info?.available,version:info?.version,license:info?.license,installation:info?.installation,source:info?.source,blocked:info?.blocked,formats:info?.formats}));}
    tool.onchange=describe;describe();bar.append(button('Run explicit tool task',catchError(out,async()=>{const result=await task(context,{operation:'tool_extract',tool:tool.value,password:password.value,passwords:dictionary.value.split('\n').filter(Boolean)},out,{open:true});password.value='';dictionary.value='';return result;})));
    if(context.report.file.format==='pdf'){heading(root,'Extract PDF attachment');const pdfbar=controls(root),number=field(pdfbar,'Attachment number',input(1,'number'));pdfbar.append(button('Extract attachment',catchError(out,()=>task(context,{operation:'pdf_extract',attachment:Number(number.value)},out,{open:true}))));}
  }

  window.StegoLabLabs={renderers:{image:imageLab,forensics:forensicsLab,audio:audioLab,flags:flagLab,specialized:specializedLab}};
  const tablist=document.querySelector('.tabs');
  [['image','Image lab'],['audio','Audio lab'],['forensics','Forensics'],['flags','Flag Finder'],['specialized','Stego tools']].forEach(([id,title])=>{
    const tab=button(title,()=>host.showTab(id),'');tab.id=`tab-${id}`;tab.dataset.tab=id;tab.setAttribute('role','tab');tab.setAttribute('aria-selected','false');tab.setAttribute('aria-controls','result-content');tab.tabIndex=-1;tablist.append(tab);
  });
  const nav=node('a',undefined,'nav-link');nav.href='#crypto';const icon=document.querySelector('a[href="#utilities"] svg').cloneNode(true);nav.append(icon,node('span','Crypto lab'));document.querySelector('.sidebar nav').append(nav);
  const view=node('section',undefined,'view recipe-view');view.id='view-crypto';view.hidden=true;view.setAttribute('aria-label','Cryptography recipe lab');document.querySelector('main').append(view);
  heading(view,'Cryptography lab');help(view,'Build byte-preserving transformation chains. All operations execute in the restricted local worker. Each intermediate result is retained within a shared 4 MiB recipe budget.');
  const panel=node('div',undefined,'utility-panel panel');view.append(panel);
  const inputBar=controls(panel),encoding=field(inputBar,'Input representation',select([['utf8','UTF-8 text'],['hex','Hexadecimal bytes'],['base64','Base64 bytes']]));
  const text=node('textarea');text.rows=6;text.setAttribute('aria-label','Recipe input');text.placeholder='Text, hexadecimal or Base64 input…';panel.append(text);
  const stepRows=node('div');panel.append(stepRows);const actions=node('div',undefined,'lab-actions');panel.append(actions);const out=status(panel),results=node('div',undefined,'lab-recipe-results');panel.append(results);
  let operations=[];
  host.api('/api/recipes/operations').then(data=>{operations=data.operations;addStep('base64_decode');}).catch(error=>{out.textContent=error.message;});
  function addStep(operation='base64_decode'){
    if(stepRows.children.length>=20)return;
    const row=node('div',undefined,'lab-recipe-row'),op=select(operations,operation),key=input(''),shift=input(13,'number');key.placeholder='Key (XOR: hex; Vigenere: letters)';op.setAttribute('aria-label','Recipe step operation');key.setAttribute('aria-label','Recipe step key');shift.setAttribute('aria-label','Caesar shift');
    const adjust=node('div',undefined,'recipe-step-actions');adjust.append(button('Up',()=>{if(row.previousElementSibling)stepRows.insertBefore(row,row.previousElementSibling);}),button('Down',()=>{if(row.nextElementSibling)stepRows.insertBefore(row.nextElementSibling,row);}),button('Remove',()=>row.remove()));
    row.append(op,key,shift,adjust);stepRows.append(row);
  }
  actions.append(button('Add step',()=>addStep()),button('Run recipe',catchError(out,async()=>{
    results.replaceChildren();const steps=Array.from(stepRows.children).map(row=>({operation:row.querySelector('select').value,key:row.querySelector('input').value,shift:Number(row.querySelectorAll('input')[1].value)}));
    const job=await host.api('/api/recipes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({input:text.value,input_encoding:encoding.value,steps})});
    const result=await watch(job,out);if(!result)return;let recipe=getStage(result.report,'crypto_lab');
    if(recipe.details_artifact_id)recipe=await fetch(artifactURL(result.job,recipe.details_artifact_id)).then(response=>response.json());
    recipe.steps.forEach(step=>{const details=node('details');details.open=true;details.append(node('summary',`${step.step}. ${step.operation} · ${step.size} bytes`),code(step.text??step.hex));results.append(details);});
    heading(results,'Final output');results.append(code(recipe.output.text??recipe.output.hex));
    result.report.artifacts.forEach(a=>download(results,'Download final bytes',artifactURL(result.job,a.id)));if(recipe.flags.length){heading(results,'Flag matches');recipe.flags.forEach(f=>results.append(code(f)));}
  }),'button primary'));
  host.route();
})();
