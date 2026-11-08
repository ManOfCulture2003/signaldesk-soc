'use strict';
// Only this bundled sample is supported. Real logs belong in the local app.
const DEMO_KEY = 'signaldesk-demo-v1';
const clone = value => JSON.parse(JSON.stringify(value));
let demoCases = clone(window.DEMO_SEED.cases);
let storageAvailable = true;
try {
  const saved = JSON.parse(sessionStorage.getItem(DEMO_KEY) || 'null');
  if (saved && typeof saved === 'object') {
    for (const [id, record] of Object.entries(saved)) {
      const base = demoCases[id];
      if (!base || !['new','investigating','closed'].includes(record.status) || typeof record.owner !== 'string' || record.owner.length>100 || !Array.isArray(record.history) || record.history.length>100) continue;
      const valid = record.history.every(h=>typeof h.note==='string' && h.note.length<=4000 && typeof h.owner==='string' && h.owner.length<=100 && ['new','investigating','closed'].includes(h.status));
      if (!valid) continue;
      Object.assign(base.alert, {status:record.status,owner:record.owner,disposition:record.disposition,version:record.history.length+1});
      base.history.push(...record.history);
    }
  }
} catch { storageAvailable = false; }
function saveDemo() {
  const changes = Object.fromEntries(Object.entries(demoCases).map(([id,c])=>[id,{status:c.alert.status,owner:c.alert.owner,disposition:c.alert.disposition,history:c.history.filter(h=>h.action==='triage')} ]));
  try { sessionStorage.setItem(DEMO_KEY,JSON.stringify(changes)); }
  catch { storageAvailable=false; }
}
window.resetDemo = () => { try { sessionStorage.removeItem(DEMO_KEY); } catch {} demoCases=clone(window.DEMO_SEED.cases); };
window.downloadDemoCase = id => {
  const data = {...clone(demoCases[id]), demo:true, notice:'Synthetic demonstration. Not a real incident or device scan.'};
  const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='signaldesk-demo-case.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
window.demoApi = async (path, options={}) => {
  const url=new URL(path,'https://demo.invalid');
  const route=url.pathname;
  if(route==='/api/session') return {token:'demo-only'};
  if(route==='/api/stats') {
    const alerts={};for(const c of Object.values(demoCases)) alerts[c.alert.status]=(alerts[c.alert.status]||0)+1;
    return {events:window.DEMO_SEED.events.length,synthetic_events:window.DEMO_SEED.events.length,alerts};
  }
  if(route==='/api/rules') return clone(window.DEMO_SEED.rules);
  if(route==='/api/alerts') return Object.values(demoCases).map(c=>clone(c.alert));
  if(route==='/api/events') {
    const rows=window.DEMO_SEED.events.filter(e=>['host','user','src_ip','kind'].every(k=>!url.searchParams.get(k)||e[k]===url.searchParams.get(k)));
    const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||50);
    if(!Number.isInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>500) throw Error('Invalid pagination.');
    return {total:rows.length,items:clone(rows.slice(offset,offset+limit)),offset,limit};
  }
  if(route==='/api/detect') {
    // Results are produced by the actual Python detector at build time. This
    // replays that fixed fixture, rather than claiming to scan the visitor.
    return {matched:Object.keys(demoCases).length,created:0,updated:0};
  }
  const match=route.match(/^\/api\/alerts\/([a-f0-9]+)(\/triage)?$/);
  if(match && demoCases[match[1]]) {
    const record=demoCases[match[1]];
    if(match[2]) {
      const data=JSON.parse(options.body||'{}');
      if(data.version!==record.alert.version) throw Error('This case changed. Open it again before saving.');
      if(!['new','investigating','closed'].includes(data.status)) throw Error('Choose a valid status.');
      if(typeof data.note!=='string'||!data.note.trim()||data.note.length>4000) throw Error('Add a rationale of 1 to 4,000 characters.');
      if(typeof data.owner!=='string'||data.owner.length>100) throw Error('Owner must be at most 100 characters.');
      if(data.status==='closed'?!['true_positive','false_positive','benign_positive'].includes(data.disposition):Boolean(data.disposition)) throw Error('Closed cases need a disposition. Open cases must use Not closed.');
      if(record.history.length>100) throw Error('Demo history limit reached. Export your case, then reset the demo.');
      Object.assign(record.alert,{status:data.status,disposition:data.disposition,owner:data.owner.trim(),version:record.alert.version+1});
      record.history.push({action:'triage',at:new Date().toISOString(),status:data.status,disposition:data.disposition,owner:data.owner.trim(),note:data.note.trim()});
      saveDemo();
      if(!storageAvailable) document.querySelector('.demo-notice p').textContent='Browser storage is unavailable. Decisions work in this page but will be lost on reload. Export a case to keep it. All evidence is synthetic.';
    }
    return clone(record);
  }
  throw Error('This demo uses its bundled sample only. Run the local app to import your own evidence.');
};
