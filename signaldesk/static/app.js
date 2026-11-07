'use strict';
const $ = id => document.getElementById(id);
let token = '', alerts = [], selected = null, offset = 0, total = 0;
const el = (tag, text, cls) => { const n = document.createElement(tag); if(text !== undefined) n.textContent = text; if(cls) n.className = cls; return n; };
function message(text) { $('message').textContent = text; }
async function api(path, options={}) {
  const response = await fetch(path, {...options, headers:{'X-SignalDesk-Token':token,...options.headers}});
  const data = await response.json();
  if(!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail));
  return data;
}
function action(fn) { return async event => { if(event) event.preventDefault(); try { await fn(); } catch(error) { message(error.message); } }; }
function badge(text, cls='') { return el('span',text,'badge '+cls); }
function eventTable(events) {
  const table = el('table'), head = el('tr');
  for(const title of ['Timestamp (UTC)','Host','Kind','User','Source IP','Origin']) head.append(el('th', title));
  const thead = el('thead'); thead.append(head); table.append(thead);
  const body = el('tbody');
  for(const event of events) { const row = el('tr'); for(const value of [event.timestamp,event.host,event.kind,event.user||'—',event.src_ip||'—',event.synthetic?'Synthetic':'Imported']) row.append(el('td',value)); body.append(row); }
  table.append(body); return table;
}
async function refresh() {
  const stats = await api('/api/stats');
  $('stats').replaceChildren();
  const active = (stats.alerts.new||0)+(stats.alerts.investigating||0);
  for(const [label,value] of [['Stored events',stats.events],['Open alerts',active],['Closed cases',stats.alerts.closed||0],['Synthetic events',stats.synthetic_events]]) {
    const card=el('div',undefined,'stat'); card.append(el('strong',String(value)),el('span',label)); $('stats').append(card);
  }
  alerts = await api('/api/alerts'); renderAlerts();
}
function renderAlerts() {
  const filter=$('status-filter').value; $('alert-list').replaceChildren();
  const rows=alerts.filter(a=>!filter||a.status===filter);
  if(!rows.length) $('alert-list').append(el('p','No matching alerts. Import evidence, then run detections.','empty'));
  for(const a of rows) {
    const card=el('button',undefined,'alert'+(a.id===selected?' selected':''));
    card.append(badge(a.severity,a.severity),badge(a.status));
    if(a.synthetic) card.append(badge('synthetic','synthetic'));
    card.append(el('h3',a.title),el('div',a.rule_id+' · '+a.technique+' · '+a.host,'meta'),el('div',a.evidence.length+' evidence events · '+a.last_seen.slice(0,19)+' UTC','meta'));
    card.addEventListener('click',action(()=>openCase(a.id))); $('alert-list').append(card);
  }
}
async function openCase(id) {
  selected=id; renderAlerts(); const report=await api('/api/alerts/'+id), a=report.alert, panel=$('case'); panel.replaceChildren();
  panel.append(badge(a.rule_id),badge(a.severity,a.severity),el('h2',a.title),el('p',a.description));
  const link=el('a','Export evidence + case history'); link.href='/api/alerts/'+id+'/export'; panel.append(link);
  panel.append(el('h3','Investigation guidance'),el('p',a.triage),el('h3','Evidence timeline'));
  const wrap=el('div',undefined,'scroll');wrap.append(eventTable(report.evidence));panel.append(wrap);
  const details=el('details');details.append(el('summary','Normalized records & source hashes'),el('pre',JSON.stringify(report.evidence,null,2)));panel.append(details);
  const history=el('details');history.append(el('summary','Case history ('+report.history.length+')'),el('pre',JSON.stringify(report.history,null,2)));panel.append(history);
  const form=el('form',undefined,'case-form');
  function field(name,node,labelText){const label=el('label',labelText);node.name=name;label.append(node);form.append(label);return node;}
  const status=field('status',el('select'),'Status'); for(const s of ['new','investigating','closed']) {const o=el('option',s);o.value=s;status.append(o);}status.value=a.status;
  const disposition=field('disposition',el('select'),'Disposition');for(const s of ['','true_positive','false_positive','benign_positive']){const o=el('option',s||'Not closed');o.value=s;disposition.append(o);}disposition.value=a.disposition;
  const owner=field('owner',el('input'),'Owner');owner.value=a.owner;owner.maxLength=100;
  const note=field('note',el('textarea'),'Triage rationale (required)');note.rows=3;note.required=true;note.maxLength=4000;note.parentNode.className='note';
  form.append(el('button','Save decision'));
  form.addEventListener('submit',action(async()=>{await api('/api/alerts/'+id+'/triage',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:a.version,status:status.value,disposition:disposition.value,owner:owner.value,note:note.value})});message('Decision saved with its case history.');await refresh();await openCase(id);}));
  panel.append(form);
}
async function loadEvents() {
  const params=new URLSearchParams(new FormData($('search')));params.set('offset',String(offset));params.set('limit','50');
  const result=await api('/api/events?'+params);total=result.total;$('event-count').textContent=`${total} matching events · showing ${result.items.length ? offset+1 : 0}–${offset+result.items.length}`;
  $('event-table').replaceChildren(eventTable(result.items));$('prev').disabled=offset===0;$('next').disabled=offset+50>=total;
}
async function loadRules() {
  const rules=await api('/api/rules');$('rule-list').replaceChildren();
  for(const [id,r] of Object.entries(rules)){const card=el('article',undefined,'rule');card.append(badge(id),badge(r.severity,r.severity),el('h3',r.title),el('p',r.description),el('p',r.triage));const link=el('a','ATT&CK '+r.technique);link.href='https://attack.mitre.org/techniques/'+r.technique.replace('.','/')+'/';link.target='_blank';link.rel='noopener noreferrer';card.append(link);$('rule-list').append(card);}
}
for(const name of ['alerts','events','rules']) $('tab-'+name).addEventListener('click',action(async()=>{for(const n of ['alerts','events','rules']){$(n).hidden=n!==name;$('tab-'+n).classList.toggle('active',n===name);}if(name==='events')await loadEvents();if(name==='rules')await loadRules();}));
$('refresh').addEventListener('click',action(refresh));$('status-filter').addEventListener('change',renderAlerts);
$('detect').addEventListener('click',action(async()=>{const result=await api('/api/detect',{method:'POST'});message(`Detections complete: ${result.created} new, ${result.updated} updated, ${result.matched} matched alerts.`);await refresh();if(selected)await openCase(selected);}));
$('search').addEventListener('submit',action(async()=>{offset=0;await loadEvents();}));
$('prev').addEventListener('click',action(async()=>{offset=Math.max(0,offset-50);await loadEvents();}));$('next').addEventListener('click',action(async()=>{offset+=50;await loadEvents();}));
$('import-form').addEventListener('submit',action(async()=>{const file=$('file').files[0];if(!file)throw new Error('Choose an evidence file.');if(file.size>5*1024*1024)throw new Error('File exceeds 5 MiB.');const result=await api('/api/import?format='+$('format').value,{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});message(`Imported ${result.inserted} events (${result.duplicates} duplicates). Run detections to analyze them.`);await refresh();}));
action(async()=>{token=(await api('/api/session')).token;await refresh();})();
