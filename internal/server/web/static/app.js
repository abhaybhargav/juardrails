'use strict';
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const esc = v => String(v ?? '').replace(/[&<>"']/g, x => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
const pretty = v => JSON.stringify(v, null, 2);
const policyYAML = v => jsyaml.dump(v, {schema: jsyaml.DEFAULT_SCHEMA, noRefs: true, lineWidth: 100});
const date = v => new Date(v).toLocaleString(undefined, {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
const badge = v => `<span class="badge ${esc(v)}">${esc(v)}</span>`;
function notify(message, error = false) { const n = $('#notice'); n.textContent = message; n.className = `notice${error ? ' error' : ''}`; n.hidden = false; n.scrollIntoView({behavior:'smooth',block:'nearest'}); }
let grantedActions=[];
const can=action=>grantedActions.includes(action);
let csrfToken="", selectedNamespace=localStorage.getItem("juardrails.namespace")||"root";
async function api(path, options = {}) {
 const r = await fetch(`/api/v1${path}`, { ...options, headers:{'Content-Type':'application/json','X-Juardrails-Namespace':selectedNamespace,'X-CSRF-Token':csrfToken,...options.headers} });
 if (r.status === 204) return null;
 const data = await r.json();
 if(r.status===401 && document.body.dataset.view!=="login"){location.href="/login";}
 if (!r.ok) { const e = new Error(data.error || `Request failed (${r.status})`); e.data = data; throw e; }
 return data;
}
const empty = (title, text, action = '') => `<div class="empty-state"><span class="empty-symbol">◇</span><h3>${esc(title)}</h3><p>${esc(text)}</p>${action}</div>`;
function download(name, value) { const url=URL.createObjectURL(new Blob([policyYAML(value)],{type:'application/yaml'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000); }
function criterion(type = 'noul', n = 1) {
 const c = {id:`criterion_${n}`,name:`Criterion ${n}`,question:{type,instructions:''},pass:{operator:'lte',threshold:0.2},weight:1};
 if(type==='noul') c.question.criteria = {'true':'The condition is present.','false':'The condition is absent.'};
 if(type==='choice') {c.question.criteria={safe:'Acceptable content',unsafe:'Unacceptable content'};c.pass={operator:'in',choices:['safe'],min_confidence:0.5};}
 if(type==='score') {c.question.criteria=['No concern','Some concern','Severe concern'];c.pass={operator:'lte',threshold:0.5,min_confidence:0.5};}
 return c;
}
function newPolicy() {return {namespace:selectedNamespace,id:'',name:'',description:'',status:'draft',model:'jev-latest',mode:'all',pass_threshold:0.8,criteria:[criterion()],version:0};}
async function policiesPage() {
 const {items}=await api('/policies');$('#stat-total').textContent=items.length;$('#stat-active').textContent=items.filter(p=>p.status==='active').length;$('#stat-criteria').textContent=items.reduce((n,p)=>n+p.criteria.length,0);$('#policy-count').textContent=items.length;
 const draw=()=>{
  const q=$('#search').value.toLowerCase(),status=$('#status-filter').value;
  const found=items.filter(p=>(!status||p.status===status)&&`${p.name} ${p.id} ${p.description}`.toLowerCase().includes(q));
  if(!found.length){$('#policy-list').innerHTML=empty(items.length?'No matching policies':'Your first guardrail starts here.',items.length?'Try another search or status filter.':'Define a policy, add focused criteria, and test your decision logic.',items.length?'':'<a class="btn primary" href="/policies/new">＋ Create your first policy</a>');return;}
  $('#policy-list').innerHTML=`<div class="table-wrap"><table class="policy-table"><thead><tr><th>POLICY</th><th>STATUS</th><th>PRIMITIVES</th><th>DECISION LOGIC</th><th>UPDATED</th><th></th></tr></thead><tbody>${found.map(p=>`<tr><td><div class="policy-title"><span class="policy-glyph">▤</span><div><a href="/policies/${encodeURIComponent(p.id)}">${esc(p.name)}</a><small>${esc(p.id)} · v${p.version}</small></div></div></td><td>${badge(p.status)}</td><td><div class="flex gap-1">${[...new Set(p.criteria.map(c=>c.question.type))].map(badge).join('')}</div><small>${p.criteria.length} criteria</small></td><td>${esc({all:'All must pass',any:'Any can pass',weighted:'Weighted score',rego:'Legacy — migration required'}[p.mode])}</td><td class="muted">${date(p.updated_at)}</td><td><a aria-label="Edit ${esc(p.name)}" href="/policies/${encodeURIComponent(p.id)}">↗</a></td></tr>`).join('')}</tbody></table></div>`;
 };draw();$('#search').oninput=draw;$('#status-filter').onchange=draw;
}
async function editorPage() {
 let id=document.body.dataset.policyId;let policy=id?await api(`/policies/${encodeURIComponent(id)}`):newPolicy();let tab='visual';let dirty=false;const canEdit=can(id?'policies:update':'policies:create');
 const markDirty=()=>{if(canEdit)dirty=true};$('#policy-form').addEventListener('input',markDirty);$('#policy-form').addEventListener('change',markDirty);
 window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
 function draw(){
  $('#editor-title').textContent=id?policy.name:'Create a policy';
  for(const [k,f] of Object.entries({name:'policy-name',id:'policy-id',description:'policy-description',status:'policy-status',model:'policy-model',mode:'policy-mode',pass_threshold:'pass-threshold'})) $(`#${f}`).value=policy[k]??'';
  $('#policy-id').disabled=!!id;$('#test-policy').href=id?`/playground?policy=${encodeURIComponent(id)}`:'/playground';
  $('#criteria').innerHTML=policy.criteria.map((c,i)=>criterionHTML(c,i)).join('');modes();bindCriteria();editorPermissions();
 }
 function editorPermissions(){
 $('#save-policy').hidden=!canEdit;$('#validate-policy').hidden=!canEdit;$('#delete-policy').hidden=!can('policies:delete');$('#import-policy').closest('label').hidden=!canEdit;$('#policy-yaml').readOnly=!canEdit;
 if(!canEdit){$$('#visual-editor input,#visual-editor select,#visual-editor textarea').forEach(el=>el.disabled=true);$$('#visual-editor button').forEach(el=>el.hidden=true);}
 $('#test-policy').hidden=!can('policies:evaluate')&&!can('policies:simulate');
 }
 function modes(){$('#weighted-options').hidden=$('#policy-mode').value!=='weighted';}
 function criterionHTML(c,i){
  const type=c.question.type;const structured=typeof c.question.instructions!=='string';
  let rubric='';
  if(type==='choice')rubric=`<div class="criteria-options">${Object.entries(c.question.criteria||{}).map(([k,v])=>optionHTML(k,v)).join('')}</div><button class="btn add-option mt-3" type="button">＋ Add option</button>`;
  if(type==='score')rubric=`<div class="criteria-options">${(c.question.criteria||[]).map((v,j)=>optionHTML(j,v,true)).join('')}</div><button class="btn add-option mt-3" type="button">＋ Add level</button><p class="help">Levels are indexed from 0. Their order defines the score scale.</p>`;
  if(type==='noul')rubric=`<div class="grid sm:grid-cols-2 gap-4"><label>True means<textarea class="true-description" rows="2">${esc(formatDescription(c.question.criteria?.true??''))}</textarea></label><label>False means<textarea class="false-description" rows="2">${esc(formatDescription(c.question.criteria?.false??''))}</textarea></label></div>`;
  const operators=type==='choice'?[['in','is one of'],['not_in','is not one of']]:[['lte','≤ at most'],['lt','< below'],['gte','≥ at least'],['gt','> above']];
  return `<article class="panel criterion" data-index="${i}"><div class="criterion-top"><span class="type-icon ${type}">${{choice:'◇',score:'▥',noul:'◐'}[type]}</span><h3>${esc(c.name||`Criterion ${i+1}`)}</h3>${badge(type)}<button class="remove-criterion" type="button" aria-label="Remove criterion ${i+1}">×</button></div><div class="p-5"><div class="grid sm:grid-cols-3 gap-3"><label>Name<input class="criterion-name" value="${esc(c.name)}" required></label><label>Criterion ID<input class="criterion-id font-mono" value="${esc(c.id)}" required></label><label>Primitive<select class="criterion-type">${['noul','choice','score'].map(v=>`<option value="${v}" ${v===type?'selected':''}>${v[0].toUpperCase()+v.slice(1)}</option>`).join('')}</select></label></div><label class="mt-4">Question / instructions<textarea class="instructions" rows="2" required placeholder="Ask one focused question…">${esc(structured?pretty(c.question.instructions):c.question.instructions)}</textarea></label><label class="flex gap-2 items-center mt-2 font-normal"><input class="structured-instructions w-auto" type="checkbox" ${structured?'checked':''}>Instructions are structured JSON</label><div class="mt-5"><h3 class="text-xs mb-3">${type==='choice'?'Choice options':type==='score'?'Scoring rubric':'Probability anchors'}</h3>${rubric}<p class="help">Descriptions may be plain text or JSON objects / arrays.</p></div><hr class="my-5"><div class="grid sm:grid-cols-3 gap-3"><label>Pass when<select class="operator">${operators.map(([v,l])=>`<option value="${v}" ${c.pass.operator===v?'selected':''}>${l}</option>`).join('')}</select></label><label>${type==='choice'?'Option keys (comma separated)':`Threshold (0–${type==='noul'?1:c.question.criteria.length-1})`}<input class="threshold" ${type==='choice'?'type="text"':'type="number" step="any" min="0"'} value="${esc(type==='choice'?(c.pass.choices||[]).join(', '):c.pass.threshold)}" required></label><label>Weight<input class="weight" type="number" min="0.001" max="1000" step="any" value="${c.weight}" required></label></div>${type!=='noul'?`<label class="mt-4">Minimum confidence (0–1)<input class="confidence" type="number" min="0" max="1" step="0.01" value="${c.pass.min_confidence||0}"></label>`:'<p class="help mt-4">Noul returns a probability, not a confidence value.</p>'}</div></article>`;
 }
 function formatDescription(v){return typeof v==='string'?v:v==null?'':pretty(v);}
 function parseDescription(text){const s=text.trim();if(s.startsWith('{')||s.startsWith('['))return JSON.parse(s);return s;}
 function optionHTML(k,v,score=false){return `<div class="option-row"><input class="option-key" aria-label="${score?'Level index':'Option key'}" value="${esc(k)}" ${score?'disabled':''}><input class="option-description" aria-label="${score?'Level':'Option'} description" value="${esc(formatDescription(v))}" placeholder="Describe this ${score?'level':'option'}"><button class="remove-option" type="button" aria-label="Remove option or level">×</button></div>`;}
 function read(){
  if(tab==='yaml'){
   const next=jsyaml.load($('#policy-yaml').value, {schema: jsyaml.JSON_SCHEMA});if(!next || typeof next !== 'object' || Array.isArray(next))throw new Error('Policy YAML must be a mapping.');if(id&&next.id!==id)throw new Error('The ID of an existing policy cannot change.');
   if(!Array.isArray(next.criteria))throw new Error('Policy criteria must be an array.');
   // Keep concurrency metadata tied to the revision loaded by this editor.
   policy={...next,version:policy.version};return policy;
  }
  for(const [k,f] of Object.entries({name:'policy-name',id:'policy-id',description:'policy-description',status:'policy-status',model:'policy-model',mode:'policy-mode'}))policy[k]=$(`#${f}`).value;
  policy.pass_threshold=Number($('#pass-threshold').value);
  policy.criteria=$$('.criterion').map(el=>{
   const type=$('.criterion-type',el).value;const c={id:$('.criterion-id',el).value,name:$('.criterion-name',el).value,question:{type,instructions:$('.structured-instructions',el).checked?JSON.parse($('.instructions',el).value):$('.instructions',el).value},weight:Number($('.weight',el).value),pass:{operator:$('.operator',el).value}};
   if(type==='choice'){
    const entries=$$('.option-row',el).map(row=>[$('.option-key',row).value,parseDescription($('.option-description',row).value)||null]);
    if(new Set(entries.map(([k])=>k)).size!==entries.length)throw new Error('Choice option keys must be unique.');c.question.criteria=Object.fromEntries(entries);c.pass.choices=$('.threshold',el).value.split(',').map(s=>s.trim()).filter(Boolean);
   }else{c.pass.threshold=Number($('.threshold',el).value);if(type==='score')c.question.criteria=$$('.option-description',el).map(x=>parseDescription(x.value));else{c.question.criteria={};for(const k of ['true','false']){const v=$(`.${k}-description`,el).value;if(v.trim())c.question.criteria[k]=parseDescription(v);}}}
   if(type!=='noul')c.pass.min_confidence=Number($('.confidence',el).value);return c;
  });return policy;
 }
 async function validateYAMLSource(){if(tab==='yaml')await api('/policies/validate',{method:'POST',headers:{'Content-Type':'application/yaml'},body:$('#policy-yaml').value});}
 function safe(fn){return async(...args)=>{try{await fn(...args)}catch(e){notify(e.message,true)}};}
 function bindCriteria(){
  $$('.criterion').forEach(el=>{
   const i=Number(el.dataset.index);
   $('.remove-criterion',el).onclick=safe(()=>{if(policy.criteria.length===1)throw new Error('Keep at least one criterion.');read();policy.criteria.splice(i,1);dirty=true;draw();});
   $('.criterion-type',el).onchange=safe(()=>{const next=$('.criterion-type',el).value;$('.criterion-type',el).value=policy.criteria[i].question.type;read();const old=policy.criteria[i],fresh=criterion(next,i+1);fresh.id=old.id;fresh.name=old.name;fresh.weight=old.weight;fresh.question.instructions=old.question.instructions;policy.criteria[i]=fresh;draw();});
   const add=$('.add-option',el);if(add)add.onclick=()=>{const score=$('.criterion-type',el).value==='score';const n=$$('.option-row',el).length;$('.criteria-options',el).insertAdjacentHTML('beforeend',optionHTML(score?n:`option_${n+1}`,'',score));dirty=true;bindOptions(el);};bindOptions(el);
  });
 }
 function bindOptions(el){$$('.remove-option',el).forEach(btn=>btn.onclick=()=>{btn.closest('.option-row').remove();if($('.criterion-type',el).value==='score')$$('.option-key',el).forEach((x,i)=>x.value=i);dirty=true;});}
 $('#add-criterion').onclick=safe(()=>{read();let n=policy.criteria.length+1;while(policy.criteria.some(c=>c.id===`criterion_${n}`))n++;policy.criteria.push(criterion('noul',n));dirty=true;draw();});
 $('#policy-mode').onchange=modes;
 $('#policy-name').oninput=()=>{if(!id&&!$('#policy-id').dataset.edited)$('#policy-id').value=$('#policy-name').value.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,64);};$('#policy-id').oninput=()=>$('#policy-id').dataset.edited='true';
 $('#yaml-tab').onclick=safe(()=>{if(tab==='yaml')return;read();$('#policy-yaml').value=policyYAML(policy);tab='yaml';setTabs();});
 $('#visual-tab').onclick=safe(async()=>{if(tab==='visual')return;if(!canEdit){tab='visual';draw();setTabs();return;}await validateYAMLSource();read();await api('/policies/validate',{method:'POST',body:pretty(policy)});tab='visual';draw();setTabs();});
 function setTabs(){for(const t of ['visual','yaml']){$(`#${t}-tab`).classList.toggle('selected',tab===t);$(`#${t}-tab`).setAttribute('aria-selected',String(tab===t));$(`#${t}-editor`).hidden=tab!==t;}}
 $('#import-policy').onchange=safe(async e=>{const file=e.target.files[0];if(file){if(file.size>1048576)throw new Error('Policy file must be at most 1 MiB.');$('#policy-yaml').value=await file.text();dirty=true;}});
 $('#export-policy').onclick=safe(()=>{read();download(`${policy.id||'policy'}.yaml`,policy);});
 $('#validate-policy').onclick=safe(async()=>{await validateYAMLSource();read();await api('/policies/validate',{method:'POST',body:pretty(policy)});notify('Policy YAML and decision rules are valid.');});
 $('#policy-form').onsubmit=safe(async e=>{
  e.preventDefault();if(!canEdit)throw Error('This policy is read-only for your account.');await validateYAMLSource();if(tab==='visual'&&!$('#policy-form').reportValidity())return;read();const btn=$('#save-policy');btn.disabled=true;
  try{const saved=await api(id?`/policies/${encodeURIComponent(id)}`:'/policies',{method:id?'PUT':'POST',body:pretty(policy)});policy=saved;dirty=false;if(!id){location.href=`/policies/${encodeURIComponent(saved.id)}`;return;}draw();if(tab==='yaml')$('#policy-yaml').value=policyYAML(policy);notify(`Saved revision ${saved.version}.`);await revisions();}finally{btn.disabled=false;}
 });
 // Hidden visual inputs must not prevent submission of the YAML editor.
 $('#policy-form').noValidate=true;
 async function revisions(){if(!id)return;$('#revision-panel').hidden=false;const {items}=await api(`/policies/${encodeURIComponent(id)}/revisions`);$('#revision-list').innerHTML=items.slice().reverse().map(p=>`<div class="revision-row"><div><strong>Version ${p.version}</strong><small>${date(p.updated_at)} · ${esc(p.status)}</small></div><button type="button" data-revision="${p.version}">${p.version===policy.version?'Current':'Load into editor'}</button></div>`).join('');$$('[data-revision]').forEach(btn=>btn.onclick=safe(()=>{const old=items.find(p=>p.version===Number(btn.dataset.revision));policy={...structuredClone(old),version:policy.version};dirty=canEdit;draw();if(tab==='yaml')$('#policy-yaml').value=policyYAML(policy);notify(canEdit?`Loaded version ${old.version}. Save to create a new revision.`:`Viewing revision ${old.version}.`);}));}
 $('#delete-policy').onclick=()=>{const dialog=$('#confirm-dialog');dialog.showModal();dialog.onclose=safe(async()=>{if(dialog.returnValue==='delete'){await api(`/policies/${encodeURIComponent(id)}?version=${policy.version}`,{method:'DELETE'});dirty=false;location.href='/';}});};
 draw();await revisions();if(!canEdit)notify('This policy definition is read-only for your account.');if(policy.mode==='rego'||policy.rego)notify('This legacy policy uses Rego. Edit its YAML, remove rego, and choose all, any, or weighted before saving. Existing history is preserved.',true);
}
function fixture(p){
 const out={};for(const c of p.criteria){const type=c.question.type;
  if(type==='noul'){let v=c.pass.threshold;if(c.pass.operator==='lt')v=Math.max(0,v-0.1);if(c.pass.operator==='gt')v=Math.min(1,v+0.1);out[c.id]={type,noul:v};}
  if(type==='choice'){const opts=Object.keys(c.question.criteria),key=opts.find(k=>c.pass.operator==='in'?c.pass.choices.includes(k):!c.pass.choices.includes(k))||opts[0];out[c.id]={type,choice:key,confidence:1,probabilities:Object.fromEntries(opts.map(k=>[k,k===key?1:0]))};}
  if(type==='score'){const n=c.question.criteria.length;let v=c.pass.operator==='lte'||c.pass.operator==='lt'?0:n-1;out[c.id]={type,score:v,confidence:1,probabilities:Object.fromEntries(c.question.criteria.map((_,i)=>[String(i),i===v?1:0])),legend:Object.fromEntries(c.question.criteria.map((x,i)=>[String(i),x]))};}
 }return out;
}
function trace(e){
 return `<div class="decision-head"><div>${badge(e.source)}<strong class="mt-2">${esc(e.decision)}</strong><p class="muted text-xs mt-2">${esc(e.policy_name)} · revision ${e.policy_version}</p></div><div class="text-right"><div class="text-2xl font-semibold">${(e.score*100).toFixed(1)}<span class="text-sm muted">%</span></div><p class="muted text-xs">weighted pass score</p><p class="muted text-xs mt-2">${e.duration_ms} ms · ${esc(e.model)}${e.provider ? ` · ${esc(e.provider)}` : ''}</p></div></div>${e.error?`<div class="notice error">${esc(e.error)}</div>`:''}${(e.results||[]).map(r=>`<div class="trace-card"><div class="flex justify-between gap-3"><h3>${esc(r.name)}</h3>${badge(r.uncertain?'review':r.passed?'allow':'block')}</div><p>${esc(r.reason)} · weight ${r.weight}</p><details class="mt-3 text-xs muted"><summary class="cursor-pointer">Typed answer & probabilities</summary><pre class="code">${esc(pretty(r.answer))}</pre></details></div>`).join('')}<details class="mt-6 text-xs muted"><summary class="cursor-pointer">Full response JSON</summary><pre class="code mt-3">${esc(pretty(e))}</pre></details>`;
}
async function playgroundPage(){
 const {items}=await api('/policies');const select=$('#evaluate-policy');items.forEach(p=>select.add(new Option(`${p.name} · v${p.version} (${p.status})`,p.id)));
 const requested=new URLSearchParams(location.search).get('policy');if(items.some(p=>p.id===requested))select.value=requested;else if(items.length)select.value=items[0].id;
 const change=()=>{const p=items.find(p=>p.id===select.value);$('#evaluate-answers').value=p?pretty(fixture(p)):'';};select.onchange=change;change();
 if(!items.length)notify('Create a policy first, then return here to test it.');
 $('#evaluate-mode').onchange=()=>{const live=$('#evaluate-mode').value==='evaluate';$('#simulation-input').hidden=live;$('#live-note').hidden=!live;$('#run-evaluation').textContent=live?'▷ Evaluate with Jev':'▷ Run simulation';};
 $('#evaluate-form').onsubmit=async e=>{
  e.preventDefault();const btn=$('#run-evaluation');btn.disabled=true;const label=btn.textContent;btn.textContent='Evaluating…';
  try{const state=$('#state-format').value==='json'?JSON.parse($('#evaluate-state').value):$('#evaluate-state').value;const body={state};const mode=$('#evaluate-mode').value;if(mode==='simulate')body.answers=JSON.parse($('#evaluate-answers').value);const result=await api(`/policies/${encodeURIComponent(select.value)}/${mode}`,{method:'POST',body:pretty(body)});$('#evaluation-result').innerHTML=trace(result);$('#notice').hidden=true;}catch(err){if(err.data?.decision)$('#evaluation-result').innerHTML=trace(err.data);else $('#evaluation-result').innerHTML=empty('Evaluation did not complete',err.message);notify(err.message,true);}finally{btn.disabled=false;btn.textContent=label;}
 };
}
async function historyPage(){
 const {items:ps}=await api('/policies');for(const p of ps)$('#history-policy').add(new Option(p.name,p.id));
 async function draw(){const {items}=await api(`/evaluations?policy_id=${encodeURIComponent($('#history-policy').value)}`);$('#history-list').innerHTML=items.length?`<div class="table-wrap"><table class="policy-table"><thead><tr><th>POLICY / REVISION</th><th>DECISION</th><th>SOURCE</th><th>PASS SCORE</th><th>DURATION</th><th>TIME</th><th></th></tr></thead><tbody>${items.map(e=>`<tr><td>${esc(e.policy_name)}<small>revision ${e.policy_version}</small></td><td>${badge(e.decision)}</td><td>${badge(e.source)}</td><td>${(e.score*100).toFixed(1)}%</td><td>${e.duration_ms} ms</td><td class="muted">${date(e.created_at)}</td><td><button class="btn view-evaluation" data-id="${esc(e.id)}">Inspect</button></td></tr>`).join('')}</tbody></table></div>`:empty('No decisions yet','Your evaluation and simulation traces will appear here.','<a class="btn" href="/playground">Try the playground ↗</a>');$$('.view-evaluation').forEach(btn=>btn.onclick=()=>{const target=$('#history-detail');target.innerHTML=trace(items.find(e=>e.id===btn.dataset.id));target.hidden=false;target.scrollIntoView({behavior:'smooth'});});}
 $('#history-policy').onchange=()=>draw().catch(e=>notify(e.message,true));await draw();
}
function formData(form){return Object.fromEntries(new FormData(form));}
function submit(form,fn){form.onsubmit=async e=>{e.preventDefault();const b=$('button',form);b.disabled=true;try{await fn(formData(form));}catch(err){notify(err.message,true);}finally{b.disabled=false;}};}
async function loginPage(){submit($('#login-form'),async data=>{await api('/auth/login',{method:'POST',body:pretty(data)});location.href='/';});}
async function accountPage(){submit($('#password-form'),async data=>{await api('/auth/password',{method:'POST',body:pretty(data)});location.href='/login';});}
async function accessPage(){
 let principals=[],policies=[],namespaces=[];
 const example={name:'namespace-reader',description:'Read policies and decisions in root',version:0,rules:[{namespace:'root',actions:['policies:read','evaluations:read']}]};
 const path=s=>encodeURIComponent(s);
 async function bindings(){const id=$('#binding-principal').value;const bound=id?(await api(`/admin/principals/${path(id)}/bindings`)).policies:[];$('#binding-options').innerHTML=policies.length?policies.map(p=>`<label class="flex gap-2 items-center"><input type="checkbox" name="policies" value="${esc(p.name)}" ${bound.includes(p.name)?'checked':''}>${esc(p.name)} <span class="muted">${esc(p.description)}</span></label>`).join(''):'<p class="help">Create an access policy first.</p>';}
 function acl(){const p=policies.find(p=>p.name===$('#acl-select').value);$('#acl-yaml').value=policyYAML(p||example);$('#acl-delete').hidden=!p;}
 async function refresh(){
 const [p,a,n,t,cfg]=await Promise.all([api('/admin/principals'),api('/admin/access-policies'),api('/namespaces'),api('/admin/tokens'),api('/admin/auth-settings')]);principals=p.items;policies=a.items;namespaces=n.items;
 $('#namespace-list').innerHTML=namespaces.map(n=>`<p class="my-2"><strong>${esc(n.name)}</strong> <span class="muted">${esc(n.description)}</span></p>`).join('');$('#available-actions').textContent=n.actions.join('\n');$('#auth-settings-form [name=session_minutes]').value=cfg.session_minutes;
 $('#principal-list').innerHTML=`<table class="policy-table"><thead><tr><th>ACCOUNT</th><th>TYPE</th><th>STATUS</th><th>DESCRIPTION</th><th></th></tr></thead><tbody>${principals.map(p=>`<tr><td>${esc(p.name)}</td><td>${esc(p.super_admin?'Super-admin':p.kind)}</td><td>${p.disabled?'Disabled':'Enabled'}</td><td>${esc(p.description)}</td><td>${p.super_admin?'Permanent identity':`<button class="btn toggle-principal" data-id="${esc(p.id)}">${p.disabled?'Enable':'Disable'}</button>`}</td></tr>`).join('')}</tbody></table>`;
 $$('.toggle-principal').forEach(b=>b.onclick=async()=>{const p=principals.find(p=>p.id===b.dataset.id);try{await api(`/admin/principals/${path(p.id)}`,{method:'PUT',body:pretty({description:p.description,disabled:!p.disabled})});await refresh();notify('Account updated.');}catch(e){notify(e.message,true);}});
 function selectOptions(id,items,value,label){const el=$(id),old=el.value;el.replaceChildren(...items.map(p=>new Option(label(p),value(p))));if(items.some(p=>value(p)===old))el.value=old;}
 selectOptions('#binding-principal',principals.filter(p=>!p.super_admin),p=>p.id,p=>`${p.name} (${p.kind})`);selectOptions('#token-principal',principals.filter(p=>p.kind==='service'&&!p.disabled),p=>p.id,p=>p.name);selectOptions('#reset-principal',principals.filter(p=>p.kind==='human'&&!p.super_admin),p=>p.id,p=>p.name);
 selectOptions('#acl-select',[{name:''},...policies],p=>p.name,p=>p.name||'New access policy');acl();await bindings();
 $('#token-list').innerHTML=`<table class="policy-table"><thead><tr><th>NAME / ACCOUNT</th><th>TYPE</th><th>EXPIRES</th><th>STATE</th><th></th></tr></thead><tbody>${t.items.map(t=>{const inactive=t.revoked||new Date(t.expires_at)<=new Date();return `<tr><td>${esc(t.name)}<small>${esc(principals.find(p=>p.id===t.principal_id)?.name)}</small></td><td>${esc(t.kind)}</td><td>${date(t.expires_at)}</td><td>${t.revoked?'Revoked':inactive?'Expired':'Active'}</td><td>${inactive?'':`<button class="btn revoke-token" data-id="${esc(t.id)}">Revoke</button>`}</td></tr>`;}).join('')}</tbody></table>`;
 $$('.revoke-token').forEach(b=>b.onclick=async()=>{try{await api(`/admin/tokens/${path(b.dataset.id)}`,{method:'DELETE'});await refresh();notify('Token revoked.');}catch(e){notify(e.message,true);}});
 }
 $('#binding-principal').onchange=()=>bindings().catch(e=>notify(e.message,true));$('#acl-select').onchange=acl;
 $('#principal-form [name=kind]').onchange=e=>{const service=e.target.value==='service';$('#new-password-label').hidden=service;$('#principal-form [name=password]').required=!service;$('#principal-form [name=password]').disabled=service;};
 submit($('#namespace-form'),async({operation,...data})=>{await api('/namespaces',{method:operation,body:pretty(data)});await refresh();await loadNamespaces();notify('Namespace saved.');});
 submit($('#principal-form'),async data=>{await api('/admin/principals',{method:'POST',body:pretty(data)});$('#principal-form [name=password]').value='';await refresh();notify('Account created. Bind an access policy to grant permissions.');});
 submit($('#acl-form'),async()=>{const selected=$('#acl-select').value;const data=jsyaml.load($('#acl-yaml').value,{schema:jsyaml.JSON_SCHEMA});if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Access policy must be a YAML mapping.');if(selected&&data.name!==selected)throw Error('An existing policy name cannot change.');data.version=selected?policies.find(p=>p.name===selected).version:0;await api('/admin/access-policies'+(selected?`/${path(selected)}`:''),{method:selected?'PUT':'POST',body:pretty(data)});await refresh();$('#acl-select').value=data.name;acl();notify('Access policy saved.');});
 $('#acl-delete').onclick=async()=>{const p=policies.find(p=>p.name===$('#acl-select').value);if(!p||!confirm(`Delete ${p.name}? All its bindings will be removed.`))return;try{await api(`/admin/access-policies/${path(p.name)}?version=${p.version}`,{method:'DELETE'});await refresh();notify('Policy deleted; bindings removed.');}catch(e){notify(e.message,true);}};
 submit($('#bindings-form'),async()=>{const id=$('#binding-principal').value;if(!id)throw Error('Create an account first.');await api(`/admin/principals/${path(id)}/bindings`,{method:'PUT',body:pretty({policies:$$('#binding-options input:checked').map(i=>i.value)})});notify('Access bindings saved.');});
 submit($('#reset-form'),async data=>{const id=$('#reset-principal').value;if(!id)throw Error('Select a human account.');await api(`/admin/principals/${path(id)}/password`,{method:'POST',body:pretty(data)});$('#reset-form').reset();await refresh();notify('Password reset; existing sessions revoked.');});
 submit($('#token-form'),async data=>{if(!$('#token-principal').value)throw Error('Create an enabled service account first.');const out=await api('/admin/tokens',{method:'POST',body:pretty({...data,principal_id:$('#token-principal').value,expires_at:new Date(data.expires_at).toISOString()})});$('#token-secret').textContent=out.token;$('#token-result').hidden=false;await refresh();notify('Token issued. Copy its secret below.');});
 $('#token-dismiss').onclick=()=>{$('#token-secret').textContent='';$('#token-result').hidden=true;};
 submit($('#auth-settings-form'),async data=>{await api('/admin/auth-settings',{method:'PUT',body:pretty({password:true,otp:false,sso:false,session_minutes:Number(data.session_minutes)})});notify('Authentication settings saved.');});
 await refresh();
}
async function loadNamespaces(){const {items,permissions}=await api('/namespaces');const select=$('#namespace-select');select.replaceChildren(...items.map(n=>new Option(n.name,n.name)));if(!items.some(n=>n.name===selectedNamespace)){selectedNamespace=items[0]?.name||'root';localStorage.setItem('juardrails.namespace',selectedNamespace);}select.value=selectedNamespace;grantedActions=permissions[selectedNamespace]||[];if(!items.length){select.add(new Option('No namespace access',''));select.disabled=true;}select.onchange=()=>{localStorage.setItem('juardrails.namespace',select.value);location.href='/';};}
async function init(){if(document.body.dataset.view==='login'){await loginPage();return;}const me=await api('/auth/me');csrfToken=me.csrf_token;await loadNamespaces();$('#logout').onclick=async()=>{try{await api('/auth/logout',{method:'POST'});location.href='/login';}catch(e){notify(e.message,true);}};const pages={policies:policiesPage,editor:editorPage,playground:playgroundPage,evaluations:historyPage,account:accountPage,access:accessPage};await pages[document.body.dataset.view]?.();
 if(!can('policies:create'))$$('a[href="/policies/new"]').forEach(el=>el.hidden=true);
 if(!can('evaluations:read'))$$('nav a[href="/evaluations"]').forEach(el=>el.hidden=true);
 if(!can('policies:evaluate')&&!can('policies:simulate'))$$('a[href="/playground"]').forEach(el=>el.hidden=true);
 if(document.body.dataset.view==='playground'){const modes=$('#evaluate-mode');Array.from(modes.options).forEach(o=>{o.disabled=!can('policies:'+o.value)});const allowed=Array.from(modes.options).find(o=>!o.disabled);if(allowed){modes.value=allowed.value;modes.onchange();}else{$('#run-evaluation').disabled=true;notify('Your account cannot run evaluations in this namespace.',true);}}
}
init().catch(e=>notify(e.message,true));
