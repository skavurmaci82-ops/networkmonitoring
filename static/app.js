'use strict';
const $ = selector => document.querySelector(selector);
const statusNames = {online:'Erişilebilir',degraded:'Geçici yanıt yok',unreachable:'Yanıt yok',unknown:'Kontrol edilmedi'};
let state = {devices:[],events:[],settings:{ranges:[],interval:300},scan:{}}, view='overview', editing=null, initialized=false, polling=false;
let token=sessionStorage.getItem('atlas-token')||'';
const esc = value => String(value ?? '').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const date = value => value ? new Date(value).toLocaleString('tr-TR',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}) : '—';

async function api(path, options={}) {
  const headers={...options.headers};
  if(token) headers.Authorization='Bearer '+token;
  if(options.body) headers['Content-Type']='application/json';
  const response=await fetch(path,{...options,headers});
  if(!response.ok){
    if(response.status===401 && !$('#access-dialog').open) $('#access-dialog').showModal();
    let message='Sunucuya bağlanılamadı.';
    try {message=(await response.json()).error||message;} catch {}
    throw new Error(message);
  }
  return response;
}
function notice(message,error=false){const el=$('#notice');el.textContent=message;el.classList.toggle('error',error);el.hidden=false;}
function setView(next){
  view=next;
  const titles={overview:['Ağınıza yakından bakın.','Cihazlarınızı keşfedin, erişilebilirliği izleyin ve envanterinizi güncel tutun.','Genel bakış'],inventory:['Cihaz envanteri','Sunucu ve ağ cihazlarınızın tüm bilgileri tek yerde.','Cihaz envanteri'],events:['Ağınızda neler oluyor?','Keşifleri ve erişilebilirlik değişikliklerini takip edin.','Olay geçmişi'],settings:['Ağlarınızı bağlayın.','Keşfedilecek ağları ve düzenli kontrol aralığını belirleyin.','Ağ ayarları']};
  const [title,description,crumb]=titles[next];
  $('#page-title').textContent=title;$('#page-description').textContent=description;$('#breadcrumb').textContent=crumb;
  for(const el of document.querySelectorAll('.nav-item')) el.classList.toggle('active',el.dataset.view===next);
  for(const name of ['overview','events','settings']) $('#'+name+'-view').hidden=next!==name;
  $('#inventory-section').hidden=!['overview','inventory'].includes(next);
}
function activity(events){
  if(!events.length) return '<div class="activity-empty">Henüz bir olay yok.<br>İlk taramadan sonra ağınızdaki değişiklikler burada görünecek.</div>';
  return events.map(e=>`<div class="activity ${esc(e.level)}"><span class="activity-icon">${e.level==='warning'?'!':e.level==='success'?'↗':'＋'}</span><div><div class="activity-message">${esc(e.message)}</div><small class="ip">${esc(e.ip)}</small></div><time>${esc(date(e.created_at))}</time></div>`).join('');
}
function render(){
  const devices=state.devices, total=devices.length, online=devices.filter(d=>d.status==='online').length, unknown=devices.filter(d=>d.status==='unknown').length, issues=total-online-unknown;
  for(const [id,value] of Object.entries({total,online,issues,networks:state.settings.ranges.length,'legend-online':online,'legend-issues':issues,'legend-unknown':unknown,'device-count':total})) $('#'+id).textContent=value;
  $('#health-percent').textContent=total?Math.round(100*online/total)+'%':'—';
  const a=total?100*online/total:0,b=total?100*(online+issues)/total:0;
  // Dynamic style is limited to locally calculated numeric percentages.
  $('#donut').style.background=`conic-gradient(#179e7c 0% ${a}%, #d59730 ${a}% ${b}%, #e7edf1 ${b}% 100%)`;
  $('#interval-label').textContent=(state.settings.interval/60)+' dakikada bir kontrol';
  $('#recent-events').innerHTML=activity(state.events.slice(0,3));$('#all-events').innerHTML=activity(state.events);
  $('#last-scan').textContent=state.scan.finished_at?'Son tarama: '+date(state.scan.finished_at)+(state.scan.error?' · Hata oluştu':' · '+state.scan.done+' adres kontrol edildi'):'Henüz tarama yapılmadı.';
  $('#scan-button').disabled=!!state.scan.running;
  $('#scan-button').textContent=state.scan.running?'Taranıyor…':'⌕ Ağı tara';
  $('#scan-progress').hidden=!state.scan.running;
  $('#scan-label').textContent=`Ağ keşfi sürüyor · ${state.scan.done} / ${state.scan.total} adres kontrol edildi`;
  $('#scan-bar').max=state.scan.total||1;$('#scan-bar').value=state.scan.done||0;
  $('#capability').textContent=state.capabilities?.icmp?'TCP + ICMP etkin':'TCP etkin · ping kurulu değil';
  if(!initialized){
    $('#ranges').value=state.settings.ranges.length?state.settings.ranges.join('\n'):'192.168.10.0/23\n192.168.100.0/23\n192.168.24.0/24\n192.168.25.0/24';
    $('#interval').value=String(state.settings.interval);
    initialized=true;
  }
  renderRows();
}
function renderRows(){
  const search=$('#search').value.toLocaleLowerCase('tr-TR'), status=$('#status-filter').value, kind=$('#kind-filter').value;
  const devices=state.devices.filter(d=>(!status||d.status===status)&&(!kind||d.kind===kind)&&(!search||[d.name,d.ip,d.site,d.owner,d.os,d.model].join(' ').toLocaleLowerCase('tr-TR').includes(search)));
  $('#device-rows').innerHTML=devices.map(d=>`<tr><td><span class="device-icon">${d.kind==='Sunucu'?'▤':d.kind==='Yazıcı'?'▣':'⌘'}</span><div><strong>${esc(d.name||'Adsız cihaz')}</strong><small>${esc(d.site||'Konum belirtilmedi')}</small></div></td><td class="ip">${esc(d.ip)}</td><td><span class="badge ${esc(d.status)}">${esc(statusNames[d.status])}</span></td><td>${esc(d.kind)}<small>${esc(d.os||'İşletim sistemi belirtilmedi')}</small></td><td>${d.latency===null?'—':esc(d.latency)+' ms'}</td><td>${esc(date(d.last_checked))}</td><td><button class="row-edit" data-edit="${d.id}" aria-label="${esc(d.ip)} cihazını düzenle">Düzenle ↗</button></td></tr>`).join('');
  $('#empty').hidden=devices.length>0;
  $('#empty h3').textContent=state.devices.length?'Filtrelere uygun cihaz bulunamadı.':'Ağınızın haritası burada başlıyor.';
  $('#empty p').textContent=state.devices.length?'Aramayı veya filtreleri değiştirebilirsiniz.':'Ağ ayarlarından IP aralığınızı kaydedin ve ilk taramayı başlatın. Cihazları envantere elle de ekleyebilirsiniz.';
  $('#empty button').hidden=state.devices.length>0;
  $('#visible-count').textContent=`${devices.length} / ${state.devices.length} cihaz`;
}
async function refresh(){
  if(polling) return;polling=true;
  try{
    const next=await (await api('/api/state')).json();
    if(next.scan.error && next.scan.error!==state.scan.error) notice(next.scan.error,true);
    state=next;render();$('#connection').textContent='● Bağlı · '+new Date().toLocaleTimeString('tr-TR',{hour:'2-digit',minute:'2-digit'});
  }catch(error){$('#connection').textContent='● Bağlantı yok';notice(error.message,true);}finally{polling=false;}
}
async function editDevice(id=null){
  editing=id;const form=$('#device-form');form.reset();$('#device-error').textContent='';$('#device-details').hidden=id===null;$('#delete-button').hidden=id===null;
  const d=state.devices.find(d=>d.id===id);
  $('#dialog-title').textContent=d?'Cihaz bilgileri':'Cihaz ekle';
  form.elements.ip.readOnly=!!d;
  if(d) for(const el of form.elements) if(el.name) el.value=d[el.name]||'';
  $('#history').textContent='Yükleniyor…';
  $('#device-dialog').showModal();
  if(d){
    $('#port-details').textContent='Son kontrolde açık portlar: '+(d.ports.map(p=>p+' / '+(state.capabilities.ports[p]||'TCP')).join(', ')||'Yok')+' · İlk kayıt: '+date(d.first_seen)+' · Son yanıt: '+date(d.last_seen);
    try{const rows=await (await api(`/api/devices/${id}/history`)).json();if(editing!==id)return;$('#history').innerHTML=rows.length?rows.reverse().map(r=>`<i class="${r.reachable?'':'fail'}" title="${esc(date(r.checked_at))} · ${r.reachable?'Yanıt verdi':'Yanıt yok'}${r.latency===null?'':' · '+esc(r.latency)+' ms'}"></i>`).join(''):'Henüz kontrol yapılmadı.';}catch(e){$('#history').textContent=e.message;}
  }
}
document.addEventListener('click',event=>{
  const nav=event.target.closest('[data-view]');if(nav)setView(nav.dataset.view);
  const close=event.target.closest('[data-close]');if(close)$('#'+close.dataset.close).close();
  const edit=event.target.closest('[data-edit]');if(edit)editDevice(Number(edit.dataset.edit));
});
for(const id of ['search','status-filter','kind-filter']) $('#'+id).addEventListener('input',renderRows);
$('#add-button').addEventListener('click',()=>editDevice());
$('#scan-button').addEventListener('click',async()=>{
  if(!state.settings.ranges.length&&!state.devices.length){setView('settings');notice('İlk tarama için ağ ayarlarını kaydedin.');return;}
  $('#scan-button').disabled=true;
  try{await api('/api/scan',{method:'POST',body:'{}'});notice('Tarama başlatıldı. Sonuçlar geldikçe envanter güncellenecek.');await refresh();}catch(e){notice(e.message,true);$('#scan-button').disabled=false;}
});
$('#settings-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const ranges=$('#ranges').value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
  try{await api('/api/settings',{method:'PUT',body:JSON.stringify({ranges,interval:Number($('#interval').value)})});notice('Ayarlar kaydedildi. Düzenli izleme etkin; ilk taramayı şimdi de başlatabilirsiniz.');await refresh();}catch(e){notice(e.message,true);}
});
$('#device-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const body=JSON.stringify(Object.fromEntries(new FormData(event.target)));
  try{await api(editing===null?'/api/devices':`/api/devices/${editing}`,{method:editing===null?'POST':'PUT',body});$('#device-dialog').close();notice('Envanter kaydı kaydedildi.');await refresh();}catch(e){$('#device-error').textContent=e.message;}
});
$('#delete-button').addEventListener('click',async()=>{
  if(!confirm('Bu cihaz ve kontrol geçmişi silinsin mi? Ağda erişilebilir ise sonraki keşifte yeniden bulunur.'))return;
  try{await api(`/api/devices/${editing}`,{method:'DELETE'});$('#device-dialog').close();await refresh();}catch(e){$('#device-error').textContent=e.message;}
});
$('#export-button').addEventListener('click',async()=>{
  try{const blob=await (await api('/api/export')).blob(), url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='ag-atlas-envanter.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){notice(e.message,true);}
});
$('#access-button').addEventListener('click',()=>$('#access-dialog').showModal());
$('#access-form').addEventListener('submit',async event=>{event.preventDefault();token=$('#access-token').value.trim();sessionStorage.setItem('atlas-token',token);$('#access-token').value='';$('#access-dialog').close();await refresh();});
setView('overview');refresh();setInterval(refresh,4000);
