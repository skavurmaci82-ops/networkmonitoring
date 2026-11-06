'use strict';
const $ = selector => document.querySelector(selector);
const statusNames = {online:'Online',degraded:'Kontrol ediliyor',unreachable:'Offline · yanıt yok',unknown:'Kontrol edilmedi',stale:'Güncel değil'};
let state = {devices:[],events:[],settings:{ranges:[],interval:300},scan:{}}, view='overview', editing=null, initialized=false, polling=false;
let selectedNetwork='';
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
  const devices=state.devices, total=devices.length, online=devices.filter(d=>d.effective_status==='online').length, unknown=devices.filter(d=>['unknown','stale'].includes(d.effective_status)).length, issues=total-online-unknown;
  for(const [id,value] of Object.entries({total,online,issues,networks:state.settings.ranges.length,'device-count':total})) $('#'+id).textContent=value;
  $('#interval-label').textContent=(state.settings.interval/60)+' dakikada bir kontrol';
  $('#all-events').innerHTML=activity(state.events);
  $('#scan-button').disabled=!!state.scan.running;
  $('#scan-button').textContent=state.scan.running?'Taranıyor…':'⌕ Ağı tara';
  $('#scan-progress').hidden=!state.scan.running;
  $('#scan-label').textContent=`Ağ keşfi sürüyor · ${state.scan.done} / ${state.scan.total} adres kontrol edildi`;
  $('#scan-bar').max=state.scan.total||1;$('#scan-bar').value=state.scan.done||0;
  $('#capability').textContent=(state.capabilities?.icmp?'TCP + ICMP':'TCP')+(state.settings.snmp_enabled?' + SNMP':'');
  $('#snmp-config-status').textContent=state.settings.snmp_configured?'Community kayıtlı. Değiştirmek istemiyorsanız alanı boş bırakın.':'Henüz community kaydedilmedi.';
  if(!initialized){
    $('#ranges').value=state.settings.ranges.length?state.settings.ranges.join('\n'):'192.168.10.0/23\n192.168.100.0/23\n192.168.24.0/24\n192.168.25.0/24';
    $('#interval').value=String(state.settings.interval);
    $('#snmp-enabled').checked=state.settings.snmp_enabled;
    $('#snmp-version').value=state.settings.snmp_version;
    initialized=true;
  }
  if(selectedNetwork && !(state.groups||[]).some(g=>g.network===selectedNetwork)) selectedNetwork='';
  renderGroups();
  renderRows();
}
function renderGroups(){
  const groups=state.groups||[];
  $('#network-groups').innerHTML=groups.length?groups.map(g=>`<button class="network-card ${selectedNetwork===g.network?'selected':''}" data-network="${esc(g.network)}" aria-pressed="${selectedNetwork===g.network}"><strong class="ip">${esc(g.network)}</strong><span>${g.total} cihaz</span><div><small class="online">${g.online} Online</small><small class="offline">${g.unreachable} Offline</small><small>${g.degraded} kontrol · ${g.unknown+g.stale} bekleyen</small></div></button>`).join(''):'<p class="help">Ağ ayarlarını kaydettiğinizde her ağ burada ayrı bir grup olarak görünür.</p>';
}
function accessButtons(d){
  const protocols=[['ssh',22,'SSH'],['rdp',3389,'RDP'],['vnc',d.ports.find(p=>[5900,5901,5902].includes(p)),'VNC']];
  if(d.effective_status!=='online') return '<span class="muted">—</span>';
  return protocols.filter(([,port])=>port&&d.ports.includes(port)).map(([protocol,,label])=>`<button class="access-button" data-connect="${protocol}" data-device="${d.id}" title="${label} bağlantı dosyasını indir">${label}</button>`).join('')||'<span class="muted">—</span>';
}
function renderRows(){
  const search=$('#search').value.toLocaleLowerCase('tr-TR'), status=$('#status-filter').value, kind=$('#kind-filter').value;
  const devices=state.devices.filter(d=>(!selectedNetwork||d.network===selectedNetwork)&&(!status||d.effective_status===status)&&(!kind||d.kind===kind)&&(!search||[d.display_name,d.ip,d.site,d.owner,d.os,d.display_model,d.manufacturer].join(' ').toLocaleLowerCase('tr-TR').includes(search)));
  const groups=[...new Set(devices.map(d=>d.network))];
  $('#device-rows').innerHTML=groups.map(group=>`<tr class="network-row"><td colspan="8"><strong class="ip">${esc(group)}</strong><span>${devices.filter(d=>d.network===group).length} cihaz</span></td></tr>`+devices.filter(d=>d.network===group).map(d=>`<tr class="device-row"><td><span class="device-icon">${d.kind==='Sunucu'?'▤':d.kind==='Yazıcı'?'▣':'⌘'}</span><div><strong>${esc(d.display_name)}</strong><small>${esc(d.kind)}${d.site?' · '+esc(d.site):''}</small></div></td><td class="ip">${esc(d.ip)}</td><td><strong>${esc(d.display_model||'Tespit edilemedi')}</strong><small>${esc(d.display_model?d.display_model_source:snmpStatus(d.snmp_status))}</small></td><td><span class="badge ${esc(d.effective_status)}">${esc(statusNames[d.effective_status])}</span></td><td>${d.latency===null?'—':esc(d.latency)+' ms'}</td><td>${esc(date(d.last_checked))}</td><td class="access-buttons">${accessButtons(d)}</td><td><button class="row-edit" data-edit="${d.id}" aria-label="${esc(d.ip)} cihazını düzenle">Bilgiler ↗</button></td></tr>`).join('')).join('');
  $('#empty').hidden=devices.length>0;
  $('#empty h3').textContent=state.devices.length?'Filtrelere uygun cihaz bulunamadı.':'Ağınızın haritası burada başlıyor.';
  $('#empty p').textContent=state.devices.length?'Aramayı veya filtreleri değiştirebilirsiniz.':'Ağ ayarlarından IP aralığınızı kaydedin ve ilk taramayı başlatın. Cihazları envantere elle de ekleyebilirsiniz.';
  $('#empty button').hidden=state.devices.length>0;
  $('#visible-count').textContent=`${devices.length} / ${state.devices.length} cihaz`;
}
function snmpStatus(status){return {ok:'SNMP yanıtı var; model sunulmadı',no_response:'SNMP yanıtı yok',not_configured:'SNMP ayarlanmamış'}[status]||'SNMP bilgisi yok';}
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
    $('#identity-details').innerHTML=`<h3>Otomatik cihaz bilgileri</h3><dl><dt>Model</dt><dd>${esc(d.detected_model||'Tespit edilemedi')}</dd><dt>Kaynak</dt><dd>${esc(d.model_source||snmpStatus(d.snmp_status))}</dd><dt>Üretici / Seri</dt><dd>${esc(d.manufacturer||'—')} / ${esc(d.display_serial||'—')}</dd><dt>SNMP agent süresi</dt><dd>${d.agent_uptime===null?'—':Math.floor(d.agent_uptime/86400)+' gün '+Math.floor(d.agent_uptime%86400/3600)+' saat'}</dd><dt>Son SNMP yanıtı</dt><dd>${esc(date(d.snmp_checked_at))}</dd><dt>SNMP durumu</dt><dd>${esc(d.snmp_status==='ok'?'Yanıt verdi':snmpStatus(d.snmp_status))}</dd></dl><p>${esc(d.sys_description||'Cihaz açıklaması alınamadı.')}</p><p class="help">Sağlık göstergesi erişilebilirliği ifade eder; CPU, disk veya sıcaklık ölçümü değildir.</p>`;
    $('#port-details').textContent='Son kontrolde açık portlar: '+(d.ports.map(p=>p+' / '+(state.capabilities.ports[p]||'TCP')).join(', ')||'Yok')+' · İlk kayıt: '+date(d.first_seen)+' · Son yanıt: '+date(d.last_seen);
    try{const rows=await (await api(`/api/devices/${id}/history`)).json();if(editing!==id)return;$('#history').innerHTML=rows.length?rows.reverse().map(r=>`<i class="${r.reachable?'':'fail'}" title="${esc(date(r.checked_at))} · ${r.reachable?'Yanıt verdi':'Yanıt yok'}${r.latency===null?'':' · '+esc(r.latency)+' ms'}"></i>`).join(''):'Henüz kontrol yapılmadı.';}catch(e){$('#history').textContent=e.message;}
  }
}
document.addEventListener('click',event=>{
  const nav=event.target.closest('[data-view]');if(nav)setView(nav.dataset.view);
  const close=event.target.closest('[data-close]');if(close)$('#'+close.dataset.close).close();
  const edit=event.target.closest('[data-edit]');if(edit)editDevice(Number(edit.dataset.edit));
  const group=event.target.closest('[data-network]');if(group){selectedNetwork=selectedNetwork===group.dataset.network?'':group.dataset.network;renderGroups();renderRows();}
  const connect=event.target.closest('[data-connect]');if(connect)connectDevice(Number(connect.dataset.device),connect.dataset.connect);
});
$('#all-networks').addEventListener('click',()=>{selectedNetwork='';renderGroups();renderRows();});
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
  try{await api('/api/settings',{method:'PUT',body:JSON.stringify({ranges,interval:Number($('#interval').value),snmp_enabled:$('#snmp-enabled').checked,snmp_version:$('#snmp-version').value,snmp_community:$('#snmp-community').value})});$('#snmp-community').value='';notice('Ayarlar kaydedildi. Model bilgilerini almak için Ağı tara düğmesine basın.');await refresh();}catch(e){notice(e.message,true);}
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
async function connectDevice(id,protocol){
  const d=state.devices.find(d=>d.id===id);if(!d)return;
  try{
    const response=await api(`/api/devices/${id}/connect/${protocol}`), blob=await response.blob();
    const filename=response.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1]||'baglanti';
    const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    const port=d.ports.find(p=>[5900,5901,5902].includes(p));
    $('#connection-help').hidden=false;$('#connection-title').textContent=protocol.toUpperCase()+' · '+d.ip;
    $('#connection-description').textContent={rdp:'İndirilen .rdp dosyasını açın. Windows Uzak Masaüstü kullanıcı adı ve parolanızı soracak.',ssh:'İndirilen .cmd dosyasını inceleyip açın veya aşağıdaki komutu Terminal’e yapıştırın. Windows OpenSSH istemcisi gerekir. SSH kullanıcı adını cihaz bilgilerinden düzenleyebilirsiniz.',vnc:'İndirilen .vnc dosyasını TightVNC uyumlu istemciyle açın veya aşağıdaki adresi VNC istemcinize girin. Bilgisayarınızda VNC istemcisi bulunmalıdır.'}[protocol];
    $('#connection-command').textContent=protocol==='ssh'?`ssh ${d.ssh_user?'-l "'+d.ssh_user+'" ':''}${d.ip}`:protocol==='rdp'?`mstsc /v:${d.ip}`:`${d.ip}::${port}`;
    notice(protocol.toUpperCase()+' bağlantı dosyası indirildi. Dosyayı bilgisayarınızda açın.');
  }catch(e){notice(e.message,true);}
}
$('#copy-connection').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('#connection-command').textContent);notice('Bağlantı komutu kopyalandı.');}catch{notice('Otomatik kopyalanamadı. Bağlantı komutunu seçerek kopyalayın.',true);}});
$('#access-button').addEventListener('click',()=>$('#access-dialog').showModal());
$('#access-form').addEventListener('submit',async event=>{event.preventDefault();token=$('#access-token').value.trim();sessionStorage.setItem('atlas-token',token);$('#access-token').value='';$('#access-dialog').close();await refresh();});
setView('overview');refresh();setInterval(refresh,4000);
