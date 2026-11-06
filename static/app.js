'use strict';
const $ = selector => document.querySelector(selector);
const statusNames = {online:'Online',degraded:'Kontrol ediliyor',unreachable:'Offline · yanıt yok',unknown:'Kontrol edilmedi',stale:'Güncel değil',observed:'Tabloda görüldü'};
let state = {devices:[],events:[],settings:{ranges:[],interval:300},scan:{}}, view='overview', editing=null, initialized=false, polling=false;
let selectedNetwork='';
let sessionTarget=null;
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
  const titles={overview:['Ağınıza yakından bakın.','Cihaz keşfi, envanter ve uzaktan yönetim.','Genel bakış'],inventory:['Cihaz envanteri','IP, MAC, marka, model ve erişim bilgileri.','Cihaz envanteri'],topology:['Ağ topolojisi','LLDP ile okunan gerçek cihaz ve port bağlantıları.','Ağ topolojisi'],events:['Ağınızda neler oluyor?','Keşifleri ve erişilebilirlik değişikliklerini takip edin.','Olay geçmişi'],settings:['Ağlarınızı bağlayın.','Keşfedilecek ağları ve düzenli kontrol aralığını belirleyin.','Ağ ayarları']};
  const [title,description,crumb]=titles[next];
  $('#page-title').textContent=title;$('#page-description').textContent=description;$('#breadcrumb').textContent=crumb;
  for(const el of document.querySelectorAll('.nav-item')) el.classList.toggle('active',el.dataset.view===next);
  for(const name of ['overview','events','settings','topology']) $('#'+name+'-view').hidden=next!==name;
  $('#inventory-section').hidden=!['overview','inventory'].includes(next);
  if(next==='topology')renderTopology();
}
function activity(events){
  if(!events.length) return '<div class="activity-empty">Henüz bir olay yok.<br>İlk taramadan sonra ağınızdaki değişiklikler burada görünecek.</div>';
  return events.map(e=>`<div class="activity ${esc(e.level)}"><span class="activity-icon">${e.level==='warning'?'!':e.level==='success'?'↗':'＋'}</span><div><div class="activity-message">${esc(e.message)}</div><small class="ip">${esc(e.ip)}</small></div><time>${esc(date(e.created_at))}</time></div>`).join('');
}
function render(){
  const devices=state.devices, total=devices.length, online=devices.filter(d=>d.effective_status==='online').length, unknown=devices.filter(d=>['unknown','stale','observed'].includes(d.effective_status)).length, issues=total-online-unknown;
  for(const [id,value] of Object.entries({total,online,issues,networks:state.settings.ranges.length,'device-count':total})) $('#'+id).textContent=value;
  $('#interval-label').textContent=(state.settings.interval/60)+' dakikada bir kontrol';
  $('#all-events').innerHTML=activity(state.events);
  $('#scan-button').disabled=!!state.scan.running;
  $('#scan-button').textContent=state.scan.running?'Taranıyor…':'⌕ Ağı tara';
  $('#scan-progress').hidden=!state.scan.running;
  $('#scan-label').textContent=`Ağ keşfi sürüyor · ${state.scan.done} / ${state.scan.total} adres kontrol edildi`;
  $('#scan-bar').max=state.scan.total||1;$('#scan-bar').value=state.scan.done||0;
  $('#capability').textContent=(state.capabilities?.icmp?'TCP + ICMP':'TCP')+(state.settings.snmp_enabled?' + SNMP':'');
  $('#gateway-state').textContent=state.capabilities?.browser_access?'Guacamole yapılandırması hazır. Docker servislerinin çalışıyor olması gerekir.':'Tarayıcı erişimi henüz kurulmamış. TARAYICI_ERISIM_KUR.cmd dosyasını çalıştırın.';
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
  if(view==='topology')renderTopology();
}
function renderGroups(){
  const groups=state.groups||[];
  $('#network-groups').innerHTML=groups.length?groups.map(g=>`<button class="network-card ${selectedNetwork===g.network?'selected':''}" data-network="${esc(g.network)}" aria-pressed="${selectedNetwork===g.network}"><strong class="ip">${esc(g.network)}</strong><span>${g.total} cihaz</span><div><small class="online">${g.online} Online</small><small class="offline">${g.unreachable} Offline</small><small>${g.degraded} kontrol · ${g.unknown+g.stale+(g.observed||0)} bekleyen</small></div></button>`).join(''):'<p class="help">Ağ ayarlarını kaydettiğinizde her ağ burada ayrı bir grup olarak görünür.</p>';
}
function accessButtons(d){
  const protocols=[['ssh',22,'SSH'],['rdp',3389,'RDP'],['vnc',d.ports.find(p=>[5900,5901,5902].includes(p)),'VNC']];
  if(d.effective_status!=='online') return '<span class="muted">—</span>';
  return protocols.filter(([,port])=>port&&d.ports.includes(port)).map(([protocol,,label])=>`<button class="access-button" data-connect="${protocol}" data-device="${d.id}" title="Tarayıcı içinde ${label}">${label}</button>`).join('')||'<span class="muted">—</span>';
}
function renderRows(){
  const search=$('#search').value.toLocaleLowerCase('tr-TR'), status=$('#status-filter').value, kind=$('#kind-filter').value;
  const devices=state.devices.filter(d=>(!selectedNetwork||d.network===selectedNetwork)&&(!status||d.effective_status===status)&&(!kind||d.kind===kind)&&(!search||[d.display_name,d.ip,d.site,d.owner,d.os,d.display_model,d.manufacturer,d.mac_vendor,...(d.mac_addresses||[])].join(' ').toLocaleLowerCase('tr-TR').includes(search)));
  const groups=[...new Set(devices.map(d=>d.network))];
  $('#device-rows').innerHTML=groups.map(group=>`<tr class="network-row"><td colspan="8"><strong class="ip">${esc(group)}</strong><span>${devices.filter(d=>d.network===group).length} cihaz</span></td></tr>`+devices.filter(d=>d.network===group).map(d=>`<tr class="device-row"><td><span class="device-icon">${d.kind==='Sunucu'?'▤':d.kind==='Yazıcı'?'▣':'⌘'}</span><div><strong>${esc(d.display_name)}</strong><small>${esc(d.kind)}${d.site?' · '+esc(d.site):''}</small></div></td><td class="ip">${esc(d.ip)}</td><td class="mac-cell"><strong class="ip">${esc((d.mac_addresses||[]).join(', ')||'Okunamadı')}</strong><small title="${esc(d.mac_note||'')}">${esc((d.mac_addresses||[]).length?d.mac_source:d.mac_status==='routed'?'Uzak ağ / VLAN':'ARP yanıtı yok')}</small></td><td><strong>${esc(d.manufacturer||(d.mac_vendor?'MAC kayıt sahibi: '+d.mac_vendor:'Marka bilinmiyor'))} · ${esc(d.display_model||'Model bilinmiyor')}</strong><small>${esc(d.mac_source||d.display_model_source||snmpStatus(d.snmp_status))}</small></td><td><span class="badge ${esc(d.effective_status)}">${esc(statusNames[d.effective_status])}</span></td><td>${esc(date(d.last_checked))}</td><td class="access-buttons">${accessButtons(d)}</td><td><button class="row-edit" data-edit="${d.id}" aria-label="${esc(d.ip)} cihazını düzenle">Bilgiler ↗</button></td></tr>`).join('')).join('');
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
    $('#identity-details').innerHTML=`<h3>Otomatik cihaz bilgileri</h3><dl><dt>Model</dt><dd>${esc(d.detected_model||'Tespit edilemedi')}</dd><dt>Kaynak</dt><dd>${esc(d.model_source||snmpStatus(d.snmp_status))}</dd><dt>Üretici / Seri</dt><dd>${esc(d.manufacturer||'—')} / ${esc(d.display_serial||'—')}</dd><dt>SNMP agent süresi</dt><dd>${d.agent_uptime===null?'—':Math.floor(d.agent_uptime/86400)+' gün '+Math.floor(d.agent_uptime%86400/3600)+' saat'}</dd><dt>Son SNMP yanıtı</dt><dd>${esc(date(d.snmp_checked_at))}</dd><dt>MAC adresi</dt><dd>${esc((d.mac_addresses||[]).join(', ')||d.mac_note||'Okunamadı')}</dd><dt>MAC kaynağı / zaman</dt><dd>${esc(d.mac_source||'—')} · ${esc(date(d.mac_checked_at))}</dd><dt>SNMP durumu</dt><dd>${esc(d.snmp_status==='ok'?'Yanıt verdi':snmpStatus(d.snmp_status))}</dd></dl><p>${esc(d.sys_description||'Cihaz açıklaması alınamadı.')}</p><p class="help">Sağlık göstergesi erişilebilirliği ifade eder; CPU, disk veya sıcaklık ölçümü değildir.</p>`;
    $('#network-details').innerHTML=`<h3>Arayüzler · ${esc(d.interfaces?.length||0)}</h3><div class="table-scroll"><table><thead><tr><th>ARAYÜZ</th><th>MAC</th><th>PORT DURUMU</th></tr></thead><tbody>${(d.interfaces||[]).map(i=>`<tr><td>${esc(i.name)}</td><td class="ip">${esc(i.mac||'—')}</td><td>${i.oper_status===1?'Up':i.oper_status===2?'Down':'Bilinmiyor'}</td></tr>`).join('')}</tbody></table></div><p class="help">LLDP: ${esc(d.lldp_status==='read'?'Okundu':d.lldp_status==='partial'?'Kısmi veri':'Okunamadı')} · Son okuma: ${esc(date(d.network_checked_at))}. Arayüz MAC’leri yönetim IP’sinin MAC’i ile aynı olmayabilir.</p>`;
    $('#port-details').textContent='Son kontrolde açık portlar: '+(d.ports.map(p=>p+' / '+(state.capabilities.ports[p]||'TCP')).join(', ')||'Yok')+' · İlk kayıt: '+date(d.first_seen)+' · Son yanıt: '+date(d.last_seen);
    try{const rows=await (await api(`/api/devices/${id}/history`)).json();if(editing!==id)return;$('#history').innerHTML=rows.length?rows.reverse().map(r=>`<i class="${r.reachable?'':'fail'}" title="${esc(date(r.checked_at))} · ${r.reachable?'Yanıt verdi':'Yanıt yok'}${r.latency===null?'':' · '+esc(r.latency)+' ms'}"></i>`).join(''):'Henüz kontrol yapılmadı.';}catch(e){$('#history').textContent=e.message;}
  }
}
document.addEventListener('click',event=>{
  const nav=event.target.closest('[data-view]');if(nav)setView(nav.dataset.view);
  const close=event.target.closest('[data-close]');if(close)$('#'+close.dataset.close).close();
  const edit=event.target.closest('[data-edit]');if(edit)editDevice(Number(edit.dataset.edit));
  const group=event.target.closest('[data-network]');if(group){selectedNetwork=selectedNetwork===group.dataset.network?'':group.dataset.network;renderGroups();renderRows();}
  const connect=event.target.closest('[data-connect]');if(connect)openSession(Number(connect.dataset.device),connect.dataset.connect);
});
$('#all-networks').addEventListener('click',()=>{selectedNetwork='';renderGroups();renderRows();});
for(const id of ['search','status-filter','kind-filter']) $('#'+id).addEventListener('input',renderRows);
$('#add-button').addEventListener('click',()=>editDevice());
$('#scan-button').addEventListener('click',async()=>{
  if(!state.settings.ranges.length&&!state.devices.length){await quickDiscover();return;}
  $('#scan-button').disabled=true;
  try{await api('/api/scan',{method:'POST',body:'{}'});notice('Tarama başlatıldı. Sonuçlar geldikçe envanter güncellenecek.');await refresh();}catch(e){notice(e.message,true);$('#scan-button').disabled=false;}
});
async function discoverySettings(){
  const ranges=$('#ranges').value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean),community=$('#snmp-community').value;
  const useSnmp=$('#snmp-enabled').checked&&!!(community||state.settings.snmp_configured);
  const response=await api('/api/settings',{method:'PUT',body:JSON.stringify({ranges,interval:Number($('#interval').value),snmp_enabled:useSnmp,snmp_version:$('#snmp-version').value,snmp_community:community})});
  $('#snmp-community').value='';$('#snmp-enabled').checked=useSnmp;
  return response;
}
async function quickDiscover(){
  $('#quick-discover').disabled=true;$('#scan-button').disabled=true;
  try{await discoverySettings();await api('/api/scan',{method:'POST',body:'{}'});state.scan.running=true;setView('overview');notice('Otomatik keşif başlatıldı. Yerel MAC ve açık SSH/RDP/VNC portları sonuçlara eklenecek. SNMP zorunlu değildir.');await refresh();}
  catch(e){notice(e.message,true);}finally{$('#quick-discover').disabled=false;$('#scan-button').disabled=!!state.scan.running;}
}
$('#quick-discover').addEventListener('click',quickDiscover);
$('#settings-form').addEventListener('submit',async event=>{
  event.preventDefault();
  try{await discoverySettings();notice('Ayarlar kaydedildi. Keşif için Ağı tara düğmesine basın; SNMP bilgisi zorunlu değildir.');await refresh();}catch(e){notice(e.message,true);}
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

function openSession(id,protocol){
  const device=state.devices.find(d=>d.id===id);if(!device)return;

  sessionTarget={id,protocol};$('#session-form').reset();$('#session-error').textContent='';
  $('#session-start').disabled=!state.capabilities?.browser_access;
  $('#session-title').textContent=protocol.toUpperCase()+' · '+device.display_name;
  $('#session-hint').textContent=device.ip+' adresine bağlanın. '+(state.capabilities?.browser_access?'Tarayıcı erişimi hazır; hedef cihazın hesabını kullanın.':'Tarayıcı erişimi için Docker/Guacamole kurulumu gerekir. Şimdilik bilgisayarınızdaki istemciyle bağlantı seçeneğini kullanabilirsiniz.');
  $('#session-username').value=protocol==='ssh'?device.ssh_user||'':'';
  $('#session-domain-label').hidden=protocol!=='rdp';$('#session-dialog').showModal();
}
$('#session-form').addEventListener('submit',async event=>{
  event.preventDefault();if(!sessionTarget)return;
  const target={...sessionTarget},popup=window.open('about:blank','_blank');
  if(!popup){$('#session-error').textContent='Tarayıcı yeni sekmeyi engelledi. Bu site için açılır pencerelere izin verin.';return;}
  popup.opener=null;
  $('#session-start').disabled=true;
  try{
    const response=await api(`/api/devices/${target.id}/session`,{method:'POST',body:JSON.stringify({protocol:target.protocol,username:$('#session-username').value,password:$('#session-password').value,domain:$('#session-domain').value})});
    const result=await response.json();popup.location.replace(result.url);$('#session-dialog').close();notice('Uzak oturum yeni tarayıcı sekmesinde açıldı.');
  }catch(error){popup.close();$('#session-error').textContent=error.message;}
  finally{$('#session-password').value='';$('#session-start').disabled=false;}
});
$('#session-dialog').addEventListener('close',()=>{$('#session-password').value='';$('#session-username').value='';$('#session-domain').value='';sessionTarget=null;});
$('#session-download').addEventListener('click',async()=>{
  if(!sessionTarget)return;
  const {id,protocol}=sessionTarget;
  try{const response=await api(`/api/devices/${id}/connect/${protocol}`),blob=await response.blob();
    const filename=response.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1]||'baglanti';
    const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    notice(protocol.toUpperCase()+' bağlantı dosyası indirildi. Dosyayı açın; SSH için Windows OpenSSH, VNC için uyumlu VNC istemcisi gerekir.');
  }catch(e){$('#session-error').textContent=e.message;}
});

function renderTopology(){
  const graph=state.topology||{nodes:[],edges:[],unlinked:0},filter=$('#topology-filter').value,query=$('#topology-search').value.toLocaleLowerCase('tr-TR');
  const graphEdges=[...graph.edges,...($('#topology-learned').checked?graph.learned_edges||[]:[])];
  const linked=new Set(graphEdges.flatMap(e=>[e.source,e.target]));
  const allNodes=graph.nodes.filter(n=>filter==='all'||(filter==='linked'?linked.has(n.id):n.status!=='online'));
  const nodes=allNodes.slice(0,200),ids=new Set(nodes.map(n=>n.id));
  const edges=graphEdges.filter(e=>ids.has(e.source)&&ids.has(e.target)).slice(0,500);
  const degree=id=>edges.filter(e=>e.source===id||e.target===id).length;
  nodes.sort((a,b)=>degree(b.id)-degree(a.id)||a.label.localeCompare(b.label,'tr'));
  const width=1100,height=Math.max(320,Math.ceil(nodes.length/4)*130+70),positions=new Map(nodes.map((n,i)=>[n.id,{x:25+(i%4)*270,y:70+Math.floor(i/4)*130}]));
  const colors={online:'#159879',unreachable:'#cc655b',degraded:'#cc992b',unknown:'#9baab6',stale:'#8e8ba8',observed:'#8b9ca9'};
  let body=edges.map((e,i)=>{
    const a=positions.get(e.source),b=positions.get(e.target),sameRow=a.y===b.y,x1=a.x+118,x2=b.x+118,y1=sameRow?a.y:a.y+(b.y>a.y?78:0),y2=sameRow?b.y:b.y+(a.y>b.y?78:0),curveY=sameRow?a.y-60-(i%3)*12:(y1+y2)/2,labelY=sameRow?a.y-33-(i%3)*6:(y1+y2)/2-8;
    return `<g class="topology-edge ${e.evidence.startsWith('BRIDGE')?'learned':''} ${e.stale?'stale':''}"><title>${esc(e.evidence+' · '+e.source_port+' → '+e.target_port+' · '+date(e.observed_at))}</title><path d="M ${x1} ${y1} Q ${(x1+x2)/2} ${curveY} ${x2} ${y2}"/><text x="${(x1+x2)/2}" y="${labelY}">${esc((e.source_port||'?')+' ↔ '+(e.target_port||'?'))}</text></g>`;
  }).join('');
  body+=nodes.map(n=>{
    const pos=positions.get(n.id),match=!query||[n.label,n.ip,n.model].join(' ').toLocaleLowerCase('tr-TR').includes(query);
    return `<g class="topology-node ${match?'':'dimmed'}" transform="translate(${pos.x} ${pos.y})" ${n.device_id?'data-edit="'+n.device_id+'" role="button" tabindex="0"':''}><title>${esc(n.label+' · '+n.ip+' · '+(statusNames[n.status]||n.status))}</title><rect width="236" height="78" rx="9"/><circle cx="16" cy="20" r="4" fill="${colors[n.status]||colors.unknown}"/><text x="28" y="24" class="node-title">${esc(n.label.slice(0,27))}</text><text x="14" y="45">${esc(n.ip||'IP doğrulanmadı')}</text><text x="14" y="63">${esc((n.model||n.network).slice(0,34))}</text></g>`;
  }).join('');
  $('#topology-canvas').innerHTML=nodes.length?`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="LLDP cihaz bağlantıları">${body}</svg>`:'';
  $('#topology-empty').hidden=graph.edges.length>0;
  $('#topology-summary').textContent=`${graph.nodes.length} düğüm · ${graph.edges.length} LLDP gözlemi · ${(graph.learned_edges||[]).length} MAC öğrenimi · ${graph.unlinked} bağlantısı bilinmeyen. ${allNodes.length>200?'Haritada ilk 200 düğüm gösteriliyor. ':''}Yerleşim otomatik; çizgiler yalnızca LLDP kanıtına dayanır.`;
  const byId=new Map(graph.nodes.map(n=>[n.id,n]));
  $('#topology-edges').innerHTML=graphEdges.slice(0,200).map(e=>`<tr><td>${esc(byId.get(e.source)?.label||e.source)}</td><td>${esc(e.source_port||'—')}</td><td>${esc(byId.get(e.target)?.label||e.target)}</td><td>${esc(e.target_port||'—')}</td><td>${e.evidence.startsWith('BRIDGE')?'MAC öğrenimi · kablo kanıtı değil':e.stale?'Eski / kısmi LLDP':'LLDP'}<small>${esc(date(e.observed_at))}</small></td></tr>`).join('');
}
$('#topology-search').addEventListener('input',renderTopology);$('#topology-filter').addEventListener('change',renderTopology);$('#topology-learned').addEventListener('change',renderTopology);
function downloadText(text,name,type){const url=URL.createObjectURL(new Blob([text],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('#topology-json').addEventListener('click',()=>downloadText(JSON.stringify(state.topology,null,2),'agatlas-topoloji.json','application/json'));
$('#topology-svg').addEventListener('click',()=>{const svg=$('#topology-canvas svg');if(!svg){notice('Önce cihaz keşfi yapın.',true);return;}const clone=svg.cloneNode(true),style=document.createElementNS('http://www.w3.org/2000/svg','style');style.textContent='.topology-node rect{fill:#fff;stroke:#b9ced3}.topology-node text{font:11px sans-serif;fill:#52717d}.topology-node .node-title{font-weight:bold;fill:#193c48}.topology-edge path{fill:none;stroke:#8eaaa9;stroke-width:2}.topology-edge text{font:9px sans-serif;fill:#607c86}.topology-edge.stale path{stroke-dasharray:5 4}.dimmed{opacity:.25}';clone.prepend(style);downloadText(new XMLSerializer().serializeToString(clone),'agatlas-topoloji.svg','image/svg+xml');});
document.addEventListener('keydown',event=>{if(event.key==='Enter'&&event.target.matches('.topology-node[data-edit]'))editDevice(Number(event.target.dataset.edit));});

$('#vendors-update').addEventListener('click',async()=>{const button=$('#vendors-update');button.disabled=true;notice('IEEE üretici listesi indiriliyor…');try{const data=await(await api('/api/vendors/update',{method:'POST',body:'{}'})).json();notice(data.prefixes+' üretici kaydı alındı.');await refresh();}catch(e){notice(e.message,true);}finally{button.disabled=false;}});
