# AğAtlas

Türkçe web arayüzlü, özel IPv4 ağları için cihaz keşfi, erişilebilirlik izleme ve sunucu envanter uygulaması. Python 3.10+ ve SQLite ile çalışır; harici Python paketi, veritabanı sunucusu veya internet bağlantısı gerekmez.

## Çalıştırma

Depo dizininde:

```sh
python app.py
```

Windows'ta `py app.py` da kullanılabilir. Tarayıcıda `http://127.0.0.1:8080` adresini açın. Ağ ayarlarında aralıkları kontrol edip **Ayarları kaydet**, ardından **Ağı tara** düğmesine basın. Varsayılan veritabanı `data/atlas.sqlite3` dosyasıdır. Çıkış için Ctrl+C kullanın. Yeniden başlatıldığında envanter ve ayarlar korunur; izleme tekrar başlar.

Windows'ta komut yazmadan başlatmak için ZIP dosyasını tamamen çıkardıktan sonra **BASLAT.cmd** dosyasına çift tıklayabilirsiniz. Bu yardımcı dosya Python 3.10+ arar, uygulamayı doğru klasörden başlatır ve hata durumunda terminali açık tutar. Python bulunamazsa kurulum adresini gösterir. Yardımcı dosyanın Windows üzerinde çalışması bu bulut ortamında doğrulanmadı.

Uygulama ilk açılışta kayıtlı ağ içermez ve tarama başlatmaz. Ayarlar formunda bu kurulum için şu ağlar hazır gelir:

| Girilen adres | Kaydedilecek ağ | Kullanılabilir adres |
| --- | --- | --- |
| `192.168.10.0/23` | `192.168.10.0/23` | `192.168.10.1–192.168.11.254` |
| `192.168.100.5/23` | `192.168.100.0/23` | `192.168.100.1–192.168.101.254` |
| `192.168.24.1/24` | `192.168.24.0/24` | `192.168.24.1–192.168.24.254` |
| `192168.25.0/24` (yazım düzeltildi) | `192.168.25.0/24` | `192.168.25.1–192.168.25.254` |

Toplam **1528** kullanılabilir adres. Ağ başına en fazla 1024 adres, en fazla 8 ağ desteklenir. Ağlar kaydedilirken adresler CIDR ağ sınırına dönüştürülür ve yinelenen hedefler tek kez kontrol edilir. Ağ listesi boşken envanterdeki tekil IP adresleri izlenmeye devam eder.

## Ağ erişimi ve cihaz desteği

İzleme motorunu bu dört ağa yönlendirme/VPN erişimi olan bir Linux, Windows veya macOS bilgisayarda çalıştırın. Bir bulut makinesinden şirket içi ağlar, gerekli ağ bağlantısı sağlanmadan izlenemez. Güvenlik duvarlarında izleme bilgisayarından gereken ICMP/TCP ve SNMP UDP 161 trafiğine izin verilmelidir. Yönetiminizdeki ağları tarayın.

| Cihaz | Erişilebilirlik kontrolü |
| --- | --- |
| Linux | SSH (22), web portları, varsa ICMP |
| Windows | SMB (445), RDP (3389), web portları, varsa ICMP |
| VMware | TCP 902, HTTPS (443), varsa ICMP |
| Aruba switch / ağ ürünleri | SSH, HTTP/HTTPS, varsa ICMP |
| Yazıcı | TCP 9100, IPP (631), LPD (515), web, varsa ICMP |

Tüm cihazlarda TCP 22, 80, 443, 445, 3389, 5900, 5901, 5902, 902, 8006, 9100, 631, 515, 8080 kontrol edilir. Bağlantı kurulması servisin uygulama düzeyinde sağlıklı olduğunu göstermez. Tarama sırasında cihazlara SSH/RDP/VNC oturumu açılmaz. SNMP etkinleştirildiğinde UDP 161 üzerinden salt okunur sorgular gönderilir.

`ping` sistemde varsa ICMP de kullanılır. Linux'ta `command -v ping` ile kontrol edin; Debian/Ubuntu için gerekirse `sudo apt-get install iputils-ping` kurun. Ping kurulu veya çalışabilir değilse açık TCP portları veya yapılandırılmış SNMP yanıtı ile keşif yapılır. ICMP engelliyse, TCP portları kapalıysa ve SNMP yanıtı yoksa cihaz keşfedilemeyebilir. Web panelinde TCP/ICMP yeteneği gösterilir; ICMP'nin hedefte engellenip engellenmediği ayrıca değerlendirilmelidir.

32 paralel çalışan kullanılır. Yanıt vermeyen cihaz sayısına bağlı olarak dört ağın taranması birkaç dakika sürebilir. Yeni tarama önceki bitmeden başlamaz; kontrol aralığı tarama tamamlandıktan sonra sayılır. Tarama çalışırken panel kullanılabilir.

## Envanter ve durumlar

- IP, ad, tür, işletim sistemi, CPU, RAM, model, seri numarası, konum, sorumlu ve notlar.
- Tür açık portlara göre **tahmin edilir**; SSH kullanan bir switch sunucu olarak tahmin edilebilir. Elle düzeltin. Model, üretici, seri numarası ve cihaz adı SNMP ile cihaz sunduğunda okunur; model/seri/ad elle değiştirilebilir. İşletim sistemi, CPU ve RAM alanları elle doldurulur.
- Online: son kontrolde ICMP, TCP veya SNMP yanıtı var. Kontrol ediliyor: 1–2 başarısız kontrol. Offline · yanıt yok: en az 3 ardışık başarısız kontrol. Kontrol edilmedi: elle eklenmiş, kontrol bekliyor. Son kontrolün üzerinden `2 × kontrol aralığı + 60 saniye` geçtiyse eski durum yerine **Güncel değil** gösterilir. Sağlık, erişilebilirlik ve yanıt süresini ifade eder; CPU, disk veya sıcaklık sağlığı ölçülmez.
- Yanıt alınmaması cihazın kapalı olduğunun kanıtı değildir. Son kontrol zamanı, son yanıt zamanı, açık portlar ve son 60 kontrol cihaz detayında görülebilir. Yanıt süresi TCP bağlantı kurma süresidir; yalnızca ICMP yanıtı varsa ping işleminin toplam süresi, yalnızca SNMP yanıtı varsa ilk sistem sorgusunun süresidir.
- Yeni cihaz, üç başarısız kontrol ve yeniden erişilebilirlik için panelde olay kaydı. E-posta/SMS bildirimi yoktur.
- Arama, durum/tür filtreleri, CSV dışa aktarma. CSV'de formül olarak yorumlanabilecek metinler kaçışlanır.
- Cihaz başına son 500 kontrol ve toplam son 2000 olay saklanır. Panel son 100 olayı gösterir. Cihaz silinirse kontrol geçmişi silinir; olay kaydı kalır. Aktif keşif cihazı yeniden bulabilir.

## Ağ grupları

Her kayıtlı CIDR ayrı bir kart ve tablo grubu olarak görünür. Kartta toplam, Online, Offline ve kontrol bekleyen cihaz sayıları vardır. Karta tıklayarak yalnızca o ağı görüntüleyin; **Tüm ağlar** seçeneği filtreyi kaldırır. Çakışan ağlarda cihaz en dar CIDR grubuna yerleştirilir; aynı cihaz iki kez sayılmaz. Kayıtlı ağların dışındaki envanter cihazları **Diğer ağlar** grubunda kalır.

## Otomatik model tespiti · SNMP

1. **Ağ ayarları → Otomatik model tespiti** bölümünde SNMP'yi etkinleştirin.
2. Cihazlarda kullanılan sürümü (v2c veya v1) ve **salt okunur community** değerini uygulamaya girin. Değeri sohbet, GitHub veya kod dosyalarında paylaşmayın.
3. **Ayarları kaydet → Ağı tara** seçeneğini kullanın. Community, tüm yapılandırılmış ağlar için ortak kullanılır; farklı community gerektiren ağ profilleri ve SNMPv3 bu sürümde desteklenmez.

Sistem `sysDescr`, `sysName`, `sysObjectID`, `sysUpTime` alanlarını okur. Donanım modeli/üretici/seri numarası **ENTITY-MIB** içindeki chassis (physicalClass=3) satırından alınır. Yazıcılarda gerekirse **HOST-RESOURCES-MIB** içindeki printer tipi cihaz açıklaması kullanılır. Modül veya transceiver modeli tüm cihazın modeli olarak gösterilmez. Cihaz model alanını sunmuyorsa **Tespit edilemedi** yazılır; cihaz açıklaması detaylarda yine gösterilir. Açık porttan model uydurulmaz. Windows/Linux/VMware'de SNMP agent kurulumu ve sunulan MIB'ler donanım modeli tespitini belirler; her agent bu bilgiyi sağlamaz.

Elle girilen ad/model/seri numarası otomatik bilgilerin önüne geçer. Elle model alanını boşaltırsanız tespit edilen model kullanılır. Son başarılı SNMP model bilgisi sonraki yanıt başarısızlığında korunur; cihaz detayındaki son SNMP yanıtı ve SNMP durumu bilginin güncelliğini gösterir. SNMP agent çalışma süresi işletim sisteminin kesin açılış süresi olmayabilir; sayaç yeniden başlayabilir veya sarabilir.

Community, yalnızca yerel SQLite veritabanında saklanır; API yanıtlarında ve CSV'de dönmez. Alanı boş bırakarak mevcut değeri koruyabilirsiniz. SNMP kutusunu kaldırmak sorgulamayı durdurur. Veritabanı ve yedeği community içerdiğinden dosya erişim izinlerini koruyun. v1/v2c ağ üzerinde şifrelenmez. Her cihaz için sorgu süresi ve yürünecek MIB satırları sınırlıdır; yalnızca GET/GETNEXT yapılır, SET yapılmaz.

## SSH / RDP / VNC erişimi

Son kontrolde servis portu açık ve cihaz güncel Online ise **Bağlan** sütununda erişim düğmeleri görünür:

- **SSH** (22): Windows OpenSSH için bir `.cmd` dosyası indirir; alternatif olarak gösterilen komutu Terminal'e kopyalayın. **Bilgiler → SSH kullanıcı adı** alanını ayarlayabilirsiniz. Boşsa SSH, bilgisayarınızdaki kullanıcı adını kullanır. Gerekirse Windows'un İsteğe Bağlı Özellikler bölümünden OpenSSH İstemcisi kurun.
- **RDP** (3389): `.rdp` dosyası indirir. Dosyayı açtığınızda Windows Uzak Masaüstü istemcisi kimlik bilgilerinizi sorar.
- **VNC** (5900–5902): TightVNC uyumlu `.vnc` dosyası indirir. Farklı bir VNC istemcisi kullanıyorsanız gösterilen `IP::port` adresini kopyalayın.

Dosyaları inceleyip kendi bilgisayarınızda açın. Tarayıcı içinde uzak masaüstü/terminal çalışmaz. Servisin açık olması hesabınızın giriş yetkisi olduğunu garanti etmez. Parolalar bağlantı dosyalarına yazılmaz ve uygulamada saklanmaz. Standart dışı servis portları bu sürümde yapılandırılamaz.

CPU/RAM kullanımı, disk doluluğu, trafik grafikleri, MAC adresi, vCenter API ve SSH/WMI/WinRM ile donanım envanteri henüz uygulanmadı.

## Başka bir bilgisayardan panele erişme

Varsayılan olarak yalnızca yerel bilgisayara açıktır. Ağa açarken en az 24 karakterli bir `ATLAS_TOKEN` ortam değişkeni gerekir:

```sh
# Güçlü anahtarı güvenli ortam değişkeni yönetiminizden sağlayın.
python app.py --host 0.0.0.0 --port 8080
```

Panelde **Erişim anahtarı** bölümüne aynı değeri girin. Anahtar sekmenin `sessionStorage` alanında tutulur. Paylaşımlı kullanımda HTTPS sağlayan bir ters proxy arkasına koyun ve güvenlik duvarıyla erişimi sınırlandırın. Düz HTTP üzerinden uzaktan anahtar kullanmayın. Kullanıcı/rol yönetimi yoktur; aynı anahtara sahip herkes envanteri değiştirebilir ve tarama başlatabilir. Anahtarı depoya kaydetmeyin.

## Yedekleme ve doğrulama

Uygulamayı durdurduktan sonra `data/` dizinini yedekleyin. Çalışan veritabanı için SQLite online backup API kullanın; WAL dosyalarını göz ardı ederek yalnızca ana dosyayı kopyalamayın. Farklı veritabanıyla çalıştırmak için `python app.py --db /path/to/atlas.sqlite3` kullanın.

```sh
python -m unittest discover -s tests -v
node --check static/app.js  # Node varsa isteğe bağlı JavaScript sözdizimi kontrolü
```

Testler geçici veritabanları, sahte ağ sonuçları ve gerçek yerel TCP/UDP/HTTP bağlantıları kullanır; şirket ağlarını taramaz. Gerçek Linux/Windows/VMware/Aruba/yazıcı erişimi, kurulumun ağınıza yerleştirilmesinden sonra doğrulanmalıdır.

İsteğe bağlı gerçek tarayıcı testi için Playwright ve Chromium kurulu bir geliştirme ortamında `PYTHONPATH=. python tests/browser_smoke.py` çalıştırın. Sistem Chromium'u kullanılacaksa `CHROMIUM_PATH` ortam değişkenini çalıştırılabilir dosyanın yoluna ayarlayın. Bu test geçici veritabanı ve sahte keşif/SNMP yanıtlarıyla SNMP ayarı, model gösterimi, ağ grupları, SSH/RDP/VNC dosyaları, envanter, geçmiş, CSV ve mobil görünümü doğrular. Gerçek Aruba, yazıcı, Windows istemcileri ve şirket ağları üzerinde uçtan uca test yapılmadı.

## Mevcut Windows kurulumunu güncelleme

1. Çalışan uygulamayı terminalde Ctrl+C ile durdurun; pencereyi kapatın.
2. Mevcut uygulama klasörünün tamamını yedekleyin. Özellikle **data/** klasörünü saklayın; envanter, geçmiş, ayarlar ve varsa SNMP community buradadır.
3. Yeni ZIP'i ayrı bir klasöre çıkarın. Yeni klasördeki program dosyalarını eski uygulama klasörüne kopyalayıp değiştirin; mevcut **data/** klasörünü silmeyin veya değiştirmeyin. Yeni pakette data/ klasörü bulunmaz.
4. Eski klasörde **BASLAT.cmd** ile yeniden başlatın. Var olan veritabanına yeni alanlar otomatik eklenir; envanter korunur. Tarayıcıda Ctrl+F5 ile yenileyin.
5. Ağ ayarlarına SNMP community değerini yerel olarak girin, kaydedin ve yeniden tarayın.
