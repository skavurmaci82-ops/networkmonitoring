# AğAtlas

## Windows üzerinde gerçek envanter ve yük testi

Bu geliştirme aşamasında merkez **Windows** üzerinde çalışacak şekilde seçilmiştir. Önce bir Windows, bir Linux ve bir switch üzerinde yetkili okumayı doğrulayın; daha sonra profil kapsamını ağ aralığına genişletin. Temel IP/ARP keşfi ve önceki tarayıcı erişimi korunur.

1. Güncellemeden önce uygulamayı durdurun ve klasörü/data/ dizinini yedekleyin. Yeni program dosyalarını mevcut klasöre kopyalayın; data/ dizinini koruyun.
2. **TOPLAYICI_KUR.cmd** dosyasını bir kez çalıştırın (Python bağımlılıkları: requirements-collectors.txt). Docker bu veri toplama için gerekmez. Ardından **BASLAT.cmd** ile yeniden başlatın ve tarayıcıda Ctrl+F5 yapın.
3. **Bağlantı profilleri → Profil ekle** seçeneğini kullanın. İlk profilde tek IP girin; **Otomatik taramalarda kullan** seçeneği kapalı kalsın. Kaydettikten sonra **Test et** düğmesine basın.

| Profil | Girilecek bilgiler | Okunabilecek bilgiler |
| --- | --- | --- |
| Windows WMI/CIM | Hedef IPv4; kendi bilgisayarınız için **Mevcut Windows hesabımı kullan**. Uzak bilgisayarda yetkili kullanıcı/parola veya yetkili mevcut alan hesabı. | Win32_ComputerSystem/BIOS ile ad, üretici, model ve seri; işlemci, RAM, disk doluluğu, IP etkin arayüzlerin MAC'leri ve sağlanırsa ağ hızı. |
| Linux SSH | IP, SSH portu, kullanıcı/parola veya özel anahtar; doğrulanmış SHA256 sunucu anahtarı. Hedefte Python 3 ve Linux /proc gereklidir. | DMI bilgileri (okunabiliyorsa), OS, CPU/RAM kullanımı, yerel diskler, arayüz MAC'leri, kısa örneklemden ağ hızları/hataları. |
| SNMP | IP, v1/v2c ve salt okunur community. | ENTITY-MIB model/üretici/seri, IP/IF-MIB MAC/topoloji, HOST-RESOURCES CPU/RAM/disk, desteklenirse HPE CPU MIB ve arayüz sayaçları. Sunulmayan sensörler **Ölçülmedi** görünür. |

**İlk Windows testi:** Komut isteminde `ipconfig` ile kendi bilgisayarınızın IPv4 adresini bulun. Windows profiline o IP'yi girin ve **Mevcut Windows hesabımı kullan** seçeneğini işaretleyin. Yerel sorguda parola gerekmez. Başarılı sonuçta gerçek model/MAC/CPU/RAM görünmelidir. Bu test, Windows bilgisayarınızda çalıştırılmalıdır; Linux'taki merkez Windows CIM/DCOM toplayıcısını çalıştıramaz.

**Uzak Windows hazırlığı:** WMI hizmeti, DCOM/RPC ve hedef güvenlik duvarı erişimi ile WMI okuma yetkili hesap gerekir. WMI/DCOM bağlantısı PacketPrivacy/PacketIntegrity ile açılır; parola işlem komut satırına konmaz, JSON yalnızca alt sürecin standart girdisinden verilir. WinRM/TrustedHosts ayarı değiştirilmez. Hesap yetkileri veya UAC güvenlik politikası otomatik gevşetilmez. İsteğe bağlı `WINDOWS_HEDEF_HAZIRLA.ps1 -MonitoringIP <merkezin-IPsi>` yardımcı dosyasını hedefte gözden geçirip yetkili PowerShell oturumunda çalıştırabilirsiniz; yalnızca o merkez IP'si için WMI hizmeti/iki güvenlik duvarı kuralını hazırlar. Betiğin gerçek Windows üzerinde çalışması bu geliştirme ortamında doğrulanmadı; kurum ilkeleri uygulanmalıdır.

**Linux sunucu anahtarı:** Profilden **Sunucunun açık anahtarını oku** ile parmak izi alınır. Bu işlem kimlik doğrulama yapmaz ve anahtarı kendiliğinden güvenilir saymaz. Hedef konsolundaki `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` sonucu ile karşılaştırın; eşleşiyorsa doğrulama kutusunu işaretleyin. Farklı sunucu anahtarı türünde ilgili public key dosyasını kullanın. Bilinmeyen/değişmiş anahtara parola gönderilmez. SSH komutu yalnızca bu projenin sabit, salt okunur Python betiğini çalıştırır; uzak cihaza paket kurulmaz veya yapılandırma yazılmaz. Seri numarası gibi ayrıcalıklı alanlar boş kalabilir.

Profilinizi **Test et** ile doğruladıktan sonra **Düzenle → Otomatik taramalarda kullan** seçeneğini açın. IP aralığına genişletirken yalnızca aynı hesabın yetkili olduğu kapsamı seçin. En dar CIDR kapsamı önceliklidir; Windows/Linux için uygun tek profil seçilir, parola listeleri denenmez. Aynı profilin cihazları sırayla okunur. Kimlik/anahtar/erişim reddi hatasında otomatik profil duraklatılır; sorunu düzelttikten sonra yeniden test edip etkinleştirin. Manuel test, kapalı profilde de tek hedef için çalışır. Otomatik Windows sorgusu açık RPC 135, Linux sorgusu profilin açık SSH portu üzerinden seçilir.

**Ölçümler:** Cihazın Bilgiler ekranında son başarılı kaynak/zaman, CPU, RAM, diskler ve ağ hızları görünür. Cihaz başına 500 ölçüm saklanır; son 60 CPU ölçümü gösterilir. CPU/RAM/disk %90 üstünde ve yeni arayüz hatasında uyarı kaydı oluşur. SNMP hızları iki geçerli sayaç örneği arasındaki farktan hesaplanır; sayaç sıfırlanması/taşması sıçrama olarak gösterilmez. Duplex kapasitesinin iki yönü ayrı değerlendirilir. Henüz yeterli örnek yoksa hız boş bırakılır. Bunlar fiziksel donanım sensörleri, kablo testi veya özel bir ICMP paket kaybı testi değildir. Veri alınamadığında önceki değer ve son başarılı zaman korunur; hata ayrıca gösterilir. Elle girilen envanter ad/model/OS alanları otomatik bilginin önüne geçer.

**Kimlik koruması ve taşıma:** Profil parolaları/community/SSH özel anahtarları API, CSV veya Git çıktısına eklenmez. Windows'ta DPAPI ile o Windows kullanıcı hesabına bağlı korunur. Linux geliştirme ortamında Fernet ve 0600 izinli data/credentials.key kullanılır. Bu anahtar da yedekle korunmalıdır. Eski genel SNMP ayarları geriye uyumluluk için önceki biçiminde kalır. data/ ve yedekleri hassastır. Profili silmek envanter/ölçüm geçmişini silmez. Yeni Windows sunucuya veri taşırken DPAPI kimlikleri farklı makine/kullanıcıda açılamayabilir; ilgili profilleri yeni çalışma hesabında silip yeniden oluşturun. Windows servis kurulacaksa korunan profiller o servis hesabında oluşturulmalıdır. Linux'a taşınırsa Windows okuması için ayrıca bir Windows toplayıcı veya ileride bir WinRM adaptörü gerekir.

Gerçek Linux SSH taşıması, anahtar eşleşmesi ve yerel Linux ölçümleri bu geliştirme ortamında doğrulandı. Windows script aktarımı/yanıt işleme kontrollü yanıtlarla, SNMP sensörleri MIB örnekleriyle ve profil ekranları Chromium ile test edildi. **Sizin Windows/Linux/switch cihazlarınızdaki üç gerçek okuma henüz doğrulanmadı.** İlk aşamanın kabulü, bu cihazlarda Test et sonucunda alınan model/MAC ve mevcut sensörlerin kontrol edilmesidir.

## SNMP bilmeden hızlı keşif

**Ağ ayarları** bölümünde IP aralıklarını girip **Kaydet ve keşfet** seçeneğini kullanın. Community veya SNMP sürümü bilmeniz gerekmez. SNMP alanları isteğe bağlı gelişmiş ayrıntılardır; boş community temel keşfi engellemez. Bulunan cihazlar, ayrı **MAC adresi** sütunu ve açık SSH/RDP/VNC portları listelenir.

Windows'ta yerel cihazların MAC adresi **GetBestRoute + SendARP** IP Helper API'siyle doğrudan alınır; SNMP ve üçüncü taraf paket sürücüsü gerekmez. ARP yanıtı veren, ICMP/TCP yanıtı vermeyen yerel cihazlar da keşfedilir. MAC sonucu tüm taramanın bitmesi beklenmeden kaydedilir. İşletim sistemi önbelleği ayrıca her 32 kontrol sonunda ve tarama bitiminde okunur.

**Farklı VLAN/yönlendirilmiş ağların cihaz MAC'leri, yalnızca IP erişimiyle uzaktan okunamaz.** Uzak cihaz yerine router MAC'i gösterilmez. Böyle durumlarda MAC alanında açıklama görünür. SNMP kullanmadan o ağların MAC'lerini toplamak için taramayı ilgili VLAN'a doğrudan bağlı bir bilgisayarda çalıştırmak gerekir. Tam marka/model bilgisi de her cihazda kimlik doğrulamasız sunulmayabilir.

Tarayıcı erişim sunucusu kurulu değilse erişim düğmesi yine açılır; **Bilgisayarımdaki istemciyle bağlan** seçeneği RDP/SSH/VNC bağlantı dosyasını indirir. Dosyayı ilgili Windows istemcisinde açın. SSH dosyasında cihaz bilgilerindeki SSH kullanıcı adı kullanılır; boşsa Windows kullanıcı adı geçerlidir. Tarayıcı içi oturumlar için aşağıdaki Docker/Guacamole kurulumu geçerlidir. Keşif, hedef cihazda kapalı uzak erişim servisini açmaz veya hesabınıza giriş yetkisi vermez.

Windows native API çağrısı yerel testlerde sahte API yanıtlarıyla doğrulandı; gerçek Windows ağına bu geliştirme ortamından erişilemedi. SNMP'siz tek düğmeli keşif, MAC gösterimi ve Docker'sız bağlantı dosyaları gerçek Chromium ile kontrollü veriler üzerinde test edildi.

Türkçe web arayüzlü, özel IPv4 ağları için cihaz keşfi, erişilebilirlik izleme ve sunucu envanter uygulaması. Python 3.10+ ve SQLite ile çalışır; temel keşif/izleme için harici Python paketi veya veritabanı sunucusu gerekmez. Tarayıcı içi uzak erişim için Docker Desktop, Apache Guacamole ve requirements-gateway.txt içindeki bağımlılık gerekir.

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

1. İsteğe bağlı olarak **Ağ ayarları → Gelişmiş bilgiler · SNMP** bölümünde SNMP'yi etkinleştirin.
2. Cihazlarda kullanılan sürümü (v2c veya v1) ve **salt okunur community** değerini uygulamaya girin. Değeri sohbet, GitHub veya kod dosyalarında paylaşmayın.
3. **Ayarları kaydet → Ağı tara** seçeneğini kullanın. Community, tüm yapılandırılmış ağlar için ortak kullanılır; farklı community gerektiren ağ profilleri ve SNMPv3 bu sürümde desteklenmez.

Sistem `sysDescr`, `sysName`, `sysObjectID`, `sysUpTime` alanlarını okur. Donanım modeli/üretici/seri numarası **ENTITY-MIB** içindeki chassis (physicalClass=3) satırından alınır. Yazıcılarda gerekirse **HOST-RESOURCES-MIB** içindeki printer tipi cihaz açıklaması kullanılır. Modül veya transceiver modeli tüm cihazın modeli olarak gösterilmez. Cihaz model alanını sunmuyorsa **Tespit edilemedi** yazılır; cihaz açıklaması detaylarda yine gösterilir. Açık porttan model uydurulmaz. Windows/Linux/VMware'de SNMP agent kurulumu ve sunulan MIB'ler donanım modeli tespitini belirler; her agent bu bilgiyi sağlamaz.

Elle girilen ad/model/seri numarası otomatik bilgilerin önüne geçer. Elle model alanını boşaltırsanız tespit edilen model kullanılır. Son başarılı SNMP model bilgisi sonraki yanıt başarısızlığında korunur; cihaz detayındaki son SNMP yanıtı ve SNMP durumu bilginin güncelliğini gösterir. SNMP agent çalışma süresi işletim sisteminin kesin açılış süresi olmayabilir; sayaç yeniden başlayabilir veya sarabilir.

Community, yalnızca yerel SQLite veritabanında saklanır; API yanıtlarında ve CSV'de dönmez. Alanı boş bırakarak mevcut değeri koruyabilirsiniz. SNMP kutusunu kaldırmak sorgulamayı durdurur. Veritabanı ve yedeği community içerdiğinden dosya erişim izinlerini koruyun. v1/v2c ağ üzerinde şifrelenmez. Her cihaz için sorgu süresi ve yürünecek MIB satırları sınırlıdır; yalnızca GET/GETNEXT/GETBULK yapılır, SET yapılmaz.

## MAC adresi, marka ve port envanteri

Her cihazın yönetim IP adresi için MAC kaynağı ve son gözlem zamanı saklanır:

- Aynı yerel ağda işletim sisteminin ARP/komşu önbelleği okunur (Windows `arp -a`, Linux `ip -j neigh`). Aktif TCP/ICMP kontrollerinden sonra önbellek tekrar okunur.
- Yönlendirilmiş ağlarda erişilebilen router/switchlerin SNMP **IP-MIB/ipNetToMedia** tabloları okunur. Ön belleğin doluluğu ve SNMP view/ACL izinleri sonucu belirler. Bir gateway MAC'i otomatik olarak tüm uzak IP'lere atanmaz.
- Cihazın yönetim IP’si **IP-MIB/ipAdEntIfIndex** ile kendi arayüzüne eşlenebiliyorsa **IF-MIB/ifPhysAddress** üzerinden MAC alınır. Diğer arayüzlerin MAC ve Up/Down bilgileri cihaz detayında ayrıca gösterilir.

Yalnızca MAC tablosunda görülen IP, **Tabloda görüldü** olarak envantere eklenir; ayrıca bir canlılık yanıtı alınmadan Online sayılmaz. Önbellek kaydı cihazın hâlâ o MAC'i kullandığının veya açık olduğunun kanıtı değildir; kaynak/zaman bilgilerini kontrol edin. Proxy ARP, sanal arayüzler ve IP değişiklikleri yorum gerektirebilir.

Marka öncelikle SNMP ENTITY-MIB ve bilinen sysObjectID enterprise kayıtlarından okunur. **Ağ ayarları → IEEE üretici listesini güncelle** ile isteğe bağlı resmi IEEE OUI listesi indirilebilir. İndirme yalnızca sabit `https://standards-oui.ieee.org/oui/oui.csv` adresinden HTTPS ile yapılır; IP/MAC veya envanter gönderilmez. İnternet erişimi yoksa SNMP bilgileri kullanılmaya devam eder. Bu indirme bulut ortamında dış erişim kısıtı nedeniyle doğrulanmadı; ayrıştırma/arama testleri yerel örneklerle doğrulandı. MAC kayıt sahibi, cihaz modeli değildir. Rastgele/yerel yönetilen MAC'lere OUI üreticisi atanmaz. Fiziksel sunucudaki sanal NIC'in kayıt sahibi VMware gibi farklı bir kuruluş olabilir.

## Ağ topolojisi

**Ağ topolojisi** ekranı şu bilgileri sunar:

- **LLDP-MIB**: kaynak cihaz/yerel port → uzak chassis/yönetim IP’si/uzak port/sysName. Envanter eşleştirmesi tekil yönetim IP'si, chassis MAC'i veya tam ve tekil SNMP adıyla yapılır. Belirsiz isimler birleştirilmez.
- IP’si doğrulanamayan LLDP komşuları ayrı **LLDP komşusu** düğümleridir. Haritada görünmeleri Online oldukları anlamına gelmez.
- **BRIDGE-MIB** MAC öğrenimi: switchin hangi portta bir MAC öğrendiği ayrıca toplanır. Haritada isteğe bağlı gösterilir ve **doğrudan kablo kanıtı değildir**. Uplink portundan arkasındaki birçok MAC öğrenilebilir. VLAN'a özgü Q-BRIDGE/FDB tabloları bu sürümde okunmaz.
- Arama, bağlantısı bilinen/sorunlu cihaz filtresi, cihaz detayına tıklama ve SVG/JSON dışa aktarma.

Aynı CIDR grubunda olmak çizgi üretmez. LLDP kanıtı bulunmayan bağlantılar uydurulmaz. Başarısız yeni okumada eski LLDP kanıtı zamanı korunur ve eski/kısmi olarak işaretlenir. LLDP local/remote port isimleri fiziksel ifIndex ile varsayımsal olarak eşlenmez. Harita otomatik yerleşir; yerleşimin yönü gerçek ağ hiyerarşisi iddiası değildir.

SNMPv2c tablo yürümeleri GETBULK (16 satır) ile yapılır; gerektiğinde GETNEXT'e düşer. SNMPv1 GETNEXT kullanır. Cihaz başına kimlik sorgusu 4 saniye, ek ağ envanteri yaklaşık 10 saniye bütçeyle sınırlıdır. LLDP/arayüz/bridge-port tabloları en fazla 128, IPv4-arayüz tablosu 256, ARP/FDB tabloları 512 satırla sınırlıdır; büyük veya yavaş cihazlarda kısmi envanter oluşabilir. Sonuç tam topoloji garantisi değildir. Harita ilk 200 düğümü/500 görünür ilişkiyi, alt tablo ilk 200 ilişkiyi çizer; JSON çıktısı toplanmış tüm ilişkileri içerir.

LLDP'nin açık olması yanında SNMP community'nin **LLDP-MIB, IF-MIB, IP-MIB, ENTITY-MIB ve BRIDGE-MIB** okuma izni gerekir. Firewall/ACL ve MIB view eksikliği boş veya kısmi veri üretebilir. Model cihaz tarafından sunulmadığında tam modeli yalnızca MAC adresinden çıkarmak mümkün değildir.

## Tarayıcı içinde SSH / RDP / VNC

Oturumlar Apache Guacamole ile **tarayıcıda yeni bir sekmede** açılır. Bilgisayarda RDP, VNC veya SSH masaüstü istemcisi gerekmez. AğAtlas sekmesi envanter/topoloji için açık kalır.

Windows üzerinde bir kez:

1. **Docker Desktop** kurun, gerekli WSL 2/sanallaştırma önkoşullarını tamamlayın ve **Linux containers** modunda başlatın: https://docs.docker.com/desktop/setup/install/windows-install/
2. ZIP'i çıkardığınız AğAtlas klasöründe **TARAYICI_ERISIM_KUR.cmd** dosyasını çalıştırın. Betik Python bağımlılığını kurar, güvenli ve rastgele paylaşımlı anahtarı yerel data/ klasöründe üretir, resmi `guacamole/guacamole:1.6.0` ve `guacamole/guacd:1.6.0` servislerini başlatır. İlk kurulum için internet gerekir; tekrar çalıştırıldığında mevcut anahtar korunur.
3. **BASLAT.cmd** ile AğAtlas'ı yeniden başlatın. Docker Desktop açık kalmalıdır. Yeniden başlatmalarda Docker servisleri `unless-stopped` politikasıyla geri gelir.
4. Cihaz satırındaki **SSH / RDP / VNC** düğmesine basın, hedef cihazın kimlik bilgilerini girin ve **Tarayıcıda bağlan** seçeneğini kullanın. Tarayıcı yeni sekmeleri engelliyorsa bu siteye izin verin.

Linux geliştirme ortamında eşdeğeri: `python -m pip install -r requirements-gateway.txt`, ardından `python gateway_setup.py`.

Guacamole yalnızca `127.0.0.1:8088` üzerinde yayımlanır; guacd'nin 4822 portu hosta açılmaz. Anahtar `data/gateway.json` ve `data/guacamole.env` içinde kalır, API/CSV/Git'e eklenmez. Docker konteynerleri de hedef ağlara TCP erişimi sağlayabilmelidir; bilgisayarın VPN/rotası her Docker kurulumunda konteynere otomatik yansımayabilir.

Uzak hesap parolası kaydedilmez. Oturum isteği Apache'nin resmi JSON-auth sözleşmesiyle HMAC-SHA256 imzalanır/AES-128-CBC şifrelenir, yalnızca seçili cihaz/protokolü kapsar ve 30 saniyelik açılış süresi taşır. Açılan oturumun süresi Guacamole tarafından yönetilir. RDP sertifika doğrulaması kapatılmaz; hedefin sertifikası Guacamole/FreeRDP tarafından güvenilir olmalıdır. SSH/RDP/VNC giriş yetkisi ve sunucu tarafındaki hesap/servis ayarları ayrıca gereklidir. NLA/AD, SSH anahtar tabanlı giriş ve gerçek Windows RDP oturumu bu ortamda doğrulanmadı. Desteklenen standart portlar SSH 22, RDP 3389, VNC 5900–5902'dir.

Docker servislerini durdurmak için `docker compose -f gateway/compose.yaml stop`, tekrar başlatmak için `docker compose -f gateway/compose.yaml up -d` kullanın. Guacamole loglarında oturum kullanıcı/IP bilgileri bulunabilir; paylaşmadan önce inceleyin. Bu tek kullanıcılı yerel kurulum kurumsal RBAC, oturum kaydı veya yetki delegasyonu sağlamaz.

vCenter API, SNMPv3, donanım sıcaklık sensörleri ve tam bir ICMP paket kaybı/jitter testi henüz uygulanmadı. Windows/Linux ve standart SNMP yük bilgileri için bağlantı profilleri bölümünü kullanın.

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
python -m pip install -r requirements-collectors.txt
python -m unittest discover -s tests -v
node --check static/app.js  # Node varsa isteğe bağlı JavaScript sözdizimi kontrolü
```

Testler geçici veritabanları, sahte ağ sonuçları ve gerçek yerel TCP/UDP/HTTP bağlantıları kullanır; şirket ağlarını taramaz. Gerçek Linux/Windows/VMware/Aruba/yazıcı erişimi, kurulumun ağınıza yerleştirilmesinden sonra doğrulanmalıdır.

İsteğe bağlı gerçek tarayıcı testi için Playwright ve Chromium kurulu bir geliştirme ortamında `PYTHONPATH=. python tests/browser_smoke.py` çalıştırın. Sistem Chromium'u kullanılacaksa `CHROMIUM_PATH` ortam değişkenini çalıştırılabilir dosyanın yoluna ayarlayın. Bu test geçici veritabanı ve sahte keşif/SNMP yanıtlarıyla SNMP ayarı, model gösterimi, ağ grupları, tarayıcı oturum diyalogları ve topoloji dışa aktarma, envanter, geçmiş, CSV ve mobil görünümü doğrular. Gerçek Aruba, yazıcı, Windows istemcileri ve şirket ağları üzerinde uçtan uca test yapılmadı.

## Mevcut Windows kurulumunu güncelleme

1. Çalışan uygulamayı terminalde Ctrl+C ile durdurun; pencereyi kapatın.
2. Mevcut uygulama klasörünün tamamını yedekleyin. Özellikle **data/** klasörünü saklayın; envanter, geçmiş, ayarlar ve varsa SNMP community buradadır.
3. Yeni ZIP'i ayrı bir klasöre çıkarın. Yeni klasördeki program dosyalarını eski uygulama klasörüne kopyalayıp değiştirin; mevcut **data/** klasörünü silmeyin veya değiştirmeyin. Yeni pakette data/ klasörü bulunmaz.
4. Eski klasörde **BASLAT.cmd** ile yeniden başlatın. Var olan veritabanına yeni alanlar otomatik eklenir; envanter korunur. Tarayıcıda Ctrl+F5 ile yenileyin.
5. Ağ ayarlarına SNMP community değerini yerel olarak girin, kaydedin ve yeniden tarayın.

Gerçek Guacamole tarayıcı/VNC entegrasyon testi: çalışan `gateway/compose.yaml` servisleri ve `data/gateway.json` ile `PYTHONPATH=. CHROMIUM_PATH=/path/to/chromium GATEWAY_TEST_HOST=<bu-test-makinesinin-Dockerdan-erisilebilir-IPsi> python tests/gateway_smoke.py`. Bu test test makinesinde geçici bir RFB masaüstü açar; şirket cihazlarına bağlanmaz. Test hedefinin Docker ağ geçidi değil, Python test sürecinin çalıştığı makine olması gerekir.

Guacamole JSON-auth uyumluluk referansı: https://github.com/apache/guacamole-client/blob/1.6.0/extensions/guacamole-auth-json/doc/README.md . Apache Guacamole resmi Docker imajları Apache projesinin bileşenleridir.
