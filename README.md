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

İzleme motorunu bu dört ağa yönlendirme/VPN erişimi olan bir Linux, Windows veya macOS bilgisayarda çalıştırın. Bir bulut makinesinden şirket içi ağlar, gerekli ağ bağlantısı sağlanmadan izlenemez. Güvenlik duvarlarında izleme bilgisayarından gereken ICMP/TCP trafiğine izin verilmelidir. Yönetiminizdeki ağları tarayın.

| Cihaz | İlk sürümde kontrol |
| --- | --- |
| Linux | SSH (22), web portları, varsa ICMP |
| Windows | SMB (445), RDP (3389), web portları, varsa ICMP |
| VMware | TCP 902, HTTPS (443), varsa ICMP |
| Aruba switch / ağ ürünleri | SSH, HTTP/HTTPS, varsa ICMP |
| Yazıcı | TCP 9100, IPP (631), LPD (515), web, varsa ICMP |

Tüm cihazlarda TCP 22, 80, 443, 445, 3389, 902, 8006, 9100, 631, 515, 8080 kontrol edilir. Bağlantı kurulması servisin uygulama düzeyinde sağlıklı olduğunu göstermez. Kullanıcı adı/parola gönderilmez, oturum açılmaz. SNMP UDP 161 bu sürümde sorgulanmaz.

`ping` sistemde varsa ICMP de kullanılır. Linux'ta `command -v ping` ile kontrol edin; Debian/Ubuntu için gerekirse `sudo apt-get install iputils-ping` kurun. Ping kurulu veya çalışabilir değilse yalnızca açık TCP portları cihazı keşfedebilir. ICMP engelliyse ve kontrol edilen TCP portları kapalıysa cihaz keşfedilemeyebilir. Web panelinde TCP/ICMP yeteneği gösterilir; ICMP'nin hedefte engellenip engellenmediği ayrıca değerlendirilmelidir.

32 paralel çalışan kullanılır. Yanıt vermeyen cihaz sayısına bağlı olarak dört ağın taranması birkaç dakika sürebilir. Yeni tarama önceki bitmeden başlamaz; kontrol aralığı tarama tamamlandıktan sonra sayılır. Tarama çalışırken panel kullanılabilir.

## Envanter ve durumlar

- IP, ad, tür, işletim sistemi, CPU, RAM, model, seri numarası, konum, sorumlu ve notlar.
- Tür açık portlara göre **tahmin edilir**; SSH kullanan bir switch sunucu olarak tahmin edilebilir. Elle düzeltin. İşletim sistemi, model ve donanım alanları elle doldurulur.
- Erişilebilir: son kontrolde ICMP veya TCP yanıtı var. Geçici yanıt yok: 1–2 başarısız kontrol. Yanıt yok: en az 3 ardışık başarısız kontrol. Henüz kontrol edilmedi: elle eklenmiş, kontrol bekliyor.
- Yanıt alınmaması cihazın kapalı olduğunun kanıtı değildir. Son kontrol zamanı, son yanıt zamanı, açık portlar ve son 60 kontrol cihaz detayında görülebilir. Gecikme TCP bağlantı kurma süresi; yalnızca ICMP yanıtı varsa ping işleminin toplam süresidir.
- Yeni cihaz, üç başarısız kontrol ve yeniden erişilebilirlik için panelde olay kaydı. E-posta/SMS bildirimi yoktur.
- Arama, durum/tür filtreleri, CSV dışa aktarma. CSV'de formül olarak yorumlanabilecek metinler kaçışlanır.
- Cihaz başına son 500 kontrol ve toplam son 2000 olay saklanır. Panel son 100 olayı gösterir. Cihaz silinirse kontrol geçmişi silinir; olay kaydı kalır. Aktif keşif cihazı yeniden bulabilir.

CPU/RAM kullanımı, disk doluluğu, trafik grafikleri, MAC adresi, SNMP donanım envanteri, vCenter API, SSH/WMI/WinRM sorguları ve otomatik marka/model tespiti henüz uygulanmadı. Bunlar için ilgili cihaz protokolleri, salt okunur hesaplar ve erişim bilgileriyle ayrı entegrasyon gerekir.

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

Testler geçici veritabanları, sahte ağ sonuçları ve gerçek yerel TCP/HTTP bağlantıları kullanır; şirket ağlarını taramaz. Gerçek Linux/Windows/VMware/Aruba/yazıcı erişimi, kurulumun ağınıza yerleştirilmesinden sonra doğrulanmalıdır.

İsteğe bağlı gerçek tarayıcı testi için Playwright ve Chromium kurulu bir geliştirme ortamında `PYTHONPATH=. python tests/browser_smoke.py` çalıştırın. Sistem Chromium'u kullanılacaksa `CHROMIUM_PATH` ortam değişkenini çalıştırılabilir dosyanın yoluna ayarlayın. Bu test geçici veritabanı ve sahte keşif yanıtlarıyla ayar, envanter, tarama, geçmiş, CSV ve mobil görünüm akışlarını doğrular.
