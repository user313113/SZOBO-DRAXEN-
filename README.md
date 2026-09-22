# SZOBO | DRAXEN

**Düşük yoğunluklu, kaynak izlenebilir OSINT, ağ topolojisi ve derin altyapı analizi motoru.**

Python 3.9+ standart kütüphanesiyle çalışan, harici Python paketi gerektirmeyen profesyonel bir keşif ve istihbarat aracıdır. iSH (iOS/Alpine) ve Termux (Android) ortamlarında C derleyicisi, Docker, headless tarayıcı veya root yetkisi olmadan çalışır. Türkçe terminal özeti, çevrimdışı görüntülenebilen interaktif HTML raporu, makine tarafından işlenebilir JSON, formül korumalı CSV, Graphviz DOT ve Gephi uyumlu GraphML ilişki grafikleri üretir.

## Kurulum

### Termux (Android)

```sh
pkg update && pkg install python git ca-certificates
git clone https://github.com/user313113/SZOBO-DRAXEN-.git
cd SZOBO-DRAXEN-
sh start.sh
```

### iSH / Alpine (iOS)

```sh
apk update && apk add python3 git ca-certificates
git clone https://github.com/user313113/SZOBO-DRAXEN-.git
cd SZOBO-DRAXEN-
sh start.sh
```

Klonlama varsayılan dalı açar. Henüz birleştirilmemiş geliştirmeleri denemek için ilgili geliştirme dalını kullanın.

iSH üzerinde `python` yerine `python3` komutunu kullanın. SSL/TLS hatalarını sertifika doğrulamasını kapatarak çözmeyin; `ca-certificates` paketinin kurulu ve sistem saatinin doğru olduğunu kontrol edin.

### İsteğe Bağlı Paket Kurulumu

```sh
python -m pip install .
draxen --help
```

`python -m draxen` doğrudan repo kök dizininden de çalıştırılabilir.

## Temel Kullanım

Yalnızca araştırma ve analiz yetkinizin bulunduğu hedefleri inceleyin.

```sh
# 1. Standart OSINT Keşfi (DNS, RDAP, Sertifika Şeffaflığı):
python -m draxen example.com

# 2. Tam Kapsamlı Derin Analiz (Arşivler, BGP, Posta/DKIM, Güvenlik, Altyapı/TLS, WAF/CDN):
python -m draxen example.com --deep --verify 5 --budget 60

# 3. Altyapı ve Kenar Güvenliği İncelemesi (WAF/CDN, SOA, RIR, Canlı TLS Kripto Profili):
python -m draxen example.com --infra

# 4. Posta Güvenliği ve DNSSEC İncelemesi (SPF, DMARC, DKIM, MTA-STS, BIMI, CAA):
python -m draxen example.com --mail

# 5. Web Güvenlik Direktifleri ve HTTP Başlık Analizi:
python -m draxen example.com --security

# 6. Önceki Taramayla Fark & Değişim Analizi:
python -m draxen example.com --deep --compare reports/onceki/report.json --output reports/guncel

# 7. Doğrudan Ana Sayfa İçeriğini Çıkarma (robots.txt izin verirse):
python -m draxen example.com --web --delay 2

# 8. Genel IP Adresi Analizi (Ters DNS, RDAP, Alt Ağ, BGP Anonsu, ASN Sahibi ve RIR):
python -m draxen 8.8.8.8 --deep

# 9. E-posta Hedefi (Alan adı analizi + pasif Gravatar profil tespiti):
python -m draxen contact@example.com --security

# 10. Görsel veya Belge Meta Veri (EXIF) Analizi (Harici kütüphanesiz, GPS ve cihaz tespiti):
python -m draxen --meta /path/to/fotograf.jpg

# 11. robots.txt ve sitemap.xml Keşfi (Gizli yollar, açık belgeler ve alt alan adları):
python -m draxen example.com --sitemap

# 12. IP, ASN, Veri Merkezi ve Ağ Konum İstihbaratı (AWS, Cloudflare, Hetzner vb., GeoIP, IP Blokları):
python -m draxen 104.16.1.1 --network
python -m draxen example.com --netintel

# 13. Yerel Sözlük Tabanlı Alt Alan Adı Keşfi (Harici API'siz, DNS Wordlist):
python -m draxen example.com --brute

# 14. Kritik Port ve Servis Karşılama (Banner Grabbing) Taraması:
python -m draxen 93.184.216.34 --ports
python -m draxen example.com --ports
```

## Yerel Terminal Arayüzü (Termux / iSH)

**Bu arayüz bir web sayfası değildir.** Menü, logo, girdiler ve sayfalı sonuçlar doğrudan terminalde çalışır. Tarayıcı, `rich`, `pyfiglet`, curses paketi veya font indirmesi gerekmez.

```sh
# Önerilen: her zaman bu klasördeki kodu çalıştırır; eski pip kurulumuyla karışmaz.
sh start.sh

# Aynı yerel menüyü Python ile aç:
python3 -m draxen --ui

# Yalnızca katmanlı SZOBO / DRAXEN başlığını göster:
sh start.sh --banner

# Tarama yapmadan tek ekranlık demo / etkileşimli demo raporu:
sh start.sh --demo
sh start.sh --demo --ui

# Klasik komut kullanımı korunur; uzun döküm isteğe bağlıdır:
sh start.sh example.com
sh start.sh example.com --details
```

### Açılış Animasyonu ve Erişim Şifresi

`sh start.sh` (veya hedefsiz `python3 -m draxen` / `--ui`) gerçek bir terminalde açıldığında önce kısa bir açılış sekansı oynar, ardından **erişim şifresi** sorulur; kontrol merkezi yalnızca doğru şifreden sonra açılır.

1. **SİSTEM paneli:** çekirdek/Python sürümü, terminal ölçüsü ve renk derinliği, yüklü modül sayısı gerçek yerel değerlerden okunur; **AĞ** satırı açılışta hiçbir istek yapılmadığını gösterir.
2. **Logo açılışı:** SZOBO / DRAXEN silüeti parıltıdan soldan sağa mor → mavi → camgöbeği → yeşil geçişle belirir. Son kare kontrol merkezindeki başlıkla birebir aynıdır; logo yer değiştirmez.
3. **ERİŞİM KONTROLÜ:** varsayılan şifre **`szobodraxen1881`**. Şifre yazarken ekranda görünmez (`getpass`). Üç hatalı denemede oturum **KİLİTLENDİ** ile kapanır (çıkış kodu 1); her hatalı denemeden sonra bekleme süresi artar. `Ctrl+C` 130, `Ctrl+D` 1 koduyla çıkar.

Animasyon yaklaşık 2,5 saniye sürer ve duvar saatine göre planlanır: yavaş cihazlarda (iSH gibi) kareler atlanır, süre uzamaz. **Enter** animasyonu atlayıp doğrudan şifre ekranına geçer; animasyon sırasında şifreyi yazıp Enter'a basmak ilk deneme olarak sayılır. Gizli imleç, alternatif ekran veya ham klavye modu kullanılmaz; yalnızca görünür ekran yeniden çizilir.

Şifre kaynak kodda düz metin olarak tutulmaz; `draxen/gate.py` içinde yalnızca PBKDF2-HMAC-SHA256 özeti bulunur ve karşılaştırma sabit zamanlıdır. Şifreyi değiştirmek için yeni özeti üretip `PASSWORD_DIGEST` değerine yazın:

```sh
python3 -c "from draxen.gate import digest; print(digest('yeni-şifre'))"
```

Kapı yalnızca etkileşimli kontrol merkezini korur. `sh start.sh example.com`, `--demo`, `--banner`, `--tools`, `--meta` gibi komut satırı akışları ve pipe/`--quiet` kullanımı şifre sormaz; betiklerde kullanılabilir kalır.

### Açılış ve Kontroller

Hedef verilmeden gerçek bir terminalde açıldığında artık uzun yardım metni basılmaz; erişim şifresinin ardından **SZOBO / DRAXEN kontrol merkezi** görünür. Açılış kendiliğinden ağ isteği yapmaz.

| Tuş + Enter | İşlev |
| --- | --- |
| `1` / `01` | Standart DNS, RDAP ve CT keşfi; hedef ve başlatma onayı ister |
| `2` / `02` | Derin analiz; TCP portları ve DNS sözlüğü dahil kapsamı onaydan önce gösterir |
| `3` / `03` | Yerel JPEG, PNG veya PDF meta verisi; ağ isteği yapmaz |
| `4` / `04` | Açıkça işaretlenmiş çevrimdışı örnek rapor |
| `5` / `05` | Hazır test araçları kataloğu; sayfalı liste, anında arama ve araç detayı — hiçbir aracı indirmez/kurmaz |
| `H` | Sayfalı komut yardımı |
| `Q` | Geri / çıkış |

Taramayı başlatmak için açıkça **E / Evet** girilir; boş Enter veya başka yanıt taramayı başlatmaz. Uzun hedef/kapsam onayları taşarsa Enter/N ile sayfalanır; Q işlemi iptal eder. Sınırlar `--budget`, `--delay`, `--timeout` ve `--limit` ile menüye de verilebilir.

Rapor ekranında `1` özet, `2` kaynaklar, `3` bulgular, `4` analiz/kapsam notları, `5` rapor yollarıdır. **N / P** ile sonraki/önceki sayfaya geçilir. Uzun değerler ve tüm kayıtlar sayfalara bölünür; sonuçları görmek için tek ekranı aşan bir döküm basılmaz. Klavye açılması veya ekran döndürme sonrası **Enter** düzeni yeni terminal ölçülerinde yeniden çizer.

Araçlar sayfasında (`05`) sayı yazmak ilgili aracın detay sayfasını açar; metin yazmak anında filtre uygular, **S** yeni arama başlatır, **N / P** sayfalar arasında gezinir, **Enter** filtreyi temizler, **Q** menüye döner. Detay sayfası açıklama, kategori, önerilen kurulum komutu (yalnızca gösterim), bağımlılıklar ve bağlantıyı listeler. Katalog yalnızca listeleme yapar: DRAXEN listedeki hiçbir aracı indirmez, kurmaz ya da çalıştırmaz.

### Referans Görünüm ve Ekrana Sığma

Renkler terminalin mevcut arka planını değiştirmez; referansa yakın görünüm için koyu tema ve sabit genişlikli terminal fontu kullanın.

- **Katmanlı blok harfler:** Büyük görünümde dolu ön yüz, ince çizgili kontur/gölge ve mor → elektrik mavisi → camgöbeği → yeşil geçiş. Dar telefonda ezilmiş üç satırlık başlık yerine tam yükseklikte gölgeli piksel harfler kullanılır.
- **SZOBO / DRAXEN:** Yeterince geniş ekranda iki ad yan yana, diğer ekranlarda alt alta; çift çizgili yeşil çerçeve içinde ortalanır. Çok kısa ekranda sade marka satırına geçilir. Açılıştaki disk bilgisi ve tarih/saat yerel sistemden okunur, uydurma sayaç değildir.
- **Yatay ve dikey sınırlar:** Gerçek terminal dosya tanımlayıcısından kolon/satır ölçüsü alınır. Menü, kısa özet ve sayfalı rapor hem genişliğe hem yüksekliğe uyar; son kolon ve girdi satırları ayrılır. `--details` bilinçli olarak uzun/kaydırılabilir çıktı üretir.
- **Düzgün Unicode:** ANSI kodları genişlik hesabına katılmaz. Türkçe, birleşen aksanlar, geniş karakterler ve yaygın emoji birleşimleri terminal hücreleriyle ölçülür. Önizlemede kısalan değerler işaretlenir; tam rapor verileri değişmez.
- **Gerçek ilerleme:** Aktif kaynak, bulgu sayısı, HTTP bütçesi ve geçen süre gösterilir; sahte yüzde yoktur. `Ctrl+C` sırasında toplanan veriler kısmi rapor olarak kaydedilir. Ham klavye modu veya gizli imleç kullanılmaz.
- **Açılış sekansı:** Sistem paneli, logo açılışı ve erişim şifresi aynı yerleşimi paylaşır; `--ascii` ve `--color never` ile de çalışır. Onay ekranındaki ışık süpürmesi süslemedir, ilerleme yüzdesi değildir.

```sh
# Font çizgileri düzgün göstermiyorsa:
sh start.sh --ascii

# Renkleri kapat, panelleri koru:
sh start.sh --color never

# Panelsiz, renksiz, animasyonsuz ve etkileşimsiz çıktı:
sh start.sh example.com --plain

# Yerleşimi daha dar tut:
sh start.sh --width 38
```

`COLORTERM=truecolor` / `24bit` veya `TERM=*-direct` için RGB, 256 renkli terminallerde palet, temel terminallerde 16 renk kullanılır. `NO_COLOR` otomatik renkleri kapatır; açık `--color always` bunu geçersiz kılar. `TERM=dumb` sade ASCII modunda kalır. Termux/iSH içinde terminal değişkeni yanlışlıkla `dumb` olmuşsa, destekleyen bu emülatörlerde `TERM=xterm-256color sh start.sh` ile başlatılabilir.

Dosya/pipe yönlendirmesinde otomatik menü açılmaz, girdi beklenmez; varsayılan çıktı kaçış kodu içermez. `--ui` gerçek terminal girişi/çıkışı ve en az **21 kolon × 12 satır** ister; `--plain`, `--quiet`, `--details` veya `--banner` ile birleştirilmez. `--ascii` yalnızca sunumu değiştirir, rapor dosyalarındaki Türkçe/Unicode veriyi değiştirmez.

`--demo` yalnızca açıkça `--output KLASÖR` verilirse örnek raporları kaydeder. Bu dosyalar **DEMO** olarak işaretlenir; gerçek hedef analizi değildir. Demo hedef veya keşif modülleriyle birlikte kullanılamaz.

### Taşınabilir Güncel Paket

Geliştirme klasöründen `python3 tools/package_terminal.py` ile `reports/releases/SZOBO-DRAXEN-terminal.zip` üretilir. ZIP yalnızca uygulama kodunu, belgeleri, test araçları kataloğunu (`data/test_tools.json`) ve başlatıcıyı içerir; `.git`, tarama raporları, ekran görüntüleri veya önbellekler dahil edilmez.

Telefona alınan ZIP'i ayrı bir klasöre açıp **o klasörde** çalıştırın; `git pull` yayımlanmamış yerel değişiklikleri başka bir cihaza taşımaz.

```sh
python3 -m zipfile -e SZOBO-DRAXEN-terminal.zip .
cd SZOBO-DRAXEN-terminal
sh start.sh
```

### İsteğe Bağlı Görsel Önizleme (Geliştirme)

`python3 tools/preview_terminal.py` açılış ekranının statik HTML önizlemesini `reports/terminal-preview/index.html` konumuna yazar. Bu dosya uygulamanın kendisi değildir; gerçek menü `sh start.sh` ile terminalde açılır. Üretilen dosyalar Git'e eklenmez.

## Test Araçları Kataloğu (05 / `--tools`)

Hazır test araçlarının **yalnızca listelendiği** çevrimdışı katalog. Kaynak veri `data/test_tools.json` dosyasıdır; her kayıt `name`, `desc`, `url`, `category[]`, `dependency[]` ve `package_manager` alanlarını taşır.

- **Terminal menüsü:** `05` ile açılır. Numaralı liste; sayı yazınca aracın detay sayfası açılır, metin anında filtre uygular, `S` yeni arama başlatır, `N`/`P` sayfalama, `Enter` filtreyi temizler, `Q` menüye döner.
- **Komut satırı:** `python -m draxen --tools` tüm kataloğu, `python -m draxen --tools sqlmap` filtrenin eşleşmesini basar.
- **Kapsam:** DRAXEN bu listedeki hiçbir aracı **indirmez, kurmaz veya çalıştırmaz**; detaydaki "KURULUM" alanı yalnızca bilgi amaçlı gösterilen komut önerisidir. Araçları yalnızca araştırma yetkinizin bulunduğu hedeflerde, eğitim amaçlı kullanın.

### Kataloğa araç ekleme

`data/test_tools.json` dosyasına mevcut biçimde yeni bir kayıt eklemeniz yeterlidir; kod değişikliği gerekmez:

```json
"ornek-aramac": {
    "name": "ornek-aramac",
    "desc": "Aracın kısa açıklaması",
    "url": "https://github.com/sahip/ornek-aramac",
    "category": ["information_gathering"],
    "dependency": ["python", "git"],
    "package_manager": "git"
}
```

Katalog `tools/package_terminal.py` ile üretilen taşınabilir ZIP'e de dahildir; bu sayede menüdeki 05 seçeneği pakette de çalışır.

## Komut Seçenekleri

| Seçenek | Varsayılan | Davranış |
| --- | --- | --- |
| `--deep` | Kapalı | `--archives`, `--network`, `--mail`, `--security`, `--infra`, `--sitemap`, `--brute` ve `--ports` modüllerini tek seferde açar |
| `--brute` | Kapalı | Harici servislere bağımlı olmadan 71 popüler ve kritik kelimelik yerel sözlükle alt alan adı keşfeder |
| `--ports` | Kapalı | Kritik TCP portlarını (21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017) ve servis banner'larını kontrol eder |
| `--sitemap` | Kapalı | `robots.txt` kurallarını ve `sitemap.xml` indekslerini analiz eder; gizli yolları ve açık belgeleri listeler |
| `--meta DOSYA` | — | Bağımsız adli mod: JPEG, PNG ve PDF dosyalarından EXIF, GPS ve meta veri ayıklar |
| `--tools [FILTRE]` | Kapalı | `data/test_tools.json` kataloğunu çevrimdışı listeler; `FILTRE` ile daraltır. Hiçbir aracı indirmez/kurmaz, ağ isteği yapmaz |
| `--infra` | Kapalı | Kenar CDN/WAF tespiti, SOA mimarisi, RIR bölgesi ve canlı TLS kriptografik profilini sorgular |
| `--archives` | Kapalı | Wayback Machine (CDX) ve urlscan mevcut arama kayıtlarını sorgular |
| `--network`, `--netintel`, `--asn` | Kapalı | IP konumu (GeoIP), ASN, 53 veri merkezi / bulut sağlayıcısı tespiti, BGP anonsu ve IP blok analizi |
| `--mail` | Kapalı | MTA-STS, TLS-RPT, BIMI, DS/DNSKEY, DKIM anahtar seçicileri ve SPF derin analizini yapar |
| `--security` | Kapalı | RFC 9116 `security.txt`, HTTP yanıt başlıkları denetimi ve pasif kimlik profilini sorgular |
| `--compare DOSYA` | — | Hedefin önceki `report.json` raporuyla fark ve değişim analizi yapar |
| `--verify N` | `0` | Kaynaklardan toplanan aday alt alan adlarından ilk N tanesini DNS ile sorgular (0–20) |
| `--web` | Kapalı | robots.txt izin verirse hedefin HTTPS ana sayfasını okur (doğrudan bağlantı) |
| `--limit N` | `100` | CT, arşiv ve sayfa bağlantı çıkarımlarında üst sınır (1–1000) |
| `--budget N` | `40` | HTTP yönlendirmeleri ve yedek sorgular dahil toplam istek bütçesi (1–100) |
| `--delay N` | `1.5` | İstekler arasında beklenecek en az süre (1–60 saniye) |
| `--timeout N` | `15` | Ağ soket zaman aşımı (2–60 saniye) |
| `--output KLASÖR` | `reports/ZAMAN` | Çıktıların yazılacağı hedef dizin |
| `--ui` | Gerçek terminalde hedefsiz açılışta otomatik | Yerel menü ve sayfalı sonuç arayüzü; pipe kabul etmez |
| `--banner` | Kapalı | Yalnızca katmanlı SZOBO / DRAXEN başlığını gösterir; ağ isteği yapmaz |
| `--details` | Kapalı | Tek ekranlık özet yerine uzun/kaydırılabilir terminal dökümü |
| `--quiet` | Kapalı | Terminal özetini ve canlı ilerleme satırını gizler; rapor dosyaları yine kaydedilir |
| `--demo` | Kapalı | Örnek verilerle çevrimdışı arayüz demosu; yalnızca `--output` verilirse örnek rapor kaydeder |
| `--color auto/always/never` | `auto` | ANSI renk politikasını seçer; otomatik mod `NO_COLOR` ve terminal yeteneklerini gözetir |
| `--ascii` | Kapalı | Unicode çizgiler, piksel blokları ve Türkçe harfler yerine ASCII karşılıklarını kullanır |
| `--plain` | Kapalı | Logo, panel, renk ve animasyon olmadan sade ASCII çıktı verir |
| `--width N` | Otomatik | Düzen genişliğini 20–160 kolon aralığında sınırlar; gerçek terminali aşmaz |
| `--version` | — | Sürüm bilgisini gösterir |

## Veri Kaynakları ve Analiz Modülleri

| Kaynak / Modül | Toplanan Bulgular | Analiz ve Kapsam Sınırları |
| --- | --- | --- |
| **Altyapı & Kenar Güvenliği (`--infra`)** | Cloudflare, Akamai, CloudFront, Fastly, Sucuri, Imperva vb. WAF/CDN tespiti; RIR kayıt bölgesi | Header, CNAME ve sunucu yanıtlarından kenar katman tespiti; gerçek kaynak IP'nin gizlenme durumunu gösterir. |
| **SOA Bölge Mimarisi (`--infra`)** | Primary NS (MNAME), Hostmaster e-postası (RFC 1035), Seri no tarih kontrolü, Refresh/Expire süreleri | RFC 1912 uyumluluk denetimi (20 dk altı refresh veya 7 gün altı expire durumları raporlanır). |
| **Canlı TLS Kripto Profili (`--infra`)** | Müzakere edilen TLS protokolü, Cipher Suite, anahtar bit uzunluğu, aktif CA yayıncısı, SAN alan adları | Port 443 üzerinde saygılı TLS el sıkışması; sertifika süresi kalan gün ve self-signed durumu denetlenir. |
| **DNS Çözümleme** | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR | Google Public DNS kullanılır; erişilemezse Cloudflare DNS yedek olarak devreye girer. Bir türün hatası diğer kayıtları engellemez. |
| **Sertifika Şeffaflığı (crt.sh)** | Sertifika alan adları, CA yayıncısı, başlangıç/bitiş tarihleri | Tekrarlar ayıklanır, en güncel kayıt detayları saklanır. Kapsam dışı veya sahte benzer alan adları filtrelenir. |
| **Kayıt Bilgisi (RDAP)** | Alan adı ve IP tescil bilgisi, durumlar, olay tarihleri, tescil kuruluşu | `rdap.org` üzerinden sorgulanır; yanıt alınamazsa IANA Bootstrap listesinden yetkili HTTPS servisi bulunur. |
| **Arşiv Kayıtları (`--archives`)** | Wayback CDX indeksleri, mevcut urlscan herkese açık taramaları | Yalnızca tarihsel indekslerdir. URL parametreleri (query/fragment) gizlilik gereği atılır. Yeni tarama başlatılmaz. |
| **IP, ASN & Ağ Konumu (`--network`)** | Şehir, ülke, koordinatlar (Google Maps linki), RDAP IP aralığı (`ip_range`), blok adı (`net_name`), BGP öneki, origin ASN, AS sahibi | RIPEstat Geoloc ve RDAP IP sorgularıyla coğrafi konum ve IP blok sınırlarını çıkarır; Anycast/dağıtık ağları tespit eder. |
| **Veri Merkezi Tespiti (`--network`)** | AWS, Google Cloud, Azure, Cloudflare, DigitalOcean, Hetzner, OVH, Vultr, Fastly, Telekom operatörleri vb. tespiti | ASN, ASN sahibi ve ağ bloğu imzalarından hedef sunucunun barındığı veri merkezi kategorisini belirler. |
| **Sertifika Derin Analizi (`--infra`)** | İmza algoritması (SHA256, ECDSA, Ed25519 vs SHA-1/MD5), kalan gün, X.509 sürümü, seri no | Canlı el sıkışması ve DER ikili ayrıştırma; süresi dolmuş veya zayıf imzalı sertifikaları raporlar. |
| **Çerez Güvenlik Denetimi (`--security`)** | `Set-Cookie` başlıklarında `HttpOnly`, `Secure` ve `SameSite` bayrakları | XSS oturum hırsızlığı ve CSRF risklerine karşı çerez yapılandırmasını denetler. |
| **Sözlük ile DNS Keşfi (`--brute`)** | `admin`, `api`, `portal`, `vpn`, `dev`, `mail` vb. gizli alt alan adları | Dış servislere gerek duymadan yerel DNS sorgularıyla kapsam içi alt alan adlarını ve IP'lerini bulur. |
| **Port & Banner Yakalama (`--ports`)** | Açık portlar ve servis karşılama mesajları (`Server`, `OpenSSH`, `MySQL`, `ESMTP`) | Hedef IP'ye zaman aşımı korumalı hafif TCP bağlantıları kurarak çalışan servis sürümlerini yakalar. |
| **E-posta Güvenlik Politikaları (`--mail`)** | SPF (RFC 7208), DMARC, MTA-STS, TLS-RPT, BIMI, DKIM Anahtarları | 10 DNS sorgu limiti denetimi, PermError tespiti, yetkili üçüncü taraf göndericileri ve RSA DKIM anahtar uzunluğu analizi. |
| **Güvenlik Direktifleri (`--security`)** | RFC 9116 `security.txt` direktifleri, HTTP güvenlik başlıkları (HSTS, CSP, XFO vb.) | Güvenlik dosyası ve tek bir root HTTPS başlık denetimiyle zafiyet oluşturmadan duruş tespiti. |
| **Kimlik Profili (`--security` + e-posta)** | Pasif Gravatar MD5 profil eşleşmesi (Display Name, Bio, Location) | Salt okunur ve açık profiller alınır; şifre veya sızıntı sorgusu yapılmaz. |
| **Parmak İzi Tespiti** | Posta sağlayıcısı, DNS altyapısı, Bulut/SaaS doğrulamaları, CNAME bağımlılıkları | MX, NS, CNAME ve TXT imzalarından türetilir. |
| **robots.txt & Sitemap (`--sitemap`)** | Disallow/Allow kuralları, sitemap URL'leri, açıkta kalan belgeler (.pdf, .doc, .zip vb.) | Hedef web sunucusuna yalnızca 2 nazik GET isteği yapar; taranan URL'lerden yeni alt alan adları ve `<lastmod>` zaman damgaları çıkarır. |
| **Meta Veri & EXIF (`--meta`)** | Cihaz markası/modeli, yazılım, çekim/oluşturulma tarihi, yazar, GPS enlem/boylam | Hiçbir ağ trafiği üretmez. Pure Python standart kütüphanesiyle JPEG/APP1, PNG chunk (`tEXt`/`zTXt`) ve PDF `/Info`/XMP verilerini yerel olarak çözer. |

## Otomatik Analiz ve Güvenlik Göstergeleri

SZOBO | DRAXEN, toplanan verileri ek ağ isteği yapmadan yerel korelasyon motorundan geçirir:

- **Eksik Çerez Güvenlik Bayrakları (`cookie_security_weak`):** Web uygulamasının bıraktığı çerezlerde `HttpOnly`, `Secure` veya `SameSite` bayraklarından biri veya birkaçı eksikse güvenlik uyarısı verir.
- **Hassas Yönetim Portu Açık (`exposed_management_port`):** SSH (22), FTP (21), MySQL (3306), PostgreSQL (5432) veya Redis (6379) gibi kritik servislerin genel ağa doğrudan açık olduğunu tespit eder.
- **Zayıf Sertifika İmzası (`tls_weak_signature`):** TLS sertifikasının güvenliği kırılmış SHA-1 veya MD5 algoritmalarıyla imzalandığını tespit eder.
- **Süresi Dolmuş Sertifika (`tls_cert_expired`):** Aktif TLS sertifikasının son kullanma tarihinin geçtiğini (expired) belirler.
- **Joker Karakter Sertifika (`tls_wildcard_cert`):** Alan adı için `*.domain.com` şeklinde joker karakterli sertifika kullanıldığını raporlar.
- **Veri Merkezi & Bulut Barındırma Tespiti (`datacenter_hosting_detected`):** Hedef IP adresinin hangi veri merkezinde veya bulut sağlayıcısında (AWS, Cloudflare, DigitalOcean, Hetzner, OVH, Azure vb.) barındırıldığını ve kategori türünü tespit eder.
- **Ağ Coğrafi Konumu (`ip_geolocation_identified`):** Hedef sunucunun RIPEstat / RDAP tabanlı şehir, ülke ve koordinat (enlem/boylam) bilgilerini haritalandırır.
- **BGP Yönlendirme Özeti (`bgp_routing_identified`):** Hedef IP'nin anons edildiği BGP CIDR öneği, origin ASN ve otonom sistem sahibini listeler.
- **robots.txt Tarafından Gizlenen Yollar (`robots_disallowed_paths`):** `robots.txt` içerisinde arama motorlarına kapatılmış yönetim panelleri (`/admin`), yedekler (`/backup`) veya API uç noktaları tespit edildiğinde listeler.
- **Açıkta Kalan Hassas Medya ve Belgeler (`media_documents_exposed`):** Site haritasında indekslenmiş PDF, Office belgeleri, arşiv (`.zip`/`.tar`) veya veritabanı dökümleri (`.sql`) gibi doğrudan indirilebilir dosyaları vurgular.
- **Kenar Koruması Tespiti (`edge_protection_active`):** Cloudflare, CloudFront, Akamai, Fastly, Sucuri veya Imperva gibi WAF/CDN platformları tespit edildiğinde anons edilen IP'nin doğrudan kaynak sunucu olmayabileceğini raporlar.
- **Sertifika Bitiş Uyarısı (`tls_expiring_soon`):** Canlı TLS sertifikasının süresi 30 günün altına indiğinde erken yenileme uyarısı üretir.
- **Kendinden İmzalı Sertifika (`tls_self_signed`):** Aktif TLS sertifikası güvenilir bir otorite (CA) tarafından imzalanmamışsa işaretler.
- **SOA Standart Uyumsuzluğu (`soa_rfc1912_issues`):** SOA parametreleri RFC 1912 tavsiyelerinin dışındaysa (örn. çok kısa expire veya refresh süreleri) vurgular.
- **SPF 10-Sorgu Limiti (`spf_lookup_limit_exceeded`):** SPF kaydındaki mekanizmaların 10 sorguyu aşıp aşmadığını denetler (RFC 7208 PermError riski).
- **Zayıf DKIM Anahtarı (`dkim_weak_key`):** Tespit edilen DKIM açık anahtarlarında 1024-bit gibi zayıf RSA anahtarlarını işaretler (modern standartlar minimum 2048-bit gerektirir).
- **CAA Yetkilendirme Politikası (`caa_policy_configured`):** CAA kaydında yetkilendirilen sertifika otoritelerini (`issue`, `issuewild`, `iodef`) listeler.
- **Sunucu Sürüm Sızıntısı (`server_version_disclosure`):** `Server` veya `X-Powered-By` başlıklarında sürüm veya teknoloji ifşasını yakalar.
- **Harici SaaS CNAME Yönlendirmesi (`external_service_cname`):** CNAME kaydı AWS S3, GitHub Pages, Azure, Heroku veya Shopify gibi dış servislere işaret eden hedefleri tespit eder.
- **Bulut Ayak İzi Özeti (`cloud_footprint_summary`):** TXT doğrulamalarından Google, Microsoft, Atlassian, Adobe, Apple, Stripe, Meta gibi entegrasyonları listeler.
- **Ortak IP Grubu (`shared_ip`):** Birden fazla alan adının aynı IP'ye çözümlendiği durumları belirler.
- **Kronolojik Zaman Çizelgesi (`timeline`):** Alan adı tescili, sertifika yayınlanması, arşiv enstantaneleri ve tarama tarihlerini tek bir kronolojik akışta sıralar.
- **Varlık Dağılım Matrisi (`entities`):** Bulguları Alan Adları, Ağ/Yönlendirme, Posta/İletişim, Bulut/Altyapı ve Güvenlik/Kimlik sepetlerine ayırır.

## Rapor Dosyaları ve İnteraktif Arayüz

Her analiz çalışmasında belirtilen çıktı klasörüne 6 dosya otomatik olarak yazılır:

1. **`report.html`:** Çift tıklandığında modern siber güvenlik / hacker operasyon paneli estetiğinde açılan interaktif koyu tema rapor.
   - **Siber Güvenlik Tasarımı:** Derin siyah arka plan (`#060a10`), neon yeşil (`#00ff66`), neon mavi (`#00e5ff`) vurgular, canlı gösterge kartları ve durum rozetleri (`🔴 KRİTİK`, `🟡 UYARI`, `🔵 BİLGİ`, `🟢 GÜVENLİ`).
   - **Gezinme Hapları (Nav Pills):** Genel Bakış, Risk Analizi, Varlık Matrisi, İlişki Haritası, Zaman Çizelgesi ve Tablo sekmeleri arasında hızlı atlama.
   - **Tek Tıkla Dışa Aktarma:** Rapor içerisinden tek tıkla `report.md` (Markdown), `report.json` ve `findings.csv` dosyalarını doğrudan tarayıcı üzerinden anında indirme.
   - **Varlık İnceleme Çekmecesi (Inspector):** İlişki grafiğindeki herhangi bir düğüme tıklandığında bağlı ilişkileri ve kanıtları listeleyen canlı panel.
   - **XSS & İzolasyon Koruması:** Dahili veriler Base64 katmanıyla script enjeksiyonuna karşı korunur; dış CDN veya yazı tipi bağlantısı gerektirmez (%100 çevrimdışı).
2. **`report.md`:** GitHub, Obsidian, Notion veya Markdown destekli tüm editörlerde renkli ve yapılandırılmış tablolarla açılan profesyonel siber istihbarat raporu.
   - Hedef ve görev üstbilgileri, risk değerlendirme tablosu, IP/ASN/Veri merkezi haritası, DNS/alt alan adları, SSL/TLS kripto profili, çerez güvenlik bayrakları, açık port/banner bilgileri ve kronolojik zaman çizelgesi içerir.
3. **`report.json`:** Bütün bulgular, kaynak URL'leri, kanıt nesneleri, zaman çizelgesi, varlık matrisi ve analiz çıktılarını barındıran tam veri dosyası.
4. **`findings.csv`:** Kanıt seviyesinde ayrıştırılmış veri tablosu. E-tablolarda formül enjeksiyonu (`=`, `+`, `-`, `@`) riskine karşı güvenli hücre koruması uygulanır.
5. **`graph.graphml`:** Gephi gibi ağ ve bağlantı analizi yazılımlarına doğrudan aktarılabilen, kenarlarında ilişki ve kanıt verisi taşıyan XML tabanlı grafik.
6. **`graph.dot`:** Graphviz ile görselleştirilebilen, düğümleri varlık kategorisine göre renklendirilmiş Directed Graph (DOT) dosyası.

## Karşılaştırma Modu (`--compare`)

```sh
python -m draxen example.com --deep --verify 5 --output reports/t1
python -m draxen example.com --deep --verify 5 --compare reports/t1/report.json --output reports/t2
```

- İki çalışma arasındaki yeni gözlenen bulguları, aynı kalanları ve yeni çalışmada görülmeyenleri listeler.
- Görülmeyen bir bulgu **silinmiş** olarak adlandırılmaz; geçici kaynak kesintisi veya parametre farkı olabileceği uyarısı raporda yer alır.
- Karşılaştırma ağ sorguları başlamadan önce dosya tipi ve hedef bütünlüğü açısından doğrulanır.

## Düşük Yoğunluk İlkeleri ve Güvenlik Korumaları

- **Düşük Yoğunluklu ve Saygılı Tarama:** Geniş hacimli saldırgan taramalar, kaba kuvvet parola denemeleri veya zafiyet istismarı yapmaz. Port ve alt alan adı kontrollerinde yalnızca kritik hedefleri hız sınırlı (rate-limited) ve zaman aşımı korumalı olarak sorgular.
- **Özel Ağ Koruması (SSRF Koruması):** `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254` ve IPv6 yerel/özel adresleri bağlantı öncesinde reddedilir.
- **İstek Bütçesi ve Hız Sınırı:** `--budget` (varsayılan 40) ve `--delay` (en az 1.0 saniye) ile hedef sunuculara veya açık servislere yük bindirilmez.
- **Saygılı Ana Sayfa Okuması:** `--web` seçildiğinde önce `robots.txt` kontrol edilir. Erişim yasaksa veya `Crawl-delay` 60 saniyeden uzunsa istek iptal edilir.
- **Kesinti Güvenliği:** `Ctrl+C` ile durdurulduğunda o ana kadar toplanmış veriler **kısmi rapor** olarak güvenle diske kaydedilir.

## Testler

Birim, entegrasyon ve terminal arayüzü regresyon testleri dış ağa bağlanmadan çalışır. Arayüz testleri dar/geniş ekranları, Unicode hücre genişliğini, ANSI/ASCII geri dönüşlerini, yönlendirmeyi, sessiz modu, demo güvenliğini ve kesinti temizliğini kapsar:

```sh
python -m unittest discover -s tests -v
python -m compileall -q draxen tests tools
```
