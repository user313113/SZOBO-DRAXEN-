# Değişiklikler

## Geliştirme — Açılış Animasyonu ve Erişim Kontrolü

- Kontrol merkezi (`sh start.sh`, hedefsiz `python3 -m draxen`, `--ui`) artık bir açılış sekansıyla başlar: gerçek yerel değerlerden okunan **SİSTEM** boot paneli (çekirdek/Python, terminal ölçüsü ve renk derinliği, modül sayısı, "AĞ: açılışta istek yok"), ardından SZOBO / DRAXEN logosunun parıltılı silüetten soldan sağa gradyanla açılması. Son kare ana ekrandaki başlıkla birebir aynıdır; logo yer değiştirmez.
- Yeni `draxen/gate.py`: **ERİŞİM KONTROLÜ** şifre kapısı. Varsayılan şifre `szobodraxen1881`; kaynakta yalnızca PBKDF2-HMAC-SHA256 özeti tutulur, karşılaştırma sabit zamanlıdır, giriş `getpass` ile gizlenir. Üç hatalı denemede **KİLİTLENDİ** (çıkış 1), her hatadan sonra artan bekleme; `Ctrl+C` 130, `Ctrl+D` 1 ile çıkar. Doğru şifrede **ERİŞİM ONAYLANDI** ve menü.
- Animasyon duvar saatine göre planlanır (≈2,5 sn): yavaş cihazlarda kare atlanır, süre uzamaz; özdeş kareler yeniden çizilmez. **Enter** atlar; animasyon sırasında yazılan şifre ilk deneme sayılır. Gizli imleç, alternatif ekran veya ham mod yok; yalnızca görünür ekran yeniden çizilir.
- `TerminalUI.banner_lines` `reveal`/`shimmer` parametreleri ve `Span.rgb` alanı; ASCII eşlemesine `▒` eklendi. Tüm ekranlar 20–160 kolon / 12–40 satır için yerleşim testlerinden geçer; `--ascii` ve `--color never` ile saf ASCII üretir.
- Kapı yalnızca etkileşimli menüyü korur: hedefli taramalar, `--demo`, `--banner`, `--tools`, `--meta`, pipe ve `--quiet` akışları şifre sormaz.
- Testler: özet/doğrulama, kare yerleşimi ve logo sürekliliği, kare atlama, atlama/ön yazım (gerçek pipe), 3 hatalı deneme, EOF/kesme; gerçek PTY üzerinden gizli şifre girişi, red, onay, menü gezintisi ve kilitlenme.

## Geliştirme — Test Araçları Kataloğu (05 / --tools)

- Menüye **05 ARAÇLAR** eklendi: `data/test_tools.json` dosyasındaki hazır test araçları sayfalı liste, anında arama ve Tool-X tarzı araç detay sayfalarıyla listelenir. Mevcut 01–04 / H / Q seçenekleri ve tarama akışları değişmeden korunur.
- Araç detay sayfası açıklama, kategori, önerilen kurulum komutu, bağımlılıklar ve bağlantıyı gösterir; DRAXEN listedeki hiçbir aracı indirmez, kurmaz veya çalıştırmaz (yalnızca listeleme + etik kullanım uyarısı).
- Yeni **`--tools [FILTRE]`** komut satırı seçeneği: kataloğu çevrimdışı listeler, filtreyle daraltır; hedef, `--compare` veya keşif modülleriyle birleştirilemez.
- Yeni `draxen/tool_registry.py` modülü: bozuk/eksik JSON'u Türkçe hata mesajıyla karşılar, alanları normalleştirir, ad/URL/kategori üzerinden büyük/küçük harf duyarsız arama yapar.
- `tools/package_terminal.py` artık `data/test_tools.json` dosyasını taşınabilir ZIP'e ekler; 05 seçeneği pakette de çalışır.
- Testler: katalog yükleme/arama/normalleştirme, `--tools` komut akışları (filtre, çakışma, ağsız çıkış), 05 sayfası gezintisi ve ana menü yerleşimi regresyonları; tamamı çevrimdışı.

## Geliştirme — Gerçek Termux / iSH Kontrol Merkezi

- Hedefsiz açılıştaki uzun yardım dökümü yerine doğrudan terminalde çalışan 01–04 / H / Q menüsü. Keşif, onaylı derin analiz, yerel meta veri ve çevrimdışı demo menüden kullanılabilir.
- Referans görsele uygun yeni gömülü blok font: dolu harf yüzü, kontur/gölge, mor–mavi–camgöbeği–yeşil geçiş ve çift çizgili çerçeve. `SZOBO / DRAXEN` geniş ekranda yan yana, telefonda alt alta yazılır.
- Sadece genişliği değil yüksekliği de gözeten açılış, tarama başlangıcı ve kısa rapor; klavye girişi için ayrılan satırlar. Tüm kaynaklar/bulgular N/P ile sayfalı olarak okunur.
- `--ui`, `--banner` ve `--details` seçenekleri. Hedef ve açık başlatma onayı olmadan menü ağ isteği yapmaz. Pipe/quiet modları hiçbir zaman girdi beklemez.
- `start.sh` çalıştırıldığı klasörden bağımsız olarak kendi yanındaki kodu açar; eski global pip sürümüyle karışmayı önler. `tools/package_terminal.py` ile temiz, taşınabilir ZIP üretimi.
- Native PTY üzerinden açılış, demo gezintisi, 256 renk, ekran boyutu değişimi, sayfalama, EOF/Ctrl+C ve menüden çıkış testleri.

## Geliştirme — Duyarlı Terminal Arayüzü

- Standart kütüphaneyle çalışan, Rich tarzı hizalı terminal panelleri ve camgöbeği–mor geçişli blok/piksel DRAXEN logosu.
- Gerçek terminal genişliği/yüksekliğine göre kompakt logo, 2×2/4 sütun sayaçları, yan yana/alt alta kaynak ve varlık panelleri. Uzun hedef, URL, hata ve rapor yolları için hücre bazlı sarma.
- ANSI kodlarını ölçüme dahil etmeyen Unicode farkındalığı; Türkçe, birleşen aksanlar, geniş karakterler ve yaygın emoji dizileri için yerleşim testleri.
- Kaynak, bulgu, gerçek HTTP bütçesi ve geçen süreyi gösteren; yeniden boyutlandırmaya uyumlu, kesintide temizlenen canlı ilerleme satırı. Mevcut kısmi rapor ve çıkış kodları korunur.
- `--demo`, `--color auto/always/never`, `--ascii`, `--plain` ve `--width` seçenekleri. `NO_COLOR`, 24-bit/256/16 renk, `TERM=dumb`, eski kodlama ve pipe geri dönüşleri.
- Yardım, meta veri, analiz, karşılaştırma, uyarı ve rapor dosyaları için ortak görsel dil. Kritik göstergeler önce gösterilir; renksiz modda da durum etiketleri korunur.
- Uzak verilerdeki ANSI/OSC/DCS ve yön değiştirme kontrolleri terminalde çalıştırılmadan temizlenir. Tam rapor verileri sunum katmanında değiştirilmez.
- Gerçek ağ istemcisini kullanmayan, örnek verileri açıkça işaretleyen çevrimdışı demo ve `tools/preview_terminal.py` ile tarayıcı önizlemesi.

## 1.6.0

- **İstihbarat ve Parmak İzi Veritabanlarının 2 Kat Genişletilmesi:**
  - **Sözlük Tabanlı Alt Alan Adı Keşfi:** Popüler sözlük 35'ten **71 kritik alt alan adına** çıkarıldı (`corp`, `internal`, `jenkins`, `grafana`, `sso`, `gitlab`, `jira`, `confluence`, `k8s`, `monitoring`, `kibana`, `elastic`, `prometheus`, `vault`, `registry`, `intranet`, `prod`, `uat`, `qa`, `demo`, `sandbox`, `assets`, `static`, `media`, `ws`, `chat`, `sftp`, `relay`, `identity`, `connect`, `hub`, `manage`, `billing`, `node`, `edge` vb.).
  - **Port ve Servis Karşılama Taraması:** Taranan kritik TCP portları 10'dan **24 kritik servis portuna** genişletildi (21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 143 IMAP, 443 HTTPS, 465 SMTPS, 587 Submission, 993 IMAPS, 995 POP3S, 1433 MSSQL, 1521 Oracle, 3306 MySQL, 3389 RDP, 5432 PostgreSQL, 6379 Redis, 8080 HTTP-Proxy, 8443 HTTPS-Alt, 8888 HTTP-Alt2, 9200 Elasticsearch, 27017 MongoDB). Redis `INFO` banner çıkarma desteği eklendi.
  - **Veri Merkezi & Bulut Barındırma Tespiti:** Desteklenen veri merkezleri 24'ten **53 sağlayıcıya** çıkarıldı (IBM Cloud, Tencent, Baidu, Huawei, Imperva, Sucuri, GoDaddy, Namecheap, Bluehost, DreamHost, SiteGround, WP Engine, Fly.io, Vercel, Netlify, Kinsta, Cogent, Lumen/CenturyLink, Telia/Arelion, NTT, Tata, Deutsche Telekom, Orange, Radore, DGN, Niobe, Natro vb.).
  - **E-posta & MX Sağlayıcıları:** MX imza motoru 15'ten **30 sağlayıcıya** çıkarıldı (Barracuda, Trend Micro, Sophos, Cisco IronPort, McAfee, SpamExperts, Postmark, Amazon SES, SparkPost, Mandrill, Mailjet, Infomaniak, Tuta Mail, Rackspace, IONOS vb.).
  - **DNS & NS Sağlayıcıları:** NS imza motoru 12'den **24 DNS sağlayıcısına** çıkarıldı (Linode, Vultr, Oracle Dyn, easyDNS, ZoneEdit, Constellix, Hurricane Electric, Gandi, DNSimple, INWX, Hostinger, Alibaba Cloud vb.).
  - **SaaS / TXT Doğrulama İmzaları:** TXT doğrulama imzaları 14'ten **28 kurumsal platforma** çıkarıldı (Zoom, Notion, Dropbox, Pinterest, Yandex, OpenAI, Miro, Canva, Airtable, Postman, Linear, Intercom, 1Password, Bitbucket vb.).
  - **CNAME SaaS / Bulut Yönlendirmeleri:** CNAME tespit motoru 12'den **24 harici platforma** çıkarıldı (Azure Blob, Google Cloud Storage, Cloudflare Pages, Fly.io, Render, Railway, Surge.sh, GitBook, ReadMe, Statuspage, Zendesk, Freshdesk vb.).
  - **Kenar CDN / WAF Başlıkları & CNAME:** WAF/CDN imzaları 11'den **22 HTTP başlığına** (Highwinds, Kinsta, Vercel, Netlify, Fly.io, DataDome, Envoy, Kong, Varnish, Alibaba Cloud WAF vb.) ve 7'den **14 CNAME örüntüsüne** (Bunny CDN, StackPath, EdgeSuite, EdgeKey, HWCDN, Tencent, Kunlun) çıkarıldı.
  - **HTTP Güvenlik Başlıkları:** Denetlenen güvenlik başlıkları 6'dan **12 başlığa** çıkarıldı (`Cross-Origin-Embedder-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `X-Permitted-Cross-Domain-Policies`, `X-XSS-Protection`, `Clear-Site-Data`).
  - **DKIM Seçici Listesi:** Standart seçiciler 8'den **16 seçiciye** çıkarıldı (`smtp`, `dkim`, `m1`, `mx`, `key1`, `email`, `api`, `mailer`).
  - **X.509 Kriptografik İmza OID'leri:** İmza algoritmaları 9'dan **18 OID'ye** çıkarıldı (`SHA512-ECDSA`, `SHA224-RSA`, `SHA224-ECDSA`, `MD2-RSA`, `MD4-RSA`, `Ed448`, `RSASSA-PSS`, `ECC`, `RSA`).

- **Otomatik Rapor Oluşturucu (HTML / Markdown / JSON / CSV Export):**
  - **Siber Tehdit ve Hacker Paneli HTML Raporu (`report.html`):** Koyu tema siber güvenlik estetiği (neon yeşil `#00ff66`, neon mavi `#00e5ff`, uyarı sarı `#ffb703`, kritik kırmızı `#ff0055`), canlı metrik kartları, SVG ilişki topolojisi ve etkileşimli arama/filtreleme çekmecesi.
  - **Tek Tıkla Doğrudan İndirme:** HTML raporu içerisinden tek tıkla doğrudan `report.md`, `report.json` veya `findings.csv` olarak dışa aktarabilme.
  - **Kapsamlı Renkli Markdown Raporu (`report.md`):** Her tarama sonucunda otomatik üretilen; Yönetici Özeti, Risk Göstergeleri (🔴 KRİTİK, 🟡 UYARI, 🔵 BİLGİ), IP/ASN/Veri Merkezi Haritası, DNS Altyapısı, SSL/TLS Kripto Profili, Çerez (Cookie) Denetim Tablosu, Port/Banner Bilgileri ve Olay Zaman Çizelgesi tabloları.

- **SSL/TLS Sertifika Derin Analizi (Certificate Insights):**
  - Sertifika yetkilisi (CA Org ve CA CN), X.509 sürümü, seri numarası ve geçerlilik başlangıç/bitiş tarihleri.
  - Kalan gün sayısı (`days_until_expiry`) ve süresi dolmuş sertifika tespiti (`tls_cert_expired`).
  - X.509 DER ikili bayt analiziyle imza algoritması tespiti (SHA256-RSA, SHA384-RSA, SHA512-RSA, ECDSA, Ed25519) ve zayıf/eski algoritmaların (SHA-1, MD5) kriptografik güvenlik uyarısı (`tls_weak_signature`).
  - Joker karakterli (wildcard) sertifika kullanım tespiti (`tls_wildcard_cert`).

- **Çerez (Cookie) Güvenlik Bayrakları Denetçisi (`cookie_audit.py`):**
  - Hedef web sunucusunun yanıtlarında ilettiği `Set-Cookie` başlıklarının adli incelemesi.
  - `HttpOnly` bayrağı denetimi (istemci taraflı XSS oturum sızıntısı riskine karşı).
  - `Secure` bayrağı denetimi (şifresiz HTTP kanalları üzerinden çerez ifşasına karşı).
  - `SameSite` bayrağı denetimi (`Strict`, `Lax`, `None` ve `SameSite=None` bayrağının `Secure` olmadan kullanımı kontrolü; CSRF riskine karşı).
  - Eksik bayraklar için otomatik `cookie_security_weak` güvenlik göstergesi üretimi.

- **Yerel Sözlük Tabanlı Alt Alan Adı Keşfi (`--brute`):**
  - Dış API servislerine (crt.sh vb.) bağımlı kalmaksızın çalışan yerel DNS sözlük keşif motoru.
  - En yaygın 35 popüler alt alan adı ön eki (`www`, `mail`, `remote`, `blog`, `webmail`, `server`, `ns1`, `ns2`, `smtp`, `secure`, `vpn`, `api`, `dev`, `staging`, `test`, `admin`, `portal`, `app`, `login`, `beta`, `cloud`, `cpanel`, `support`, `autodiscover`, `git`, `dashboard`, `auth`, `m`, `gateway`, `direct`, `panel`, `status`, `stage`, `shop`, `cdn`).
  - Çözümlenen IP adreslerinin otomatik olarak hedef IP havuzuna ve doğrulama kuyruğuna aktarımı.

- **Temel Port ve Servis Banner Yakalama Modülü (`--ports`):**
  - Hedef sunucunun dışa açık kritik TCP servis portlarının (21 FTP, 22 SSH, 25 SMTP, 80 HTTP, 110 POP3, 143 IMAP, 443 HTTPS, 3306 MySQL, 8080 HTTP-Proxy, 8443 HTTPS-Alt) saygılı ve zaman aşımı korumalı tespiti.
  - Bağlantı sırasında servislerin gönderdiği karşılama mesajlarının (`banner`) okunması: SSH sürüm dizgileri (`OpenSSH`), HTTP `Server` başlıkları, SMTP ve FTP karşılama mesajları, MySQL handshake paketinden sunucu sürümü çıkarımı.
  - Dış ağa açık yönetim veya veritabanı portları için otomatik `exposed_management_port` uyarısı.
  - `--deep` modunda `--brute` ve `--ports` modüllerinin otomatik olarak devreye alınması.


## 1.5.0

- `--network` / `--netintel` / `--asn` (IP, ASN ve Ağ Konum İstihbaratı):
  - RIPEstat Geolocation API (`geoloc`) üzerinden hedefin ülke (`country`), şehir (`city`) ve coğrafi koordinatlarının (`latitude`, `longitude`) pasif tespiti ve tıklanabilir Google Maps koordinat eşleştirmesi.
  - RDAP IP ağı sorgulaması ile ağ blok adı (`net_name`, örn. `CLOUDFLARENET`, `AMAZON-EC2`, `HETZNER-EU`) ve tahsis edilen IP aralığı (`ip_range`, örn. `104.16.0.0 - 104.31.255.255`) çıkarımı.
  - Veri Merkezi ve Bulut Sağlayıcısı Parmak İzi Tespiti (`DATACENTER_PROVIDERS`): Hedef IP'nin ASN, ASN sahibi kuruluşu ve RDAP ağ adı taranarak AWS, Google Cloud, Microsoft Azure, Cloudflare, DigitalOcean, Hetzner, OVHcloud, Linode/Akamai, Vultr, Fastly, Scaleway, Alibaba Cloud, Leaseweb, Contabo, UpCloud, Rackspace, Equinix, Türk Telekom, Turkcell Superonline, Vodafone ve TurkNet gibi 25+ kritik veri merkezi ve operatörün otomatik sınıflandırılması.
  - Yerel korelasyon motorunda yeni güvenlik içgörüleri:
    - `datacenter_hosting_detected`: Hedef sunucunun barındırıldığı veri merkezi ve bulut türünün (Hiperekolojik Bulut, Dedicated Sunucu, Anycast Kenar Ağı vb.) tespiti.
    - `ip_geolocation_identified`: Şehir, ülke ve koordinat detaylı coğrafi konum analizi.
    - `bgp_routing_identified`: BGP anons öneği, origin ASN ve otonom sistem sahibi özet raporu.
  - CLI üzerinden `--netintel` ve `--asn` takma adlarıyla doğrudan çağrılabilme desteği.

- `--meta DOSYA` seçeneği (Görsel ve Belge Meta Veri / EXIF Adli Analizcisi):
  - Harici pip / C bağımlılığı (Pillow, ExifTool vb.) gerektirmeksizin %100 saf Python standart kütüphanesiyle JPEG, PNG ve PDF analizi.
  - JPEG/TIFF IFD0 ve Exif IFD ayrıştırma: Kamera/cihaz markası (`Make`), modeli (`Model`), yazılımı (`Software`), çekim tarihi (`DateTimeOriginal`).
  - GPS IFD koordinat çözme: Enlem/boylam derecelerini ondalık derecelere dönüştürme ve doğrudan tıklanabilir Google Maps bağlantısı üretme.
  - PNG blok (chunk) analizi: `tEXt`, `zTXt` (zlib decompress) ve `iTXt` bloklarından yazar, başlık ve telif/araç verilerini çıkarma.
  - PDF meta veri ve XMP akışı ayrıştırma: `/Info` sözlüğünden Başlık, Yazar, Oluşturucu (`Creator`), Üretici (`Producer`) ve Oluşturulma tarihi çıkarma.
  - Komut satırında renkli konsol çıktısı ve opsiyonel `metadata_report.json` rapor dosyası üretimi.
- `--sitemap` seçeneği (robots.txt ve sitemap.xml Keşif Motoru):
  - `robots.txt` tarama kuralları: Engellenen (`Disallow`) hassas dizinler/yollar ve izin verilen (`Allow`) kuralların çıkarılması.
  - `sitemap.xml` analizi: `xml.etree.ElementTree` ile sitemap indeksleri ve URL listelerinin ayrıştırılması.
  - Açıkta kalan medya ve belge tespiti: `.pdf`, `.doc`, `.xls`, `.zip`, `.sql`, `.bak` gibi hassas dosyaların filtrelenmesi.
  - Hedef kapsamı içi yeni alt alan adlarının (subdomain) otomatik keşfi ve doğrulama kuyruğuna aktarımı.
  - `<lastmod>` zaman damgalarının otomatik kronolojik olay zaman çizelgesine (`Timeline`) entegrasyonu.
  - `--deep` modunda `--sitemap` analizinin otomatik olarak devreye alınması.


## 1.4.0

- `--infra` seçeneği (Altyapı, Kenar Güvenliği ve Kriptografik Profil Analizi):
  - WAF / CDN kenar platformu tespiti: Cloudflare, Amazon CloudFront, Akamai, Fastly, Sucuri, Imperva/Incapsula, Azure Front Door (HTTP yanıt başlıkları ve CNAME örüntüleri üzerinden).
  - DNS SOA (Start of Authority) mimarisi analizi: Primary NS (MNAME), Hostmaster e-postası (RNAME RFC 1035 dönüşümü), seri numarası tarih formatı kontrolü, Refresh, Retry, Expire süreleri ve RFC 1912 uyumluluk denetimleri.
  - Doğrudan port 443 TLS kriptografik el sıkışma profili: Müzakere edilen TLS protokol sürümü (TLSv1.2, TLSv1.3), şifreleme paketi (Cipher Suite), anahtar uzunluğu (bits), aktif sertifika yayıncısı, Subject Alternative Names (SANs) alt alan adı keşfi, bitişe kalan gün hesabı (`days_until_expiry`) ve kendinden imzalı (self-signed) sertifika tespiti.
  - IP adresleri için Bölgesel İnternet Kayıt Kuruluşu (RIR) tespiti: ARIN, RIPE NCC, APNIC, AFRINIC, LACNIC.
  - `--deep` modunda `--infra` modülünün otomatik olarak etkinleştirilmesi.

## 1.3.0

- RFC 7208 SPF derin analizi: 10 DNS sorgu limiti kontrolü (`exceeds_10_lookup_limit`), PermError riski tespiti ve `include:` direktiflerinden yetkili üçüncü taraf servis sağlayıcılarının otomatik ayrıştırılması.
- Yaygın DKIM anahtar seçicileri tespiti (`COMMON_DKIM_SELECTORS`): Base64 açık anahtar çözümleme, RSA anahtar uzunluğu (bit) kestirimi ve 1024-bit zayıf anahtar uyarıları (`dkim_weak_key`).
- DNS CAA (Sertifika Yetkilisi Yetkilendirme) yönergeleri ayrıştırması (`issue`, `issuewild`, `iodef`) ve politika özeti.
- Düşük yoğunluklu HTTP güvenlik başlıkları analizi (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- HTTP yanıt başlıklarından sunucu sürüm ve teknoloji sızıntısı tespiti (`Server`, `X-Powered-By`).
- HTML raporunda interaktif varlık inceleme çekmecesi (Inspector) ve gezinme hapları (Nav pills).
- HTML raporuna gömülü istemci taraflı Base64 JSON ve CSV indirme butonları (harici sunucu olmadan tek tıkla doğrudan dışa aktarma).
- XSS ve script enjeksiyonuna karşı HTML içi Base64 veri izolasyonu.

## 1.2.0

- `--security` seçeneği: RFC 9116 `security.txt` yönergeleri (Contact, Encryption, Policy, Hiring, Expires) ve e-posta hedefinde pasif Gravatar profil/kimlik keşfi.
- MX ve NS kayıtları üzerinden posta sağlayıcısı ve DNS altyapı parmak izi tespiti (Google Workspace, Microsoft 365, Proton, Cloudflare, AWS Route 53, Azure DNS vb.).
- TXT kayıtları üzerinden kurumsal bulut ve SaaS doğrulama imzalarının tespiti (Google, Microsoft, Atlassian, Adobe, Apple, DocuSign, Stripe, Slack, GitHub vb.).
- CNAME harici servis yönlendirmeleri ve SaaS bağımlılık analizi (AWS S3, GitHub Pages, Azure App Service, Heroku, WP Engine, Shopify vb.).
- RIPEstat ASN Overview üzerinden AS sahibi organizasyon adı (Holder) ve menşe ülke çıkarımı.
- Her genel IP için otomatik alt ağ (Subnet CIDR) hesaplaması.
- Bütünleşik kronolojik olay ve sertifika zaman çizelgesi motoru (`timeline`).
- Maltego tarzı varlık kategorizasyonu ve Varlık Dağılım Matrisi (`entities`).
- HTML ve DOT raporlarında varlık türlerine göre kategorik renk kodlamalı ilişki ağı.
- HTML raporunda interaktif Varlık Matrisi ve Kronolojik Zaman Çizelgesi tabloları.
- Terminal çıktısında varlık dağılımı ve güvenlik göstergeleri özeti.

## 1.1.0

- `--deep`, `--archives`, `--network`, `--mail` ve `--compare` seçenekleri.
- Wayback CDX ve urlscan mevcut kayıtlarından kapsam denetimli tarihsel keşif.
- RIPEstat BGP önek/origin ASN ilişkileri ve IP-önek tutarlılık kontrolü.
- MTA-STS, TLS-RPT, BIMI, DS ve DNSKEY kayıtları.
- RDAP.org erişim hatasında IANA bootstrap üzerinden HTTPS yetkili hizmet yedeği.
- Bağımsız temel DNS türlerinde hata izolasyonu.
- Kaynaklar arası ad korelasyonu, ortak IP grupları, açıklamalı SPF/DMARC değerlendirmeleri.
- Önceki raporla yeni/aynı/bu çalışmada görülmeyen kayıt karşılaştırması.
- CSV formül koruması ve kanıt metadatalı GraphML dışa aktarımı.
- HTML raporunda değerlendirme ve karşılaştırma bölümleri.
- Python 3.9/3.11/3.13 için test iş akışı.

## 1.0.0

- Standart kütüphane ile CLI, DNS, CT, RDAP, PTR ve isteğe bağlı ana sayfa toplama.
- Kaynak izlenebilir HTML/JSON/DOT çıktıları.
- Düşük yoğunluk sınırları, robots.txt kontrolü ve kısmi rapor kaydı.
