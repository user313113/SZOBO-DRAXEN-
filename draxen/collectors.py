import ipaddress
import re
import urllib.parse
import urllib.robotparser
from html.parser import HTMLParser

from .core import BudgetExceeded, FetchError, domain_name, public_ip
from .crawlers import CrawlerAnalyzer
from .enrichment import Enrichment, scoped_host
from .fingerprints import CNAME_SERVICES, MX_PROVIDERS, NS_PROVIDERS, match_provider, match_txt
from .http_audit import HttpAuditor
from .infra import detect_edge_from_cname, detect_rir, parse_soa_record
from .mail_security import COMMON_DKIM_SELECTORS, parse_caa_record, parse_dkim_key, parse_spf_record
from .network_intel import NetworkIntelligence
from .port_scanner import PortScanner
from .subdomain_discovery import SubdomainDiscoverer
from .rdap import lookup
from .security import SecurityCollector
from .tls_inspector import inspect_tls


DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA"}


class Collector:
    def __init__(self, client, report, target, limit=100, verify=0, web=False, progress=None, archives=False, network=False, mail=False, security=False, infra=False, sitemap=False, brute=False, ports=False):
        self.client = client
        self.report = report
        self.target = target
        self.limit = limit
        self.verify = verify
        self.web = web
        self.progress = progress or (lambda text: None)
        self.candidates = set()
        self.ips = set()
        self.archives = archives
        self.network = network
        self.mail = mail
        self.security = security
        self.infra = infra
        self.sitemap = sitemap
        self.brute = brute
        self.ports = ports
        self.enrichment = Enrichment(self)
        self.sec_collector = SecurityCollector(self)
        self.http_auditor = HttpAuditor(self.client, self.report, self.target.domain)
        self.crawler = CrawlerAnalyzer(self.client, self.report, self.target.domain, limit=self.limit, candidates=self.candidates)
        self.network_intel = NetworkIntelligence(self.client, self.report)
        self.sub_discoverer = SubdomainDiscoverer(self, limit=35)
        self.port_scanner = PortScanner(self.report, timeout=min(1.5, getattr(self.client, 'timeout', 2.0)), client=self.client)

    def run_source(self, name, operation):
        before = len(self.report.data["findings"])
        self.progress(name)
        try:
            operation()
            self.report.source(name, "ok", len(self.report.data["findings"]) - before)
        except (FetchError, ValueError, TypeError, KeyError, AttributeError) as exc:
            self.report.source(name, "incomplete", len(self.report.data["findings"]) - before, str(exc))

    def inspect_live_tls(self):
        if not self.target.domain:
            return
        res = inspect_tls(self.target.domain, timeout=getattr(self.client, "timeout", 10))
        if not res:
            return
        self.report.add("tls_protocol", f"{res['protocol']} ({res['cipher']})", f"https://{self.target.domain}:443", "observed", subject=self.target.domain, relation="tls_handshake", details=res)
        if res.get("issuer_cn") or res.get("issuer_org"):
            issuer_label = res.get("issuer_org") or res.get("issuer_cn")
            self.report.add("tls_certificate", f"Issuer: {issuer_label}, Expiry: {res['not_after']}, Alg: {res.get('signature_algorithm', 'Bilinmiyor')}", f"https://{self.target.domain}:443", "observed", subject=self.target.domain, relation="active_cert", details=res)
        if res.get("is_weak_signature"):
            self.report.add("tls_weak_signature", f"Zayıf İmza Algoritması: {res['signature_algorithm']}", f"https://{self.target.domain}:443", "cryptographic_audit", subject=self.target.domain, relation="weak_signature", details=res)
        for san in res.get("sans", []):
            scoped = scoped_host(san, self.target.domain)
            if scoped:
                self.report.add("discovered_domain", scoped, f"https://{self.target.domain}:443", "observed", subject=self.target.domain, relation="cert_san")
                if scoped != self.target.domain:
                    self.candidates.add(scoped)

    def run(self):
        if self.target.kind == "email":
            self.report.add("domain", self.target.domain, "user_input", "input", relation="email_domain")
            self.report.warn("E-posta girişi yalnızca alan adını araştırır; posta kutusu varlığı, sahibi veya sızıntı durumu doğrulanmaz.")
            if self.security:
                self.run_source("Profil / Gravatar", self.sec_collector.gravatar)
        if self.target.domain:
            self.run_source("DNS / Google Public DNS + Cloudflare yedeği", self.dns)
            if self.brute:
                self.run_source("Kelime Listesi ile Alt Alan Adı Keşfi (Brute-Force)", self.sub_discoverer.run)
            self.run_source("RDAP / alan adı", lambda: self.rdap(self.target.domain, "domain"))
            self.run_source("Sertifika şeffaflığı / crt.sh", self.certificates)
            if self.archives:
                self.run_source("Wayback / CDX", self.enrichment.wayback)
                self.run_source("urlscan / mevcut kayıtlar", self.enrichment.urlscan)
            if self.mail:
                for prefix, marker, relation in (("_mta-sts.", "v=STSv1", "MTA-STS"), ("_smtp._tls.", "v=TLSRPTv1", "TLS-RPT"), ("default._bimi.", "v=BIMI1", "BIMI")):
                    self.run_source(relation, lambda prefix=prefix, marker=marker, relation=relation: self.enrichment.mail_record(prefix + self.target.domain, marker, relation))
                self.run_source("DNSSEC kayıtları", self.enrichment.dnssec)
                self.run_source("DKIM Anahtar Taraması", self.dkim_hunt)
            if self.security:
                self.run_source("Güvenlik Politikası / security.txt", self.sec_collector.security_txt)
                self.run_source("HTTP Güvenlik Başlıkları", self.http_auditor.audit_headers)
            if self.sitemap:
                self.run_source("Site Haritası & robots.txt Analizi", self.crawler.run)
            if self.infra:
                self.run_source("Altyapı / TLS Kriptografik Profil", self.inspect_live_tls)
                for ip in sorted(self.ips)[:3]:
                    rir_name = detect_rir(ip)
                    self.report.add("rir_registry", rir_name, "local_calculation", "observed", subject=ip, relation="regional_internet_registry")
            if self.network:
                for ip in sorted(self.ips)[:3]:
                    self.run_source("RIPEstat / " + ip, lambda ip=ip: self.enrichment.network(ip))
                    self.run_source("Ağ Konumu & Veri Merkezi / " + ip, lambda ip=ip: self.network_intel.analyze_ip(ip))
            if self.ports:
                for ip in sorted(self.ips)[:3]:
                    self.run_source("Port & Servis Banner Taraması / " + ip, lambda ip=ip: self.port_scanner.scan_ip(ip))
            if self.verify:
                self.run_source("Kaynaklardan bulunan adayların DNS kontrolü", self.verify_candidates)
            for ip in sorted(self.ips)[:3]:
                self.run_source("RDAP / " + ip, lambda ip=ip: self.rdap(ip, "ip"))
            if self.web:
                self.run_source("Herkese açık ana sayfa", self.homepage)
        else:
            self.run_source("RDAP / IP", lambda: self.rdap(self.target.value, "ip"))
            self.run_source("Ters DNS", self.reverse_dns)
            if self.infra:
                rir_name = detect_rir(self.target.value)
                self.report.add("rir_registry", rir_name, "local_calculation", "observed", subject=self.target.value, relation="regional_internet_registry")
            if self.network:
                self.run_source("RIPEstat / IP", lambda: self.enrichment.network(self.target.value))
                self.run_source("Ağ Konumu & Veri Merkezi / IP", lambda: self.network_intel.analyze_ip(self.target.value))
            if self.ports:
                self.run_source("Port & Servis Banner Taraması / IP", lambda: self.port_scanner.scan_ip(self.target.value))
        self.report.warn("Açık kaynak kayıtları eksik veya eski olabilir. DNS kaydı hizmetin erişilebilirliğini, CT kaydı ise güncel DNS varlığını veya sahipliği kanıtlamaz.")
        return self.report.finish(self.client.requests)

    def query_dns(self, name, record_type):
        url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": name, "type": record_type})
        try:
            data = self.client.json(url)
        except BudgetExceeded:
            raise
        except FetchError:
            url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": record_type})
            data = self.client.json(url, accept="application/dns-json")
            self.report.warn("En az bir Google DNS sorgusu başarısız oldu; Cloudflare yedek çözümleyicisi kullanıldı.")
        if not isinstance(data, dict) or "Status" not in data:
            raise FetchError("Beklenmeyen DNS yanıtı")
        code = data["Status"]
        if code not in (0, 3):
            raise FetchError(f"DNS {name}/{record_type} durum kodu: {code}")
        if code == 3:
            return [], url
        return data.get("Answer", []), url

    def dkim_hunt(self):
        for sel in COMMON_DKIM_SELECTORS:
            name = f"{sel}._domainkey.{self.target.domain}"
            try:
                answers, url = self.query_dns(name, "TXT")
            except (FetchError, BudgetExceeded):
                continue
            for answer in answers:
                if answer.get("type") == 16:
                    val = str(answer.get("data", ""))
                    if "v=dkim1" in val.lower() or "p=" in val.lower():
                        info = parse_dkim_key(val)
                        preview = info.get("public_key_preview", "")
                        self.report.add("dkim_record", f"{sel}: {preview}", url, "dns_observed", subject=self.target.domain, relation="dkim_key", details=info)

    def dns(self):
        failures = []
        for kind in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"):
            try:
                answers, url = self.query_dns(self.target.domain, kind)
            except BudgetExceeded:
                raise
            except FetchError as exc:
                failures.append(f"{kind}: {exc}")
                continue
            for answer in answers:
                record = DNS_TYPES.get(answer.get("type"), str(answer.get("type")))
                value = str(answer.get("data", ""))
                owner = str(answer.get("name", self.target.domain)).rstrip(".")
                self.report.add("dns_" + record.lower(), value, url, "dns_observed", subject=owner, relation=record, details={"ttl": answer.get("TTL")})
                if record in ("A", "AAAA") and public_ip(value):
                    self.ips.add(value)
                if record == "MX":
                    provider = match_provider(value, MX_PROVIDERS)
                    if provider:
                        self.report.add("identified_service", provider, url, "dns_observed", subject=self.target.domain, relation="mail_provider")
                if record == "NS":
                    provider = match_provider(value, NS_PROVIDERS)
                    if provider:
                        self.report.add("identified_service", provider, url, "dns_observed", subject=self.target.domain, relation="dns_provider")
                if record == "CNAME":
                    target_svc = match_provider(value, CNAME_SERVICES)
                    if target_svc:
                        self.report.add("external_service_pointer", f"{owner} -> {target_svc}", url, "dns_observed", subject=owner, relation="cname_target", details={"target": value, "service": target_svc})
                    edge_cname = detect_edge_from_cname(value)
                    if edge_cname:
                        self.report.add("edge_infrastructure", f"{edge_cname} (CNAME)", url, "dns_observed", subject=owner, relation="cdn_waf", details={"cname": value})
                if record == "SOA":
                    soa_info = parse_soa_record(value)
                    if soa_info:
                        if soa_info.get("hostmaster_email"):
                            self.report.add("dns_hostmaster", soa_info["hostmaster_email"], url, "dns_observed", subject=self.target.domain, relation="hostmaster")
                        self.report.add("soa_architecture", f"Serial: {soa_info['serial']}, Refresh: {soa_info['refresh_seconds']}s, Expire: {soa_info['expire_seconds']}s", url, "dns_observed", subject=self.target.domain, relation="soa_parameters", details=soa_info)
                if record == "CAA":
                    caa = parse_caa_record(value)
                    if caa:
                        self.report.add("dns_caa_directive", f"{caa['tag']}: {caa['value']}", url, "dns_observed", subject=owner, relation="caa_" + caa["tag"], details=caa)
                if record == "TXT":
                    if "v=spf1" in value.lower():
                        self.report.add("email_policy", value, url, "dns_observed", subject=owner, relation="SPF")
                        spf_details = parse_spf_record(value)
                        for svc_name, inc_target in spf_details["authorized_services"]:
                            self.report.add("cloud_footprint", f"{svc_name} (SPF Yetkili Gönderici)", url, "dns_observed", subject=self.target.domain, relation="spf_sender", details={"include": inc_target})
                    for label, vendor, token in match_txt(value):
                        self.report.add("cloud_footprint", f"{vendor} ({label})", url, "dns_observed", subject=owner, relation="cloud_integration", details={"token": token})
        try:
            answers, url = self.query_dns("_dmarc." + self.target.domain, "TXT")
        except BudgetExceeded:
            raise
        except FetchError as exc:
            failures.append(f"DMARC: {exc}")
            answers, url = [], ""
        for answer in answers:
            if answer.get("type") == 16 and "v=dmarc1" in str(answer.get("data", "")).lower():
                self.report.add("email_policy", answer["data"], url, "dns_observed", subject=self.target.domain, relation="DMARC")

        if failures:
            raise FetchError("Bazı DNS kayıtları alınamadı: " + "; ".join(failures))

    def certificates(self):
        url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + self.target.domain, "output": "json"})
        data = self.client.json(url)
        if not isinstance(data, list):
            raise FetchError("Beklenmeyen CT yanıtı")
        candidates = {}
        for row in data:
            for raw in str(row.get("name_value", "")).splitlines():
                wildcard = raw.startswith("*.")
                try:
                    name = domain_name(raw[2:] if wildcard else raw)
                except ValueError:
                    continue
                if name != self.target.domain and not name.endswith("." + self.target.domain):
                    continue
                label = "*." + name if wildcard else name
                details = {key: row[key] for key in ("id", "issuer_name", "not_before", "not_after", "entry_timestamp") if key in row}
                previous = candidates.get(label)
                if previous is None or str(details.get("not_before", "")) > str(previous.get("not_before", "")):
                    candidates[label] = details
        ordered = sorted(candidates)
        if len(ordered) > self.limit:
            self.report.warn(f"CT: {len(ordered)} benzersiz ad içinden {self.limit} tanesi gösterildi (--limit).")
        for name in ordered[:self.limit]:
            self.report.add("certificate_name", name, url, "historical_candidate", subject=self.target.domain, relation="certificate_mentions", details=candidates[name])
            if not name.startswith("*.") and name != self.target.domain:
                self.candidates.add(name)

    def verify_candidates(self):
        selected = sorted(self.candidates)[:self.verify]
        if len(self.candidates) > len(selected):
            self.report.warn(f"DNS kontrolü {len(selected)}/{len(self.candidates)} kaynak adayı ile sınırlandı.")
        if selected:
            self.report.warn("Aday DNS yanıtları wildcard DNS kaynaklı olabilir; rastgele adlarla wildcard testi yapılmaz.")
        for name in selected:
            for kind in ("A", "AAAA"):
                answers, url = self.query_dns(name, kind)
                for answer in answers:
                    if answer.get("type") in (1, 28):
                        value = str(answer.get("data", ""))
                        self.report.add("dns_" + DNS_TYPES[answer["type"]].lower(), value, url, "dns_observed", subject=name, relation="resolves_to", details={"ttl": answer.get("TTL")})

    def rdap(self, value, kind):
        data, url, fallback = lookup(self.client, value, kind)
        if fallback:
            self.report.warn("En az bir RDAP sorgusunda IANA yönlendirme listesi üzerinden yetkili hizmet yedeği kullanıldı.")
        if not isinstance(data, dict) or "objectClassName" not in data:
            raise FetchError("Beklenmeyen RDAP yanıtı")
        for field in ("handle", "name", "ldhName", "startAddress", "endAddress", "ipVersion", "country", "type", "port43"):
            if data.get(field):
                self.report.add("registration_" + field, data[field], url, "registry_reported", subject=value, relation=field)
        for status in data.get("status", []):
            self.report.add("registration_status", status, url, "registry_reported", subject=value, relation="status")
        for event in data.get("events", []):
            if event.get("eventDate"):
                self.report.add("registration_event", event["eventDate"], url, "registry_reported", subject=value, relation=str(event.get("eventAction", "event")))
        for ns in data.get("nameservers", []):
            if ns.get("ldhName"):
                self.report.add("nameserver", ns["ldhName"], url, "registry_reported", subject=value, relation="nameserver")
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            card = entity.get("vcardArray", [])
            if len(card) != 2 or not isinstance(card[1], list):
                continue
            for item in card[1]:
                if not isinstance(item, list) or len(item) < 4 or item[0] not in ("fn", "org", "email"):
                    continue
                content = item[3]
                if isinstance(content, list):
                    content = "; ".join(str(part) for part in content)
                if content:
                    self.report.add("registry_contact_" + item[0], content, url, "registry_reported", subject=value, relation="registry_contact", details={"roles": roles})
        self.report.warn("RDAP kişi/kuruluş bilgisi gizlilik servisine veya kayıt kuruluşuna ait olabilir; IP ülkesi kullanıcının fiziksel konumu değildir.")

    def reverse_dns(self):
        name = ipaddress.ip_address(self.target.value).reverse_pointer
        answers, url = self.query_dns(name, "PTR")
        for answer in answers:
            if answer.get("type") == 12:
                self.report.add("ptr", answer["data"].rstrip("."), url, "dns_observed", relation="reverse_dns")

    def homepage(self):
        root = "https://" + self.target.domain
        robots_url = root + "/robots.txt"
        try:
            text, final = self.client.get(robots_url, "text/plain")
        except FetchError as exc:
            raise FetchError(f"robots.txt okunamadı; ana sayfa isteği yapılmadı: {exc}") from exc
        if urllib.parse.urlsplit(final).hostname != self.target.domain:
            raise FetchError("robots.txt başka bir alan adına yönlendi; ana sayfa isteği yapılmadı")
        parser = urllib.robotparser.RobotFileParser()
        parser.parse(text.splitlines())
        if not parser.can_fetch("SZOBO-DRAXEN", root + "/"):
            raise FetchError("robots.txt ana sayfa erişimine izin vermiyor")
        delay = parser.crawl_delay("SZOBO-DRAXEN")
        if delay and delay > 60:
            raise FetchError("robots.txt 60 saniyeden uzun bekleme istiyor; ana sayfa isteği yapılmadı")
        if delay and delay > self.client.delay:
            self.client.delay = delay
        body, final = self.client.get(root + "/", "text/html")
        final_host = urllib.parse.urlsplit(final).hostname or ""
        if final_host != self.target.domain and not final_host.endswith("." + self.target.domain):
            self.report.warn("Ana sayfa kapsam dışı bir alan adına yönlendi; içerik analize alınmadı.")
            return
        page = PageParser()
        page.feed(body)
        visible = " ".join(page.text)
        for email in sorted(set(re.findall(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", visible + " " + " ".join(page.emails))))[:self.limit]:
            try:
                host = domain_name(email.rsplit("@", 1)[1])
            except ValueError:
                continue
            if host == self.target.domain or host.endswith("." + self.target.domain):
                self.report.add("public_email", email, final, "page_observed", subject=self.target.domain, relation="publishes_email")
        if page.title:
            self.report.add("page_title", " ".join(page.title).strip()[:300], final, "page_observed", subject=self.target.domain, relation="title")
        for href in sorted(set(page.links))[:self.limit]:
            parsed = urllib.parse.urlsplit(urllib.parse.urljoin(final, href))
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
                continue
            host = parsed.hostname.lower()
            if host == self.target.domain or host.endswith("." + self.target.domain):
                if host != self.target.domain:
                    self.report.add("linked_subdomain", host, final, "page_observed", subject=self.target.domain, relation="links_to")
            elif any(host == site or host.endswith("." + site) for site in ("github.com", "linkedin.com", "x.com", "twitter.com", "instagram.com", "facebook.com", "youtube.com")):
                self.report.add("social_link", urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")), final, "page_observed", subject=self.target.domain, relation="links_to")
        self.report.warn("Sayfadaki e-posta ve sosyal bağlantılar yalnızca yayınlanmış referanslardır; kişi kimliği veya hesap sahipliği doğrulanmaz.")


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.emails = []
        self.links = []
        self.title = []
        self.hidden = 0
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1
        if tag == "title":
            self.in_title = True
        if tag == "a" and not self.hidden:
            href = dict(attrs).get("href", "")
            if href.lower().startswith("mailto:"):
                self.emails.append(urllib.parse.unquote(href[7:].split("?", 1)[0]))
            else:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.in_title:
                self.title.append(data)
