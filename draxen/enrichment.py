import ipaddress
import re
import urllib.parse

from .core import BudgetExceeded, FetchError, domain_name, public_ip


def scoped_host(raw, domain):
    try:
        name = domain_name(raw)
    except (ValueError, AttributeError):
        return None
    return name if name == domain or name.endswith("." + domain) else None


def clean_url(raw, domain):
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = scoped_host(parsed.hostname, domain)
        if parsed.scheme not in ("http", "https") or not host or parsed.username or parsed.password:
            return None
        port = parsed.port
        netloc = host + (":" + str(port) if port else "")
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))
    except (ValueError, TypeError):
        return None


class Enrichment:
    def __init__(self, collector):
        self.c = collector
        self.client = collector.client
        self.report = collector.report
        self.domain = collector.target.domain
        self.limit = collector.limit

    def discovered(self, host, source, status, relation, details=None):
        host = scoped_host(host, self.domain)
        if not host:
            return
        self.report.add("discovered_domain", host, source, status, subject=self.domain, relation=relation, details=details)
        if host != self.domain:
            self.c.candidates.add(host)

    def wayback(self):
        url = "https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode({
            "url": "*." + self.domain + "/*", "output": "json", "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey", "filter": "statuscode:200", "limit": self.limit,
        })
        data = self.client.json(url)
        if not isinstance(data, list):
            raise FetchError("Beklenmeyen Wayback yanıtı")
        if not data:
            return
        if not isinstance(data[0], list) or "original" not in data[0]:
            raise FetchError("Wayback alan başlıkları eksik")
        header = data[0]
        for row in data[1:self.limit + 1]:
            if not isinstance(row, list) or len(row) != len(header):
                raise FetchError("Geçersiz Wayback satırı")
            record = dict(zip(header, row))
            address = clean_url(record["original"], self.domain)
            if not address:
                continue
            details = {key: record[key] for key in ("timestamp", "statuscode", "mimetype") if key in record}
            self.report.add("archived_url", address, url, "historical_candidate", subject=self.domain, relation="archived_reference", details=details)
            self.discovered(urllib.parse.urlsplit(address).hostname, url, "historical_candidate", "archive_mentions")
        self.report.warn("Wayback sonuçları sınırlı tarihsel örneklemdir; tüm arşiv veya en yeni kayıtlar değildir. URL sorgu parametreleri ve fragmentler saklanmaz; arşiv içeriği indirilmez.")
        if len(data) - 1 >= self.limit:
            self.report.warn("Wayback sonuç sınırına ulaştı; ek sayfalar istenmedi.")

    def urlscan(self):
        url = "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": "domain:" + self.domain, "size": min(self.limit, 100)})
        data = self.client.json(url)
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise FetchError("Beklenmeyen urlscan yanıtı")
        for row in data["results"][:min(self.limit, 100)]:
            page = row.get("page", {})
            address = clean_url(page.get("url", ""), self.domain)
            if not address:
                continue
            host = urllib.parse.urlsplit(address).hostname
            details = {key: page[key] for key in ("status", "server", "mimeType") if key in page}
            details["scan_time"] = row.get("task", {}).get("time")
            self.report.add("indexed_url", address, url, "historical_candidate", subject=host, relation="existing_scan", details=details)
            self.discovered(host, url, "historical_candidate", "scan_mentions")
            ip = str(page.get("ip", ""))
            if public_ip(ip):
                self.report.add("historical_ip", ip, url, "historical_candidate", subject=host, relation="scan_reported_ip", details={"scan_time": details["scan_time"]})
        self.report.warn("urlscan yalnızca mevcut herkese açık kayıtları sorgular; yeni tarama göndermez. Tarihsel IP'ler güncel IP sayılmaz ve ağ zenginleştirmesine alınmaz.")
        if data.get("has_more") or len(data["results"]) >= min(self.limit, 100):
            self.report.warn("urlscan sonuçları sınırlı; devam sayfaları istenmedi.")

    def network(self, ip):
        if not public_ip(ip):
            raise FetchError("Ağ zenginleştirmesi yalnızca genel IP için kullanılabilir")
        addr = ipaddress.ip_address(ip)
        mask = 24 if addr.version == 4 else 64
        subnet = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        self.report.add("network_subnet", str(subnet), "local_calculation", "observed", subject=ip, relation="subnet")
        url = "https://stat.ripe.net/data/network-info/data.json?" + urllib.parse.urlencode({"resource": ip})
        result = self.client.json(url)
        if not isinstance(result, dict) or result.get("status") != "ok" or not isinstance(result.get("data"), dict):
            raise FetchError("Beklenmeyen RIPEstat yanıtı")
        data = result["data"]
        prefix = data.get("prefix")
        if prefix:
            network = ipaddress.ip_network(prefix, strict=False)
            if addr not in network:
                raise FetchError("RIPEstat öneki sorgulanan IP'yi kapsamıyor")
            self.report.add("bgp_prefix", str(network), url, "routing_observed", subject=ip, relation="announced_in")
        for asn in data.get("asns", [])[:5]:
            number = str(asn)
            if not number.isdigit() or not 1 <= int(number) <= 4294967295:
                continue
            asn_str = "AS" + number
            self.report.add("asn", asn_str, url, "routing_observed", subject=ip, relation="origin_asn")
            try:
                as_url = f"https://stat.ripe.net/data/as-overview/data.json?" + urllib.parse.urlencode({"resource": asn_str})
                as_res = self.client.json(as_url)
                if isinstance(as_res, dict) and as_res.get("status") == "ok":
                    holder = as_res.get("data", {}).get("holder")
                    if holder:
                        self.report.add("asn_holder", holder, as_url, "routing_observed", subject=asn_str, relation="holder")
            except (FetchError, BudgetExceeded):
                pass
        self.report.warn("BGP origin ASN, yönlendirme ilişkisidir; hedef kuruluşun mülkiyeti veya fiziksel konumu değildir.")

    def mail_record(self, name, marker, relation):
        answers, url = self.c.query_dns(name, "TXT")
        for answer in answers:
            if answer.get("type") != 16:
                continue
            value = str(answer.get("data", ""))
            normalized = "".join(re.findall(r'"([^"]*)"', value)) if '"' in value else value
            if normalized.lower().startswith(marker.lower()):
                self.report.add("email_policy", normalized, url, "dns_observed", subject=self.domain, relation=relation)

    def dnssec(self):
        for kind in ("DS", "DNSKEY"):
            answers, url = self.c.query_dns(self.domain, kind)
            for answer in answers:
                if answer.get("type") in (43, 48):
                    self.report.add("dnssec_record", answer.get("data", ""), url, "dns_observed", subject=self.domain, relation=kind)
        self.report.warn("DS/DNSKEY kayıtlarının görülmesi DNSSEC zincirinin bağımsız kriptografik doğrulaması değildir.")
