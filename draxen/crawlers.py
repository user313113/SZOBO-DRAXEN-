import urllib.parse
import xml.etree.ElementTree as ET

from .core import BudgetExceeded, FetchError
from .enrichment import clean_url

MEDIA_EXTENSIONS = (".pdf", ".jpg", ".jpeg", ".png", ".docx", ".xlsx", ".pptx", ".zip", ".tar.gz", ".tgz", ".sql", ".bak", ".7z", ".rar", ".csv")


class CrawlerAnalyzer:
    def __init__(self, client, report, domain, limit=100, candidates=None):
        self.client = client
        self.report = report
        self.domain = domain
        self.limit = limit
        self.candidates = candidates if candidates is not None else set()

    def run(self):
        if not self.domain:
            return
        sitemap_urls = set()
        default_sitemap = f"https://{self.domain}/sitemap.xml"
        sitemap_urls.add(default_sitemap)

        robots_url = f"https://{self.domain}/robots.txt"
        try:
            body, final_url = self.client.get(robots_url, accept="text/plain")
            final_host = urllib.parse.urlsplit(final_url).hostname or ""
            if final_host == self.domain or final_host.endswith("." + self.domain):
                disallows = 0
                for line in body.splitlines():
                    clean = line.strip()
                    if not clean or clean.startswith("#"):
                        continue
                    if ":" in clean:
                        directive, val = clean.split(":", 1)
                        directive = directive.strip().lower()
                        val = val.strip()
                        if directive == "disallow" and val and val != "/":
                            disallows += 1
                            if disallows <= min(self.limit, 50):
                                self.report.add("crawler_disallowed_path", val, final_url, "page_observed", subject=self.domain, relation="disallowed_path")
                        elif directive == "allow" and val:
                            self.report.add("crawler_allowed_path", val, final_url, "page_observed", subject=self.domain, relation="allowed_path")
                        elif directive == "sitemap" and val.startswith("http"):
                            sitemap_urls.add(val)
        except (FetchError, BudgetExceeded):
            pass

        parsed_sitemaps = 0
        total_locs = 0
        for s_url in sorted(sitemap_urls)[:3]:
            try:
                content, final_s_url = self.client.get(s_url, accept="application/xml,text/xml")
                root = ET.fromstring(content)
                parsed_sitemaps += 1
                for elem in root.iter():
                    tag = elem.tag.split("}")[-1]
                    if tag in ("url", "sitemap"):
                        loc_val = None
                        lastmod_val = None
                        for child in elem:
                            ctag = child.tag.split("}")[-1]
                            if ctag == "loc" and child.text:
                                loc_val = child.text.strip()
                            elif ctag == "lastmod" and child.text:
                                lastmod_val = child.text.strip()
                        if loc_val:
                            address = clean_url(loc_val, self.domain)
                            if address:
                                total_locs += 1
                                if total_locs <= self.limit:
                                    host = urllib.parse.urlsplit(address).hostname
                                    details = {"lastmod": lastmod_val} if lastmod_val else None
                                    self.report.add("sitemap_url", address, final_s_url, "page_observed", subject=host, relation="sitemap_entry", details=details)
                                    if host != self.domain and host.endswith("." + self.domain):
                                        self.report.add("discovered_domain", host, final_s_url, "page_observed", subject=self.domain, relation="sitemap_subdomain")
                                        self.candidates.add(host)
                                    path_lower = urllib.parse.urlsplit(address).path.lower()
                                    if any(path_lower.endswith(ext) for ext in MEDIA_EXTENSIONS):
                                        self.report.add("media_reference", address, final_s_url, "page_observed", subject=host, relation="media_document")
            except (FetchError, BudgetExceeded, ET.ParseError, Exception):
                continue

        if total_locs > 0:
            self.report.warn(f"Site haritasından {total_locs} indeksli URL adresi tespit edildi.")
