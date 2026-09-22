import urllib.parse
import urllib.request

from .cookie_audit import audit_cookies
from .core import BudgetExceeded, FetchError
from .infra import detect_edge_from_headers

AUDITED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "X-XSS-Protection",
    "Clear-Site-Data",
]


class HttpAuditor:
    def __init__(self, client, report, domain):
        self.client = client
        self.report = report
        self.domain = domain

    def audit_headers(self):
        if not self.domain:
            return
        url = f"https://{self.domain}/"
        try:
            self.client.before_request(url)
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "SZOBO-DRAXEN/1.6 (low-impact OSINT)", "Accept": "text/html,application/xhtml+xml"},
            )
            with self.client.opener.open(request, timeout=self.client.timeout) as response:
                headers = response.headers
                final_url = response.geturl()
        except (BudgetExceeded, FetchError, Exception):
            return

        final_host = urllib.parse.urlsplit(final_url).hostname or ""
        if final_host != self.domain and not final_host.endswith("." + self.domain):
            return

        found_headers = {}
        headers_dict = dict(headers.items())
        for hdr in AUDITED_HEADERS:
            val = headers.get(hdr)
            if val:
                val_clean = str(val).strip()[:200]
                found_headers[hdr] = val_clean
                self.report.add("http_security_header", f"{hdr}: {val_clean}", final_url, "page_observed", subject=self.domain, relation=hdr)

        for leak_hdr in ("Server", "X-Powered-By", "X-AspNet-Version"):
            leak_val = headers.get(leak_hdr)
            if leak_val:
                val_clean = str(leak_val).strip()[:100]
                self.report.add("server_banner", f"{leak_hdr}: {val_clean}", final_url, "page_observed", subject=self.domain, relation=leak_hdr)

        cookie_headers = []
        if hasattr(headers, "get_all"):
            cookie_headers = headers.get_all("Set-Cookie") or []
        elif hasattr(headers, "get"):
            c = headers.get("Set-Cookie")
            if c:
                cookie_headers = [c]

        for audited in audit_cookies(cookie_headers):
            self.report.add(
                "cookie_policy",
                f"{audited['name']} [Secure: {audited['secure']}, HttpOnly: {audited['httponly']}, SameSite: {audited['samesite']}]",
                final_url,
                "page_observed",
                subject=self.domain,
                relation="cookie_policy",
                details=audited,
            )
            if audited["is_insecure"]:
                self.report.add(
                    "cookie_insecurity",
                    f"{audited['name']} (Eksik: {', '.join(audited['missing'])})",
                    final_url,
                    "security_audit",
                    subject=self.domain,
                    relation="cookie_insecurity",
                    details=audited,
                )

        for edge_name, edge_ev in detect_edge_from_headers(headers_dict):
            self.report.add("edge_infrastructure", f"{edge_name} ({edge_ev})", final_url, "page_observed", subject=self.domain, relation="cdn_waf")

        missing = [h for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options") if h not in found_headers]
        if missing:
            self.report.warn(f"HTTP Güvenlik Başlıkları Eksik: {', '.join(missing)}")
