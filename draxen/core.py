import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return address.is_global and not address.is_multicast
    except ValueError:
        return False


def domain_name(value):
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Geçersiz alan adı") from exc
    if len(value) > 253 or "." not in value:
        raise ValueError("Tam bir alan adı girin: example.com")
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("Geçersiz alan adı")
    if labels[-1].isdigit() or value.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".onion")):
        raise ValueError("Yalnızca herkese açık internet hedefleri desteklenir")
    return value


@dataclass(frozen=True)
class Target:
    value: str
    kind: str
    domain: str = ""

    @classmethod
    def parse(cls, raw):
        raw = raw.strip()
        if "://" in raw or "/" in raw or any(ord(c) < 32 for c in raw):
            raise ValueError("URL veya ağ bloğu yerine alan adı, genel IP ya da e-posta girin")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            address = None
        if address:
            if not public_ip(str(address)):
                raise ValueError("Özel, yerel veya ayrılmış IP adresleri desteklenmez")
            return cls(str(address), "ip")
        if "@" in raw:
            if raw.count("@") != 1:
                raise ValueError("Geçersiz e-posta")
            local, domain = raw.rsplit("@", 1)
            if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local) or local.startswith(".") or local.endswith(".") or ".." in local:
                raise ValueError("Geçersiz e-posta")
            domain = domain_name(domain)
            return cls(local + "@" + domain, "email", domain)
        domain = domain_name(raw)
        return cls(domain, "domain", domain)


class FetchError(Exception):
    pass


class BudgetExceeded(FetchError):
    pass


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, validate):
        super().__init__()
        self.validate = validate

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.validate(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Client:
    def __init__(self, delay=1.5, timeout=15, budget=40, max_bytes=4_000_000):
        self.delay = max(1.0, delay)
        self.timeout = timeout
        self.budget = budget
        self.max_bytes = max_bytes
        self.requests = 0
        self.last_request = None
        self.cache = {}
        self.opener = urllib.request.build_opener(SafeRedirect(self.before_request))

    def validate_url(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.port not in (None, 443):
            raise FetchError("Yalnızca kimlik bilgisi içermeyen HTTPS/443 bağlantıları kullanılabilir")
        try:
            results = socket.getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise FetchError("Kaynak sunucunun DNS çözümlemesi başarısız") from exc
        if not results or any(not public_ip(row[4][0]) for row in results):
            raise FetchError("Yerel/özel ağ yönlendirmesi engellendi")

    def before_request(self, url):
        if self.requests >= self.budget:
            raise BudgetExceeded("İstek bütçesine ulaşıldı")
        self.validate_url(url)
        if self.last_request is not None:
            time.sleep(max(0, self.delay - (time.monotonic() - self.last_request)))
        self.requests += 1
        self.last_request = time.monotonic()

    def get(self, url, accept="application/json"):
        key = (url, accept)
        if key in self.cache:
            return self.cache[key]
        self.before_request(url)
        request = urllib.request.Request(url, headers={"User-Agent": "SZOBO-DRAXEN/1.6 (low-impact OSINT)", "Accept": accept, "Accept-Encoding": "identity"})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise FetchError("Yanıt boyut sınırını aştı; veri sessizce kesilmedi")
                charset = response.headers.get_content_charset() or "utf-8"
                result = (body.decode(charset, errors="replace"), response.geturl())
        except urllib.error.HTTPError as exc:
            detail = "Kaynak hız sınırı uyguluyor; tekrar denenmedi" if exc.code == 429 else "Kaynak HTTP hatası"
            raise FetchError(f"{detail} ({exc.code})") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            label = type(reason).__name__ if isinstance(reason, Exception) else "ağ erişimi başarısız"
            raise FetchError(f"Kaynağa ulaşılamadı: {label}") from exc
        except (OSError, ValueError, LookupError) as exc:
            raise FetchError(f"Bağlantı/okuma hatası: {type(exc).__name__}") from exc
        self.cache[key] = result
        return result

    def json(self, url, accept="application/json"):
        body, _ = self.get(url, accept)
        try:
            return json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise FetchError("Kaynak geçerli JSON döndürmedi") from exc


class Report:
    def __init__(self, target):
        self.data = {
            "tool": "SZOBO | DRAXEN", "version": "1.6.0", "started_at": utcnow(),
            "target": {"value": target.value, "kind": target.kind},
            "findings": [], "sources": [], "warnings": [],
            "policy": "Pasif üçüncü taraf sorguları; yalnızca --web ile tek ana sayfa isteği. Brute-force ve port taraması yok.",
        }
        self.index = {}

    def add(self, kind, value, source, status="observed", subject=None, relation="related_to", details=None):
        value = str(value).strip()
        if not value:
            return
        subject = subject or self.data["target"]["value"]
        key = (kind, value, subject, relation)
        evidence = {"source": source, "observed_at": utcnow(), "status": status}
        if details:
            evidence["details"] = details
        if key in self.index:
            finding = self.index[key]
            if evidence not in finding["evidence"]:
                finding["evidence"].append(evidence)
            return
        finding = {"kind": kind, "value": value, "subject": subject, "relation": relation, "evidence": [evidence]}
        self.index[key] = finding
        self.data["findings"].append(finding)

    def warn(self, text):
        if text not in self.data["warnings"]:
            self.data["warnings"].append(text)

    def source(self, name, state, count, message=""):
        self.data["sources"].append({"name": name, "state": state, "new_findings": count, "message": message, "checked_at": utcnow()})

    def finish(self, requests):
        self.data["finished_at"] = utcnow()
        self.data["requests"] = requests
        return self.data
