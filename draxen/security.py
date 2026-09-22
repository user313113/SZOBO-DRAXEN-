import hashlib
import urllib.parse

from .core import BudgetExceeded, FetchError


def parse_security_txt(text):
    fields = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            directive, value = line.split(":", 1)
            directive = directive.strip().capitalize()
            value = value.strip()
            if directive in ("Contact", "Encryption", "Acknowledgments", "Policy", "Hiring", "Expires", "Canonical") and value:
                fields.append((directive, value))
    return fields


class SecurityCollector:
    def __init__(self, collector):
        self.c = collector
        self.client = collector.client
        self.report = collector.report
        self.domain = collector.target.domain
        self.target = collector.target

    def security_txt(self):
        if not self.domain:
            return
        paths = ["/.well-known/security.txt", "/security.txt"]
        found = False
        for path in paths:
            url = f"https://{self.domain}{path}"
            try:
                body, final_url = self.client.get(url, accept="text/plain")
            except (BudgetExceeded, FetchError):
                continue
            final_host = urllib.parse.urlsplit(final_url).hostname or ""
            if final_host != self.domain and not final_host.endswith("." + self.domain):
                continue
            fields = parse_security_txt(body)
            if fields:
                found = True
                for directive, val in fields:
                    self.report.add("security_directive", val, final_url, "page_observed", subject=self.domain, relation=directive)
                break
        if not found:
            self.report.warn("security.txt (RFC 9116) dosyası bulunamadı veya erişilemedi.")

    def gravatar(self):
        if self.target.kind != "email":
            return
        email_clean = self.target.value.strip().lower()
        digest = hashlib.md5(email_clean.encode("utf-8")).hexdigest()
        url = f"https://en.gravatar.com/{digest}.json"
        try:
            data = self.client.json(url)
        except (BudgetExceeded, FetchError):
            return
        if not isinstance(data, dict) or "entry" not in data or not isinstance(data["entry"], list) or not data["entry"]:
            return
        entry = data["entry"][0]
        if not isinstance(entry, dict):
            return
        if entry.get("profileUrl"):
            self.report.add("gravatar_profile", entry["profileUrl"], url, "registry_reported", subject=self.target.value, relation="public_profile")
        if entry.get("displayName"):
            self.report.add("public_identity", entry["displayName"], url, "registry_reported", subject=self.target.value, relation="display_name")
        if entry.get("currentLocation"):
            self.report.add("reported_location", entry["currentLocation"], url, "registry_reported", subject=self.target.value, relation="reported_location")
        if entry.get("aboutMe"):
            bio = str(entry["aboutMe"]).strip()[:200]
            if bio:
                self.report.add("public_bio", bio, url, "registry_reported", subject=self.target.value, relation="about_me")
