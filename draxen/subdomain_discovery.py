from .core import BudgetExceeded, FetchError

DEFAULT_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "admin",
    "portal", "app", "login", "beta", "cloud", "cpanel", "support",
    "autodiscover", "git", "dashboard", "auth", "m", "gateway", "direct",
    "panel", "status", "stage", "shop", "cdn", "corp", "internal",
    "jenkins", "grafana", "sso", "gitlab", "jira", "confluence", "docs",
    "k8s", "monitoring", "kibana", "elastic", "prometheus", "vault",
    "registry", "intranet", "prod", "uat", "qa", "demo", "sandbox",
    "assets", "static", "media", "ws", "chat", "sftp", "relay",
    "identity", "connect", "hub", "manage", "billing", "node", "edge",
]


class SubdomainDiscoverer:
    def __init__(self, collector, words=None, limit=70):
        self.collector = collector
        self.domain = collector.target.domain
        self.words = list(words) if words else list(DEFAULT_SUBDOMAINS)
        self.limit = min(limit, len(self.words))

    def run(self):
        if not self.domain:
            return
        active_words = self.words[:self.limit]
        for word in active_words:
            sub = f"{word.strip().lower()}.{self.domain}"
            if not sub or sub == self.domain:
                continue
            try:
                answers, url = self.collector.query_dns(sub, "A")
                for answer in answers:
                    if answer.get("type") == 1:
                        ip = answer.get("data")
                        self.collector.report.add("discovered_domain", sub, url, "dns_wordlist", subject=self.domain, relation="discovered_subdomain")
                        if ip:
                            self.collector.report.add("dns_a", str(ip), url, "dns_wordlist", subject=sub, relation="resolves_to")
                            self.collector.ips.add(str(ip))
                            self.collector.current_ips.add(str(ip))
                        self.collector.candidates.add(sub)
                        break
            except BudgetExceeded:
                break
            except FetchError:
                continue
            except Exception:
                continue
