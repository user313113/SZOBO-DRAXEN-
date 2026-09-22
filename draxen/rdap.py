import ipaddress
import urllib.parse

from .core import BudgetExceeded, FetchError


def lookup(client, value, kind):
    url = f"https://rdap.org/{kind}/" + urllib.parse.quote(value, safe=":.")
    try:
        return client.json(url), url, False
    except BudgetExceeded:
        raise
    except FetchError:
        pass
    if kind == "domain":
        bootstrap = "dns"
        resource = value.lower()
    else:
        resource = ipaddress.ip_address(value)
        bootstrap = "ipv4" if resource.version == 4 else "ipv6"
    data = client.json(f"https://data.iana.org/rdap/{bootstrap}.json")
    if not isinstance(data, dict) or not isinstance(data.get("services"), list):
        raise FetchError("IANA RDAP yönlendirme listesi alınamadı")
    matches = []
    for service in data["services"]:
        if not isinstance(service, list) or len(service) != 2:
            continue
        ranges, urls = service
        for entry in ranges:
            if kind == "domain":
                suffix = str(entry).lower()
                score = len(suffix) if resource == suffix or resource.endswith("." + suffix) else -1
            else:
                try:
                    network = ipaddress.ip_network(entry)
                    score = network.prefixlen if resource in network else -1
                except ValueError:
                    continue
            if score >= 0:
                for base in urls:
                    parsed = urllib.parse.urlsplit(base)
                    if parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and parsed.port in (None, 443):
                        matches.append((score, base))
    if not matches:
        raise FetchError("Hedef için HTTPS RDAP hizmeti bulunamadı")
    base = sorted(matches, key=lambda item: (-item[0], item[1]))[0][1]
    url = base.rstrip("/") + f"/{kind}/" + urllib.parse.quote(value, safe=":.")
    return client.json(url), url, True
