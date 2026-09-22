import re
import urllib.parse

from .core import BudgetExceeded, FetchError, public_ip
from .rdap import lookup as rdap_lookup

DATACENTER_PROVIDERS = [
    {
        "name": "Amazon Web Services (AWS)",
        "category": "Hiperekolojik Bulut",
        "asns": {16509, 14618, 8987, 10124},
        "patterns": [r"\bamazon", r"\baws\b", r"\bamazon-ec2\b"],
    },
    {
        "name": "Google Cloud Platform (GCP)",
        "category": "Hiperekolojik Bulut",
        "asns": {15169, 396982, 36040, 19527},
        "patterns": [r"\bgoogle", r"\bgcp\b"],
    },
    {
        "name": "Microsoft Azure",
        "category": "Hiperekolojik Bulut",
        "asns": {8075, 8068, 8069, 12076},
        "patterns": [r"\bmicrosoft", r"\bazure"],
    },
    {
        "name": "Cloudflare Network",
        "category": "Bulut & Anycast Kenar Ağı",
        "asns": {13335, 209242},
        "patterns": [r"\bcloudflare"],
    },
    {
        "name": "DigitalOcean",
        "category": "Veri Merkezi & VPS Bulutu",
        "asns": {14061, 62567, 200130},
        "patterns": [r"\bdigitalocean"],
    },
    {
        "name": "Hetzner Online",
        "category": "Veri Merkezi & Dedicated Sunucu",
        "asns": {24940, 213230},
        "patterns": [r"\bhetzner"],
    },
    {
        "name": "OVHcloud",
        "category": "Veri Merkezi & VPS Barındırma",
        "asns": {16276, 35540},
        "patterns": [r"\bovh"],
    },
    {
        "name": "Linode / Akamai Connected Cloud",
        "category": "Bulut & VPS Barındırma",
        "asns": {63949, 3258, 20940},
        "patterns": [r"\blinode", r"\bakamai\b"],
    },
    {
        "name": "Oracle Cloud Infrastructure (OCI)",
        "category": "Hiperekolojik Bulut",
        "asns": {31898},
        "patterns": [r"\boracle"],
    },
    {
        "name": "Vultr (The Constant Company)",
        "category": "Veri Merkezi & VPS Bulutu",
        "asns": {20473},
        "patterns": [r"\bvultr", r"\bchoopa\b", r"\bthe constant company\b"],
    },
    {
        "name": "Fastly",
        "category": "Bulut & CDN Kenar Ağı",
        "asns": {54113},
        "patterns": [r"\bfastly"],
    },
    {
        "name": "Leaseweb",
        "category": "Veri Merkezi & Dedicated Sunucu",
        "asns": {60781, 16265, 28753},
        "patterns": [r"\bleaseweb"],
    },
    {
        "name": "Scaleway",
        "category": "Bulut & Veri Merkezi",
        "asns": {12876, 53667},
        "patterns": [r"\bscaleway", r"\bonline s\.a\.s\b"],
    },
    {
        "name": "Alibaba Cloud",
        "category": "Hiperekolojik Bulut",
        "asns": {45102, 37963},
        "patterns": [r"\balibaba", r"\baliyun\b"],
    },
    {
        "name": "Contabo",
        "category": "Veri Merkezi & VPS Barındırma",
        "asns": {51167},
        "patterns": [r"\bcontabo"],
    },
    {
        "name": "Hostinger",
        "category": "Web & VPS Barındırma",
        "asns": {47583},
        "patterns": [r"\bhostinger"],
    },
    {
        "name": "IONOS / 1&1",
        "category": "Web & Veri Merkezi Barındırma",
        "asns": {8560},
        "patterns": [r"\bionos", r"\b1&1\b"],
    },
    {
        "name": "UpCloud",
        "category": "Bulut & VPS Barındırma",
        "asns": {202184},
        "patterns": [r"\bupcloud"],
    },
    {
        "name": "Rackspace",
        "category": "Yönetilen Bulut & Veri Merkezi",
        "asns": {27357, 19994},
        "patterns": [r"\brackspace"],
    },
    {
        "name": "Equinix",
        "category": "Küresel Kolokasyon & Veri Merkezi",
        "asns": {24115},
        "patterns": [r"\bequinix"],
    },
    {
        "name": "Türk Telekom",
        "category": "Ulusal Telekom & Taşıyıcı Ağ",
        "asns": {9121},
        "patterns": [r"\bturk telekom\b", r"\bturkiyetelekom\b"],
    },
    {
        "name": "Turkcell Superonline",
        "category": "Telekom & Veri Merkezi",
        "asns": {34984},
        "patterns": [r"\bsuperonline\b", r"\bturkcell\b"],
    },
    {
        "name": "Vodafone",
        "category": "Telekomünikasyon Ağı",
        "asns": {15924, 3209, 1273},
        "patterns": [r"\bvodafone"],
    },
    {
        "name": "TurkNet",
        "category": "İnternet Servis Sağlayıcı & Ağ",
        "asns": {12735},
        "patterns": [r"\bturknet"],
    },
    {
        "name": "IBM Cloud / SoftLayer",
        "category": "Hiperekolojik Bulut",
        "asns": {36351, 14907, 27653},
        "patterns": [r"\bsoftlayer", r"\bibm\b"],
    },
    {
        "name": "Tencent Cloud",
        "category": "Hiperekolojik Bulut",
        "asns": {132203, 132591, 45090},
        "patterns": [r"\btencent"],
    },
    {
        "name": "Baidu Cloud",
        "category": "Hiperekolojik Bulut",
        "asns": {55967, 38365},
        "patterns": [r"\bbaidu"],
    },
    {
        "name": "Huawei Cloud",
        "category": "Hiperekolojik Bulut",
        "asns": {55990, 136907},
        "patterns": [r"\bhuawei"],
    },
    {
        "name": "Akamai Technologies",
        "category": "Bulut & Anycast Kenar Ağı",
        "asns": {20940, 16625, 32787},
        "patterns": [r"\bakamai"],
    },
    {
        "name": "Imperva / Incapsula",
        "category": "Siber Güvenlik & Anycast WAF",
        "asns": {19551},
        "patterns": [r"\bincapsula", r"\bimperva"],
    },
    {
        "name": "Sucuri / GoDaddy Security",
        "category": "Siber Güvenlik & Anycast WAF",
        "asns": {30148, 26496},
        "patterns": [r"\bsucuri"],
    },
    {
        "name": "StackPath / Highwinds",
        "category": "Bulut & Anycast Kenar Ağı",
        "asns": {33438, 20446},
        "patterns": [r"\bstackpath", r"\bhighwinds"],
    },
    {
        "name": "GoDaddy Infrastructure",
        "category": "Web & Alan Adı Barındırma",
        "asns": {26496, 44273},
        "patterns": [r"\bgodaddy"],
    },
    {
        "name": "Namecheap / WebHostingBuzz",
        "category": "Web & VPS Barındırma",
        "asns": {22612},
        "patterns": [r"\bnamecheap"],
    },
    {
        "name": "Bluehost / Endurance (Newfold)",
        "category": "Web & VPS Barındırma",
        "asns": {46606, 19871},
        "patterns": [r"\bbluehost", r"\bendurance"],
    },
    {
        "name": "DreamHost",
        "category": "Web & VPS Barındırma",
        "asns": {26347},
        "patterns": [r"\bdreamhost"],
    },
    {
        "name": "SiteGround",
        "category": "Yönetilen Bulut Barındırma",
        "asns": {203875, 49760},
        "patterns": [r"\bsiteground"],
    },
    {
        "name": "WP Engine",
        "category": "Yönetilen Bulut Barındırma",
        "asns": {395747},
        "patterns": [r"\bwpengine"],
    },
    {
        "name": "Fly.io",
        "category": "Uç Nokta Bulut Platformu",
        "asns": {400518},
        "patterns": [r"\bfly\.io"],
    },
    {
        "name": "Vercel / Next.js Edge",
        "category": "Sunucusuz Uç Nokta Bulutu",
        "asns": {398324},
        "patterns": [r"\bvercel"],
    },
    {
        "name": "Netlify Infrastructure",
        "category": "Sunucusuz Uç Nokta Bulutu",
        "asns": {397555},
        "patterns": [r"\bnetlify"],
    },
    {
        "name": "Kinsta",
        "category": "Yönetilen Bulut Platformu",
        "asns": {398324, 15169},
        "patterns": [r"\bkinsta"],
    },
    {
        "name": "Cogent Communications",
        "category": "Küresel Taşıyıcı Ağ & Tier-1",
        "asns": {174},
        "patterns": [r"\bcogent"],
    },
    {
        "name": "Lumen / CenturyLink (Level 3)",
        "category": "Küresel Taşıyıcı Ağ & Tier-1",
        "asns": {3356, 209},
        "patterns": [r"\blumen", r"\blevel\s*3", r"\bcenturylink"],
    },
    {
        "name": "Telia Carrier (Arelion)",
        "category": "Küresel Taşıyıcı Ağ & Tier-1",
        "asns": {1299},
        "patterns": [r"\btelia", r"\barelion"],
    },
    {
        "name": "NTT Communications",
        "category": "Küresel Taşıyıcı Ağ & Tier-1",
        "asns": {2914},
        "patterns": [r"\bntt"],
    },
    {
        "name": "Tata Communications",
        "category": "Küresel Taşıyıcı Ağ & Tier-1",
        "asns": {6453},
        "patterns": [r"\btata"],
    },
    {
        "name": "Deutsche Telekom",
        "category": "Uluslararası Telekomünikasyon",
        "asns": {3320},
        "patterns": [r"\bdeutsche\s*telekom", r"\bdtag"],
    },
    {
        "name": "Orange / France Telecom",
        "category": "Uluslararası Telekomünikasyon",
        "asns": {5511},
        "patterns": [r"\borange", r"\bopentransit"],
    },
    {
        "name": "Radore Veri Merkezi",
        "category": "Ulusal Veri Merkezi & Kolokasyon",
        "asns": {34619},
        "patterns": [r"\bradore"],
    },
    {
        "name": "DGN Teknoloji",
        "category": "Ulusal Veri Merkezi & Barındırma",
        "asns": {44391},
        "patterns": [r"\bdgn"],
    },
    {
        "name": "Niobe / IHS Telekom",
        "category": "Ulusal Web Barındırma",
        "asns": {39457},
        "patterns": [r"\bniobe", r"\bihs"],
    },
    {
        "name": "Natro / Çizgi Telekom",
        "category": "Ulusal Web Barındırma",
        "asns": {30860},
        "patterns": [r"\bnatro", r"\bcizgi"],
    },
]


def detect_datacenter_provider(asns=None, holder="", netname=""):
    asns = asns or []
    asn_nums = set()
    for item in asns:
        if isinstance(item, int):
            asn_nums.add(item)
        elif isinstance(item, str):
            digits = re.findall(r"\d+", item)
            if digits:
                try:
                    asn_nums.add(int(digits[0]))
                except ValueError:
                    pass
    search_haystack = f"{holder} {netname}".lower()
    for prov in DATACENTER_PROVIDERS:
        if asn_nums.intersection(prov["asns"]):
            return prov
        for pattern in prov["patterns"]:
            if re.search(pattern, search_haystack, re.IGNORECASE):
                return prov
    return None


class NetworkIntelligence:
    def __init__(self, client, report):
        self.client = client
        self.report = report

    def analyze_ip(self, ip):
        if not public_ip(ip):
            return
        holder_text = ""
        netname_text = ""
        found_asns = []

        try:
            geoloc_url = f"https://stat.ripe.net/data/geoloc/data.json?resource={ip}"
            res = self.client.json(geoloc_url)
            if isinstance(res, dict) and res.get("status") == "ok":
                data = res.get("data", {})
                locations = data.get("locations", [])
                if isinstance(locations, list) and locations:
                    loc = locations[0]
                    country = loc.get("country")
                    city = loc.get("city")
                    lat = loc.get("latitude")
                    lon = loc.get("longitude")
                    if country:
                        self.report.add("ip_country", str(country), geoloc_url, "routing_observed", subject=ip, relation="located_in")
                    if city:
                        self.report.add("ip_city", str(city), geoloc_url, "routing_observed", subject=ip, relation="located_in")
                    if lat is not None and lon is not None:
                        coords_str = f"{lat}, {lon}"
                        self.report.add("ip_coordinates", coords_str, geoloc_url, "routing_observed", subject=ip, relation="coordinates")
        except (FetchError, BudgetExceeded):
            pass

        try:
            rdap_data, rdap_url, _ = rdap_lookup(self.client, ip, "ip")
            if isinstance(rdap_data, dict):
                net_name = rdap_data.get("name")
                if net_name:
                    netname_text = str(net_name)
                    self.report.add("ip_net_name", netname_text, rdap_url, "rdap_observed", subject=ip, relation="net_name")
                start = rdap_data.get("startAddress")
                end = rdap_data.get("endAddress")
                if start and end:
                    self.report.add("ip_range", f"{start} - {end}", rdap_url, "rdap_observed", subject=ip, relation="allocated_range")
                country = rdap_data.get("country")
                if country:
                    existing_countries = {item["value"] for item in self.report.data["findings"] if item["kind"] == "ip_country" and item.get("subject") == ip}
                    if not existing_countries:
                        self.report.add("ip_country", str(country), rdap_url, "rdap_observed", subject=ip, relation="located_in")
        except (FetchError, BudgetExceeded):
            pass

        for item in self.report.data["findings"]:
            if item.get("subject") == ip and item["kind"] == "asn":
                found_asns.append(item["value"])
            elif item["kind"] == "asn_holder":
                holder_text += " " + item["value"]

        provider = detect_datacenter_provider(found_asns, holder_text, netname_text)
        if provider:
            display_val = f"{provider['name']} [{provider['category']}]"
            self.report.add("datacenter_provider", display_val, "fingerprint_rule", "infrastructure_fingerprint", subject=ip, relation="hosted_at")
