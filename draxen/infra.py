import ipaddress
import re

EDGE_HEADER_SIGNATURES = [
    ("cf-ray", "Cloudflare WAF / CDN"),
    ("cf-cache-status", "Cloudflare CDN"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-amz-cf-pop", "Amazon CloudFront"),
    ("x-akamai-transformed", "Akamai Edge Platform"),
    ("x-akamai-session-info", "Akamai Edge Platform"),
    ("x-fastly-request-id", "Fastly Edge Cloud"),
    ("x-sucuri-id", "Sucuri CloudProxy WAF"),
    ("x-iinfo", "Imperva / Incapsula WAF"),
    ("x-azure-ref", "Microsoft Azure Front Door"),
    ("x-edge-connect", "Verizon Digital Media / Edgecast"),
    ("x-hw-cache", "Highwinds / StackPath CDN"),
    ("x-cache-status-stackpath", "StackPath EdgeEngine"),
    ("x-kinsta-cache", "Kinsta Cloudflare Edge"),
    ("x-vercel-id", "Vercel Edge Network"),
    ("x-nf-request-id", "Netlify Edge"),
    ("fly-request-id", "Fly.io Edge Proxy"),
    ("x-datadome", "DataDome Bot Protection"),
    ("x-envoy-upstream-service-time", "Envoy Edge Gateway"),
    ("x-kong-proxy-latency", "Kong API Gateway"),
    ("x-varnish", "Varnish Caching Proxy"),
    ("x-alibaba-cloud-waf", "Alibaba Cloud WAF"),
]

EDGE_CNAME_PATTERNS = [
    (r"cloudflare\.net", "Cloudflare CDN"),
    (r"cloudfront\.net", "Amazon CloudFront"),
    (r"akamaiedge\.net|akamai\.net", "Akamai Edge Platform"),
    (r"fastly\.net", "Fastly Edge Cloud"),
    (r"azureedge\.net|afd\.azure\.com", "Microsoft Azure Front Door / CDN"),
    (r"incapdns\.net", "Imperva / Incapsula WAF"),
    (r"sucuri\.net", "Sucuri CloudProxy WAF"),
    (r"b-cdn\.net", "Bunny CDN"),
    (r"stackpathdns\.com", "StackPath CDN"),
    (r"edgesuite\.net", "Akamai EdgeSuite"),
    (r"edgekey\.net", "Akamai EdgeKey"),
    (r"hwcdn\.net", "Highwinds CDN"),
    (r"cdngp\.net", "Tencent Cloud CDN"),
    (r"kunlun.*\.com", "Alibaba Cloud CDN"),
]


def detect_edge_from_headers(headers_dict):
    lowered = {k.lower(): v for k, v in headers_dict.items()}
    detected = []
    for hdr, name in EDGE_HEADER_SIGNATURES:
        if hdr in lowered:
            detected.append((name, f"Header: {hdr}"))
    server = lowered.get("server", "").lower()
    if "cloudflare" in server:
        detected.append(("Cloudflare", "Server Header"))
    elif "akamai" in server:
        detected.append(("Akamai", "Server Header"))
    elif "cloudfront" in server:
        detected.append(("Amazon CloudFront", "Server Header"))
    return detected


def detect_edge_from_cname(cname_target):
    low = cname_target.lower()
    for pat, name in EDGE_CNAME_PATTERNS:
        if re.search(pat, low):
            return name
    return None


def parse_soa_record(soa_data):
    clean = str(soa_data).strip().rstrip(".")
    parts = clean.split()
    if len(parts) < 7:
        return None

    mname = parts[0].rstrip(".")
    rname_raw = parts[1]
    rname = ""
    if "." in rname_raw:
        user, dom = rname_raw.split(".", 1)
        rname = f"{user}@{dom}".rstrip(".")
    else:
        rname = rname_raw

    try:
        serial = int(parts[2])
        refresh = int(parts[3])
        retry = int(parts[4])
        expire = int(parts[5])
        minimum = int(parts[6])
    except ValueError:
        return None

    compliance_issues = []
    if refresh < 1200:
        compliance_issues.append(f"Refresh ({refresh}s) RFC 1912 önerisinin (20 dk) altında")
    if expire < 604800:
        compliance_issues.append(f"Expire ({expire}s) RFC 1912 önerisinin (7 gün) altında")
    if retry > refresh:
        compliance_issues.append("Retry süresi Refresh süresinden büyük")

    serial_str = str(serial)
    is_date_serial = False
    if len(serial_str) >= 8 and serial_str[:4].isdigit():
        year = int(serial_str[:4])
        if 1990 <= year <= 2035:
            is_date_serial = True

    return {
        "primary_ns": mname,
        "hostmaster_email": rname,
        "serial": serial,
        "is_date_serial": is_date_serial,
        "refresh_seconds": refresh,
        "retry_seconds": retry,
        "expire_seconds": expire,
        "minimum_ttl_seconds": minimum,
        "rfc1912_issues": compliance_issues,
    }


def detect_rir(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Bilinmiyor"

    if addr.version == 4:
        first_octet = int(str(addr).split(".")[0])
        if first_octet in (3, 4, 8, 9, 11, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 28, 29, 30, 32, 33, 34, 35, 38, 40, 44, 47, 48, 50, 52, 54, 55, 56, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128, 129, 130, 131, 132, 134, 135, 136, 140, 142, 143, 144, 146, 147, 148, 149, 152, 155, 156, 157, 158, 159, 160, 161, 162, 164, 166, 167, 168, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207, 208, 209, 216):
            return "ARIN (Kuzey Amerika)"
        if first_octet in (2, 5, 25, 31, 37, 46, 51, 62, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 109, 141, 145, 151, 176, 178, 185, 188, 193, 194, 195, 212, 213, 217):
            return "RIPE NCC (Avrupa / Orta Doğu / Orta Asya)"
        if first_octet in (1, 14, 27, 36, 39, 42, 43, 49, 58, 59, 60, 61, 101, 103, 106, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150, 153, 163, 171, 175, 180, 182, 183, 202, 203, 210, 211, 218, 219, 220, 221, 222, 223):
            return "APNIC (Asya-Pasifik)"
        if first_octet in (41, 102, 105, 154, 196, 197):
            return "AFRINIC (Afrika)"
        if first_octet in (45, 138, 169, 177, 179, 181, 186, 187, 189, 190, 191, 200, 201):
            return "LACNIC (Latin Amerika & Karayipler)"
    return "Küresel / IANA Tahsisi"
