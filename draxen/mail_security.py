import base64
import re


COMMON_DKIM_SELECTORS = [
    "google",
    "selector1",
    "selector2",
    "k1",
    "default",
    "s1",
    "s2",
    "mail",
    "smtp",
    "dkim",
    "m1",
    "mx",
    "key1",
    "email",
    "api",
    "mailer",
]

SPF_SERVICE_PATTERNS = [
    (r"_spf\.google\.com", "Google Workspace"),
    (r"protection\.outlook\.com", "Microsoft 365"),
    (r"mailgun\.org", "Mailgun"),
    (r"sendgrid\.net", "Twilio SendGrid"),
    (r"servers\.mcsv\.net", "Mailchimp"),
    (r"zendesk\.com", "Zendesk"),
    (r"amazonses\.com", "Amazon SES"),
    (r"zoho\.(com|eu)", "Zoho Mail"),
    (r"createsend\.com", "Campaign Monitor"),
    (r"spf\.mandrillapp\.com", "Mandrill"),
    (r"freshdesk\.com", "Freshdesk"),
    (r"hubspotemail\.net", "HubSpot"),
    (r"sparkpostmail\.com", "SparkPost"),
    (r"postmarkapp\.com", "Postmark"),
    (r"salesforce\.com", "Salesforce"),
    (r"klaviyomail\.com", "Klaviyo"),
    (r"cust-spf\.exacttarget\.com", "Salesforce Marketing Cloud"),
    (r"secureserver\.net", "GoDaddy"),
    (r"yandex\.net", "Yandex 360"),
    (r"protonmail\.ch", "Proton Mail"),
    (r"fastmail\.com", "Fastmail"),
]


def parse_spf_record(spf_text):
    text = spf_text.replace('" "', '').strip('"').strip()
    tokens = text.split()
    lookups = 0
    authorized_services = []
    ip_ranges = []
    qualifier_all = None

    for token in tokens[1:]:
        t_low = token.lower()
        if t_low.startswith(("include:", "a:", "mx:", "ptr:", "exists:", "redirect=")):
            lookups += 1
            if t_low.startswith("include:"):
                target = t_low[8:]
                for pat, svc in SPF_SERVICE_PATTERNS:
                    if re.search(pat, target):
                        authorized_services.append((svc, target))
                        break
                else:
                    authorized_services.append((target, target))
        elif t_low.startswith(("ip4:", "ip6:")):
            ip_ranges.append(token.split(":", 1)[1])
        elif t_low in ("all", "+all", "-all", "~all", "?all"):
            qualifier_all = t_low
        elif t_low in ("a", "mx", "ptr"):
            lookups += 1

    return {
        "raw": text,
        "dns_lookup_count": lookups,
        "exceeds_10_lookup_limit": lookups > 10,
        "authorized_services": authorized_services,
        "ip_ranges": ip_ranges,
        "qualifier_all": qualifier_all,
    }


def parse_dkim_key(raw_dkim):
    clean = raw_dkim.replace('" "', '').strip('"').strip()
    tags = dict(part.strip().split("=", 1) for part in clean.split(";") if "=" in part)
    k_type = tags.get("k", "rsa").strip().lower()
    p_data = tags.get("p", "").strip().replace(" ", "")
    bit_length = 0
    if p_data:
        try:
            decoded = base64.b64decode(p_data)
            bit_length = len(decoded) * 8
        except Exception:
            pass
    return {
        "key_type": k_type,
        "public_key_preview": p_data[:24] + "..." if len(p_data) > 24 else p_data,
        "estimated_bits": bit_length,
    }


def parse_caa_record(data_str):
    clean = data_str.strip('"').strip()
    parts = clean.split(maxsplit=2)
    if len(parts) >= 3:
        flag, tag, val = parts[0], parts[1].lower(), parts[2].strip('"')
        return {"flag": flag, "tag": tag, "value": val}
    return None
