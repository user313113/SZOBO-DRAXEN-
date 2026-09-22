import re

MX_PROVIDERS = [
    (r"google|googlemail|aspmx\.l\.google\.com", "Google Workspace / Gmail"),
    (r"outlook\.com|microsoft\.com|pphosted\.com.*outlook", "Microsoft 365 / Exchange Online"),
    (r"protonmail\.ch|proton\.me", "Proton Mail"),
    (r"zoho\.(com|eu|in)", "Zoho Mail"),
    (r"yandex\.(ru|com|net)", "Yandex 360"),
    (r"pphosted\.com|proofpoint", "Proofpoint Protection"),
    (r"mimecast\.com", "Mimecast Email Security"),
    (r"mailhostbox\.com", "Mailhostbox / ResellerClub"),
    (r"ovh\.(net|com)", "OVHcloud Mail"),
    (r"secureserver\.net", "GoDaddy Email"),
    (r"yahoodns\.net", "Yahoo Mail / Small Business"),
    (r"fastmail\.com", "Fastmail"),
    (r"icloud\.com", "Apple iCloud Mail"),
    (r"sendgrid\.net", "Twilio SendGrid"),
    (r"mailgun\.org", "Mailgun"),
    (r"barracuda|barracudanetworks", "Barracuda Email Security"),
    (r"trendmicro|tmes\.trendmicro", "Trend Micro Email Security"),
    (r"sophos\.com", "Sophos Email Gateway"),
    (r"cisco\.com|ironport", "Cisco IronPort / CES"),
    (r"mxlogic\.net|mcafee", "McAfee MX Logic"),
    (r"spamexperts\.(com|net)", "N-able SpamExperts"),
    (r"postmarkapp\.com", "Postmark Mail"),
    (r"amazonses\.com", "Amazon Simple Email Service (SES)"),
    (r"sparkpostmail\.com", "SparkPost"),
    (r"mandrillapp\.com", "Mailchimp Mandrill"),
    (r"mailjet\.com", "Mailjet / Sinch"),
    (r"infomaniak\.com", "Infomaniak Mail"),
    (r"tutanota\.com|tuta\.com", "Tuta Mail"),
    (r"rackspace\.com|emailsrvr\.com", "Rackspace Email"),
    (r"ionos\.(com|de|es)", "IONOS / 1&1 Mail"),
]

NS_PROVIDERS = [
    (r"cloudflare\.com", "Cloudflare DNS"),
    (r"awsdns|route53", "Amazon Web Services Route 53"),
    (r"azure-dns", "Microsoft Azure DNS"),
    (r"googledomains\.com|cloud-dns", "Google Cloud DNS"),
    (r"akam\.net|akamai", "Akamai Edge DNS"),
    (r"domaincontrol\.com", "GoDaddy DNS"),
    (r"registrar-servers\.com", "Namecheap DNS"),
    (r"digitalocean\.com", "DigitalOcean DNS"),
    (r"hetzner\.(com|de)", "Hetzner DNS"),
    (r"ovh\.net", "OVHcloud DNS"),
    (r"dnsmadeeasy\.com", "DNS Made Easy"),
    (r"nsone\.net|namesafari", "NS1 / IBM"),
    (r"linode\.com", "Linode DNS"),
    (r"vultr\.com", "Vultr DNS"),
    (r"oraclecloud\.com|ultradns", "Oracle Dyn / UltraDNS"),
    (r"easydns\.com", "easyDNS"),
    (r"zoneedit\.com", "ZoneEdit"),
    (r"constellix\.com", "Constellix DNS"),
    (r"he\.net|hurricane", "Hurricane Electric DNS"),
    (r"gandi\.net", "Gandi DNS"),
    (r"dnsimple\.com", "DNSimple"),
    (r"inwx\.com", "INWX DNS"),
    (r"hostinger\.com", "Hostinger DNS"),
    (r"alidns\.com", "Alibaba Cloud DNS"),
]

TXT_PATTERNS = [
    (r"google-site-verification=([A-Za-z0-9_-]+)", "Google Hizmet Doğrulaması", "Google"),
    (r"MS=ms([0-9a-fA-F]+)", "Microsoft 365 Alan Doğrulaması", "Microsoft"),
    (r"atlassian-domain-verification=([A-Za-z0-9_-]+)", "Atlassian Doğrulaması", "Atlassian"),
    (r"adobe-idp-site-verification=([A-Za-z0-9_-]+)", "Adobe IDP Doğrulaması", "Adobe"),
    (r"apple-domain-verification=([A-Za-z0-9_-]+)", "Apple Alan Doğrulaması", "Apple"),
    (r"docusign=([A-Za-z0-9_-]+)", "DocuSign Doğrulaması", "DocuSign"),
    (r"facebook-domain-verification=([A-Za-z0-9_-]+)", "Meta / Facebook Doğrulaması", "Meta"),
    (r"stripe-verification=([A-Za-z0-9_-]+)", "Stripe Doğrulaması", "Stripe"),
    (r"hubspot-developer-verification=([A-Za-z0-9_-]+)", "HubSpot Doğrulaması", "HubSpot"),
    (r"cisco-ci-domain-verification=([A-Za-z0-9_-]+)", "Cisco Doğrulaması", "Cisco"),
    (r"zendeskverification=([A-Za-z0-9_-]+)", "Zendesk Doğrulaması", "Zendesk"),
    (r"slack-domain-verification=([A-Za-z0-9_-]+)", "Slack Doğrulaması", "Slack"),
    (r"github-domain-verification=([A-Za-z0-9_-]+)", "GitHub Doğrulaması", "GitHub"),
    (r"brave-ledger-verification=([A-Za-z0-9_-]+)", "Brave Doğrulaması", "Brave"),
    (r"zoom-domain-verification=([A-Za-z0-9_-]+)", "Zoom Doğrulaması", "Zoom"),
    (r"notion-domain-verification=([A-Za-z0-9_-]+)", "Notion Doğrulaması", "Notion"),
    (r"dropbox-domain-verification=([A-Za-z0-9_-]+)", "Dropbox Doğrulaması", "Dropbox"),
    (r"pinterest-site-verification=([A-Za-z0-9_-]+)", "Pinterest Doğrulaması", "Pinterest"),
    (r"yandex-verification=([A-Za-z0-9_-]+)", "Yandex Doğrulaması", "Yandex"),
    (r"openai-domain-verification=([A-Za-z0-9_-]+)", "OpenAI Doğrulaması", "OpenAI"),
    (r"miro-verification=([A-Za-z0-9_-]+)", "Miro Doğrulaması", "Miro"),
    (r"canva-domain-verification=([A-Za-z0-9_-]+)", "Canva Doğrulaması", "Canva"),
    (r"airtable-site-verification=([A-Za-z0-9_-]+)", "Airtable Doğrulaması", "Airtable"),
    (r"postman-domain-verification=([A-Za-z0-9_-]+)", "Postman Doğrulaması", "Postman"),
    (r"linear-domain-verification=([A-Za-z0-9_-]+)", "Linear Doğrulaması", "Linear"),
    (r"intercom-domain-verification=([A-Za-z0-9_-]+)", "Intercom Doğrulaması", "Intercom"),
    (r"1password-site-verification=([A-Za-z0-9_-]+)", "1Password Doğrulaması", "1Password"),
    (r"bitbucket-domain-verification=([A-Za-z0-9_-]+)", "Bitbucket Doğrulaması", "Atlassian"),
]

CNAME_SERVICES = [
    (r"github\.io", "GitHub Pages"),
    (r"s3[.-].*\.amazonaws\.com|s3\.amazonaws\.com", "AWS S3 Bucket"),
    (r"azurewebsites\.net|trafficmanager\.net", "Microsoft Azure App Service"),
    (r"herokuapp\.com", "Heroku"),
    (r"wpengine\.com", "WP Engine"),
    (r"myshopify\.com", "Shopify"),
    (r"ghost\.io", "Ghost"),
    (r"firebaseapp\.com|web\.app", "Google Firebase"),
    (r"vercel-dns\.com|vercel\.app", "Vercel"),
    (r"netlify\.app|netlify\.com", "Netlify"),
    (r"cloudfront\.net", "AWS CloudFront CDN"),
    (r"fastly\.net", "Fastly CDN"),
    (r"blob\.core\.windows\.net", "Azure Blob Storage"),
    (r"storage\.googleapis\.com", "Google Cloud Storage"),
    (r"pages\.dev", "Cloudflare Pages"),
    (r"fly\.dev", "Fly.io"),
    (r"render\.com|onrender\.com", "Render"),
    (r"railway\.app", "Railway"),
    (r"surge\.sh", "Surge.sh"),
    (r"gitbook\.io", "GitBook"),
    (r"readmesoftware\.com|readme\.io", "ReadMe Documentation"),
    (r"custom\.statuspage\.io", "Atlassian Statuspage"),
    (r"zendesk\.com", "Zendesk Help Center"),
    (r"freshdesk\.com", "Freshdesk Portal"),
]


def match_provider(value, rules):
    low = value.lower()
    for pattern, name in rules:
        if re.search(pattern, low):
            return name
    return None


def match_txt(value):
    findings = []
    for pattern, label, vendor in TXT_PATTERNS:
        match = re.search(pattern, value)
        if match:
            findings.append((label, vendor, match.group(0)))
    return findings
