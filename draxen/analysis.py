ENTITY_TITLES = {
    "domains_subdomains": "Alan Adları & Alt Alan Adları",
    "network_routing": "Ağ & Yönlendirme (IP/BGP/ASN)",
    "mail_communication": "Posta & İletişim Altyapısı",
    "cloud_infrastructure": "Bulut & Kenar Altyapı",
    "security_identity": "Güvenlik, Kimlik & İlkeler",
    "registration_other": "Kayıt & Diğer Bulgular",
}

import json
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

from .mail_security import parse_spf_record
from .timeline import build_timeline


def insight_level(itype):
    """Shared presentation severity for terminal, HTML and Markdown reports."""
    if itype in ("exposed_management_port", "tls_cert_expired", "tls_weak_signature", "spf_permissive"):
        return "critical"
    if itype in ("cookie_security_weak", "tls_expiring_soon", "tls_self_signed", "server_version_disclosure", "soa_rfc1912_issues", "spf_lookup_limit_exceeded", "dkim_weak_key"):
        return "warn"
    return "info"


def identity(item):
    return tuple(item[key] for key in ("kind", "value", "subject", "relation"))


def load_baseline(path, target):
    path = Path(path)
    with path.open("rb") as handle:
        body = handle.read(16_000_001)
    if len(body) > 16_000_000:
        raise ValueError("Önceki rapor 16 MB sınırını aşıyor")
    data = json.loads(body)
    if not isinstance(data, dict) or data.get("tool") != "SZOBO | DRAXEN" or data.get("target") != {"value": target.value, "kind": target.kind}:
        raise ValueError("Karşılaştırma için aynı hedefe ait DRAXEN JSON raporu gerekli")
    if not isinstance(data.get("findings"), list):
        raise ValueError("Önceki raporda bulgu listesi eksik")
    for item in data["findings"]:
        if not isinstance(item, dict) or any(not isinstance(item.get(key), str) for key in ("kind", "value", "subject", "relation")):
            raise ValueError("Önceki raporun bulgu şeması geçersiz")
    return data


def categorize_finding(kind):
    if kind in ("domain", "certificate_name", "discovered_domain", "linked_subdomain", "archived_url", "indexed_url", "sitemap_url"):
        return "domains_subdomains"
    if kind in ("dns_a", "dns_aaaa", "ptr", "historical_ip", "network_subnet", "bgp_prefix", "asn", "asn_holder", "rir_registry", "ip_country", "ip_city", "ip_coordinates", "ip_net_name", "ip_range", "open_port"):
        return "network_routing"
    if kind in ("dns_mx", "public_email", "email_policy", "identified_service", "dkim_record"):
        return "mail_communication"
    if kind in ("cloud_footprint", "external_service_pointer", "edge_infrastructure", "soa_architecture", "nameserver", "dns_ns", "dns_cname", "dns_soa", "dns_caa", "server_banner", "datacenter_provider"):
        return "cloud_infrastructure"
    if kind in ("security_directive", "dnssec_record", "dns_caa_directive", "http_security_header", "tls_protocol", "tls_certificate", "tls_weak_signature", "cookie_policy", "cookie_insecurity", "dns_hostmaster", "media_reference", "public_identity", "public_bio", "gravatar_profile", "registry_contact_fn", "registry_contact_org", "registry_contact_email"):
        return "security_identity"
    return "registration_other"


def build_entity_matrix(findings):
    matrix = defaultdict(set)
    for item in findings:
        cat = categorize_finding(item["kind"])
        matrix[cat].add((item["kind"], item["value"]))
    return {cat: [{"kind": k, "value": v} for k, v in sorted(items)] for cat, items in sorted(matrix.items())}


def analyze(data, baseline=None):
    hosts_by_ip = defaultdict(set)
    dns_names = set()
    mentions = defaultdict(set)
    insights = []
    policies = defaultdict(list)
    cloud_integrations = []
    external_cnames = []
    services_found = []
    caa_rules = []
    server_banners = []
    edge_detected = []
    soa_issues = []
    disallowed_paths = []
    media_files = []

    for item in data["findings"]:
        kind = item["kind"]
        val = item["value"]
        subj = item["subject"]
        if kind in ("dns_a", "dns_aaaa"):
            hosts_by_ip[val].add(subj)
            dns_names.add(subj)
        if kind in ("certificate_name", "discovered_domain", "linked_subdomain", "sitemap_url"):
            for evidence in item["evidence"]:
                host = urllib.parse.urlsplit(evidence["source"]).hostname
                if host:
                    mentions[val].add(host)
        if kind == "email_policy":
            policies[item["relation"]].append(item)
        if kind == "cloud_footprint":
            cloud_integrations.append(val)
        if kind == "external_service_pointer":
            external_cnames.append(val)
        if kind == "identified_service":
            services_found.append(f"{item['relation']}: {val}")
        if kind == "dns_caa_directive":
            caa_rules.append(val)
        if kind == "server_banner":
            server_banners.append(val)
        if kind == "edge_infrastructure":
            edge_detected.append(val)
        if kind == "crawler_disallowed_path":
            disallowed_paths.append(val)
        if kind == "media_reference":
            media_files.append(val)
        if kind == "soa_architecture":
            for ev in item["evidence"]:
                issues = ev.get("details", {}).get("rfc1912_issues", [])
                if issues:
                    soa_issues.extend(issues)
        if kind == "tls_certificate":
            for ev in item["evidence"]:
                details = ev.get("details", {})
                days_left = details.get("days_until_expiry")
                if days_left is not None and days_left < 30:
                    insights.append({"type": "tls_expiring_soon", "subject": subj, "values": [f"{days_left} gün kaldı"], "message": f"Aktif TLS sertifikasının süresi {days_left} gün içinde doluyor."})
                if details.get("is_self_signed"):
                    insights.append({"type": "tls_self_signed", "subject": subj, "values": [val], "message": "Aktif TLS sertifikası kendinden imzalı (self-signed); güvenilir CA doğrulaması yok."})
        if kind == "dkim_record":
            for ev in item["evidence"]:
                bits = ev.get("details", {}).get("estimated_bits", 0)
                if bits and bits <= 1024:
                    insights.append({"type": "dkim_weak_key", "subject": val, "values": [f"{bits}-bit RSA"], "message": f"DKIM anahtarı {bits}-bit; modern standartlar minimum 2048-bit anahtar uzunluğu önermektedir."})

    for ip, hosts in sorted(hosts_by_ip.items()):
        if len(hosts) > 1:
            insights.append({"type": "shared_ip", "subject": ip, "values": sorted(hosts), "message": "Birden fazla ad aynı IP'ye çözümlendi; ortak barındırma veya CDN olabilir, mülkiyet kanıtı değildir."})
    for name, sources in sorted(mentions.items()):
        if len(sources) > 1:
            insights.append({"type": "multiple_source_mentions", "subject": name, "values": sorted(sources), "message": "Birden fazla kaynakta anılıyor; kaynaklar aynı veriyi yeniden kullanmış olabilir."})
        if name in dns_names:
            insights.append({"type": "candidate_dns_observed", "subject": name, "values": sorted(sources), "message": "Aday ad için bu çalışmada aktif A/AAAA yanıtı da görüldü; hizmet erişimi test edilmedi."})
    for item in policies["SPF"]:
        spf_obj = parse_spf_record(item["value"])
        if spf_obj["exceeds_10_lookup_limit"]:
            insights.append({"type": "spf_lookup_limit_exceeded", "subject": item["subject"], "values": [f"{spf_obj['dns_lookup_count']} sorgu"], "message": f"SPF kaydı RFC 7208 sınırını aşıyor ({spf_obj['dns_lookup_count']}/10); e-posta alıcıları PermError üretebilir."})
        if spf_obj["qualifier_all"] in ("+all", "all"):
            insights.append({"type": "spf_permissive", "subject": item["subject"], "values": [item["value"]], "message": "SPF +all tüm göndericilere izin verir; yetkili yönetici tarafından incelenmeli."})
    for item in policies["DMARC"]:
        tags = dict(part.strip().split("=", 1) for part in item["value"].replace('"', '').split(";") if "=" in part)
        if tags.get("p", "").strip().lower() == "none":
            insights.append({"type": "dmarc_monitoring", "subject": item["subject"], "values": [item["value"]], "message": "DMARC p=none izleme politikasıdır; tek başına zafiyet veya ihlal kanıtı değildir."})
    for cname_info in sorted(set(external_cnames)):
        insights.append({"type": "external_service_cname", "subject": cname_info, "values": [cname_info], "message": "CNAME harici bir bulut/SaaS platformuna yönlendirilmiş; harici kaynak mülkiyeti teyit edilmelidir."})
    if edge_detected:
        insights.append({"type": "edge_protection_active", "subject": data["target"]["value"], "values": sorted(set(edge_detected)), "message": "CDN / WAF kenar koruma platformu tespit edildi; anons edilen IP doğrudan kaynak sunucu olmayabilir."})
    if soa_issues:
        insights.append({"type": "soa_rfc1912_issues", "subject": data["target"]["value"], "values": sorted(set(soa_issues)), "message": "SOA kayıt parametreleri RFC 1912 standartlarıyla uyuşmuyor."})
    if disallowed_paths:
        insights.append({"type": "robots_disallowed_paths", "subject": data["target"]["value"], "values": sorted(set(disallowed_paths))[:15], "message": f"{len(set(disallowed_paths))} adet arama motorlarına kısıtlanmış yol (robots.txt) listelendi."})
    if media_files:
        insights.append({"type": "media_documents_exposed", "subject": data["target"]["value"], "values": sorted(set(media_files))[:15], "message": f"{len(set(media_files))} adet doğrudan indekslenmiş belge veya görsel referansı bulundu."})
    if cloud_integrations:
        insights.append({"type": "cloud_footprint_summary", "subject": data["target"]["value"], "values": sorted(set(cloud_integrations)), "message": f"{len(set(cloud_integrations))} farklı kurumsal bulut veya SaaS doğrulama imzası tespit edildi."})
    if services_found:
        insights.append({"type": "infrastructure_services", "subject": data["target"]["value"], "values": sorted(set(services_found)), "message": "Temel posta ve DNS sağlayıcı altyapısı parmak iziyle eşleştirildi."})
    if caa_rules:
        insights.append({"type": "caa_policy_configured", "subject": data["target"]["value"], "values": caa_rules, "message": "Sertifika Yetkilisi Yetkilendirme (CAA) kaydı aktif; sertifika basım yetkisi sınırlandırılmıştır."})
    if server_banners:
        for ban in sorted(set(server_banners)):
            insights.append({"type": "server_version_disclosure", "subject": ban, "values": [ban], "message": "HTTP sunucu yanıt başlığı yazılım/sürüm detayı sızdırıyor."})
    datacenter_hosts = [item for item in data["findings"] if item["kind"] == "datacenter_provider"]
    for dc in datacenter_hosts:
        insights.append({"type": "datacenter_hosting_detected", "subject": dc.get("subject", data["target"]["value"]), "values": [dc["value"]], "message": f"Hedef IP adresi veri merkezi / bulut sağlayıcısında barındırılıyor: {dc['value']}."})
    coords = [item for item in data["findings"] if item["kind"] == "ip_coordinates"]
    for c in coords:
        sub = c.get("subject", data["target"]["value"])
        city_item = next((item for item in data["findings"] if item["kind"] == "ip_city" and item.get("subject") == sub), None)
        country_item = next((item for item in data["findings"] if item["kind"] == "ip_country" and item.get("subject") == sub), None)
        loc_parts = [p for p in (city_item["value"] if city_item else None, country_item["value"] if country_item else None) if p]
        loc_str = ", ".join(loc_parts) if loc_parts else "Konum"
        insights.append({"type": "ip_geolocation_identified", "subject": sub, "values": [c["value"]], "message": f"Ağ coğrafi konumu: {loc_str} (Koordinat: {c['value']})."})
    bgp_prefixes = [item for item in data["findings"] if item["kind"] == "bgp_prefix"]
    for bp in bgp_prefixes:
        sub = bp.get("subject", data["target"]["value"])
        asn_item = next((item for item in data["findings"] if item["kind"] == "asn" and item.get("subject") == sub), None)
        holder_item = next((item for item in data["findings"] if item["kind"] == "asn_holder" and (item.get("subject") == (asn_item["value"] if asn_item else None) or item.get("subject") == sub)), None)
        details = [bp["value"]]
        if asn_item:
            details.append(asn_item["value"])
        if holder_item:
            details.append(holder_item["value"])
        insights.append({"type": "bgp_routing_identified", "subject": sub, "values": details, "message": f"BGP anons öneği ve otonom sistem yönlendirmesi tespit edildi: {' | '.join(details)}."})
    insecure_cookies = [item for item in data["findings"] if item["kind"] == "cookie_insecurity"]
    for ic in insecure_cookies:
        insights.append({"type": "cookie_security_weak", "subject": ic.get("subject", data["target"]["value"]), "values": [ic["value"]], "message": f"Eksik çerez (cookie) güvenlik bayrakları tespit edildi: {ic['value']}."})
    open_ports = [item for item in data["findings"] if item["kind"] == "open_port"]
    for op in open_ports:
        val = op["value"].lower()
        if any(p in val for p in ("21/tcp", "22/tcp", "23/tcp", "3306/tcp", "5432/tcp", "6379/tcp", "27017/tcp")):
            insights.append({"type": "exposed_management_port", "subject": op.get("subject", data["target"]["value"]), "values": [op["value"]], "message": f"Hassas yönetim veya veritabanı portu dış dünyaya açık: {op['value']}."})
    weak_sigs = [item for item in data["findings"] if item["kind"] == "tls_weak_signature"]
    for ws in weak_sigs:
        insights.append({"type": "tls_weak_signature", "subject": ws.get("subject", data["target"]["value"]), "values": [ws["value"]], "message": f"TLS sertifikasında zayıf veya kullanım dışı imza algoritması tespit edildi: {ws['value']}."})
    for item in data["findings"]:
        if item["kind"] == "tls_certificate":
            for ev in item.get("evidence", []):
                details = ev.get("details", {})
                if details.get("is_expired"):
                    insights.append({"type": "tls_cert_expired", "subject": item.get("subject", data["target"]["value"]), "values": [item["value"]], "message": "Aktif TLS sertifikasının süresi dolmuştur (expired)!"})
                    break
    for item in data["findings"]:
        if item["kind"] == "tls_certificate":
            for ev in item.get("evidence", []):
                details = ev.get("details", {})
                if details.get("is_wildcard"):
                    insights.append({"type": "tls_wildcard_cert", "subject": item.get("subject", data["target"]["value"]), "values": [item["value"]], "message": "Alan adı için joker karakterli (wildcard) TLS sertifikası kullanılmaktadır."})
                    break

    data["timeline"] = build_timeline(data["findings"])
    data["entities"] = build_entity_matrix(data["findings"])
    data["analysis"] = {
        "finding_types": dict(sorted(Counter(item["kind"] for item in data["findings"]).items())),
        "entity_counts": {cat: len(items) for cat, items in data["entities"].items()},
        "source_states": dict(Counter(source["state"] for source in data["sources"])),
        "timeline_event_count": len(data["timeline"]),
        "insights": insights,
    }

    if baseline is not None:
        old = {identity(item): item for item in baseline["findings"]}
        new = {identity(item): item for item in data["findings"]}
        compact = lambda keys, lookup: [{key: lookup[k][key] for key in ("kind", "value", "subject", "relation")} for k in sorted(keys)]
        data["comparison"] = {
            "baseline_started_at": baseline.get("started_at"),
            "added": compact(new.keys() - old.keys(), new),
            "not_observed": compact(old.keys() - new.keys(), old),
            "unchanged_count": len(new.keys() & old.keys()),
            "caution": "Bu karşılaştırma kayıt değerlerini karşılaştırır, zaman/kanıt metadatasını değil. Bu çalışmada görülmeyen bulgu silinmiş sayılmaz; kaynak hataları, seçenekler ve limitler sonucu değiştirebilir.",
        }
    return data
