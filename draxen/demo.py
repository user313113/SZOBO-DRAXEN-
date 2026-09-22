"""Small, explicitly fictional UI fixture. No clients, sockets or file writes."""

from .analysis import analyze
from .core import Report, Target


def sample_report():
    report = Report(Target.parse("example.com"))
    report.data.update({
        "demo": True,
        "started_at": "2026-09-20T12:08:00+00:00",
        "settings": {"budget": 40, "delay": 1.5, "timeout": 15},
        "policy": "Çevrimdışı arayüz demosu. Tüm bulgular temsili örnek verilerdir; ağ isteği yapılmaz.",
    })
    groups = [
        ("DNS / örnek çözümleyici", [
            ("dns_a", "203.0.113.42"),
            ("dns_aaaa", "2001:db8::42"),
            ("dns_ns", "ns1.example.net"),
        ]),
        ("RDAP / alan adı", [
            ("registration_ldhName", "example.com"),
            ("registration_event", "1995-08-14T00:00:00Z"),
        ]),
        ("Sertifika şeffaflığı / örnek kayıt", [
            ("certificate_name", "api.example.com"),
            ("certificate_name", "mail.example.com"),
        ]),
        ("Ağ / örnek yönlendirme", [
            ("asn", "AS64500"),
            ("bgp_prefix", "203.0.113.0/24"),
        ]),
        ("TLS / örnek kriptografik profil", [
            ("tls_protocol", "TLSv1.3 / TLS_AES_256_GCM_SHA384"),
            ("tls_certificate", "Örnek CA / demo sertifikası"),
        ]),
        ("HTTP / örnek güvenlik denetimi", [
            ("http_security_header", "Strict-Transport-Security: max-age=31536000"),
            ("server_banner", "Server: demo-server/1.0"),
            ("cookie_insecurity", "demo_session: HttpOnly bayrağı eksik"),
        ]),
    ]
    for name, findings in groups:
        for kind, value in findings:
            report.add(kind, value, "demo://offline", "demo", relation="demo")
        report.source(name, "ok", len(findings))
    data = report.finish(0)
    # Keep the demonstration deterministic, including each evidence timestamp.
    data["finished_at"] = "2026-09-20T12:08:00+00:00"
    for finding in data["findings"]:
        for evidence in finding["evidence"]:
            evidence["observed_at"] = data["started_at"]
    report.warn("DEMO: Belgelenmiş örnek IP/ASN aralıkları ve temsili bulgular kullanılır. Gerçek bir hedef değerlendirmesi değildir.")
    return analyze(data)
