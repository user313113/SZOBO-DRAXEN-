import unittest
from unittest.mock import Mock, patch

from draxen.analysis import analyze
from draxen.cli import main, parser
from draxen.cookie_audit import audit_cookies, parse_single_cookie
from draxen.core import Report, Target
from draxen.port_scanner import PortScanner, probe_port
from draxen.subdomain_discovery import SubdomainDiscoverer
from draxen.tls_inspector import extract_sig_alg, inspect_tls
try:
    from test_draxen import FakeClient
except ImportError:
    from tests.test_draxen import FakeClient


class CookieAuditTests(unittest.TestCase):
    def test_insecure_cookie(self):
        raw = "sessionid=xyz123; Path=/"
        res = parse_single_cookie(raw)
        self.assertIsNotNone(res)
        self.assertEqual(res["name"], "sessionid")
        self.assertFalse(res["secure"])
        self.assertFalse(res["httponly"])
        self.assertEqual(res["samesite"], "Eksik")
        self.assertTrue(res["is_insecure"])
        self.assertIn("HttpOnly", res["missing"])
        self.assertIn("Secure", res["missing"])
        self.assertIn("SameSite", res["missing"])

    def test_secure_cookie(self):
        raw = "jwt_token=abc; Path=/; Secure; HttpOnly; SameSite=Strict"
        res = parse_single_cookie(raw)
        self.assertIsNotNone(res)
        self.assertTrue(res["secure"])
        self.assertTrue(res["httponly"])
        self.assertEqual(res["samesite"], "Strict")
        self.assertFalse(res["is_insecure"])
        self.assertEqual(len(res["missing"]), 0)

    def test_audit_cookies_list(self):
        raw_list = [
            "pref=dark; Path=/",
            "auth=secret; Secure; HttpOnly; SameSite=Lax",
        ]
        results = audit_cookies(raw_list)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0]["is_insecure"])
        self.assertFalse(results[1]["is_insecure"])

    def test_cookie_insights(self):
        report = Report(Target.parse("example.com"))
        report.add("cookie_insecurity", "sessionid (Eksik: HttpOnly, Secure)", "https://example.com")
        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("cookie_security_weak", types)


class TlsCertificateDeepTests(unittest.TestCase):
    def test_extract_sig_alg_sha1(self):
        der_sha1 = b"\x30\x82\x01\x00" + b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05" + b"\x00"
        name, is_weak = extract_sig_alg(der_sha1)
        self.assertEqual(name, "SHA1-RSA")
        self.assertTrue(is_weak)

    def test_extract_sig_alg_sha256(self):
        der_sha256 = b"\x30\x82\x01\x00" + b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b" + b"\x00"
        name, is_weak = extract_sig_alg(der_sha256)
        self.assertEqual(name, "SHA256-RSA")
        self.assertFalse(is_weak)

    def test_tls_deep_insights(self):
        report = Report(Target.parse("example.com"))
        report.add("tls_weak_signature", "Zayıf İmza Algoritması: SHA1-RSA", "https://example.com:443")
        report.add("tls_certificate", "Issuer: DigiCert, Expiry: 2020-01-01", "https://example.com:443", details={"is_expired": True, "is_wildcard": True})
        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("tls_weak_signature", types)
        self.assertIn("tls_cert_expired", types)
        self.assertIn("tls_wildcard_cert", types)


class SubdomainDiscoveryTests(unittest.TestCase):
    def test_subdomain_discoverer(self):
        target = Target.parse("example.com")
        report = Report(target)
        dns_res = {
            "admin.example.com": {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]},
            "api.example.com": {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.35"}]},
        }
        client = FakeClient(dns_res)
        collector = Mock()
        collector.target = target
        collector.report = report
        collector.ips = set()
        collector.current_ips = set()
        collector.candidates = set()

        def fake_query(name, rtype):
            if name in dns_res:
                return dns_res[name]["Answer"], f"https://dns.google/resolve?name={name}"
            return [], "https://dns.google/resolve"

        collector.query_dns.side_effect = fake_query

        discoverer = SubdomainDiscoverer(collector, words=["admin", "api", "missing"], limit=10)
        discoverer.run()

        findings = {item["value"] for item in report.data["findings"]}
        self.assertIn("admin.example.com", findings)
        self.assertIn("api.example.com", findings)
        self.assertIn("admin.example.com", collector.candidates)
        self.assertIn("93.184.216.34", collector.ips)


class PortScannerTests(unittest.TestCase):
    def test_port_scanner_mock_data(self):
        target = Target.parse("93.184.216.34")
        report = Report(target)
        client = FakeClient()
        client.mock_ports = [
            {"port": 22, "service": "SSH", "open": True, "banner": "SSH-2.0-OpenSSH_8.9p1"},
            {"port": 80, "service": "HTTP", "open": True, "banner": "Server: nginx/1.18.0"},
            {"port": 3306, "service": "MySQL", "open": True, "banner": "MySQL 8.0.35"},
        ]
        scanner = PortScanner(report, client=client)
        scanner.scan_ip("93.184.216.34")

        kinds = {item["kind"]: item["value"] for item in report.data["findings"]}
        self.assertIn("open_port", kinds)
        self.assertIn("service_banner", kinds)

        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("exposed_management_port", types)

    def test_probe_port_private_ip(self):
        res = probe_port("127.0.0.1", 80, "HTTP")
        self.assertFalse(res["open"])


class CliV16Tests(unittest.TestCase):
    def test_cli_flags(self):
        p = parser()
        args = p.parse_args(["example.com", "--brute", "--ports"])
        self.assertTrue(args.brute)
        self.assertTrue(args.ports)

    def test_cli_brute_rejected_for_ip(self):
        with self.assertRaises(SystemExit):
            main(["8.8.8.8", "--brute"])




class MarkdownReportTests(unittest.TestCase):
    def test_markdown_report_generation(self):
        from draxen.output import markdown_report, save_reports
        import tempfile
        from pathlib import Path

        target = Target.parse("example.com")
        report = Report(target)
        report.add("dns_a", "93.184.216.34", "https://dns.google", "dns_observed", subject="example.com", relation="resolves_to")
        report.add("asn", "AS15169", "https://stat.ripe.net", "routing_observed", subject="93.184.216.34", relation="origin_asn")
        report.add("datacenter_provider", "Google Cloud Platform (GCP)", "fingerprint_rule", "infrastructure_fingerprint", subject="93.184.216.34", relation="hosted_at")
        report.add("open_port", "443/tcp (HTTPS)", "socket://93.184.216.34:443", "port_probe", subject="93.184.216.34", relation="open_port")
        report.add("cookie_insecurity", "test_cookie (Eksik: HttpOnly)", "https://example.com", "security_audit", subject="example.com", relation="cookie_insecurity")

        data = analyze(report.finish(1))
        md = markdown_report(data)

        self.assertIn("# SZOBO | DRAXEN — Siber İstihbarat & OSINT Raporu", md)
        self.assertIn("## 1. Yönetici Özeti ve Risk Değerlendirmesi", md)
        self.assertIn("## 2. IP, ASN, Veri Merkezi ve Ağ Konum Haritası", md)
        self.assertIn("## 5. Web Güvenlik Başlıkları ve Çerez (Cookie) Denetimi", md)
        self.assertIn("## 6. Açık Portlar ve Servis Banner Bilgileri", md)

        with tempfile.TemporaryDirectory() as folder:
            paths = save_reports(data, folder)
            self.assertEqual(len(paths), 6)
            md_path = Path(folder) / "report.md"
            self.assertTrue(md_path.exists())
            self.assertGreater(len(md_path.read_text()), 100)


if __name__ == "__main__":
    unittest.main()
