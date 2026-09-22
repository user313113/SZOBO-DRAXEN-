import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from draxen.analysis import analyze
from draxen.cli import main, parser
from draxen.core import Report, Target
from draxen.infra import (
    detect_edge_from_cname,
    detect_edge_from_headers,
    detect_rir,
    parse_soa_record,
)
from draxen.tls_inspector import inspect_tls


class InfraV14Tests(unittest.TestCase):
    def test_detect_edge_headers(self):
        headers = {"cf-ray": "12345-IST", "server": "cloudflare"}
        detected = detect_edge_from_headers(headers)
        names = [d[0] for d in detected]
        self.assertIn("Cloudflare WAF / CDN", names)
        self.assertIn("Cloudflare", names)

    def test_detect_edge_cname(self):
        self.assertEqual(detect_edge_from_cname("d123.cloudfront.net"), "Amazon CloudFront")
        self.assertEqual(detect_edge_from_cname("example.azureedge.net"), "Microsoft Azure Front Door / CDN")
        self.assertIsNone(detect_edge_from_cname("direct.customhost.org"))

    def test_parse_soa_record(self):
        soa = "ns1.example.com. hostmaster.example.com. 2026092001 7200 3600 1209600 3600"
        res = parse_soa_record(soa)
        self.assertEqual(res["primary_ns"], "ns1.example.com")
        self.assertEqual(res["hostmaster_email"], "hostmaster@example.com")
        self.assertEqual(res["serial"], 2026092001)
        self.assertTrue(res["is_date_serial"])
        self.assertEqual(len(res["rfc1912_issues"]), 0)

    def test_parse_soa_rfc1912_issues(self):
        soa = "ns1.example.com. hostmaster.example.com. 1 300 7200 86400 300"
        res = parse_soa_record(soa)
        self.assertGreater(len(res["rfc1912_issues"]), 0)

    def test_detect_rir(self):
        self.assertIn("ARIN", detect_rir("8.8.8.8"))
        self.assertIn("RIPE NCC", detect_rir("185.199.108.153"))
        self.assertIn("APNIC", detect_rir("1.1.1.1"))
        self.assertEqual(detect_rir("invalid-ip"), "Bilinmiyor")


class TlsInspectorV14Tests(unittest.TestCase):
    @patch("draxen.tls_inspector.socket.create_connection")
    @patch("draxen.tls_inspector.ssl.create_default_context")
    @patch("draxen.tls_inspector.socket.getaddrinfo")
    def test_inspect_tls_mock(self, mock_addr, mock_ctx, mock_conn):
        mock_addr.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        mock_sock = Mock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        ssock = Mock()
        ssock.version.return_value = "TLSv1.3"
        ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssock.getpeercert.return_value = {
            "subject": [[("commonName", "example.com")], [("organizationName", "Example Corp")]],
            "issuer": [[("commonName", "DigiCert Global Root CA")], [("organizationName", "DigiCert Inc")]],
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
            "notAfter": "May 15 12:00:00 2028 GMT",
        }
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = ssock

        res = inspect_tls("example.com")
        self.assertIsNotNone(res)
        self.assertEqual(res["protocol"], "TLSv1.3")
        self.assertEqual(res["cipher"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(res["subject_cn"], "example.com")
        self.assertEqual(res["issuer_cn"], "DigiCert Global Root CA")
        self.assertIn("www.example.com", res["sans"])
        self.assertFalse(res["is_self_signed"])
        self.assertGreater(res["days_until_expiry"], 100)


class AnalysisV14Tests(unittest.TestCase):
    def test_edge_protection_insight(self):
        report = Report(Target.parse("example.com"))
        report.add("edge_infrastructure", "Cloudflare WAF / CDN (Header)", "https://example.com")
        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("edge_protection_active", types)

    def test_tls_expiring_soon_insight(self):
        report = Report(Target.parse("example.com"))
        report.add("tls_certificate", "Issuer: Test", "https://example.com", details={"days_until_expiry": 15})
        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("tls_expiring_soon", types)


if __name__ == "__main__":
    unittest.main()
