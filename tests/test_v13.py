import json
import unittest
from unittest.mock import Mock, patch

from draxen.analysis import analyze
from draxen.core import Client, Report, Target
from draxen.http_audit import HttpAuditor
from draxen.mail_security import (
    parse_caa_record,
    parse_dkim_key,
    parse_spf_record,
)
from draxen.output import html_report


class MailSecurityV13Tests(unittest.TestCase):
    def test_parse_spf_normal(self):
        spf = '"v=spf1 include:_spf.google.com ip4:192.0.2.0/24 -all"'
        res = parse_spf_record(spf)
        self.assertEqual(res["dns_lookup_count"], 1)
        self.assertFalse(res["exceeds_10_lookup_limit"])
        self.assertEqual(res["qualifier_all"], "-all")
        self.assertEqual(res["ip_ranges"], ["192.0.2.0/24"])
        self.assertEqual(res["authorized_services"][0][0], "Google Workspace")

    def test_parse_spf_exceeds_10_lookups(self):
        many_includes = " ".join(f"include:spf{i}.example.com" for i in range(12))
        spf = f'"v=spf1 {many_includes} ~all"'
        res = parse_spf_record(spf)
        self.assertEqual(res["dns_lookup_count"], 12)
        self.assertTrue(res["exceeds_10_lookup_limit"])

    def test_parse_dkim(self):
        dkim = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3..."
        res = parse_dkim_key(dkim)
        self.assertEqual(res["key_type"], "rsa")
        self.assertIn("MIGfMA0GCSqGSIb3DQEBAQUA", res["public_key_preview"])

    def test_parse_caa(self):
        caa = '0 issue "letsencrypt.org"'
        res = parse_caa_record(caa)
        self.assertEqual(res["flag"], "0")
        self.assertEqual(res["tag"], "issue")
        self.assertEqual(res["value"], "letsencrypt.org")


class HttpAuditV13Tests(unittest.TestCase):
    def test_http_auditor(self):
        report = Report(Target.parse("example.com"))
        client = Mock()
        client.timeout = 5
        client.before_request = Mock()
        resp = Mock()
        resp.geturl.return_value = "https://example.com/"
        resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Server": "nginx/1.18.0",
        }
        resp.__enter__ = Mock(return_value=resp)
        resp.__exit__ = Mock(return_value=False)
        client.opener.open.return_value = resp

        auditor = HttpAuditor(client, report, "example.com")
        auditor.audit_headers()

        kinds = {item["kind"]: item["value"] for item in report.data["findings"]}
        self.assertIn("http_security_header", kinds)
        self.assertIn("server_banner", kinds)
        self.assertEqual(kinds["server_banner"], "Server: nginx/1.18.0")


class AnalysisV13Tests(unittest.TestCase):
    def test_spf_lookup_limit_insight(self):
        report = Report(Target.parse("example.com"))
        many = " ".join(f"include:s{i}.net" for i in range(11))
        report.add("email_policy", f'"v=spf1 {many} -all"', "dns", relation="SPF")
        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("spf_lookup_limit_exceeded", types)

    def test_dkim_weak_key_insight(self):
        report = Report(Target.parse("example.com"))
        report.add("dkim_record", "google: MIGf...", "dns", relation="dkim_key", details={"estimated_bits": 1024})
        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("dkim_weak_key", types)

    def test_caa_insight(self):
        report = Report(Target.parse("example.com"))
        report.add("dns_caa_directive", 'issue: "letsencrypt.org"', "dns")
        data = analyze(report.finish(0))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("caa_policy_configured", types)

    def test_html_buttons_and_nav(self):
        report = Report(Target.parse("example.com"))
        report.add("domain", "example.com", "input")
        data = analyze(report.finish(0))
        html = html_report(data)
        self.assertIn("btn-json", html)
        self.assertIn("btn-csv", html)
        self.assertIn("JSON Olarak İndir", html)
        self.assertIn("CSV Olarak İndir", html)
        self.assertIn("nav-pills", html)
        self.assertIn("inspector", html)


if __name__ == "__main__":
    unittest.main()
