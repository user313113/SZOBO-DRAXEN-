import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from draxen.analysis import analyze, build_entity_matrix, categorize_finding
from draxen.cli import main, parser
from draxen.collectors import Collector
from draxen.core import Client, Report, Target
from draxen.enrichment import Enrichment
from draxen.fingerprints import (
    CNAME_SERVICES,
    MX_PROVIDERS,
    NS_PROVIDERS,
    match_provider,
    match_txt,
)
from draxen.output import dot_report, html_report, node_color, print_summary
from draxen.security import SecurityCollector, parse_security_txt
from draxen.timeline import build_timeline, parse_iso
from test_draxen import FakeClient


class FingerprintsTests(unittest.TestCase):
    def test_mx_matching(self):
        self.assertEqual(match_provider("aspmx.l.google.com.", MX_PROVIDERS), "Google Workspace / Gmail")
        self.assertEqual(match_provider("example-com.mail.protection.outlook.com", MX_PROVIDERS), "Microsoft 365 / Exchange Online")
        self.assertEqual(match_provider("mail.protonmail.ch", MX_PROVIDERS), "Proton Mail")
        self.assertIsNone(match_provider("custom-mail.example.org", MX_PROVIDERS))

    def test_ns_matching(self):
        self.assertEqual(match_provider("ns1.cloudflare.com", NS_PROVIDERS), "Cloudflare DNS")
        self.assertEqual(match_provider("ns-123.awsdns-45.org", NS_PROVIDERS), "Amazon Web Services Route 53")
        self.assertIsNone(match_provider("ns1.privatecustom.net", NS_PROVIDERS))

    def test_cname_matching(self):
        self.assertEqual(match_provider("myorg.github.io", CNAME_SERVICES), "GitHub Pages")
        self.assertEqual(match_provider("bucket.s3.amazonaws.com", CNAME_SERVICES), "AWS S3 Bucket")
        self.assertIsNone(match_provider("lb.internal.org", CNAME_SERVICES))

    def test_txt_matching(self):
        matches = match_txt("google-site-verification=abc123xyz")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1], "Google")
        matches = match_txt("MS=ms12345678")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][1], "Microsoft")
        self.assertEqual(len(match_txt("v=spf1 include:_spf.google.com ~all")), 0)


class SecurityTests(unittest.TestCase):
    def test_parse_security_txt(self):
        sample = "Contact: mailto:security@example.com\nEncryption: https://example.com/pgp.key\nPolicy: https://example.com/security-policy\nExpires: 2027-01-01T00:00:00Z\n"
        fields = parse_security_txt(sample)
        self.assertEqual(len(fields), 4)
        self.assertEqual(fields[0], ("Contact", "mailto:security@example.com"))
        self.assertEqual(fields[3], ("Expires", "2027-01-01T00:00:00Z"))

    def test_security_txt_collection(self):
        target = Target.parse("example.com")
        client = FakeClient({"https://example.com/.well-known/security.txt": "Contact: mailto:sec@example.com\nPolicy: https://example.com/policy"})
        report = Report(target)
        collector = Collector(client, report, target, security=True)
        collector.sec_collector.security_txt()
        vals = {item["value"] for item in report.data["findings"]}
        self.assertIn("mailto:sec@example.com", vals)
        self.assertIn("https://example.com/policy", vals)

    def test_gravatar_collection(self):
        target = Target.parse("user@example.com")
        gravatar_payload = {
            "entry": [{
                "profileUrl": "https://gravatar.com/testuser",
                "displayName": "Test User",
                "currentLocation": "Europe",
                "aboutMe": "Security researcher",
            }]
        }
        client = FakeClient({"en.gravatar.com": gravatar_payload})
        report = Report(target)
        collector = Collector(client, report, target, security=True)
        collector.sec_collector.gravatar()
        kinds = {item["kind"]: item["value"] for item in report.data["findings"]}
        self.assertEqual(kinds["gravatar_profile"], "https://gravatar.com/testuser")
        self.assertEqual(kinds["public_identity"], "Test User")
        self.assertEqual(kinds["reported_location"], "Europe")
        self.assertEqual(kinds["public_bio"], "Security researcher")


class TimelineTests(unittest.TestCase):
    def test_parse_iso(self):
        self.assertEqual(parse_iso("2026-09-20T12:00:00Z"), "2026-09-20T12:00:00+00:00")
        self.assertEqual(parse_iso("2026-09-20"), "2026-09-20T00:00:00+00:00")
        self.assertEqual(parse_iso("20200101123000"), "2020-01-01T12:30:00+00:00")
        self.assertIsNone(parse_iso("not-a-date"))

    def test_build_timeline(self):
        findings = [
            {"kind": "registration_event", "value": "2020-01-01T00:00:00Z", "subject": "example.com", "relation": "registration", "evidence": [{"source": "rdap", "details": {}}]},
            {"kind": "certificate_name", "value": "sub.example.com", "subject": "example.com", "relation": "mentions", "evidence": [{"source": "crt.sh", "details": {"not_before": "2025-01-01", "not_after": "2026-01-01"}}]},
            {"kind": "archived_url", "value": "https://example.com/old", "subject": "example.com", "relation": "ref", "evidence": [{"source": "wayback", "details": {"timestamp": "20210505120000"}}]},
        ]
        events = build_timeline(findings)
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0]["category"], "Sertifika")
        self.assertEqual(events[-1]["category"], "Kayıt / Domain")


class AnalysisV12Tests(unittest.TestCase):
    def test_categories(self):
        self.assertEqual(categorize_finding("domain"), "domains_subdomains")
        self.assertEqual(categorize_finding("dns_a"), "network_routing")
        self.assertEqual(categorize_finding("dns_mx"), "mail_communication")
        self.assertEqual(categorize_finding("cloud_footprint"), "cloud_infrastructure")
        self.assertEqual(categorize_finding("security_directive"), "security_identity")

    def test_matrix_and_insights(self):
        report = Report(Target.parse("example.com"))
        report.add("cloud_footprint", "Google (Google Hizmet Doğrulaması)", "dns")
        report.add("external_service_pointer", "docs.example.com -> GitHub Pages", "dns")
        report.add("identified_service", "Google Workspace / Gmail", "dns", relation="mail_provider")
        data = analyze(report.finish(0))
        self.assertIn("cloud_infrastructure", data["entities"])
        insights = {item["type"] for item in data["analysis"]["insights"]}
        self.assertIn("cloud_footprint_summary", insights)
        self.assertIn("external_service_cname", insights)
        self.assertIn("infrastructure_services", insights)

    def test_node_coloring(self):
        self.assertEqual(node_color("domain"), "#58d8ae")
        self.assertEqual(node_color("dns_a"), "#fca311")
        self.assertEqual(node_color("asn"), "#b5838d")
        self.assertEqual(node_color("identified_service"), "#48cae4")
        self.assertEqual(node_color("cloud_footprint"), "#80ed99")
        self.assertEqual(node_color("security_directive"), "#ffd166")

    def test_html_includes_matrix_and_timeline(self):
        report = Report(Target.parse("example.com"))
        report.add("registration_event", "2020-01-01T00:00:00Z", "https://rdap.org", relation="registration")
        report.add("cloud_footprint", "Google (Verification)", "https://dns.google")
        data = analyze(report.finish(0))
        rendered = html_report(data)
        self.assertIn("Varlık Dağılım Matrisi", rendered)
        self.assertIn("Kronolojik Olay &amp; Sertifika Çizelgesi", rendered)


class NetworkSubnetTests(unittest.TestCase):
    def test_network_subnet_and_asn_holder(self):
        target = Target.parse("example.com")
        ripe_net = {
            "status": "ok",
            "data": {"prefix": "8.8.8.0/24", "asns": [15169]},
        }
        ripe_as = {
            "status": "ok",
            "data": {"holder": "GOOGLE - Google LLC, US"},
        }
        client = FakeClient({
            "network-info": ripe_net,
            "as-overview": ripe_as,
        })
        report = Report(target)
        enrichment = Enrichment(Collector(client, report, target))
        enrichment.network("8.8.8.8")
        kinds = {item["kind"]: item["value"] for item in report.data["findings"]}
        self.assertEqual(kinds["network_subnet"], "8.8.8.0/24")
        self.assertEqual(kinds["bgp_prefix"], "8.8.8.0/24")
        self.assertEqual(kinds["asn"], "AS15169")
        self.assertEqual(kinds["asn_holder"], "GOOGLE - Google LLC, US")


class CliV12Tests(unittest.TestCase):
    def test_deep_enables_security_and_fingerprints(self):
        fixture = {
            "crt.sh": [{"name_value": "api.example.com"}],
            "rdap.org": {"objectClassName": "domain"},
            "web.archive.org": [],
            "urlscan.io": {"results": []},
            "security.txt": "Contact: mailto:sec@example.com",
            "stat.ripe.net": {"status": "ok", "data": {"prefix": "8.8.8.0/24", "asns": [15169]}},
        }
        with tempfile.TemporaryDirectory() as folder, patch("draxen.cli.Client", return_value=FakeClient(fixture)):
            code = main(["example.com", "--deep", "--quiet", "--output", folder])
            self.assertEqual(code, 0)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertTrue(data["settings"]["security"])
            self.assertTrue(data["settings"]["archives"])
            self.assertTrue(data["settings"]["network"])
            self.assertIn("timeline", data)
            self.assertIn("entities", data)

    def test_security_flag_rejected_for_ip(self):
        with self.assertRaises(SystemExit):
            main(["8.8.8.8", "--security"])


if __name__ == "__main__":
    unittest.main()
