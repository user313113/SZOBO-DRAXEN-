import csv
import io
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from draxen.analysis import analyze, load_baseline
from draxen.cli import main
from draxen.collectors import Collector
from draxen.core import BudgetExceeded, FetchError, Report, Target
from draxen.enrichment import clean_url, scoped_host
from draxen.exports import csv_report, graphml_report, safe_cell
from draxen.output import html_report
from draxen.rdap import lookup
from test_draxen import FakeClient


class EnrichmentTests(unittest.TestCase):
    def collector(self, data=None, **kwargs):
        target = Target.parse("example.com")
        return Collector(FakeClient(data), Report(target), target, **kwargs)

    def test_dns_failure_does_not_drop_remaining_types(self):
        c = self.collector({"type=A&": FetchError("offline")})
        def query(name, kind):
            if kind == "A":
                raise FetchError("A unavailable")
            if kind == "MX":
                return [{"type": 15, "data": "10 mail.example.com.", "name": "example.com.", "TTL": 60}], "https://dns.google"
            return [], "https://dns.google"
        c.query_dns = query
        c.run_source("DNS", c.dns)
        self.assertEqual(c.report.data["sources"][0]["state"], "incomplete")
        self.assertEqual(c.report.data["findings"][0]["kind"], "dns_mx")
        self.assertIn("A unavailable", c.report.data["sources"][0]["message"])

    def test_dns_budget_stops_remaining_types(self):
        c = self.collector()
        calls = []
        def query(name, kind):
            calls.append(kind)
            raise BudgetExceeded("budget")
        c.query_dns = query
        with self.assertRaises(BudgetExceeded):
            c.dns()
        self.assertEqual(calls, ["A"])

    def test_scoped_host(self):
        self.assertEqual(scoped_host("WWW.Example.com.", "example.com"), "www.example.com")
        for raw in (None, "evil-example.com", "example.com.evil.com", "*.example.com", "localhost"):
            self.assertIsNone(scoped_host(raw, "example.com"))

    def test_clean_url(self):
        self.assertEqual(clean_url("https://www.example.com/path?token=secret#private", "example.com"), "https://www.example.com/path")
        for raw in ("https://example.com@evil.com", "javascript:alert(1)", "https://a:b@example.com", "https://example.com:bad/x", "https://[", None):
            self.assertIsNone(clean_url(raw, "example.com"))

    def test_wayback(self):
        c = self.collector({"web.archive.org": [["original", "timestamp", "statuscode", "mimetype"], ["https://old.example.com/a?secret=1", "20200101000000", "200", "text/html"], ["https://evil.com/a", "20200101000000", "200", "text/html"]]})
        c.enrichment.wayback()
        values = {item["value"] for item in c.report.data["findings"]}
        self.assertEqual(values, {"https://old.example.com/a", "old.example.com"})
        self.assertEqual(c.candidates, {"old.example.com"})
        self.assertEqual(c.client.requests, 1)
        self.assertNotIn("secret", json.dumps(c.report.data))

    def test_wayback_empty(self):
        c = self.collector({"web.archive.org": []})
        c.enrichment.wayback()
        self.assertEqual(c.report.data["findings"], [])

    def test_wayback_invalid_header(self):
        c = self.collector({"web.archive.org": [["wrong"]]})
        with self.assertRaises(FetchError):
            c.enrichment.wayback()

    def test_wayback_limit(self):
        c = self.collector({"web.archive.org": [["original"], ["https://a.example.com"], ["https://b.example.com"]]}, limit=1)
        c.enrichment.wayback()
        self.assertEqual(c.candidates, {"a.example.com"})
        self.assertTrue(any("sınır" in warning for warning in c.report.data["warnings"]))

    def test_urlscan_scope_and_historical_ip(self):
        c = self.collector({"urlscan.io": {"results": [{"page": {"url": "https://a.example.com/?key=secret", "ip": "8.8.8.8"}, "task": {"time": "2020-01-01"}}, {"page": {"url": "https://external.org", "ip": "1.1.1.1"}}]}})
        c.enrichment.urlscan()
        self.assertEqual(c.candidates, {"a.example.com"})
        self.assertEqual(c.ips, set())
        ips = [item for item in c.report.data["findings"] if item["kind"] == "historical_ip"]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0]["evidence"][0]["status"], "historical_candidate")
        self.assertNotIn("secret", json.dumps(c.report.data))
        self.assertEqual(c.client.requests, 1)

    def test_urlscan_private_ip_ignored(self):
        c = self.collector({"urlscan.io": {"results": [{"page": {"url": "https://example.com", "ip": "127.0.0.1"}}]}})
        c.enrichment.urlscan()
        self.assertFalse(any(item["kind"] == "historical_ip" for item in c.report.data["findings"]))

    def test_urlscan_auth_failure_not_empty(self):
        c = self.collector({"urlscan.io": {"message": "API key required"}})
        c.run_source("urlscan", c.enrichment.urlscan)
        self.assertEqual(c.report.data["sources"][0]["state"], "incomplete")

    def test_network(self):
        c = self.collector({"stat.ripe.net": {"status": "ok", "data": {"prefix": "8.8.8.0/24", "asns": [15169, "invalid", 0]}}})
        c.enrichment.network("8.8.8.8")
        self.assertEqual({item["value"] for item in c.report.data["findings"]}, {"8.8.8.0/24", "AS15169"})

    def test_network_wrong_prefix(self):
        c = self.collector({"stat.ripe.net": {"status": "ok", "data": {"prefix": "1.1.1.0/24", "asns": [13335]}}})
        with self.assertRaises(FetchError):
            c.enrichment.network("8.8.8.8")

    def test_network_private_ip(self):
        c = self.collector()
        with self.assertRaises(FetchError):
            c.enrichment.network("127.0.0.1")
        self.assertEqual(c.client.requests, 0)

    def test_mail(self):
        c = self.collector({"dns.google": {"Status": 0, "Answer": [{"type": 16, "data": '"v=STSv1; " "id=123"'}, {"type": 16, "data": '"other"'}]}})
        c.enrichment.mail_record("_mta-sts.example.com", "v=STSv1", "MTA-STS")
        self.assertEqual(c.report.data["findings"][0]["value"], "v=STSv1; id=123")
        self.assertEqual(len(c.report.data["findings"]), 1)

    def test_dnssec(self):
        c = self.collector({"type=DS": {"Status": 0, "Answer": [{"type": 43, "data": "123 13 2 ABC"}]}, "type=DNSKEY": {"Status": 0, "Answer": [{"type": 48, "data": "257 3 13 ABC"}]}})
        c.enrichment.dnssec()
        self.assertEqual(len(c.report.data["findings"]), 2)
        self.assertTrue(c.report.data["warnings"])

    def test_archives_candidates_verified_after_collection(self):
        c = self.collector({"crt.sh": [], "rdap.org": {"objectClassName": "domain"}, "web.archive.org": [["original"], ["https://a.example.com"]], "urlscan.io": {"results": []}}, archives=True, verify=1)
        calls = []
        c.verify_candidates = lambda: calls.append(set(c.candidates))
        c.run()
        self.assertEqual(calls, [{"a.example.com"}])


class RdapTests(unittest.TestCase):
    def test_direct(self):
        client = FakeClient({"rdap.org": {"objectClassName": "domain"}})
        data, url, fallback = lookup(client, "example.com", "domain")
        self.assertFalse(fallback)
        self.assertIn("rdap.org", url)
        self.assertEqual(client.requests, 1)

    def test_bootstrap_domain(self):
        client = FakeClient({"rdap.org": FetchError("offline"), "data.iana.org": {"services": [[["com"], ["https://registry.example/rdap/"]]]}, "registry.example": {"objectClassName": "domain"}})
        data, url, fallback = lookup(client, "example.com", "domain")
        self.assertTrue(fallback)
        self.assertEqual(url, "https://registry.example/rdap/domain/example.com")
        self.assertEqual(client.requests, 3)

    def test_bootstrap_ip_longest_prefix(self):
        client = FakeClient({"rdap.org": FetchError("offline"), "data.iana.org": {"services": [[["8.0.0.0/8"], ["https://broad.example/"]], [["8.8.0.0/16"], ["https://specific.example/"]]]}, "specific.example": {"objectClassName": "ip network"}})
        data, url, fallback = lookup(client, "8.8.8.8", "ip")
        self.assertEqual(url, "https://specific.example/ip/8.8.8.8")

    def test_bootstrap_no_https(self):
        client = FakeClient({"rdap.org": FetchError("offline"), "data.iana.org": {"services": [[["com"], ["http://registry.example/"]]]}})
        with self.assertRaises(FetchError):
            lookup(client, "example.com", "domain")

    def test_budget_no_fallback(self):
        client = FakeClient({"rdap.org": BudgetExceeded("budget")})
        with self.assertRaises(BudgetExceeded):
            lookup(client, "example.com", "domain")
        self.assertEqual(client.requests, 1)


class AnalysisTests(unittest.TestCase):
    def report(self):
        return Report(Target.parse("example.com"))

    def test_shared_ip(self):
        report = self.report()
        for name in ("a.example.com", "b.example.com"):
            report.add("dns_a", "8.8.8.8", "https://dns.google", subject=name)
        data = analyze(report.finish(2))
        self.assertEqual(data["analysis"]["insights"][0]["type"], "shared_ip")

    def test_cross_source_and_dns(self):
        report = self.report()
        report.add("certificate_name", "a.example.com", "https://crt.sh")
        report.add("discovered_domain", "a.example.com", "https://web.archive.org")
        report.add("dns_a", "8.8.8.8", "https://dns.google", subject="a.example.com")
        data = analyze(report.finish(3))
        self.assertEqual({item["type"] for item in data["analysis"]["insights"]}, {"multiple_source_mentions", "candidate_dns_observed"})

    def test_policy_insights(self):
        report = self.report()
        report.add("email_policy", '"v=spf1 +all"', "https://dns.google", relation="SPF")
        report.add("email_policy", '"v=DMARC1; p=none; rua=mailto:x@example.com"', "https://dns.google", relation="DMARC")
        data = analyze(report.finish(2))
        self.assertEqual({item["type"] for item in data["analysis"]["insights"]}, {"spf_permissive", "dmarc_monitoring"})

    def test_comparison_not_removed(self):
        old, new = self.report(), self.report()
        old.add("dns_a", "1.1.1.1", "https://dns.google")
        new.add("dns_a", "8.8.8.8", "https://dns.google")
        data = analyze(new.finish(1), old.finish(1))
        self.assertEqual(data["comparison"]["not_observed"][0]["value"], "1.1.1.1")
        self.assertEqual(data["comparison"]["added"][0]["value"], "8.8.8.8")
        self.assertIn("silinmiş sayılmaz", data["comparison"]["caution"])

    def test_comparison_ignores_timestamp(self):
        old, new = self.report(), self.report()
        old.add("dns_a", "1.1.1.1", "https://dns.google", details={"ttl": 100})
        new.add("dns_a", "1.1.1.1", "https://dns.google", details={"ttl": 200})
        data = analyze(new.finish(1), old.finish(1))
        self.assertEqual(data["comparison"]["unchanged_count"], 1)
        self.assertEqual(data["comparison"]["added"], [])

    def test_baseline_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "old.json"
            path.write_text(json.dumps(self.report().finish(0)))
            self.assertEqual(load_baseline(path, Target.parse("example.com"))["target"]["value"], "example.com")
            with self.assertRaises(ValueError):
                load_baseline(path, Target.parse("other.com"))
            path.write_text('{"tool":"SZOBO | DRAXEN","target":{"kind":"domain","value":"example.com"},"findings":[{}]}')
            with self.assertRaises(ValueError):
                load_baseline(path, Target.parse("example.com"))

    def test_analysis_html_escapes(self):
        report = self.report()
        report.add("dns_a", "8.8.8.8", "https://dns.google", subject="<script>alert(1)</script>")
        report.add("dns_a", "8.8.8.8", "https://dns.google", subject="b.example.com")
        data = analyze(report.finish(0))
        self.assertNotIn("<script>alert(1)</script>", html_report(data))


class ExportTests(unittest.TestCase):
    def test_csv_formula_protection(self):
        for value in ("=1+1", "+SUM(A1)", "-1+1", "@cmd", "  =cmd", "\tcmd"):
            self.assertTrue(safe_cell(value).startswith("'"))
        self.assertEqual(safe_cell("example.com"), "example.com")

    def test_csv_roundtrip(self):
        report = Report(Target.parse("example.com"))
        report.add("text", 'a,b"c\nline', "https://example.com")
        rows = list(csv.reader(io.StringIO(csv_report(report.finish(0)))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][1], 'a,b"c\nline')

    def test_graphml_valid_and_evidence(self):
        report = Report(Target.parse("example.com"))
        report.add("text", '<a> & "\x00', "https://example.com")
        root = ET.fromstring(graphml_report(report.finish(0)))
        ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
        self.assertEqual(len(root.findall(".//g:node", ns)), 2)
        self.assertEqual(len(root.findall(".//g:edge", ns)), 1)
        self.assertIsNotNone(root.find('.//g:edge/g:data[@key="evidence"]', ns))


class DeepCliTests(unittest.TestCase):
    def test_deep_end_to_end_offline(self):
        fixture = {"crt.sh": [{"name_value": "api.example.com"}], "rdap.org": {"objectClassName": "domain"}, "web.archive.org": [["original"], ["https://old.example.com/a"]], "urlscan.io": {"results": []}}
        with tempfile.TemporaryDirectory() as folder, patch("draxen.cli.Client", return_value=FakeClient(fixture)):
            result = main(["example.com", "--deep", "--quiet", "--output", folder])
            self.assertEqual(result, 0)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertTrue(data["settings"]["archives"])
            self.assertTrue(data["settings"]["mail"])
            self.assertFalse(data["settings"]["web"])
            self.assertIn("analysis", data)
            self.assertEqual(len(list(Path(folder).iterdir())), 6)
            result = main(["example.com", "--deep", "--quiet", "--compare", str(Path(folder) / "report.json"), "--output", folder])
            self.assertEqual(result, 0)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertEqual(data["comparison"]["added"], [])

    def test_compare_rejects_before_network(self):
        with patch("draxen.cli.Client") as client, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["example.com", "--compare", "/does-not-exist"])
        client.assert_not_called()

    def test_domain_only_flags_reject_ip(self):
        for flag in ("--archives", "--mail"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["8.8.8.8", flag])

    def test_deep_ip_network_only(self):
        fixture = {"rdap.org": {"objectClassName": "ip network"}, "stat.ripe.net": {"status": "ok", "data": {"prefix": "8.8.8.0/24", "asns": [15169]}}}
        with tempfile.TemporaryDirectory() as folder, patch("draxen.cli.Client", return_value=FakeClient(fixture)):
            self.assertEqual(main(["8.8.8.8", "--deep", "--quiet", "--output", folder]), 0)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertFalse(data["settings"]["archives"])
            self.assertFalse(data["settings"]["mail"])
            self.assertTrue(data["settings"]["network"])
