import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from draxen.cli import main, parser
from draxen.collectors import Collector, PageParser
from draxen.core import BudgetExceeded, Client, FetchError, Report, SafeRedirect, Target, domain_name, public_ip
from draxen.output import dot_report, html_report, save_reports, terminal


class FakeClient:
    def __init__(self, data=None):
        self.data = data or {}
        self.requests = 0
        self.delay = 1.5
        self.timeout = 15

    def json(self, url, accept=None):
        self.requests += 1
        for key, value in self.data.items():
            if key in url:
                if isinstance(value, Exception):
                    raise value
                return value
        return {"Status": 0, "Answer": []}

    def get(self, url, accept=None):
        self.requests += 1
        for key, value in self.data.items():
            if key in url:
                if isinstance(value, Exception):
                    raise value
                return value, url
        raise FetchError("Kaynak bulunamadı: 404")


class TargetTests(unittest.TestCase):
    def test_domains(self):
        self.assertEqual(Target.parse("EXAMPLE.COM.").value, "example.com")
        self.assertEqual(domain_name("örnek.com"), "xn--rnek-4qa.com")

    def test_ips(self):
        for value in ("8.8.8.8", "2606:4700:4700::1111"):
            self.assertEqual(Target.parse(value).kind, "ip")

    def test_email(self):
        target = Target.parse("Contact@EXAMPLE.COM")
        self.assertEqual(target.value, "Contact@example.com")
        self.assertEqual(target.domain, "example.com")

    def test_rejected(self):
        for value in ("127.0.0.1", "10.2.3.4", "::1", "169.254.169.254", "192.0.2.1", "224.0.0.1", "localhost", "abc.local", "http://example.com", "x.com/", "foo..com", "a@b@c.com", "a b@c.com", "a..b@c.com", "-foo.com", "999.999.999.999"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Target.parse(value)

    def test_global(self):
        self.assertTrue(public_ip("1.1.1.1"))
        self.assertFalse(public_ip("not an ip"))


class ClientTests(unittest.TestCase):
    def client(self, body=b'{"ok":true}'):
        client = Client(delay=1, budget=3)
        client.validate_url = Mock()
        response = Mock()
        response.read.return_value = body
        response.headers.get_content_charset.return_value = "utf-8"
        response.geturl.return_value = "https://example.com/"
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        client.opener = Mock()
        client.opener.open.return_value = response
        return client

    def test_cache(self):
        client = self.client()
        self.assertEqual(client.json("https://example.com/"), {"ok": True})
        client.json("https://example.com/")
        self.assertEqual(client.requests, 1)

    def test_budget(self):
        client = self.client()
        client.budget = 0
        with self.assertRaises(BudgetExceeded):
            client.get("https://example.com/")
        client.opener.open.assert_not_called()

    @patch("draxen.core.time.sleep")
    def test_delay(self, sleep):
        client = self.client()
        client.get("https://example.com/a")
        client.get("https://example.com/b")
        self.assertEqual(sleep.call_count, 1)
        self.assertGreater(sleep.call_args.args[0], 0)

    def test_redirect_counts_toward_budget(self):
        client = self.client()
        client.budget = 1
        client.get("https://example.com/")
        handler = SafeRedirect(client.before_request)
        with self.assertRaises(BudgetExceeded):
            handler.redirect_request(Mock(), None, 302, "", {}, "https://example.org/")

    def test_limit(self):
        client = self.client(b"x" * 20)
        client.max_bytes = 10
        with self.assertRaises(FetchError):
            client.get("https://example.com/")

    def test_bad_json(self):
        with self.assertRaises(FetchError):
            self.client(b"<html>").json("https://example.com/")

    def test_rate_limit_no_retry(self):
        client = self.client()
        client.opener.open.side_effect = urllib.error.HTTPError("https://example.com", 429, "rate", {}, None)
        with self.assertRaisesRegex(FetchError, "429"):
            client.get("https://example.com/")
        self.assertEqual(client.requests, 1)

    @patch("draxen.core.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))])
    def test_private_destination(self, resolver):
        with self.assertRaises(FetchError):
            Client().validate_url("https://example.com")

    def test_non_https(self):
        for value in ("http://example.com", "file:///etc/passwd", "https://user:pass@example.com", "https://example.com:80"):
            with self.subTest(value=value), self.assertRaises(FetchError):
                Client().validate_url(value)


class CollectorTests(unittest.TestCase):
    def collector(self, data=None, **kwargs):
        target = Target.parse("example.com")
        return Collector(FakeClient(data), Report(target), target, **kwargs)

    def test_ct_scope_dedup_and_wildcard(self):
        collector = self.collector({"crt.sh": [
            {"name_value": "a.example.com\n*.example.com\nevil-example.com\nexample.com.evil.com", "not_before": "2020"},
            {"name_value": "a.example.com", "not_before": "2026"},
        ]})
        collector.certificates()
        items = collector.report.data["findings"]
        self.assertEqual({item["value"] for item in items}, {"a.example.com", "*.example.com"})
        self.assertEqual(collector.candidates, {"a.example.com"})
        item = next(item for item in items if item["value"] == "a.example.com")
        self.assertEqual(item["evidence"][0]["details"]["not_before"], "2026")
        self.assertEqual(item["evidence"][0]["status"], "historical_candidate")

    def test_ct_limit(self):
        collector = self.collector({"crt.sh": [{"name_value": "a.example.com\nb.example.com"}]}, limit=1)
        collector.certificates()
        self.assertEqual(len(collector.report.data["findings"]), 1)
        self.assertTrue(collector.report.data["warnings"])

    def test_dns_fallback(self):
        collector = self.collector({"dns.google": FetchError("offline"), "cloudflare-dns.com": {"Status": 0, "Answer": []}})
        answers, url = collector.query_dns("example.com", "A")
        self.assertIn("cloudflare-dns.com", url)
        self.assertEqual(collector.client.requests, 2)
        self.assertTrue(collector.report.data["warnings"])

    def test_dns_budget_no_fallback(self):
        collector = self.collector({"dns.google": BudgetExceeded("limit")})
        with self.assertRaises(BudgetExceeded):
            collector.query_dns("example.com", "A")
        self.assertEqual(collector.client.requests, 1)

    def test_dns_status(self):
        collector = self.collector({"dns.google": {"Status": 2}})
        with self.assertRaises(FetchError):
            collector.query_dns("example.com", "A")
        collector.client.data = {"dns.google": {"Status": 3}}
        self.assertEqual(collector.query_dns("example.com", "A")[0], [])

    def test_dns_record_owner(self):
        collector = self.collector({"dns.google": {"Status": 0, "Answer": [{"name": "cdn.example.net.", "type": 1, "data": "8.8.8.8", "TTL": 100}]}})
        collector.dns()
        item = collector.report.data["findings"][0]
        self.assertEqual(item["subject"], "cdn.example.net")
        self.assertEqual(collector.ips, {"8.8.8.8"})

    def test_rdap(self):
        collector = self.collector({"rdap.org": {"objectClassName": "domain", "handle": "EXAMPLE", "events": [{"eventAction": "registration", "eventDate": "2000-01-01"}], "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar Inc"]]]}]}})
        collector.rdap("example.com", "domain")
        self.assertEqual(len(collector.report.data["findings"]), 3)
        self.assertIn("registrar", collector.report.data["findings"][-1]["evidence"][0]["details"]["roles"])

    def test_failure_is_not_empty_success(self):
        collector = self.collector({"rdap.org": FetchError("offline")})
        collector.run_source("RDAP", lambda: collector.rdap("example.com", "domain"))
        self.assertEqual(collector.report.data["sources"][0]["state"], "incomplete")

    def test_verify_bounded(self):
        collector = self.collector(verify=1)
        collector.candidates = {"a.example.com", "b.example.com"}
        collector.verify_candidates()
        self.assertEqual(collector.client.requests, 2)

    def test_web_robots_denied(self):
        collector = self.collector({"https://example.com/robots.txt": "User-agent: *\nDisallow: /"})
        with self.assertRaises(FetchError):
            collector.homepage()
        self.assertEqual(collector.client.requests, 1)

    def test_web_robots_failure(self):
        collector = self.collector({"https://example.com/robots.txt": FetchError("404")})
        with self.assertRaises(FetchError):
            collector.homepage()
        self.assertEqual(collector.client.requests, 1)

    def test_web_scope(self):
        collector = self.collector({"https://example.com/robots.txt": "User-agent: *\nAllow: /", "https://example.com/": '<title>Example</title><a href="mailto:info@example.com">Mail</a><p>outside@other.com</p><script>secret@example.com</script><a href="https://github.com/example?token=abc">GitHub</a><a href="https://dev.example.com">Dev</a>'})
        collector.homepage()
        values = {item["value"] for item in collector.report.data["findings"]}
        self.assertIn("info@example.com", values)
        self.assertNotIn("secret@example.com", values)
        self.assertNotIn("outside@other.com", values)
        self.assertIn("https://github.com/example", values)
        self.assertIn("dev.example.com", values)

    def test_default_no_direct_web(self):
        collector = self.collector({"crt.sh": [], "rdap.org": {"objectClassName": "domain"}})
        collector.homepage = Mock()
        collector.run()
        collector.homepage.assert_not_called()

    def test_email_not_claimed_verified(self):
        target = Target.parse("person@example.com")
        collector = Collector(FakeClient({"crt.sh": [], "rdap.org": {"objectClassName": "domain"}}), Report(target), target)
        result = collector.run()
        self.assertEqual(result["findings"][0]["evidence"][0]["status"], "input")
        self.assertTrue(any("posta kutusu" in warning for warning in result["warnings"]))


class OutputTests(unittest.TestCase):
    def report(self):
        report = Report(Target.parse("example.com"))
        report.add("text", '</script><script>alert("x")</script>', "https://example.com/\"x", details={"x": "<b>"})
        return report.finish(1)

    def test_html_escape(self):
        text = html_report(self.report())
        self.assertNotIn('</script><script>alert("x")', text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn('<script src=', text)

    def test_dot_escape(self):
        text = dot_report(self.report())
        self.assertIn('digraph DRAXEN', text)
        self.assertIn(r'\"x\"', text)

    def test_save(self):
        with tempfile.TemporaryDirectory() as folder:
            files = save_reports(self.report(), folder)
            self.assertEqual(len(files), 6)
            data = json.loads((Path(folder) / "report.json").read_text())
            self.assertEqual(data["target"]["value"], "example.com")
            save_reports(self.report(), folder)
            self.assertEqual(len(list(Path(folder).iterdir())), 6)

    def test_terminal_control_stripped(self):
        self.assertNotIn("\x1b", terminal("\x1b[2J"))

    def test_deduplicate_evidence(self):
        report = Report(Target.parse("example.com"))
        report.add("ip", "8.8.8.8", "https://source1.com")
        report.add("ip", "8.8.8.8", "https://source2.com")
        self.assertEqual(len(report.data["findings"]), 1)
        self.assertEqual(len(report.data["findings"][0]["evidence"]), 2)


class CliTests(unittest.TestCase):
    def test_help(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)

    def test_ranges(self):
        for flag, value in (("--budget", "0"), ("--verify", "21"), ("--delay", "nan"), ("--delay", "0"), ("--timeout", "inf")):
            with self.subTest(flag=flag, value=value), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser().parse_args(["example.com", flag, value])

    @patch("draxen.cli.Collector.run", side_effect=KeyboardInterrupt)
    def test_interrupt_saves_report(self, run):
        with tempfile.TemporaryDirectory() as folder:
            result = main(["example.com", "--output", folder, "--quiet"])
            self.assertEqual(result, 130)
            self.assertTrue((Path(folder) / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
