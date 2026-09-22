import unittest
from draxen.analysis import analyze
from draxen.cli import parser
from draxen.core import Report, Target
from draxen.network_intel import NetworkIntelligence, detect_datacenter_provider
try:
    from test_draxen import FakeClient
except ImportError:
    from tests.test_draxen import FakeClient


class NetworkIntelTests(unittest.TestCase):
    def test_detect_datacenter_by_asn(self):
        prov = detect_datacenter_provider(asns=[16509])
        self.assertIsNotNone(prov)
        self.assertEqual(prov["name"], "Amazon Web Services (AWS)")

        prov = detect_datacenter_provider(asns=[14061])
        self.assertIsNotNone(prov)
        self.assertEqual(prov["name"], "DigitalOcean")

    def test_detect_datacenter_by_holder_pattern(self):
        prov = detect_datacenter_provider(holder="Hetzner Online GmbH")
        self.assertIsNotNone(prov)
        self.assertEqual(prov["name"], "Hetzner Online")

    def test_detect_datacenter_by_netname(self):
        prov = detect_datacenter_provider(netname="CLOUDFLARENET")
        self.assertIsNotNone(prov)
        self.assertEqual(prov["name"], "Cloudflare Network")

    def test_detect_datacenter_unknown(self):
        prov = detect_datacenter_provider(asns=[99999], holder="Private Local Entity", netname="LOCAL-NET")
        self.assertIsNone(prov)

    def test_network_intel_analyze_ip(self):
        target = Target.parse("104.16.1.1")
        report = Report(target)
        report.add("asn", "AS13335", "https://stat.ripe.net", "routing_observed", subject="104.16.1.1", relation="origin_asn")
        report.add("asn_holder", "CLOUDFLARENET", "https://stat.ripe.net", "routing_observed", subject="AS13335", relation="holder")
        report.add("bgp_prefix", "104.16.0.0/12", "https://stat.ripe.net", "routing_observed", subject="104.16.1.1", relation="announced_in")

        geoloc_res = {
            "status": "ok",
            "data": {
                "locations": [
                    {
                        "country": "US",
                        "city": "San Francisco",
                        "latitude": 37.7749,
                        "longitude": -122.4194,
                    }
                ]
            },
        }
        rdap_res = {
            "name": "CLOUDFLARENET",
            "startAddress": "104.16.0.0",
            "endAddress": "104.31.255.255",
            "country": "US",
        }
        client = FakeClient({
            "geoloc": geoloc_res,
            "rdap.org": rdap_res,
        })

        intel = NetworkIntelligence(client, report)
        intel.analyze_ip("104.16.1.1")

        kinds = {item["kind"]: item["value"] for item in report.data["findings"]}
        self.assertIn("ip_country", kinds)
        self.assertEqual(kinds["ip_country"], "US")
        self.assertIn("ip_city", kinds)
        self.assertEqual(kinds["ip_city"], "San Francisco")
        self.assertIn("ip_coordinates", kinds)
        self.assertIn("37.7749", kinds["ip_coordinates"])
        self.assertIn("ip_net_name", kinds)
        self.assertEqual(kinds["ip_net_name"], "CLOUDFLARENET")
        self.assertIn("ip_range", kinds)
        self.assertEqual(kinds["ip_range"], "104.16.0.0 - 104.31.255.255")
        self.assertIn("datacenter_provider", kinds)
        self.assertIn("Cloudflare Network", kinds["datacenter_provider"])

        data = analyze(report.finish(client.requests))
        types = {i["type"] for i in data["analysis"]["insights"]}
        self.assertIn("datacenter_hosting_detected", types)
        self.assertIn("ip_geolocation_identified", types)
        self.assertIn("bgp_routing_identified", types)

    def test_cli_network_aliases(self):
        p = parser()
        args = p.parse_args(["example.com", "--netintel"])
        self.assertTrue(args.network)
        args2 = p.parse_args(["example.com", "--asn"])
        self.assertTrue(args2.network)


if __name__ == "__main__":
    unittest.main()
