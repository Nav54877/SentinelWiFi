"""Tests for vendors, DHCP parsing, ports helpers, report rendering, and
the demo dataset. For auditing networks you own or are authorized to test."""

import json
import os
import tempfile
import unittest

from sentinelwifi.dhcp import parse_leases_text
from sentinelwifi.ports import PORTS, risk_summary, OpenPort
from sentinelwifi.vendors import lookup_vendor


class TestVendors(unittest.TestCase):
    def test_known_prefixes(self):
        self.assertEqual(lookup_vendor("B8:27:EB:12:34:56"),
                         "Raspberry Pi Foundation")
        self.assertEqual(lookup_vendor("a4:b1:97:00:11:22"), "Apple")

    def test_unknown(self):
        self.assertEqual(lookup_vendor("FF:FF:FF:00:00:00"), "Unknown vendor")
        self.assertEqual(lookup_vendor(""), "Unknown vendor")


class TestDhcpParse(unittest.TestCase):
    def test_extracts_servers(self):
        text = """
lease {
  interface "wlp2s0";
  option dhcp-server-identifier 192.168.1.1;
}
lease {
  option dhcp-server-identifier 10.0.0.66;
}
"""
        self.assertEqual(parse_leases_text(text),
                         {"192.168.1.1", "10.0.0.66"})

    def test_empty(self):
        self.assertEqual(parse_leases_text("no leases here"), set())


class TestPorts(unittest.TestCase):
    def test_risky_ports_flagged(self):
        svc = {"10.0.0.5": [OpenPort(23, PORTS[23]), OpenPort(443, "HTTPS")]}
        notes = risk_summary(svc)
        self.assertEqual(len(notes), 1)
        self.assertIn("Telnet", notes[0])
        self.assertIn("10.0.0.5", notes[0])

    def test_curated_list_reasonable(self):
        self.assertLessEqual(len(PORTS), 30)
        self.assertIn(7547, PORTS)   # TR-069 router exploit target
        self.assertIn(23, PORTS)     # Telnet
        self.assertIn(5900, PORTS)   # VNC


class TestReportAndDemo(unittest.TestCase):
    def test_demo_json_and_html(self):
        import sentinel
        from sentinelwifi.report import report_to_json, write_html_report
        data = sentinel._demo_data()
        payload = json.loads(report_to_json(data))
        self.assertIn("score", payload)
        self.assertGreater(len(payload["devices"]), 0)
        self.assertGreater(len(payload["score"]["findings"]), 0)
        with tempfile.TemporaryDirectory() as td:
            path = write_html_report(data, os.path.join(td, "r.html"))
            html = open(path).read()
        self.assertIn("Findings", html)
        self.assertIn("grade", html)


if __name__ == "__main__":
    unittest.main()


class TestNeighParse(unittest.TestCase):
    def test_standard_order(self):
        from sentinelwifi.lan_scan import _parse_neigh
        text = ("192.168.1.1 dev wlp3s0 lladdr 10:20:30:40:50:60 REACHABLE\n"
                "192.168.1.5 dev wlp3s0  failed\n"
                "192.168.1.9 dev wlp3s0 lladdr aa:bb:cc:dd:ee:ff STALE\n")
        self.assertEqual(_parse_neigh(text),
                         [("192.168.1.1", "10:20:30:40:50:60"),
                          ("192.168.1.9", "AA:BB:CC:DD:EE:FF")])

    def test_lladdr_first_order(self):
        from sentinelwifi.lan_scan import _parse_neigh
        text = "192.168.1.2 lladdr de:ad:be:ef:00:01 dev eth0 REACHABLE\n"
        self.assertEqual(_parse_neigh(text),
                         [("192.168.1.2", "DE:AD:BE:EF:00:01")])
