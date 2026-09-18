"""Tests for AP environment analysis. For auditing networks you own or
are authorized to test."""

import unittest

from sentinelwifi.ap_scan import AccessPoint, analyze_environment


def _ap(ssid, bssid, ch, enc="WPA2", band="2.4"):
    return AccessPoint(ssid=ssid, bssid=bssid, channel=ch, signal=-60,
                       encryption=enc, band=band)


class TestEvilTwin(unittest.TestCase):
    def test_same_ssid_two_bssids_flagged(self):
        aps = [_ap("Home", "AA:BB:CC:DD:EE:01", 6),
               _ap("Home", "AA:BB:CC:DD:EE:02", 11)]
        cur = {"ssid": "Home", "bssid": "AA:BB:CC:DD:EE:01", "channel": 6}
        kinds = [r.kind for r in analyze_environment(aps, cur)]
        self.assertIn("evil_twin", kinds)

    def test_trusted_bssid_suppresses(self):
        aps = [_ap("Home", "AA:BB:CC:DD:EE:01", 6),
               _ap("Home", "AA:BB:CC:DD:EE:02", 11)]
        cur = {"ssid": "Home", "bssid": "AA:BB:CC:DD:EE:01", "channel": 6}
        out = analyze_environment(aps, cur,
                                  trusted=frozenset({"AA:BB:CC:DD:EE:02"}))
        self.assertNotIn("evil_twin", [r.kind for r in out])

    def test_single_bssid_clean(self):
        aps = [_ap("Home", "AA:BB:CC:DD:EE:01", 6),
               _ap("Other", "11:22:33:44:55:66", 1)]
        cur = {"ssid": "Home", "bssid": "AA:BB:CC:DD:EE:01", "channel": 6}
        self.assertNotIn("evil_twin",
                         [r.kind for r in analyze_environment(aps, cur)])


class TestCongestion(unittest.TestCase):
    def test_24ghz_overlap_counts_neighbors(self):
        # Me on ch6; 3 APs on ch6, 2 on overlapping ch4, ch9 (±4 overlap)
        aps = [_ap("Home", "AA:AA:AA:AA:AA:01", 6)] + \
              [_ap(f"N{i}", f"BB:BB:BB:BB:BB:0{i}", 6) for i in range(3)] + \
              [_ap("X1", "CC:CC:CC:CC:CC:01", 4), _ap("X2", "CC:CC:CC:CC:CC:02", 9)]
        cur = {"ssid": "Home", "bssid": "AA:AA:AA:AA:AA:01", "channel": 6,
               "band": "2.4"}
        cong = [r for r in analyze_environment(aps, cur) if r.kind == "congestion"]
        self.assertTrue(cong)
        self.assertIn("Total co-channel + adjacent-channel load: 6 APs",
                      cong[0].message)

    def test_far_channels_no_overlap(self):
        aps = [_ap("Home", "AA:AA:AA:AA:AA:01", 6),
               _ap("Far", "BB:BB:BB:BB:BB:01", 13)]
        cur = {"ssid": "Home", "bssid": "AA:AA:AA:AA:AA:01", "channel": 6,
               "band": "2.4"}
        self.assertFalse([r for r in analyze_environment(aps, cur)
                          if r.kind == "congestion"])


class TestUnexpectedChannel(unittest.TestCase):
    def test_same_ssid_other_channel_noted(self):
        aps = [_ap("Home", "AA:AA:AA:AA:AA:01", 6),
               _ap("Home", "DD:DD:DD:DD:DD:01", 11)]
        cur = {"ssid": "Home", "bssid": "AA:AA:AA:AA:AA:01", "channel": 6}
        kinds = [r.kind for r in analyze_environment(aps, cur)]
        self.assertIn("unexpected_channel", kinds)


if __name__ == "__main__":
    unittest.main()


class TestParseIwScan(unittest.TestCase):
    SAMPLE = """
BSS 10:20:30:40:50:60(on wlp3s0)
\tTSF: 12345 usec (0d, 0h, 0m)
\tfreq: 2437
\tcapability: ESS Privacy ShortSlotTime (0x0411)
\tsignal: -41.00 dBm
\tSSID: RouterTest-2.4
\tRSN:\t * Version: 1
\t * Authentication suites: PSK 00-0f-ac-2
BSS f0:9f:c2:77:aa:01(on wlp3s0)
\tfreq: 2462
\tcapability: ESS Privacy ShortPreamble ShortSlotTime (0x0431)
\tsignal: -71.00 dBm
\tSSID: OpenCafe
\tRSN:\t * Version: 1
\t * Authentication suites: SAE 00-0f-ac-8
BSS 0a:11:22:33:44:55(on wlp3s0)
\tfreq: 2412
\tcapability: ESS (0x0001)
\tsignal: -83.00 dBm
\tSSID: xfinitywifi
"""

    def test_parses_bss_blocks(self):
        from sentinelwifi.ap_scan import _parse_iw_scan
        aps = {a.ssid: a for a in _parse_iw_scan(self.SAMPLE)}
        self.assertEqual(len(aps), 3)
        self.assertEqual(aps["RouterTest-2.4"].channel, 6)
        self.assertEqual(aps["RouterTest-2.4"].encryption, "WPA2")
        self.assertEqual(aps["RouterTest-2.4"].band, "2.4")
        self.assertEqual(aps["OpenCafe"].channel, 11)
        self.assertEqual(aps["OpenCafe"].encryption, "WPA3")
        self.assertEqual(aps["xfinitywifi"].encryption, "Open")
        self.assertEqual(aps["xfinitywifi"].bssid, "0A:11:22:33:44:55")
