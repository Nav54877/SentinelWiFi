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
