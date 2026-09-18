"""Tests for SentinelWiFi scoring rules. For auditing networks you own or
are authorized to test."""

import unittest

from sentinelwifi.dhcp import DhcpInfo
from sentinelwifi.scoring import (check_dhcp, check_evil_twin,
                                  check_exposed_services, check_http_admin,
                                  check_new_aps, check_ssid_leak,
                                  check_unknown_devices, check_wifi_encryption,
                                  compute_grade)


class TestEncryption(unittest.TestCase):
    def test_open_is_critical_45(self):
        f = check_wifi_encryption("Open")
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.penalty, 45)

    def test_wep_is_critical_45(self):
        f = check_wifi_encryption("WEP")
        self.assertEqual(f.penalty, 45)

    def test_wpa2_small_penalty(self):
        f = check_wifi_encryption("WPA2")
        self.assertEqual(f.penalty, 5)

    def test_wpa3_no_finding(self):
        self.assertIsNone(check_wifi_encryption("WPA3"))


class TestAdminAndSsid(unittest.TestCase):
    def test_http_admin_15(self):
        f = check_http_admin("http", "192.168.1.1")
        self.assertEqual(f.penalty, 15)

    def test_https_admin_clean(self):
        self.assertIsNone(check_http_admin("https", "192.168.1.1"))

    def test_ssid_brand_leak(self):
        self.assertIsNotNone(check_ssid_leak("dlink-Home"))
        self.assertIsNotNone(check_ssid_leak("NETGEAR-5G"))
        self.assertIsNone(check_ssid_leak("PurpleOctopus"))
        self.assertIsNone(check_ssid_leak(""))


class TestDevicesAndDhcp(unittest.TestCase):
    def test_unknown_devices_tiers(self):
        self.assertEqual(check_unknown_devices(1).penalty, 10)
        self.assertEqual(check_unknown_devices(3).penalty, 25)
        self.assertIsNone(check_unknown_devices(0))

    def test_rogue_dhcp_critical(self):
        info = DhcpInfo(servers=["192.168.1.66", "192.168.1.1"],
                        gateway="192.168.1.1", rogue=True, detail="x")
        f = check_dhcp(info)
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.penalty, 20)

    def test_clean_dhcp_is_info_only(self):
        info = DhcpInfo(servers=["192.168.1.1"], gateway="192.168.1.1",
                        rogue=False, detail="ok")
        self.assertEqual(check_dhcp(info).penalty, 0)

    def test_no_dhcp_data_no_finding(self):
        self.assertIsNone(check_dhcp(DhcpInfo()))


class TestServicesAndAps(unittest.TestCase):
    def test_exposed_services(self):
        f = check_exposed_services(["10.0.0.5 exposes Telnet on port 23"])
        self.assertEqual(f.penalty, 10)
        self.assertIsNone(check_exposed_services([]))

    def test_new_aps_penalty(self):
        class AP:
            def __init__(self, ssid):
                self.ssid = ssid
        f = check_new_aps([AP("MyHome"), AP("CafeWifi")], "MyHome")
        self.assertEqual(f.penalty, 10)
        f2 = check_new_aps([AP("CafeWifi")], "MyHome")
        self.assertEqual(f2.penalty, 3)
        self.assertIsNone(check_new_aps([], "MyHome"))

    def test_evil_twin_20(self):
        f = check_evil_twin("same SSID two BSSIDs")
        self.assertEqual(f.penalty, 20)
        self.assertIsNone(check_evil_twin(None))


class TestGradeBands(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(compute_grade([]).grade, "A")                    # 100
        self.assertEqual(compute_grade(
            [check_wifi_encryption("WPA2")]).grade, "A")                  # 95
        self.assertEqual(compute_grade(
            [check_http_admin("http", "g")]).grade, "B")                  # 85
        self.assertEqual(compute_grade(
            [check_unknown_devices(1),
             check_ssid_leak("dlink")]).grade, "B")                       # 80
        self.assertEqual(compute_grade(
            [check_wifi_encryption("WEP")]).grade, "D")                   # 55
        self.assertEqual(compute_grade(
            [check_wifi_encryption("WEP"),
             check_http_admin("http", "g")]).grade, "D")                  # 40
        self.assertEqual(compute_grade(
            [check_wifi_encryption("Open"),
             check_unknown_devices(9)]).grade, "F")                       # 30

    def test_score_clamped(self):
        self.assertEqual(compute_grade(
            [check_wifi_encryption("Open"),
             check_unknown_devices(9)]).score, 30)


if __name__ == "__main__":
    unittest.main()
