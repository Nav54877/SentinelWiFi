"""SentinelWiFi — bundled OUI vendor prefix map.

For auditing networks you own or are authorized to test.

A small, hand-curated prefix map (first 3 bytes of a MAC address -> vendor).
This is intentionally NOT a full IEEE database (~50MB); a few hundred common
entries cover the vast majority of home-network devices. Unknown prefixes are
reported as "Unknown vendor" — that is expected and fine.
"""

# OUI prefix (uppercase, no separators) -> vendor name
OUI_MAP = {
    # Apple
    "001CB3": "Apple", "001E52": "Apple", "0021E9": "Apple",
    "00236C": "Apple", "3CAB8E": "Apple", "685B35": "Apple",
    "7081EB": "Apple", "7CD1C3": "Apple", "8866A5": "Apple",
    "8C7C92": "Apple", "A4B197": "Apple", "AC87A3": "Apple",
    "B8098A": "Apple", "D49A20": "Apple", "DC56E7": "Apple",
    "F0766F": "Apple", "F4F15A": "Apple", "002590": "Apple",
    "041552": "Apple", "04D3CF": "Apple", "087045": "Apple",
    # Google / Nest
    "001A11": "Google", "3C5A37": "Google", "3C8BFE": "Google",
    "54A6D6": "Google", "94EB2C": "Google", "C80E77": "Google",
    "F484FC": "Google", "F8DAE5": "Google", "D83BBF": "Nest Labs",
    # Microsoft
    "000D3A": "Microsoft", "0022C8": "Microsoft", "04F3EE": "Microsoft",
    "28CD1C": "Microsoft", "B0CA68": "Microsoft", "C4346B": "Microsoft",
    "C83F26": "Microsoft", "F02F74": "Microsoft", "F44637": "Microsoft",
    # Samsung
    "0007AB": "Samsung", "000EE6": "Samsung", "0012FB": "Samsung",
    "001377": "Samsung", "0023C7": "Samsung", "0C14DC": "Samsung",
    "1CBFCE": "Samsung", "305A3A": "Samsung", "3CBDD8": "Samsung",
    "5001BB": "Samsung", "54FA3E": "Samsung", "5C2E59": "Samsung",
    "64B310": "Samsung", "7854D2": "Samsung", "849866": "Samsung",
    "8CEA48": "Samsung", "B09928": "Samsung", "E4B021": "Samsung",
    "F4E5F2": "Samsung", "F85AD8": "Samsung",
    # Sony
    "00131D": "Sony", "001BEA": "Sony", "0024BE": "Sony",
    "30F7C5": "Sony", "4C15E6": "Sony", "702687": "Sony",
    "A8B8E0": "Sony", "E0B5B1": "Sony", "F834C0": "Sony",
    # LG
    "00023F": "LG", "000D0E": "LG", "0022A9": "LG",
    "16807B": "LG", "3085A9": "LG", "582C80": "LG",
    "98D67B": "LG", "D4E892": "LG", "E80214": "LG",
    # Xiaomi
    "14F65A": "Xiaomi", "3C9BC0": "Xiaomi", "44C34A": "Xiaomi",
    "58B961": "Xiaomi", "64A2F9": "Xiaomi", "74ACB9": "Xiaomi",
    "782C29": "Xiaomi", "9CE33F": "Xiaomi", "F8A45F": "Xiaomi",
    # Huawei
    "000C6E": "Huawei", "00464B": "Huawei", "2816A8": "Huawei",
    "3CF808": "Huawei", "54DF60": "Huawei", "983B16": "Huawei",
    "AC853D": "Huawei", "C46AB7": "Huawei", "E8CD2D": "Huawei",
    # Cisco
    "00000C": "Cisco", "0005DC": "Cisco", "000A8A": "Cisco",
    "000D28": "Cisco", "0014A9": "Cisco", "001B2F": "Cisco",
    "0021A1": "Cisco", "64E950": "Cisco", "84B802": "Cisco",
    # Netgear
    "00095B": "Netgear", "0024B2": "Netgear", "04A151": "Netgear",
    "08BD43": "Netgear", "204E7F": "Netgear", "2CC8F5": "Netgear",
    "44E4D9": "Netgear", "9C3DCF": "Netgear", "B03956": "Netgear",
    # TP-Link
    "001478": "TP-Link", "0015EB": "TP-Link", "0023CD": "TP-Link",
    "18A6F7": "TP-Link", "30B5C2": "TP-Link", "3C46D8": "TP-Link",
    "50FA84": "TP-Link", "5C628B": "TP-Link", "8CAB8E": "TP-Link",
    "A0F3C1": "TP-Link", "D87533": "TP-Link", "EC4C4D": "TP-Link",
    # D-Link
    "001195": "D-Link", "0015E9": "D-Link", "001DE0": "D-Link",
    "002191": "D-Link", "1C7EE5": "D-Link", "34D760": "D-Link",
    "6C198F": "D-Link", "90C93C": "D-Link", "B8A386": "D-Link",
    # Linksys / Belkin
    "000C41": "Linksys", "001150": "Linksys", "00259C": "Linksys",
    "0C4CC8": "Linksys", "14B56F": "Linksys", "28FDB8": "Linksys",
    "40EE15": "Linksys", "8071BE": "Linksys", "E4671E": "Linksys",
    "08527A": "Belkin", "944452": "Belkin",
    # Asus
    "000C6E": "Asus", "001FC6": "Asus", "0040F4": "Asus",
    "04D9F5": "Asus", "08C5E1": "Asus", "10BF48": "Asus",
    "2C4D54": "Asus", "AC9E17": "Asus", "E0CB4E": "Asus",
    # Ubiquiti
    "002722": "Ubiquiti", "040D84": "Ubiquiti", "24A43C": "Ubiquiti",
    "68298C": "Ubiquiti", "74ACB9": "Ubiquiti", "FCF0C2": "Ubiquiti",
    # Amazon (Echo, Ring, Kindle)
    "001A4F": "Amazon", "001BB9": "Amazon", "00355A": "Amazon",
    "084656": "Amazon", "14B1C8": "Amazon", "4C5E0C": "Amazon",
    "50097B": "Amazon", "68FCB3": "Amazon", "B0FC0D": "Amazon",
    "F0C24B": "Amazon", "F03575": "Amazon",
    # Intel / PC hardware
    "001C42": "Intel", "0024D7": "Intel", "348A7B": "Intel",
    "4CD98F": "Intel", "6C8814": "Intel", "8CD956": "Intel",
    "AC7285": "Intel", "CC790C": "Intel", "E86A64": "Intel",
    "E8A71C": "Intel", "F88E85": "Intel",
    "001212": "Dell", "0019B9": "Dell", "A4BAD3": "Dell",
    "F075C4": "Dell", "BCE150": "HP", "10E7C6": "HP",
    "C4346B": "HP", "E83935": "Lenovo", "4851B7": "Lenovo",
    "50E549": "Lenovo", "008CFA": "Micro-Star (MSI)",
    # Raspberry Pi / SBC
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    # ESP / IoT
    "A020A6": "Espressif (ESP32/ESP8266)",
    "240AC4": "Espressif (ESP32/ESP8266)",
    "3C71BF": "Espressif (ESP32/ESP8266)",
    "483FDA": "Espressif (ESP32/ESP8266)",
    "98CDAC": "Espressif (ESP32/ESP8266)",
    "600194": "Shenzhen RAK Wireless (IoT)",
    # Networking: Aruba, Juniper, Ubiquiti APs, Mikrotik, Zyxel
    "001B78": "Aruba (HPE)", "D8C7C8": "Aruba (HPE)",
    "002128": "Juniper", "EC13DB": "Juniper",
    "749DDC": "MikroTik", "CC2D21": "MikroTik", "48575D": "Zyxel",
    # Cameras / smart home
    "0023AB": "Amcrest/Loongson (camera)",
    "A03E6B": "Hikvision", "B4218C": "Hikvision",
    "4894DD": "Arlo (camera)", "80A255": "Arlo (camera)",
    "D466A6": "Ring (Amazon)", "DC7478": "Ring (Amazon)",
    "5C417A": "Philips Hue", "001788": "Philips Hue",
    "EC10BF": "LIFX", "D073D5": "LIFX",
    "00BB3A": "Nest / Google", "18B430": "Google Nest",
    # TVs / streaming
    "60AF6D": "Roku", "AC3A7A": "Roku", "B4A8B9": "Roku",
    "847207": "Sonos", "5CA6E6": "Sonos", "B8E937": "Sonos",
    "086A0A": "TCL TV", "044EAF": "TCL TV",
    "087D21": "Samsung Smart TV (subset)",
    "4CC2BF": "LG TV", "8C579B": "LG TV", "00C3F4": "Samsung TV",
    "807926": "Toshiba TV", "D89880": "Hisense TV",
    # Consoles
    "0024BE": "Sony PlayStation", "FCBC4C": "Sony PlayStation",
    "00125A": "Nintendo", "40F407": "Nintendo", "58BDA3": "Nintendo",
    "70F87A": "Nintendo", "98B6E9": "Nintendo",
    "50E695": "Microsoft Xbox",
    # Phones / misc
    "D05785": "OnePlus", "200A0D": "OnePlus",
    "34B7DA": "Motorola Mobility", "64C0D7": "Motorola Mobility",
    "980BFA": "Vivo", "E81F1B": "OPPO",
    # Printers
    "000110": "Brother", "0024E9": "Brother", "60CDA9": "Brother",
    "001F29": "Canon", "000085": "Canon",
    # Router vendors (common defaults)
    "001018": "Askey (router OEM)", "00130F": "Sagemcom (router OEM)",
    "F81A67": "Sagemcom (router OEM)", "A0B1FB": "Technicolor (router OEM)",
    "E04F43": "Technicolor (router OEM)", "C45200": "Zoom Telephonics",
    # Cameras / security
    "D0C5D3": "Xiaomi (IoT)", "74E12F": "Tenda",
    "EC8EB5": "Tenda", "C4836F": "Tenda", "D860B0": "Buffalo",
    "3475C7": "AVM (Fritz!Box)", "2447E0": "AVM (Fritz!Box)",
}


def lookup_vendor(mac: str) -> str:
    """Return vendor name for a MAC address, or 'Unknown vendor'.

    Accepts any separator style: 'aa:bb:cc:dd:ee:ff', 'AA-BB-...', etc.
    """
    if not mac:
        return "Unknown vendor"
    prefix = "".join(ch for ch in mac.upper()[:8] if ch in "0123456789ABCDEF")
    if len(prefix) < 6:
        return "Unknown vendor"
    return OUI_MAP.get(prefix[:6], "Unknown vendor")
