# Detecting CobaltStrike for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] cobaltstrikescan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] cobaltstrikescan -pid [PID]

from . import basescan

import logging
from collections import OrderedDict
from socket import inet_ntoa


# logger for volatility
vollog = logging.getLogger(__name__)


class cobaltstrikeConfig(basescan.baseConfig):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            "keyspace1": "rule CobaltStrike { \
                    strings: \
                        $v1 = { 73 70 72 6E 67 00} \
                        $v2 = { 69 69 69 69 69 69 69 69} \
                    condition: $v1 and $v2}"
        }
        self._config_sig = [b"\x69\x68\x69\x68\x69"]  # signature for searching configuration data
        self.config_info = [(b"\x00\x01\x00\x01\x00\x02", "BeaconType", 0x2, "int"),
                            (b"\x00\x02\x00\x01\x00\x02", "Port", 0x2, "int"),
                            (b"\x00\x03\x00\x02\x00\x04", "Polling(ms)", 0x4, "int"),
                            # (b"\x00\x04\x00\x02\x00\x04", "Unknown1", 0x4, "big"),
                            (b"\x00\x05\x00\x01\x00\x02", "Jitter", 0x2, "int"),
                            (b"\x00\x06\x00\x01\x00\x02", "Maxdns", 0x2, "int"),
                            # (b"\x00\x07\x00\x03\x01\x00", "Unknown2", 0x100, "big"),
                            (b"\x00\x08\x00\x03\x01\x00", "C2Server", 0x100, "big"),
                            (b"\x00\x09\x00\x03\x00\x80", "UserAgent", 0x80, "big"),
                            (b"\x00\x0a\x00\x03\x00\x40", "HTTP_Method2_Path", 0x40, "big"),
                            # (b"\x00\x0b\x00\x03\x01\x00", "Unknown3", 0x100, "big"),
                            (b"\x00\x0c\x00\x03\x01\x00", "HTTP_Header1", 0x100, "big"),
                            (b"\x00\x0d\x00\x03\x01\x00", "HTTP_Header2", 0x100, "big"),
                            (b"\x00\x0e\x00\x03\x00\x40", "Injection_Process", 0x40, "big"),
                            (b"\x00\x0f\x00\x03\x00\x80", "PipeName", 0x80, "big"),
                            (b"\x00\x10\x00\x01\x00\x02", "Year", 0x2, "int"),
                            (b"\x00\x11\x00\x01\x00\x02", "Month", 0x2, "int"),
                            (b"\x00\x12\x00\x01\x00\x02", "Day", 0x2, "int"),
                            (b"\x00\x13\x00\x02\x00\x04", "DNS_idle", 0x4, "inet"),
                            (b"\x00\x14\x00\x02\x00\x04", "DNS_sleep(ms)", 0x2, "int"),
                            (b"\x00\x1a\x00\x03\x00\x10", "Method1", 0x10, "big"),
                            (b"\x00\x1b\x00\x03\x00\x10", "Method2", 0x10, "big"),
                            # (b"\x00\x1c\x00\x02\x00\x04", "Unknown4", 0x4, "big"),
                            (b"\x00\x1d\x00\x03\x00\x40", "Spawnto_x86", 0x40, "big"),
                            (b"\x00\x1e\x00\x03\x00\x40", "Spawnto_x64", 0x40, "big"),
                            # (b"\x00\x1f\x00\x01\x00\x02", "Unknown5", 0x2, "int"),
                            (b"\x00\x20\x00\x03\x00\x80", "Proxy_HostName", 0x80, "big"),
                            (b"\x00\x21\x00\x03\x00\x40", "Proxy_UserName", 0x40, "big"),
                            (b"\x00\x22\x00\x03\x00\x40", "Proxy_Password", 0x40, "big"),
                            (b"\x00\x23\x00\x01\x00\x02", "Proxy_AccessType", 0x2, "int"),
                            (b"\x00\x24\x00\x01\x00\x02", "create_remote_thread", 0x2, "bool")]
        self.config_size = 0x1000
        self.BEACONTYPE = {0x0: "0 (HTTP)", 0x1: "1 (Hybrid HTTP and DNS)", 0x8: "8 (HTTPS)"}
        self.ACCESSTYPE = {0x0: "0 (not use)", 0x1: "1 (use direct connection)", 0x2: "2 (use IE settings)", 0x4: "4 (use proxy server)"}

    @staticmethod
    def xor(data, key):
        _len = len(key)
        return bytearray(((b ^ key[i % _len]) for i, b in enumerate(data)))

    def parse_config(self, blob):

        p_data = OrderedDict()

        for pattern, key, size, _type in self.config_info:
            offset = blob.find(pattern)

            if offset == -1:
                continue

            if _type == "int":
                value = int.from_bytes(blob[offset + 6:offset + 6 + size], "big")
                if key == "BeaconType":
                    p_data[key] = self.BEACONTYPE[value]
                elif key == "Proxy_AccessType":
                    p_data[key] = self.ACCESSTYPE[value]
                else:
                    p_data[key] = value

            elif _type == "inet":
                p_data[key] = inet_ntoa(blob[offset + 6:offset + 6 + size])

            elif _type == "bool":
                value = blob[offset + 6:offset + 6 + size]
                if value:
                    p_data[key] = "Enable"
                else:
                    p_data[key] = "Disable"

            elif _type == "big":
                if "Header" in key:
                    _tmp = blob[offset + 6:offset + 6 + size].split(b"\x00\x00\x00")
                    cnt = 1
                    for d in _tmp:
                        value = self.remove_unascii(d)

                        if value:
                            if not value[0].isalpha():
                                value = value[1:]
                            p_data[key + "_" + str(cnt)] = value
                            cnt += 1
                else:
                    try:
                        value = blob[offset + 6:offset + 6 + size].decode()
                    except UnicodeDecodeError:
                        value = blob[offset + 6:offset + 6 + size].hex()

                    p_data[key] = value

        return p_data

    def extract_config(self, data: bytes, malkey: str, vad_base_addr: int) -> OrderedDict:
        """process dump data will be passed as data"""
        config_data = OrderedDict()

        for sig in self._config_sig:
            config_addr = data.find(sig)
            if config_addr:
                break

        if not config_addr:
            vollog.error("[!] CobaltStrike config signature was not found.")
            return config_data

        config_blob = self.xor(data[config_addr:config_addr + self.config_size], b"\x69")  # config data is xor-ed with single byte key.
        config_data = self.parse_config(config_blob)

        return config_data
