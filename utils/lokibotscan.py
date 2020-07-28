# Detecting Lokibot for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] lokibotscan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] lokibotscan -pid [PID]

from . import basescan

import logging
import re
from collections import OrderedDict

try:
    from Crypto.Cipher import DES3
    has_crypto = True
except ImportError:
    has_crypto = False

# logger for volatility
vollog = logging.getLogger(__name__)


class lokibotConfig(basescan.baseConfig):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            'namespace1': 'rule Lokibot { \
                strings: \
                    $des3 = { 68 03 66 00 00 } \
                    $param = "MAC=%02X%02X%02XINSTALL=%08X%08X" \
                    $string = { 2d 00 75 00 00 00 46 75 63 6b 61 76 2e 72 75 00 00} \
                condition: all of them} '
        }
        self._config_sig = [re.compile(b"(..)\x0F\x84(......)\xe9(....)\x90\x90\x90\x90\x90\x90", re.DOTALL)]  # signature for searching configuration data

    def config_decoder(self, name, data, config_index, enc_data_count):
        enc_data = []
        key_data = bytes()
        enc_set = bytes()
        p_data = OrderedDict()
        x = 0
        for i in range(enc_data_count):
            while True:
                if data[config_index + x] != 0x00:
                    enc_set += data[config_index + x].to_bytes(1, "little")
                    x += 1
                else:
                    enc_data.append(enc_set)
                    enc_set = bytes()
                    x += 4
                    break

        config_index = config_index + x
        iv = self.remove_00_bytes(data[config_index:config_index + 12])

        config_index = config_index + 12
        for i in range(3)[::-1]:
            key_data += self.remove_00_bytes(data[config_index + (12 * i):config_index + (12 * (i + 1))])

        i = 0
        for data in enc_data:
            des = DES3.new(key_data, IV=iv, mode=DES3.MODE_CBC)
            data_dec = des.decrypt(data)
            p_data[name + " " + str(i)] = self.remove_unascii(data_dec)
            i += 1
        return p_data

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        config_data = OrderedDict()
        config_index = data.find("ckav.ru".encode("utf-8")) + 12
        config_data.update(self.config_decoder("Original URL", data, config_index, 4))
        config_index = data.find("INSTALL=%08X%08X".encode("utf-8")) + 16
        config_data.update(self.config_decoder("Registry key", data, config_index, 1))

        for pattern in self._config_sig:
            mk = re.search(pattern, data)

        enc_set = bytes()
        x = 0
        if mk:
            if chr(data[mk.start() + 0x30]) == "h":
                key = 0x0
            else:
                key = 0xFF

            while True:
                if data[mk.start() + 0x30 + x] != 0x00:
                    enc_set += (data[mk.start() + 0x30 + x] ^ key).to_bytes(1, "little")
                    x += 1
                else:
                    break
        config_data["Setting URL"] = self.remove_unascii(enc_set)
        return config_data
