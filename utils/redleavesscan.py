# Detecting redleaves for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] redleavesscan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] redleavesscan -pid [PID]

from . import basescan

import logging
import re
from collections import OrderedDict
from struct import unpack, unpack_from

try:
    """import crypto libs here"""
    has_crypto = True
except ImportError:
    has_crypto = False

# logger for volatility
vollog = logging.getLogger(__name__)


class redleavesConfig(basescan.baseConfig):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            'namespace1': 'rule RedLeaves { \
                    strings: \
                       $v1 = "red_autumnal_leaves_dllmain.dll" \
                       $b1 = { FF FF 90 00 } \
                    condition: $v1 and $b1 at 0}',
            'namespace2': 'rule Himawari { \
                    strings: \
                       $h1 = "himawariA" \
                       $h2 = "himawariB" \
                       $h3 = "HimawariDemo" \
                    condition: $h1 and $h2 and $h3}',
            'namespace3': 'rule Lavender { \
                    strings: \
                       $l1 = {C7 ?? ?? 4C 41 56 45} \
                       $l2 = {C7 ?? ?? 4E 44 45 52} \
                    condition: $l1 and $l2}',
            'namespace4': 'rule Armadill { \
                    strings: \
                       $a1 = {C7 ?? ?? 41 72 6D 61 } \
                       $a2 = {C7 ?? ?? 64 69 6C 6C } \
                    condition: $a1 and $a2}',
            'namespace5': 'rule zark20rk { \
                    strings: \
                       $a1 = {C7 ?? ?? 7A 61 72 6B } \
                       $a2 = {C7 ?? ?? 32 30 72 6B } \
                    condition: $a1 and $a2}'
        }
        self._config_sig = {"RedLeaves": re.compile(b"\x68\x88\x13\x00\x00\xFF", re.DOTALL),
                            "Himawari": re.compile(b"\x68\x70\x03\x00\x00\xBF", re.DOTALL),
                            "Lavender": re.compile(b"\x68\x70\x03\x00\x00\xBF", re.DOTALL),
                            "Armadill": re.compile(b"\x68\x70\x03\x00\x00\xBF", re.DOTALL),
                            "zark20rk": re.compile(b"\x68\x70\x03\x00\x00\x8D", re.DOTALL),
                            }  # signature for searching configuration data

        self.CONNECT_MODE = {1: 'TCP', 2: 'HTTP', 3: 'HTTPS', 4: 'TCP and HTTP'}

    def parse_config(self, cfg_blob, cfg_sz, cfg_addr):
        p_data = OrderedDict()
        p_data["Server1"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x0)[0])
        p_data["Server2"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x40)[0])
        p_data["Server3"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x80)[0])
        p_data["Port"] = unpack_from('<I', cfg_blob, 0xC0)[0]
        mode = unpack_from('<I', cfg_blob, 0x1D0)[0]
        p_data["Mode"] = self.CONNECT_MODE[mode]
        p_data["ID"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x1E4)[0])
        p_data["Mutex"] = self.remove_unascii(unpack_from('<550s', cfg_blob, 0x500)[0])
        p_data["Injection Process"] = unpack_from('<104s', cfg_blob, 0x726)[0].decode()
        p_data["RC4 Key"] = self.remove_unascii(unpack_from('<10s', cfg_blob, 0x82A)[0])

        return p_data

    def parse_config_himawari(self, cfg_blob, cfg_sz, cfg_addr):
        p_data = OrderedDict()
        p_data["Server1"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x4)[0])
        p_data["Server2"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x44)[0])
        p_data["Server3"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x84)[0])
        p_data["Server4"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0xC4)[0])
        p_data["Port"] = unpack_from('<I', cfg_blob, 0x104)[0]
        mode = unpack_from('<I', cfg_blob, 0x1D8)[0]
        p_data["Mode"] = self.CONNECT_MODE[mode]
        p_data["ID"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x1E0)[0])
        p_data["Mutex"] = self.remove_unascii(unpack_from('<62s', cfg_blob, 0x224)[0])
        p_data["Key"] = self.remove_unascii(unpack_from('<10s', cfg_blob, 0x366)[0])
        p_data["UserAgent"] = self.remove_unascii(unpack_from('<260s', cfg_blob, 0x262)[0])
        p_data["Proxy server"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x10C)[0])
        p_data["Proxy username"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x14C)[0])
        p_data["Proxy password"] = self.remove_unascii(unpack_from('<64s', cfg_blob, 0x18C)[0])

        return p_data

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        """process dump data will be passed as data"""
        config_data = OrderedDict()
        _config_sig = self._config_sig[malname]
        if re.search(_config_sig, data):
            config_offset = re.search(_config_sig, data).start()
        else:
            vollog.info("{} configuration signature not found.".format(malname))
            return config_data
        print(len(data), config_offset)
        if "RedLeaves" in malname:
            config_size = 2100

            config_offset -= 1
            while data[config_offset] != 0xC7 and data[config_offset] != 0xBE and data[config_offset] != 0xBF:
                config_offset -= 1

            # if data[config_offset] != "\xC7" and data[config_offset] != "\xBE" and data[config_offset] != "\xBF":
            #    pass
            if data[config_offset] == 0xC7 and data[config_offset + 1] != 0x85 and data[config_offset + 1] != 0x45:
                config_offset -= 6

            # get address
            if data[config_offset] == 0xC7 and data[config_offset + 1] != 0x85:
                (config_addr, ) = unpack("=I", data[config_offset + 3:config_offset + 7])
            elif data[config_offset] == 0xC7 and data[config_offset + 1] == 0x85:
                (config_addr, ) = unpack("=I", data[config_offset + 6:config_offset + 10])
            else:
                (config_addr, ) = unpack("=I", data[config_offset + 1:config_offset + 5])

            if config_addr < vad_base_addr:
                vollog.error("Invalid config address. VAD_BASE:{}  Config Address:{}".format(vad_base_addr, config_addr))
                return config_data

            config_addr -= vad_base_addr
            config = data[config_addr:config_addr + config_size]
            if len(config) > 0:
                config_data = self.parse_config(config, config_size, config_addr)

        if malname in ["Himawari", "Lavender", "Armadill", "zark20rk"]:
            config_offset += 6
            if malname in ["zark20rk"]:
                config_offset += 6
            config_size = 880

            # get address
            (config_addr, ) = unpack("=I", data[config_offset:config_offset + 4])

            if config_addr < vad_base_addr:
                vollog.error("Invalid config address. VAD_BASE:{}  Config Address:{}".format(vad_base_addr, config_addr))
                return config_data

            config_addr -= vad_base_addr
            config = data[config_addr:config_addr + config_size]
            if len(config) > 0:
                config_data = self.parse_config_himawari(config, config_size, config_addr)

        return config_data
