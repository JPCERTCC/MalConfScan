# Detecting QuasarRat for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] quasarscan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] quasarscan -pid [PID]

from . import basescan

import logging
import re
import hashlib
from base64 import b64decode
from collections import OrderedDict
from binascii import a2b_hex

try:
    from pbkdf2 import PBKDF2
    from Crypto.Cipher import AES
    has_crypto = True
except ImportError:
    has_crypto = False

# logger for volatility
vollog = logging.getLogger(__name__)


class quasarConfig(basescan.baseConfig):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            'namespace1': 'rule Quasar { \
                    strings: \
                       $quasarstr1 = "Client.exe" wide \
                       $quasarstr2 = "({0}:{1}:{2})" wide \
                       $sql1 = "SELECT * FROM Win32_DisplayConfiguration" wide \
                       $sql2 = "{0}d : {1}h : {2}m : {3}s" wide \
                       $sql3 = "SELECT * FROM FirewallProduct" wide \
                       $net1 = "echo DONT CLOSE THIS WINDOW!" wide \
                       $net2 = "freegeoip.net/xml/" wide \
                       $net3 = "http://api.ipify.org/" wide \
                       $resource = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 } \
                    condition: ((all of ($quasarstr*) or all of ($sql*)) and $resource) or all of ($net*)}'
        }
        self._config_sig = [re.compile(b"\x52\x00\x65\x00\x73\x00\x6F\x00\x75\x00\x72\x00\x63\x00\x65\x00\x73\x00\x00\x17\x69\x00\x6E\x00\x66\x00\x6F\x00\x72\x00\x6D\x00\x61\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x00", re.DOTALL),
                            re.compile(b"\x61\x00\x70\x00\x69\x00\x2E\x00\x69\x00\x70\x00\x69\x00\x66\x00\x79\x00\x2E\x00\x6F\x00\x72\x00\x67\x00\x2F\x00\x00\x03\x5C\x00\x00", re.DOTALL),
                            re.compile(b"\x3C\x00\x2F\x00\x73\x00\x74\x00\x79\x00\x6C\x00\x65\x00\x3E\x00\x00\x03\x5C\x00\x00", re.DOTALL)]  # signature for searching configuration data
        self._config_index = {
            0: ["VERSION", True],
            1: ["HOSTS", True],
            2: ["KEY (Base64)", False],
            3: ["AUTHKEY (Base64)", False],
            4: ["SUBDIRECTORY", True],
            5: ["INSTALLNAME", True],
            6: ["MUTEX", True],
            7: ["STARTUPKEY", True],
            8: ["ENCRYPTIONKEY", False],
            9: ["TAG", True],
            10: ["LOGDIRECTORYNAME", True],
            11: ["unknown1", True],
            12: ["unknown2", True]
        }
        self._config_index_2 = {
            0: ["VERSION", True],
            1: ["HOSTS", True],
            2: ["KEY (Base64)", False],
            3: ["SUBDIRECTORY", True],
            4: ["INSTALLNAME", True],
            5: ["MUTEX", True],
            6: ["STARTUPKEY", True],
            7: ["ENCRYPTIONKEY", False],
            8: ["TAG", True]
        }

    def storage_stream_us_parser(self, data):
        """
        parse storage_stream for unicode strings in .NET assembly.
        unicode_strings chunk patterns
            pat1: [size of unicode strings(1byte)][unicode strings][terminate code(0x00 or 0x01)]
            pat2: [size of unicode strings(2byte)][unicode strings][terminate code(0x00 or 0x01)]
        """
        if len(data) < 2:
            return list()
        unicode_strings = list()

        while True:
            # first byte must be the size of unicode strings.
            if data[0] == 0x00:
                break
            elif data[0] < 0x80:
                size = data[0]
                p = 1
            elif data[0] >= 0x80:
                size = int.from_bytes(
                    bytes([data[0] - 0x80, data[1]]), "big")
                p = 2

            if size < 0 or 0x7FFF < size or size > len(data) - 3:
                vollog.warning("Invalid string size.")
                break

            unicode_strings.append(
                data[p:size + p - 1].decode().replace("\x00", ""))
            # check the termination code.
            if data[size + p - 1] == 0x00 or data[size + p - 1] == 0x01:
                # goto next block
                data = data[size + p:]
                continue
            else:
                break
        return unicode_strings

    def decrypt_string(self, key, configs, mode, idx):
        p_data = OrderedDict()
        for i, config in enumerate(configs):
            if idx[i][1]:
                if len(configs) < 10:
                    config = b64decode(config)
                    aes_iv = config[:16]
                    cipher = AES.new(key, mode, IV=aes_iv)
                    value = cipher.decrypt(config[16:])
                else:
                    config = b64decode(config)
                    aes_iv = config[32:48]
                    cipher = AES.new(key, mode, IV=aes_iv)
                    value = cipher.decrypt(config[48:])
                value = self.remove_unascii(value).strip()
            else:
                value = config
            p_data[idx[i][0]] = value

        return p_data

    def parse_config(self, configs):
        if len(configs) > 10:
            idx = self._config_index
            key, salt = configs[8], a2b_hex('BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941')
            generator = PBKDF2(key, salt, 50000)
            aes_key = generator.read(16)
        else:
            idx = self._config_index_2
            aes_key = hashlib.md5(configs[7]).digest()

        if(len(configs) > 12):
            mode = AES.MODE_CFB
        else:
            mode = AES.MODE_CBC
        p_data = self.decrypt_string(aes_key, configs, mode, idx)

        return p_data

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        """process dump data will be passed as data"""
        config_data = OrderedDict()

        for pattern in self._config_sig:
            mc = re.search(pattern, data)
            if mc:
                offset = mc.end()

                if data[offset] == 0x0:
                    offset += 1

        configs = []
        unicode_strings = self.storage_stream_us_parser(data[offset:])

        for unicode_string in unicode_strings:
            if len(unicode_string) < 5:
                break
            else:
                configs.append(unicode_string)

        config_data = self.parse_config(configs)
        return config_data
