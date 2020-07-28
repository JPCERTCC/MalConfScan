# Detecting Lokibot for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] hawkeyescan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] hawkeyescan -pid [PID]

from . import basescan

import logging
from collections import OrderedDict
from base64 import b64decode
from binascii import a2b_hex

try:
    from Crypto.Cipher import AES
    from pbkdf2 import PBKDF2
    has_crypto = True
except ImportError:
    has_crypto = False


# logger for volatility
vollog = logging.getLogger(__name__)


class hawkeyeConfig(basescan.baseConfig):
    """please rename class name the same name as [yara_rule_name]Config."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            'namespace1': 'rule Hawkeye { \
                    strings: \
                       $hawkstr1 = "HawkEye Keylogger" wide \
                       $hawkstr2 = "Dear HawkEye Customers!" wide \
                       $hawkstr3 = "HawkEye Logger Details:" wide \
                    condition: all of them}'
        }
        self._config_sig = [b"\x57\x00\x69\x00\x6E\x00\x46\x00\x6F\x00\x72\x00\x6D\x00\x73\x00\x5F\x00\x53\x00\x65\x00\x65\x00\x49\x00\x6E\x00\x6E\x00\x65\x00\x72\x00\x45\x00\x78\x00\x63\x00\x65\x00\x70\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x00\x80"]  # signature for searching configuration data
        self._config_index = {
            0: "encryptedemailstring",
            1: "encryptedpassstring",
            2: "encryptedsmtpstring",
            3: "portstring",
            4: "timerstring",
            5: "fakemgrstring",
            6: "encryptedftphost",
            7: "encryptedftpuser",
            8: "encryptedftppass",
            9: "encryptedphplink",
            10: "useemail",
            11: "useftp",
            12: "usephp",
            13: "delaytime",
            14: "clearie",
            15: "clearff",
            16: "binder",
            17: "downloader",
            18: "websitevisitor",
            19: "websiteblocker",
            20: "notify",
            21: "DisableSSL",
            22: "fakerror",
            23: "startup",
            24: "screeny",
            25: "clip",
            26: "TaskManager",
            27: "logger",
            28: "stealers",
            29: "melt",
            30: "reg",
            31: "cmd",
            32: "misconfig",
            33: "spreaders",
            34: "steam",
            35: "meltLocation",
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

    def decrypt_string(self, key, salt, coded):
        generator = PBKDF2(key, salt)
        aes_iv = generator.read(16)
        aes_key = generator.read(32)
        mode = AES.MODE_CBC
        cipher = AES.new(aes_key, mode, IV=aes_iv)
        value = self.remove_00_bytes(cipher.decrypt(b64decode(coded)))
        return self.remove_unascii(value)

    def parse_config(self, unicode_strings):
        i = 0
        p_data = OrderedDict()
        key, salt = 'HawkEyeKeylogger', a2b_hex('3000390039007500370038003700390037003800370038003600')
        for config in unicode_strings[:36]:
            if i in [0, 1, 2, 6, 7, 8, 9]:  # decode encrypted config value
                config = self.decrypt_string(key, salt, config)
            p_data[self._config_index[i]] = config
            i += 1
        return p_data

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        """process dump data will be passed as data"""
        config_data = OrderedDict()

        for pattern in self._config_sig:
            m = data.find(pattern)
            offset = m + len(pattern) - 1
            if m:
                unicode_strings = self.storage_stream_us_parser(data[offset:])
                config_data = self.parse_config(unicode_strings)
        return config_data
