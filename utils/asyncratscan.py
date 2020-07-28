# Detecting AsyncRat for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] asyncratscan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] asyncratscan -pid [PID]

from . import basescan

import logging
from collections import OrderedDict

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    has_crypto = True
except ImportError:
    has_crypto = False

from base64 import b64decode
from binascii import a2b_hex

# logger for volatility
vollog = logging.getLogger(__name__)


class asyncratConfig(basescan.baseConfig):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            'namespace1': 'rule asyncrat { \
                strings: \
                    $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}\
                    $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}\
                    $b2 = {09 50 00 6F 00 6E 00 67 00 00}\
                    $s1 = "pastebin" ascii wide nocase \
                    $s2 = "pong" wide\
                    $s3 = "Stub.exe" ascii wide\
                condition: ($salt and (2 of($s*) or 1 of($b*))) or (all of($b*) and 2 of($s*))} '
        }
        self._config_sig = [b"\x00\x00\x00\x0D\x53\x00\x48\x00\x41\x00\x32\x00\x35\x00\x36\x00\x00"]
        self._config_index = {
            1: (2, "Server", "aes"),
            2: (1, "Ports", "aes"),
            3: (3, "Version", "aes"),
            4: (4, "Autorun", "aes"),
            5: (5, "Install_Folder", ""),
            6: (6, "Install_File", "aes"),
            7: (7, "AES_key", "base64"),
            8: (8, "Mutex", "aes"),
            9: (11, "AntiDetection", "aes"),
            10: (12, "External_config_on_Pastebin", "aes"),
            11: (13, "BDOS", "aes"),
            12: (14, "HWID", ""),
            13: (15, "Startup_Delay", ""),
            14: (9, "Certificate", "aes"),
            15: (10, "ServerSignature", "aes")
        }

    def parse_config(self, unicode_strings):
        """parse asyncrat configuration from unicode strings"""

        if len(unicode_strings) < 7:
            vollog.info("unicode strings list is too short.")
            return OrderedDict()

        config = OrderedDict()

        key = b64decode(unicode_strings[7])
        salt = a2b_hex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")
        aes_key = PBKDF2(key, salt, 32, 50000)

        for _, params in self._config_index.items():
            pos, field, enc_type = params
            if enc_type == "aes" and len(unicode_strings[pos]) > 48:
                enc_data = b64decode(unicode_strings[pos])
                # hmac = enc_data[:32]
                aes_iv = enc_data[32:48]
                cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                value = self.remove_unascii(cipher.decrypt(enc_data[48:]))
            elif enc_type == "base64":
                value = self.remove_unascii(b64decode(unicode_strings[pos]))
            else:
                value = unicode_strings[pos]
            config[field] = value
        return config

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

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        config_data = OrderedDict()
        for pattern in self._config_sig:
            m = data.find(pattern)
            if m > 0:
                unicode_strings = self.storage_stream_us_parser(
                    data[m + 3:])
                config_data = self.parse_config(unicode_strings)
                break
            else:
                vollog.info("Asyncrat configuration signature not found.")

        return config_data
