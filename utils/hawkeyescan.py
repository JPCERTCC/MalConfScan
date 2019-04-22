# Detecting HawkEye Keylogger for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv hawkeyescan.py volatility/plugins/malware
# 3. python vol.py hawkeyeconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
from base64 import b64decode
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    from Crypto.Cipher import AES
    has_crypto = True
except ImportError:
    has_crypto = False

try:
    from pbkdf2 import PBKDF2
    has_pbkdf2 = True
except ImportError:
    has_pbkdf2 = False

hawkeye_sig = {
    'namespace1' : 'rule Hawkeye { \
                    strings: \
                       $hawkstr1 = "HawkEye Keylogger" wide \
                       $hawkstr2 = "Dear HawkEye Customers!" wide \
                       $hawkstr3 = "HawkEye Logger Details:" wide \
                    condition: all of them}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x57\x00\x69\x00\x6E\x00\x46\x00\x6F\x00\x72\x00\x6D\x00\x73\x00\x5F\x00\x53\x00\x65\x00\x65\x00\x49\x00\x6E\x00\x6E\x00\x65\x00\x72\x00\x45\x00\x78\x00\x63\x00\x65\x00\x70\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x00\x80", re.DOTALL)]

idx_list = {
    0:  "encryptedemailstring",
    1:  "encryptedpassstring",
    2:  "encryptedsmtpstring",
    3:  "portstring",
    4:  "timerstring",
    5:  "fakemgrstring",
    6:  "encryptedftphost",
    7:  "encryptedftpuser",
    8:  "encryptedftppass",
    9:  "encryptedphplink",
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


class hawkeyeConfig(taskmods.DllList):
    """Parse the Hawkeye configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def string_print(self, line):
        try:
            return "".join((char for char in line if 32 < ord(char) < 127))
        except:
            return line

    def decrypt_string(self, key, salt, coded):
        generator = PBKDF2(key, salt)
        aes_iv = generator.read(16)
        aes_key = generator.read(32)

        mode = AES.MODE_CBC
        cipher = AES.new(aes_key, mode, IV=aes_iv)
        value = cipher.decrypt(b64decode(coded)).replace('\x00', '')
        return self.string_print(value)

    def parse_config(self, configs):
        i = 0
        p_data = OrderedDict()
        key, salt = 'HawkEyeKeylogger', '3000390039007500370038003700390037003800370038003600'.decode('hex')
        for config in configs:
            if i in [0, 1, 2, 6, 7, 8, 9]:
                config = self.decrypt_string(key, salt, config)
            p_data[idx_list[i]] = config
            i += 1

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        if not has_crypto:
            debug.error("pycrypto must be installed for this plugin")

        if not has_pbkdf2:
            debug.error("pbkdf2 must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=hawkeye_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                offset = 0
                for pattern in CONFIG_PATTERNS:
                    mc = re.search(pattern, data)
                    if mc:
                        offset = mc.end()

                configs = []
                if offset > 0:
                    while 1:
                        strings = []
                        string_len = ord(data[offset])
                        if data[offset] == "\x80":
                            string_len = ord(data[offset + 1])
                            offset += 1
                        offset += 1
                        for i in range(string_len):
                            if data[offset + i] != "\x00":
                                strings.append(data[offset + i])
                        configs.append("".join(strings))
                        offset = offset + string_len
                        if len(configs) > 35:
                            break

                if not configs[13].isdigit():
                    configs.insert(13, 0)
                    configs.pop(-1)

                config_data.append(self.parse_config(configs))

                yield task, vad_base_addr, end, hit, memory_model, config_data
                break

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, end, malname, memory_model, config_data in data:
            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.ImageFileName, task.UniqueProcessId))

            outfd.write("[Config Info]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0:<21}: {1}\n".format(id, param))
