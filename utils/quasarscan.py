# Detecting QuasarRAT for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv quasarscan.py volatility/plugins/malware
# 3. python vol.py quasarconfig -f images.mem --profile=Win7SP1x64

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

quasar_sig = {
    'namespace1' : 'rule Quasar { \
                    strings: \
                       $quasarstr1 = "[PRIVATE KEY LOCATION: \\"{0}\\"]" wide \
                       $quasarstr2 = "User: {0}{3}Pass: {1}{3}Host: {2}" wide \
                       $quasarstr3 = "Core.MouseKeyHook.WinApi" ascii fullword \
                    condition: all of them}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x52\x00\x65\x00\x73\x00\x6F\x00\x75\x00\x72\x00\x63\x00\x65\x00\x73\x00\x00\x17\x69\x00\x6E\x00\x66\x00\x6F\x00\x72\x00\x6D\x00\x61\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x00\x80", re.DOTALL)]

idx_list = {
    0:  "VERSION",
    1:  "HOSTS",
    2:  "KEY (Base64)",
    3:  "AUTHKEY (Base64)",
    4:  "SUBDIRECTORY",
    5:  "INSTALLNAME",
    6:  "MUTEX",
    7:  "STARTUPKEY",
    8:  "ENCRYPTIONKEY",
    9:  "TAG",
    10: "LOGDIRECTORYNAME",
}


class quasarConfig(taskmods.DllList):
    """Parse the QuasarRAT configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def decrypt_string(self, key, coded):
        mode = AES.MODE_CBC
        if len(coded) < 48:
            value = ""
        else:
            aes_iv = coded[32:48]
            cipher = AES.new(key, mode, IV=aes_iv)
            value = cipher.decrypt(coded[48:]).replace('\x00', '').replace('\x0a', '').replace('\x0b', '')

        return value

    def parse_config(self, configs):
        i = 0
        p_data = OrderedDict()
        key, salt = configs[8], 'BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941'.decode('hex')
        generator = PBKDF2(key, salt, 50000)
        aes_key = generator.read(16)

        for i, config in enumerate(configs):
            if i not in [2, 3, 8]:
                try:
                    config = self.decrypt_string(aes_key, b64decode(config))
                except:
                    pass
            p_data[idx_list[i]] = config

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

        rules = yara.compile(sources=quasar_sig)

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
                        if ord(data[offset]) == 0x80 or ord(data[offset]) == 0x81:
                            string_len = ord(data[offset + 1]) + ((ord(data[offset]) - 0x80) * 256)
                            offset += 1
                        offset += 1
                        for i in range(string_len):
                            if data[offset + i] != "\x00":
                                strings.append(data[offset + i])
                        configs.append("".join(strings))
                        offset = offset + string_len
                        if len(configs) > 10:
                            break

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
