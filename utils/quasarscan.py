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
import hashlib
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

# Config pattern
CONFIG_PATTERNS = [re.compile("\x52\x00\x65\x00\x73\x00\x6F\x00\x75\x00\x72\x00\x63\x00\x65\x00\x73\x00\x00\x17\x69\x00\x6E\x00\x66\x00\x6F\x00\x72\x00\x6D\x00\x61\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x00\x80", re.DOTALL),
                   re.compile("\x61\x00\x70\x00\x69\x00\x2E\x00\x69\x00\x70\x00\x69\x00\x66\x00\x79\x00\x2E\x00\x6F\x00\x72\x00\x67\x00\x2F\x00\x00\x03\x5C\x00\x00", re.DOTALL),
                   re.compile("\x3C\x00\x2F\x00\x73\x00\x74\x00\x79\x00\x6C\x00\x65\x00\x3E\x00\x00\x03\x5C\x00\x00\x80", re.DOTALL)]

idx_list = {
    0:  ["VERSION", True],
    1:  ["HOSTS", True],
    2:  ["KEY (Base64)", False],
    3:  ["AUTHKEY (Base64)", False],
    4:  ["SUBDIRECTORY", True],
    5:  ["INSTALLNAME",True],
    6:  ["MUTEX", True],
    7:  ["STARTUPKEY", True],
    8:  ["ENCRYPTIONKEY", False],
    9:  ["TAG", True],
    10: ["LOGDIRECTORYNAME",True ],
    11: ["unknown1", True],
    12: ["unknown2", True]
}

idx_list_2 = {
    0:  ["VERSION", True],
    1:  ["HOSTS", True],
    2:  ["KEY (Base64)", False],
    3:  ["SUBDIRECTORY", True],
    4:  ["INSTALLNAME",True],
    5:  ["MUTEX", True],
    6:  ["STARTUPKEY", True],
    7:  ["ENCRYPTIONKEY", False],
    8:  ["TAG", True]
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

    def decrypt_string(self, key, configs, mode, idx):
        p_data = OrderedDict()
        for i, config in enumerate(configs):
            if idx[i][1] == True:
                if len(configs) < 10:
                    config = b64decode(config)
                    aes_iv = config[:16]
                    cipher = AES.new(key, mode, IV=aes_iv)
                    value = re.sub("[\x00-\x19]" ,"" , cipher.decrypt(config[16:]))
                else:
                    config = b64decode(config)
                    aes_iv = config[32:48]
                    cipher = AES.new(key, mode, IV=aes_iv)
                    value = re.sub("[\x00-\x19]" ,"" , cipher.decrypt(config[48:]))
            else:
                value = config
            p_data[idx[i][0]] = value

        return p_data

    def parse_config(self, configs):
        if len(configs) > 10:
            idx = idx_list
            key, salt = configs[8], 'BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941'.decode('hex')

            generator = PBKDF2(key, salt, 50000)
            aes_key = generator.read(16)
        else:
            idx = idx_list_2
            aes_key = hashlib.md5(configs[7]).digest()

        if(len(configs) > 12):
            mode = AES.MODE_CFB
        else:
            mode = AES.MODE_CBC
        p_data = self.decrypt_string(aes_key, configs, mode, idx)

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

                        if ord(data[offset]) == 0x0:
                            offset += 1

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

                        if ord(data[offset]) < 0x20:
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
