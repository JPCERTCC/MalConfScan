# Detecting LokiBot for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv lokibotscan.py volatility/plugins/malware
# 3. python vol.py lokibotconfig -f images.mem --profile=Win7SP1x64

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
    from Crypto.Cipher import DES3
    has_crypto = True
except ImportError:
    has_crypto = False

lokibot_sig = {
    'namespace1' : 'rule Lokibot { \
                    strings: \
                       $des3 = { 68 03 66 00 00 } \
                       $param = "MAC=%02X%02X%02XINSTALL=%08X%08X" \
                       $string = { 2d 00 75 00 00 00 46 75 63 6b 61 76 2e 72 75 00 00} \
                    condition: all of them}'
}

# Config pattern
CONF_PATTERNS = [re.compile("(..)\x0F\x84(......)\xe9(....)\x90\x90\x90\x90\x90\x90", re.DOTALL)]


class lokibotConfig(taskmods.DllList):
    """Parse the Lokibot configuration"""

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

    def config_decode(self, name, data, config_index, enc_data_count):
        enc_data = []
        key_data = []
        enc_set = []
        p_data = OrderedDict()
        x = 0
        for i in range(enc_data_count):
            while 1:
                if data[config_index + x] != "\0":
                    enc_set.append(data[config_index + x])
                    x += 1
                else:
                    enc_data.append("".join(enc_set))
                    enc_set = []
                    x += 4
                    break

        config_index = config_index + x
        iv = data[config_index:config_index + 12].replace("\0", "")

        config_index = config_index + 12
        for i in range(3)[::-1]:
            key_data.append(data[config_index + (12 * i):config_index + (12 * (i + 1))].replace("\0", ""))

        key = "".join(key_data)
        i = 0
        for data in enc_data:
            des = DES3.new(key, IV=iv, mode=DES3.MODE_CBC)
            data_dec = des.decrypt(data)
            p_data[name + " " + str(i)] = self.string_print(data_dec)
            i += 1

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        if not has_crypto:
            debug.error("pycrypto must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=lokibot_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                config_index = data.find("ckav.ru") + 12
                config_data.append(self.config_decode("Original URL", data, config_index, 4))
                config_index = data.find("INSTALL=%08X%08X") + 16
                config_data.append(self.config_decode("Registry key", data, config_index, 1))

                for pattern in CONF_PATTERNS:
                    mk = re.search(pattern, data)

                enc_set = []
                x = 0
                if mk:
                    if "h" in data[mk.start() + 0x30]:
                        key = 0x0
                    else:
                        key = 0xFF

                    while 1:
                        if data[mk.start() + 0x30 + x] != "\0":
                            enc_set.append(chr(ord(data[mk.start() + 0x30 + x]) ^ key))
                            x += 1
                        else:
                            enc_data = "".join(enc_set)
                            break

                p_data = {}
                p_data["Setting URL"] = self.string_print(enc_data)
                config_data.append(p_data)

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
                    outfd.write("{0:<16}: {1}\n".format(id, param))
