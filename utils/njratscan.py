# Detecting njRAT Keylogger for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv njratscan.py volatility/plugins/malware
# 3. python vol.py njratconfig -f images.mem --profile=Win7SP1x64

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

njrat_sig = {
    'namespace1' : 'rule Njrat { \
                    strings: \
                       $reg = "SEE_MASK_NOZONECHECKS" wide \
                       $msg = "Execute ERROR" wide \
                       $ping = "cmd.exe /c ping 0 -n 2 & del" wide \
                    condition: all of them}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x46\x69\x78\x00\x6b\x00\x57\x52\x4B\x00\x6D\x61\x69\x6E\x00\x00\x00", re.DOTALL)]

idx_list = {
    0:  "ID",
    1:  "Version",
    2:  "Name of Executable",
    3:  "Copy Direcroty",
    4:  "Registry Name",
    5:  "Server",
    6:  "Port",
    7:  "Split",
    8:  "Registry Key",
}


class njratConfig(taskmods.DllList):
    """Parse the njRAT configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def parse_config(self, configs):
        i = 0
        p_data = OrderedDict()
        for config in configs:
            if i == 0:
                p_data[idx_list[i]] = b64decode(config)
            else:
                p_data[idx_list[i]] = config
            i += 1

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=njrat_sig)

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
                        while data[offset] == "\x01" or data[offset] == "\x00":
                            offset += 1
                        string_len = ord(data[offset])
                        offset += 1
                        for i in range(string_len):
                            if data[offset + i] != "\x00":
                                strings.append(data[offset + i])
                        if "False" not in "".join(strings) and "True" not in "".join(strings):
                            configs.append("".join(strings))
                        offset = offset + string_len
                        if len(configs) > 8:
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
