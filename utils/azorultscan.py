# Detecting Azorult for Volatilitv
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv azorultconfigallocate.py volatility/plugins/malware
# 3. python vol.py azorultconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
from struct import unpack, unpack_from

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

azorult_sig = {
    'namespace1' : 'rule Azorult { \
                    strings: \
                       $v1 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)" \
                       $v2 = "http://ip-api.com/json" \
                       $v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 } \
                    condition: all of them}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("[-+]{10}\x0D\x0A", re.DOTALL)]


class azorultConfig(taskmods.DllList):
    "Parse the Azorult configuration"

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End
        return None

    def calculate(self):

        if not has_yara:
            debug.error('Yara must be installed for this plugin.')

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error('This command does not support the selected profile.')

        rules = yara.compile(sources=azorult_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                memdata = proc_addr_space.get_available_addresses()

                config_data = []

                for m in memdata:
                    if m[1] < 0x100000:
                        continue
                    p_data = {}

                    data = proc_addr_space.zread(m[0], m[1])

                    for pattern in CONFIG_PATTERNS:
                        m = re.search(pattern, data)

                    if m:
                        offset = m.start() - 0x1c
                    else:
                        continue

                    i = 0
                    while(True):
                        _, _, param_len = unpack_from("<III", data, offset)
                        if param_len > 0x100:
                            break
                        offset = offset + 0xc
                        param_data = data[offset:offset + param_len]
                        p_data[i] = param_data
                        rest_len = 4 - (param_len % 4)
                        offset += param_len + rest_len
                        i += 1

                    config_data.append(p_data)
                yield task, vad_base_addr, end, hit, memory_model, config_data
                break

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, end, malname, memory_model, config_data in data:
            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.ImageFileName, task.UniqueProcessId))

            outfd.write("[Download Config Info]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0:<4}: {1}\n".format(id, param))
