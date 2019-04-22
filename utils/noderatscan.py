# Detecting NodeRat for Volatilitv
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv noderatconfigallocate.py volatility/plugins/malware
# 3. python vol.py noderatconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import json
from struct import unpack, unpack_from

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

noderat_sig = {
    'namespace1' : 'rule Noderat { \
                    strings: \
                       $config = "/config/app.json" \
                       $key = "/config/.regeditKey.rc" \
                       $message = "uninstall error when readFileSync: " \
                    condition: all of them}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x7B\x0D\x0A\x20\x20\x22\x6E\x61\x6D\x65\x22\x3A\x20(.*)\x65\x0d\x0a\x7d", re.DOTALL)]


class noderatConfig(taskmods.DllList):
    "Parse the Noderat configuration"

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

        rules = yara.compile(sources=noderat_sig)

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
                        offset = m.start()
                    else:
                        continue

                    json_data = data[offset:m.end()]
                    d = json.loads(json_data)

                    config_data.append(d)
                    break
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
                    outfd.write("{0:<10}: {1}\n".format(id, param))
