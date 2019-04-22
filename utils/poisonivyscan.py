# Detecting PoisonIvy for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv poisonivyscan.py volatility/plugins/malware
# 3. python vol.py poisonivyconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import pefile
from struct import unpack, unpack_from

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

poisonivy_sig = {
    'namespace1' : 'rule PoisonIvy { \
                    strings: \
                       $a1 = { 0E 89 02 44 } \
                       $b1 = { AD D1 34 41 } \
                       $c1 = { 66 35 20 83 66 81 F3 B8 ED } \
                    condition: all of them}'
}

# idx list
idx_list = {
    0x012d: ["Install Name", 1],
    0x0145: ["Password", 1],
    0x0165: ["AcviteX Key", 1],
    0x018c: ["C&C Servers Count", 0],
    0x0190: ["Server", 1],
    0x02c1: ["Proxy Servers Count", 0],
    0x03f3: ["Install Path", 1],
    0x03f6: ["AcviteX Flag", 2],
    0x03f7: ["Installation Folder", 3],
    0x03f8: ["Auto-remove Flag", 2],
    0x03f9: ["Thread Persistence Flag", 2],
    0x03fa: ["Keylog Flag", 2],
    0x03fb: ["Mutex", 1],
    0x040f: ["Active Setup Name", 1],
    0x0418: ["Default Browser Path", 1],
    0x0441: ["Injection Flag", 2],
    0x0442: ["Injection Process", 1],
    0x0456: ["Active Key", 1],
    0x0af4: ["Proxy Hijack", 2],
    0x0af5: ["Persistent Proxy", 2],
    0x0afa: ["Campaign ID", 1],
    0x0bf9: ["Group ID", 1],
    0x0d08: ["Inject Default Browser", 2],
    0x0d09: ["Registry Key Flag", 2],
    0x0d12: ["ADS Flag", 2],
    0x0e12: ["Registry Key Value", 1],
    0x1201: ["Server", 1],
    0xeffc: ["unknow 1", 2],
    0xef8c: ["unknow 2", 2],
    0xef7c: ["unknow 3", 2],
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\xFA\x0A(.)\x00", re.DOTALL)]

MODE = {0: "Disable", 1: "Enable"}
FOLDER = {1: "%systemroot%", 2: "%systemroot%\system32"}


class poisonivyConfig(taskmods.DllList):
    """Parse the PoisonIvy configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def parse_config(self, idx, data):
        p_data = {}
        if idx in idx_list:
            field, field_type = idx_list[idx]
        else:
            field = hex(idx)
            field_type = 0

        if field_type == 0:
            if unpack_from("<I", data)[0] == 0xffffffff:
                p_data[field] = 0
            else:
                p_data[field] = unpack_from("<I", data)[0]
        if field_type == 1:
            p_data[field] = data
        if field_type == 2:
            p_data[field] = MODE[ord(data)]
        if field_type == 3:
            p_data[field] = FOLDER[ord(data)]

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=poisonivy_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                for pattern in CONFIG_PATTERNS:
                    mc = re.search(pattern, data)
                    if mc:
                        offset = mc.start()
                        while data[offset] != "\xC3":
                            offset -= 1

                        while data[offset:offset + 2] != "\x00\x00":
                            (idx, size) = unpack_from("<HH", data, offset + 1)
                            if size > 0:
                                enc = data[offset + 5:offset + 5 + size]
                                config_data.append(self.parse_config(idx, enc))
                            offset = offset + size + 4

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
                    outfd.write("{0:<20}: {1}\n".format(id, param))
