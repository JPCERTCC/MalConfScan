# NetWire config dumper for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mkdir contrib/plugins/malware
# 3. mv netwirescan.py contrib/plugins/malware
# 4. python vol.py --plugins=contrib/plugins/malware netwireconfig -f images.mem --profile=WinXPSP3x86

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
from struct import unpack
import re
from collections import OrderedDict

NETWIRE_INFO = [{
    'version': '1.5b',
    'pattern': re.compile("\xE8\x8B(.)\x00\x00\xC7\x44(.)\x08\x03\x00\x00\x00", re.DOTALL),
    'cfg_offset': 17,
    'cfg_size': 0x3A4,
    'cfg_info': [['Unknown0', 0], ['Unknown1', 0x4], ['KeyLog Dir', 0x8], ['Active Setup', 0x8C], ['Run Key', 0xB4], ['Startup', 0xC8], ['Mutex', 0x14C], ['UUID', 0x158],
                 ['Password', 0x180], ['Unknown2', 0x1A4], ['Host', 0x2A4]]
}, {
    'version': '1.5d',
    'pattern': re.compile("\xE8(..)\x00\x00\x89\x1C(.)\xC7\x44\x24\x08", re.DOTALL),
    'cfg_offset': 20,
    'cfg_size': 0x3A8,
    'cfg_info': [['Unknown0', 0], ['Unknown1', 0x4], ['Unknown2', 0x8], ['KeyLog Dir', 0xC], ['Active Setup', 0x90], ['Run Key', 0xB8], ['Startup', 0xCC], ['Mutex', 0x150], ['UUID', 0x15C],
                 ['Password', 0x184], ['Unknown3', 0x1A8], ['Host', 0x2A8]]
}, {
    'version': '1.6a Final?',
    'pattern': re.compile("\xE8\x87(.)\x00\x00\x89\x1C(.)\xC7\x44\x24\x08\x03", re.DOTALL),
    'cfg_offset': 20,
    'cfg_size': 0x3A8,
    'cfg_info': [['Unknown0', 0], ['Unknown1', 0x4], ['Unknown2', 0x8], ['KeyLog Dir', 0xC], ['Active Setup', 0x90], ['Run Key', 0xB8], ['Startup', 0xCC], ['Mutex', 0x150], ['UUID', 0x15C],
                 ['Password', 0x184], ['Unknown3', 0x1A8], ['Host', 0x2A8]]
}, {
    'version': '1.6a',
    'pattern': re.compile("\xE8\x9F(.)\x00\x00\x89\x1C(.)\xC7\x44\x24\x08\x03", re.DOTALL),
    'cfg_offset': 20,
    'cfg_size': 0x3A8,
    'cfg_info': [['Unknown0', 0], ['Unknown1', 0x4], ['Unknown2', 0x8], ['KeyLog Dir', 0xC], ['Active Setup', 0x90], ['Run Key', 0xB8], ['Startup', 0xCC], ['Mutex', 0x150], ['UUID', 0x15C],
                 ['Password', 0x184], ['Unknown3', 0x1A8], ['Host', 0x2A8]]
}, {
    'version': '1.7a',
    'pattern': re.compile("\xE8(..)\x00\x00\xC7\x44(.)\x08\xFF\x00\x00\x00", re.DOTALL),
    'cfg_offset': 17,
    'cfg_size': 0x3D0,
    'cfg_info': [['C2', 0], ['Unknown0', 0x100], ['AES Key', 0x200], ['Host ID', 0x238], ['Mutex', 0x24C], ['Install Path', 0x260], ['Startup', 0x2E4], ['UUID', 0x300],
                 ['KeyLog Dir', 0x340], ['Unknown1', 0x3C4], ['Unknown2', 0x3C8], ['Unknown3', 0x3CC]]
}, {
    'version': 'Unknown',
    'pattern': re.compile("\xE8\x53(.)\x00\x00\xC7\x44(.)\x10\xFF\x00\x00\x00", re.DOTALL),
    'cfg_offset': 17,
    'cfg_size': 0x468,
    'cfg_info': [['C2', 0], ['Unknown0', 0x100], ['AES Key', 0x200], ['Host ID', 0x238], ['Group', 0x24C], ['Mutex', 0x260], ['Install Path', 0x280], ['Startup', 0x320], ['UUID', 0x360],
                 ['KeyLog Dir', 0x3A0], ['Unknown1', 0x424], ['Unknown2', 0x440], ['Unknown3', 0x464]]
}]

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

signatures = {
    'namespace1' : 'rule netwire { \
                    strings: \
                       $v1 = "HostId-%Rand%" \
                       $v2 = "mozsqlite3" \
                       $v3 = "[Scroll Lock]" \
                       $v4 = "GetRawInputData" \
                       $ping = "ping 192.0.2.2" \
                       $log = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]" \
                    condition: ($v1) or ($v2 and $v3 and $v4) or ($ping and $log)}'
}


class netwireConfig(taskmods.DllList):
    """Parse the NetWire configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        """ Get the VAD starting address """

        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        # This should never really happen
        return None

    def parse_config(self, cfg_blob, nw):
        p_data = OrderedDict()
        p_data["Version"] = nw["version"]

        for name, offset in nw["cfg_info"]:
            data = cfg_blob[offset:].split("\x00")[0]
            p_data[name] = data

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=signatures)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                if len(data) < 0x10000 or len(data) > 0x200000:
                    continue

                for nw in NETWIRE_INFO:
                    m = re.search(nw["pattern"], data)
                    if m:
                        offset = m.start()
                        break
                else:
                    continue

                cfg_addr = unpack("=I", data[offset + nw["cfg_offset"]:offset + nw["cfg_offset"] + 4])[0]
                if cfg_addr < vad_base_addr:
                    continue

                cfg_addr -= vad_base_addr
                cfg_blob = data[cfg_addr:cfg_addr + nw["cfg_size"]]
                config_data.append(self.parse_config(cfg_blob, nw))

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
