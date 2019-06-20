# Detecting Remcos for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv remcosscan.py volatility/plugins/malware
# 3. python vol.py remcosconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import pefile
from struct import unpack, unpack_from
from socket import inet_ntoa
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

remcos_sig = {
    'namespace1' : 'rule Remcos { \
                    strings: \
                       $remcos = "Remcos" ascii fullword \
                       $url = "Breaking-Security.Net" ascii fullword \
                       $resource = "SETTINGS" wide fullword \
                    condition:  all of them}'
}

# MZ Header
MZ_HEADER = b"\x4D\x5A\x90\x00"

# Resource pattern
RESOURCE_PATTERNS = [re.compile("\xE0\x00\x00\x07\xE0\x00\x00\x07\xFF\xFF\xFF\xFF", re.DOTALL)]

# Flag
FLAG = {"\x00": "Disable", "\x01": "Enable"}

idx_list = {
    0: "Host:Port:Password",
    1: "Assigned name",
    2: "Connect interval",
    3: "Install flag",
    4: "Setup HKCU\\Run",
    5: "Setup HKLM\\Run",
    6: "Setup HKLM\\Explorer\\Run",
    7: "Setup HKLM\\Winlogon\\Shell",
    8: "Setup HKLM\\Winlogon\\Userinit",
    9: "Install path",
    10: "Copy file",
    11: "Startup value",
    12: "Hide file",
    13: "Unknown13",
    14: "Mutex",
    15: "Keylog flag",
    16: "Keylog path",
    17: "Keylog file",
    18: "Keylog crypt",
    19: "Hide keylog file",
    20: "Screenshot flag",
    21: "Screenshot time",
    22: "Take Screenshot option",
    23: "Take screenshot title",
    24: "Take screenshot time",
    25: "Screenshot path",
    26: "Screenshot file",
    27: "Screenshot crypt",
    28: "Mouse option",
    29: "Unknown29",
    30: "Delete file",
    31: "Unknown31",
    32: "Unknown32",
    33: "Unknown33",
    34: "Unknown34",
    35: "Unknown35",
    36: "Audio record time",
    37: "Audio path",
    38: "Audio folder",
    39: "Unknown39",
    40: "Unknown40",
    41: "Connect delay",
    42: "Unknown42",
    43: "Unknown43",
    44: "Unknown44",
    45: "Unknown45",
    46: "Unknown46",
    47: "Unknown47",
    48: "Copy folder",
    49: "Keylog folder",
    50: "Unknown50",
    51: "Unknown51",
    52: "Unknown52",
    53: "Unknown53",
    54: "Keylog file max size"
}

setup_list = {
    0: "Temp",
    2: "Root",
    3: "Windows",
    4: "System32",
    5: "Program Files",
    6: "AppData",
    7: "User Profile",
    8: "Application path",
}

class remcosConfig(taskmods.DllList):
    """Parse the Remcos configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    # RC4
    def rc4(self, data, key):
        x = 0
        box = range(256)
        for i in range(256):
            x = (x + box[i] + ord(key[i % len(key)])) % 256
            box[i], box[x] = box[x], box[i]
        x = 0
        y = 0
        out = []
        for char in data:
            x = (x + 1) % 256
            y = (y + box[x]) % 256
            box[x], box[y] = box[y], box[x]
            out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

        return ''.join(out)

    def parse_config(self, data):
        p_data = OrderedDict()

        key_len = ord(data[0])
        key = data[1:key_len + 1]
        enc_data = data[key_len + 1:]
        config = self.rc4(enc_data, key)

        #configs = config.split("@@")
        configs = re.split("\x1E|@@", config)

        for i, cont in enumerate(configs):
            if cont == "\x00" or cont == "\x01":
                p_data[idx_list[i]] = FLAG[cont]
            else:
                if i in [9, 16, 25, 37]:
                    p_data[idx_list[i]] = setup_list[int(cont)]
                else:
                    p_data[idx_list[i]] = cont

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=remcos_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                # resource PE search
                dll_index = data.rfind(MZ_HEADER)
                dll_data = data[dll_index:]

                try:
                    pe = pefile.PE(data=dll_data)
                except:
                    outfd.write("[!] Can't mapped PE.\n")
                    continue

                rc_data = ""
                for idx in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for entry in idx.directory.entries:
                        if str(entry.name) in "SETTINGS":
                            try:
                                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                                size = entry.directory.entries[0].data.struct.Size
                                rc_data = dll_data[data_rva:data_rva + size]
                                print("[*] Found SETTINGS resource.")
                            except:
                                debug.error("Faild to load SETTINGS resource.")

                if not len(rc_data):
                    for pattern in RESOURCE_PATTERNS:
                        mc = re.search(pattern, dll_data)
                        if mc:
                            try:
                                config_end = mc.end() + 1
                                while dll_data[config_end:config_end + 2] != "\x00\x00":
                                    config_end += 1
                                rc_data = dll_data[mc.end():config_end - 1]
                            except:
                                debug.error("Remcos resource not found.")

                config_data.append(self.parse_config(rc_data))

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
