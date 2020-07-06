# Detecting Wellmess for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv wellmessscan.py volatility/plugins/malware
# 3. python vol.py wellmessconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import pefile
from struct import unpack, unpack_from
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

wellmess_sig = {
    'namespace1' : 'rule Wellmess { \
                    strings: \
                       $botlib1 = "botlib.wellMess" ascii\
                       $botlib2 = "botlib.Command" ascii\
                       $botlib3 = "botlib.Download" ascii\
                       $botlib4 = "botlib.AES_Encrypt" ascii\
                       $dotnet1 = "WellMess" ascii\
                       $dotnet2 = "<;head;><;title;>" ascii wide\
                       $dotnet3 = "<;title;><;service;>" ascii wide\
                       $dotnet4 = "AES_Encrypt" ascii\
                    condition: (uint16(0) == 0x5A4D) and (all of ($botlib*) or all of ($dotnet*))}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x00(.)\x00\x00\x00\x8B\x05...\x00\x85\xC0\x0F\x85..\x00\x00\x8D\x05(....)\x89\x05...\x00\xC7\x05", re.DOTALL),
                   re.compile("\x00(.)\x00\x00\x00\x8B\x05...\x00\x85\xC0\x0F\x85..\x00\x00\x48\x8D\x05(....)\x48\x89\x05...\x00\x48\xC7\x05", re.DOTALL)]

CONFIG_PATTERNS_DOTNET = [re.compile("\x00\x0B\x61\x00\x3A\x00\x31\x00\x5F\x00\x30\x00\x00\x0B\x61\x00\x3A\x00\x31\x00\x5F\x00\x31\x00\x00", re.DOTALL)]

class wellmessConfig(taskmods.DllList):
    """Parse the Wellmess configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def parse_config(self, config):
        p_data = OrderedDict()
        for i, d in enumerate(config):
            p_data["conf " + str(i)] = d

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=wellmess_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                pe = pefile.PE(data=data)

                config_data = []
                configs = []
                for pattern in CONFIG_PATTERNS:
                    mc = list(re.finditer(pattern, data))
                    if mc:
                        for m in mc:
                            hit_adderss = m.span()
                            config_rva = unpack("=I", m.groups()[1])[0]

                            if pe.FILE_HEADER.Machine == 0x14C: # for 32bit
                                config_offset = config_rva - pe.NT_HEADERS.OPTIONAL_HEADER.ImageBase
                                #config_offset = pe.get_physical_by_rva(config_rva - pe.NT_HEADERS.OPTIONAL_HEADER.ImageBase) + 0x1000
                            else: # for 64bit
                                config_offset = config_rva + hit_adderss[0] + 26
                                
                            configs.append(data[config_offset:config_offset + ord(m.groups()[0])])

                for pattern in CONFIG_PATTERNS_DOTNET:
                    mc = re.search(pattern, data)
                    if mc:
                        offset = mc.end()
                        for i in range(6):
                            strings = []
                            string_len = ord(data[offset])

                            if ord(data[offset]) == 0x80 or ord(data[offset]) == 0x83:
                                string_len = ord(data[offset + 1]) + ((ord(data[offset]) - 0x80) * 256)
                                offset += 1

                            offset += 1
                            for i in range(string_len):
                                if data[offset + i] != "\x00":
                                    strings.append(data[offset + i])
                            if string_len != 1:
                                configs.append("".join(strings))
                            offset = offset + string_len

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
                    outfd.write("{0:<25}: {1}\n".format(id, param))
