# Detecting ELF_Wellmess for Volatilitv
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv elf_wellmessconfig.py volatility/plugins/malware
# 3. python vol.py elf_wellmessconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.linux_yarascan as linux_yarascan
import re
import io
from struct import unpack, unpack_from
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

elf_wellmess_sig = {
    'namespace1' : 'rule elf_wellmess { \
                    strings: \
                       $botlib1 = "botlib.wellMess" ascii\
                       $botlib2 = "botlib.Command" ascii\
                       $botlib3 = "botlib.Download" ascii\
                       $botlib4 = "botlib.AES_Encrypt" ascii\
                    condition: (uint32(0) == 0x464C457F) and all of ($botlib*)}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x00(.)\x00\x00\x00\x8B\x05...\x00\x85\xC0\x0F\x85..\x00\x00\x8D\x05(....)\x89\x05...\x00\xC7\x05", re.DOTALL),
                   re.compile("\x00(.)\x00\x00\x00\x8B\x05...\x00\x85\xC0\x0F\x85..\x00\x00\x48\x8D\x05(....)\x48\x89\x05...\x00\x48\xC7\x05", re.DOTALL)]

class elf_wellmessConfig(linux_pslist.linux_pslist):
    "Parse the ELF_Wellmess configuration"

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown'), profile.metadata.get('memory_model', '32bit')

    def get_vma_base(self, task, address):
        for vma in task.get_proc_maps():
            if address >= vma.vm_start and address < vma.vm_end:
                return vma.vm_start, vma.vm_end

        return None

    def filter_tasks(self):
        tasks = linux_pslist.linux_pslist(self._config).calculate()

        if self._config.PID is not None:
            try:
                pidlist = [int(p) for p in self._config.PID.split(',')]
            except ValueError:
                debug.error("Invalid PID {0}".format(self._config.PID))

            pids = [t for t in tasks if t.pid in pidlist]
            if len(pids) == 0:
                debug.error("Cannot find PID {0}. If its terminated or unlinked, use psscan and then supply --offset=OFFSET".format(self._config.PID))
            return pids

        return tasks

    def parse_config(self, config):
        p_data = OrderedDict()
        for i, d in enumerate(config):
            p_data["conf " + str(i)] = d

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error('Yara must be installed for this plugin.')

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error('This command does not support the selected profile.')

        rules = yara.compile(sources=elf_wellmess_sig)

        for task in self.filter_tasks():
            scanner = linux_yarascan.VmaYaraScanner(task = task, rules = rules)
            for hit, address in scanner.scan():

                start, end = self.get_vma_base(task, address)
                data = scanner.address_space.zread(start, (end - start) * 2)
                #data = scanner.address_space.zread(address - self._config.REVERSE, self._config.SIZE)

                config_data = []
                configs = []
                for pattern in CONFIG_PATTERNS:
                    mc = list(re.finditer(pattern, data))
                    if mc:
                        for m in mc:
                            hit_adderss = m.span()
                            config_rva = unpack("=I", m.groups()[1])[0]

                            if ord(data[0x4]) == 0x2: # for 64bit
                                config_offset = config_rva + hit_adderss[0] + 26
                            else: # for 32bit
                                config_offset = config_rva - 0x40000
                                
                            configs.append(data[config_offset:config_offset + ord(m.groups()[0])])

                yield task, start, end, hit, memory_model, config_data
                break

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, end, malname, memory_model, config_data in data:
            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.comm, task.pid))

            outfd.write("[Config Info]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0:<20}: {1}\n".format(id, param))
