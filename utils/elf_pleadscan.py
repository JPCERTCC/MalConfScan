# Detecting ELF_PLEAD for Volatilitv
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv elf_pleadconfig.py volatility/plugins/malware
# 3. python vol.py elf_pleadconfig -f images.mem --profile=Win7SP1x64

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

elf_plead_sig = {
    'namespace1' : 'rule elf_plead { \
                    strings: \
                       $ioctl = "ioctl TIOCSWINSZ error" \
                       $class1 = "CPortForwardManager" \
                       $class2 = "CRemoteShell" \
                       $class3 = "CFileManager" \
                       $lzo = { 81 ?? FF 07 00 00 81 ?? 1F 20 00 00 } \
                    condition: 3 of them}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\xBA(...)\x00\xB9\xAA\x01\x00\x00\xBE\x20\x00\x00\x00\xBF(...)\x00", re.DOTALL)]

CONFIG_SIZE = 0x1AA
KEY_SIZE    = 0x20

class elf_pleadConfig(linux_pslist.linux_pslist):
    "Parse the ELF_PLEAD configuration"

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

    def parse_config(self, data, start, memory_model):

        p_data = OrderedDict()

        for pattern in CONFIG_PATTERNS:
            if "64" in memory_model:
                data_base_address = unpack("=Q", data[0x90:0x98])[0] - unpack("=Q", data[0x80:0x88])[0]
            else:
                data_base_address = unpack("=I", data[0x60:0x64])[0] - unpack("=I", data[0x58:0x5C])[0]

            mc = re.search(pattern, data)
            if mc:
                config_offset = mc.start(1)
                config_address = unpack("=I", data[config_offset:config_offset + 4])[0] - data_base_address
                enc_config = data[config_address:config_address + CONFIG_SIZE]

                key_offset = mc.start(2)
                key_address = unpack("=I", data[key_offset:key_offset + 4])[0] - data_base_address
                key = data[key_address:key_address + KEY_SIZE]

                if enc_config[0] == "\x00":
                    print("[!] Config area is brank.")
                else:
                    config = self.rc4(enc_config, key)

                    p_data["ID"] = unpack_from("<8s", config, 0)[0].replace("\0", "")
                    p_data["Unknown1"] = u"0x{0:X}".format(unpack_from("=Q", config, 0x8)[0])
                    p_data["Unknown2"] = u"0x{0:X}".format(unpack_from("=Q", config, 0x10)[0])
                    p_data["Unknown3"] = u"0x{0:X}".format(unpack_from("=Q", config, 0x18)[0])
                    p_data["Port1"] = unpack_from("<H", config, 0x20)[0]
                    p_data["Port2"] = unpack_from("<H", config, 0x22)[0]
                    p_data["Server"] = unpack_from("<384s", config, 0x26)[0].replace("\0", "")
                    p_data["Key"] = u"0x{0:X}".format(unpack_from(">I", config, 0x1A6)[0])

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error('Yara must be installed for this plugin.')

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error('This command does not support the selected profile.')

        rules = yara.compile(sources=elf_plead_sig)

        for task in self.filter_tasks():
            scanner = linux_yarascan.VmaYaraScanner(task = task, rules = rules)
            for hit, address in scanner.scan():

                start, end = self.get_vma_base(task, address)
                data = scanner.address_space.zread(start, (end - start) * 2)
                #data = scanner.address_space.zread(address - self._config.REVERSE, self._config.SIZE)

                config_data = []
                config_data.append(self.parse_config(data, start, memory_model))

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
