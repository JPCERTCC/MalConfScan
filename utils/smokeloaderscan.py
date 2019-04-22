# Detecting SmokeLoader for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv smokeloaderscan.py volatility/plugins/malware
# 3. python vol.py smokeloaderconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
from struct import unpack, unpack_from
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

smokeloader_sig = {
    'namespace1' : 'rule SmokeLoader { \
                    strings: \
                       $a1 = { B8 25 30 38 58 } \
                       $b1 = { 81 3D ?? ?? ?? ?? 25 00 41 00 } \
                       $c1 = { C7 ?? ?? ?? 25 73 25 73 } \
                    condition: $a1 and $b1 and $c1}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x68\x58\x02\x00\x00\xFF(.....)\x4E\x75\xF2\x8B", re.DOTALL)]

STRINGS_PATTERNS = [re.compile("\x57\xBB(....)\x8B(.)\x8B(.)", re.DOTALL)]


class smokeloaderConfig(taskmods.DllList):
    """Parse the SmokeLoader configuration"""

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

    def decode(self, data, keydata):
        url = []
        key = 0xff
        for i in range(0, 4):
            key = key ^ (keydata >> (i * 8) & 0xff)
        for y in data:
            url.append(chr(ord(y) ^ key))

        return "".join(url)

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=smokeloader_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                dll_data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                mz_magic = unpack_from("=2s", dll_data, 0x0)[0]
                nt_magic = unpack_from("<H", dll_data, 0x3c)[0]
                if mz_magic == "\x00\x00":
                    dll_data = "\x4d\x5a" + dll_data[2:]
                    dll_data = dll_data[:nt_magic] + "\x50\x45" + dll_data[nt_magic + 2:]

                p_data = OrderedDict()
                url_base = []
                for pattern in CONFIG_PATTERNS:
                    mc = re.search(pattern, dll_data)
                    if mc:
                        offset = mc.end() + 1
                        while dll_data[offset] != "\x8B":
                            offset += 1

                        config_rva = unpack("=I", dll_data[offset + 3:offset + 7])[0] - vad_base_addr

                        d = 0
                        while dll_data[config_rva + d:config_rva + d + 4] != "\x00\x00\x00\x00":
                            url_base.append(unpack("=I", dll_data[config_rva + d:config_rva + d + 4])[0])

                            d += 4

                        i = 1
                        for base in url_base:
                            base -= vad_base_addr
                            size = ord(dll_data[base])
                            key = unpack("=I", dll_data[base + size + 1:base + size + 5])[0]
                            enc_data = dll_data[base + 1:base + size + 1]
                            url = self.decode(enc_data, key)
                            p_data["Static URL " + str(i)] = url
                            i += 1

                for pattern in STRINGS_PATTERNS:
                    mc = re.search(pattern, dll_data)
                    if mc:
                        offset = mc.start() + 2
                        config_rva = unpack("=I", dll_data[offset:offset + 4])[0] - vad_base_addr
                        key = dll_data[config_rva - 4:config_rva]
                        enc = []
                        while dll_data[config_rva:config_rva + 2] != "\x00\x00":
                            enc.append(dll_data[config_rva])
                            config_rva += 1
                        enc_strings = "".join(enc)
                        x = 0
                        i = 1
                        while x < len(enc_strings):
                            size = ord(enc_strings[x])
                            strings = self.rc4(enc_strings[x + 1:x + size + 1], key)
                            x = x + size + 1
                            p_data["Encoded string " + str(i)] = strings
                            i += 1

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
                    outfd.write("{0:<18}: {1}\n".format(id, param))
