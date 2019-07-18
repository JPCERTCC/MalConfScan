# Detecting TSCookie for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv tscookiescan.py volatility/plugins/malware
# 3. python vol.py tscookieconfig -f images.mem --profile=Win7SP1x64

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

tscookie_sig = {
    'namespace1' : 'rule TSCookie { \
                    strings: \
                       $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide\
                       $mz = { 4D 5A 90 00 } \
                       $b1 = { 68 D4 08 00 00 } \
                    condition: all of them}',
    'namespace2' : 'rule TSC_Loader { \
                    strings: \
                       $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide\
                       $mz = { 4D 5A 90 00 } \
                       $b1 = { 68 78 0B 00 00 } \
                    condition: all of them}'
}

# MZ Header
MZ_HEADER = b"\x4D\x5A\x90\x00"

# Config pattern
CONFIG_PATTERNS = [re.compile("\xC3\x90\x68\x00(...)\xE8(....)\x59\x6A\x01\x58\xC3", re.DOTALL),
                   re.compile("\x6A\x04\x68(....)\x8D(.....)\x56\x50\xE8", re.DOTALL),
                   re.compile("\x68(....)\xE8(....)\x59\x6A\x01\x58\xC3", re.DOTALL),
                   re.compile("\x68(....)\xE8(....)\x59", re.DOTALL)]

CONNECT_MODE   = {0: 'TCP', 1: 'HTTP with Credentials', 2: 'HTTP with Credentials', 3: 'HTTP with Credentials',
                  5: 'HTTP', 6: 'HTTPS', 7: 'HTTPS', 8: 'HTTPS'}
PROXY_MODE     = {0: 'Detect proxy settings', 1: 'Use config'}
INJECTION_MODE = {0 : 'Create process' , 1 : 'Injection running process'}
PROCESS_NAME   = {0 : 'svchost.exe', 1 : 'iexplorer.exe', 2 : 'explorer.exe', 3 : 'Default browser' , 4: 'Setting process'}

class tscookieConfig(taskmods.DllList):
    """Parse the TSCookie configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

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

    def parse_config(self, config):
        p_data = OrderedDict()
        for i in xrange(4):
            if config[0x10 + 0x100 * i] != "\x00":
                p_data["Server " + str(i)] = unpack_from("<240s", config, 0x10 + 0x100 * i)[0].replace("\0", "")
                p_data["Server " + str(i) + " (port 1)"] = unpack_from("<H", config, 0x4 + 0x100 * i)[0]
                p_data["Server " + str(i) + " (port 2)"] = unpack_from("<H", config, 0x8 + 0x100 * i)[0]
        if config[0x400] != "\x00":
            p_data["Proxy server"] = unpack_from("<128s", config, 0x400)[0].replace("\0", "")
            p_data["Proxy port"] = unpack_from("<H", config, 0x480)[0]
        p_data["ID"] = unpack_from("<256s", config, 0x500)[0]
        p_data["KEY"] = unpack_from(">I", config, 0x604)[0]
        if len(config) > 0x89C:
            p_data["Sleep time"] = unpack_from("<H", config, 0x89C)[0]

        return p_data

    def parse_loader_config(self, config):
        p_data = OrderedDict()
        p_data["Server name"] = unpack_from("<1024s", config, 0)[0]
        p_data["KEY"] = unpack_from(">I", config, 0x400)[0]
        p_data["Sleep count"] = unpack_from("<H", config, 0x404)[0]
        p_data["Mutex"] = unpack_from("<32s", config, 0x40c)[0]
        mode = unpack_from("<H", config, 0x44c)[0]
        p_data["Connect mode"] = CONNECT_MODE[mode]
        p_data["Connect keep"] = unpack_from("<H", config, 0x454)[0]
        icmp = unpack_from("<H", config, 0x458)[0]
        if icmp == 100:
            p_data["ICMP mode"] = "Enable"
            p_data["ICMP bind IP"] = unpack_from("<330s", config, 0x4D4)[0]
        else:
            p_data["ICMP mode"] = "Disable"
        injection = unpack_from("<H", config, 0x624)[0]
        p_data["Injection mode"] = INJECTION_MODE[injection]
        p_data["Injection process name"] = PROCESS_NAME[unpack_from("<H", config, 0x628)[0]]
        p_data["Injection custom name"] = unpack_from("<256s", config, 0x62c)[0].replace("\0", "")
        if config[0x72c] != "\x00":
            p_data["Proxy server"] = unpack_from("<64s", config, 0x72c)[0]
            p_data["Proxy port"] = unpack_from("<H", config, 0x76c)[0]
            p_data["Proxy username"] = unpack_from("<64s", config, 0x770)[0]
            p_data["Proxy password"] = unpack_from("<64s", config, 0x790)[0]
        proxy = unpack_from("<H", config, 0x7b0)[0]
        p_data["Proxy mode"] = PROXY_MODE[proxy]
        p_data["AuthScheme"] = unpack_from("<H", config, 0x7b4)[0]

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=tscookie_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                dll_index = data.find(MZ_HEADER)
                if dll_index:
                    dll_data = data[dll_index:]
                    dll = pefile.PE(data=dll_data)
                else:
                    continue

                if "TSCookie" in str(hit):
                    d = 2
                else:
                    d = 0

                for pattern in CONFIG_PATTERNS:
                    mc = re.search(pattern, dll_data)
                    if mc:
                        try:
                            (config_rva, ) = unpack("=I", dll_data[mc.start() + d + 1:mc.start() + d + 5])
                            config_addr = dll.get_physical_by_rva(config_rva - dll.NT_HEADERS.OPTIONAL_HEADER.ImageBase)
                            break
                        except:
                            print("[!] Not found config data.\n")

                config_size = 0
                enc = []
                while not (dll_data[config_addr + config_size] == "\x00" and dll_data[config_addr + config_size + 1] == "\x00" and dll_data[config_addr + config_size + 2] == "\x00"):
                    enc.append(dll_data[config_addr + config_size])
                    config_size += 1

                enc_config_data = "".join(enc)
                if config_size == 0x8D4:
                    rc4key_length = 4
                else:
                    rc4key_length = 0x80

                try:
                    enc_config = enc_config_data[rc4key_length:]
                    rc4key = enc_config_data[:rc4key_length]
                    config = self.rc4(enc_config, rc4key)
                    if len(config) > 0:
                        if "TSCookie" in str(hit):
                            config_data.append(self.parse_config(config))
                        else:
                            config_data.append(self.parse_loader_config(config))
                except:
                    print("[!] Not found config data.\n")

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
