# Detecting RedLeaves for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv redleavesscan.py volatility/plugins/malware
# 3. python vol.py redleavesconfig -f images.mem --profile=Win7SP1x64

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

redleaves_sig = {
    'namespace1' : 'rule RedLeaves { \
                    strings: \
                       $v1 = "red_autumnal_leaves_dllmain.dll" \
                       $b1 = { FF FF 90 00 } \
                    condition: $v1 and $b1 at 0}',
    'namespace2' : 'rule Himawari { \
                    strings: \
                       $h1 = "himawariA" \
                       $h2 = "himawariB" \
                       $h3 = "HimawariDemo" \
                    condition: $h1 and $h2 and $h3}',
    'namespace3' : 'rule Lavender { \
                    strings: \
                       $l1 = {C7 ?? ?? 4C 41 56 45} \
                       $l2 = {C7 ?? ?? 4E 44 45 52} \
                    condition: $l1 and $l2}',
    'namespace4' : 'rule Armadill { \
                    strings: \
                       $a1 = {C7 ?? ?? 41 72 6D 61 } \
                       $a2 = {C7 ?? ?? 64 69 6C 6C } \
                    condition: $a1 and $a2}',
    'namespace5' : 'rule zark20rk { \
                    strings: \
                       $a1 = {C7 ?? ?? 7A 61 72 6B } \
                       $a2 = {C7 ?? ?? 32 30 72 6B } \
                    condition: $a1 and $a2}'
}

CONF_PATTERNS = {"RedLeaves": re.compile("\x68\x88\x13\x00\x00\xFF", re.DOTALL),
                 "Himawari": re.compile("\x68\x70\x03\x00\x00\xBF", re.DOTALL),
                 "Lavender": re.compile("\x68\x70\x03\x00\x00\xBF", re.DOTALL),
                 "Armadill": re.compile("\x68\x70\x03\x00\x00\xBF", re.DOTALL),
                 "zark20rk": re.compile("\x68\x70\x03\x00\x00\x8D", re.DOTALL),
                 }

CONNECT_MODE = {1: 'TCP', 2: 'HTTP', 3: 'HTTPS', 4: 'TCP and HTTP'}


class redleavesConfig(taskmods.DllList):
    """Detect processes infected with redleaves malware"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def parse_config(self, cfg_blob, cfg_sz, cfg_addr):

        p_data = OrderedDict()

        p_data["Server1"]           = unpack_from('<64s', cfg_blob, 0x0)[0]
        p_data["Server2"]           = unpack_from('<64s', cfg_blob, 0x40)[0]
        p_data["Server3"]           = unpack_from('<64s', cfg_blob, 0x80)[0]
        p_data["Port"]              = unpack_from('<I', cfg_blob, 0xC0)[0]
        mode = unpack_from('<I', cfg_blob, 0x1D0)[0]
        p_data["Mode"]              = CONNECT_MODE[mode]
        p_data["ID"]                = unpack_from('<64s', cfg_blob, 0x1E4)[0]
        p_data["Mutex"]             = unpack_from('<550s', cfg_blob, 0x500)[0].replace('\0', '')
        p_data["Injection Process"] = unpack_from('<104s', cfg_blob, 0x726)[0].replace('\0', '')
        p_data["RC4 Key"]           = unpack_from('<10s', cfg_blob, 0x82A)[0]

        return p_data

    def parse_config_himawari(self, cfg_blob, cfg_sz, cfg_addr):

        p_data = OrderedDict()

        p_data["Server1"]        = unpack_from('<64s', cfg_blob, 0x4)[0]
        p_data["Server2"]        = unpack_from('<64s', cfg_blob, 0x44)[0]
        p_data["Server3"]        = unpack_from('<64s', cfg_blob, 0x84)[0]
        p_data["Server4"]        = unpack_from('<64s', cfg_blob, 0xC4)[0]
        p_data["Port"]           = unpack_from('<I', cfg_blob, 0x104)[0]
        mode = unpack_from('<I', cfg_blob, 0x1D8)[0]
        p_data["Mode"]           = CONNECT_MODE[mode]
        p_data["ID"]             = unpack_from('<64s', cfg_blob, 0x1E0)[0]
        p_data["Mutex"]          = unpack_from('<62s', cfg_blob, 0x224)[0].replace('\0', '')
        p_data["Key"]            = unpack_from('<10s', cfg_blob, 0x366)[0]
        p_data["UserAgent"]      = unpack_from('<260s', cfg_blob, 0x262)[0]
        p_data["Proxy server"]   = unpack_from('<64s', cfg_blob, 0x10C)[0]
        p_data["Proxy username"] = unpack_from('<64s', cfg_blob, 0x14C)[0]
        p_data["Proxy password"] = unpack_from('<64s', cfg_blob, 0x18C)[0]

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=redleaves_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                c_pt = CONF_PATTERNS[str(hit)]
                if re.search(c_pt, data):
                    m_conf = re.search(c_pt, data)
                else:
                    continue

                offset_conf = m_conf.start()

                if "RedLeaves" in str(hit):
                    config_size = 2100

                    offset_conf -= 1
                    while data[offset_conf] != "\xC7" and data[offset_conf] != "\xBE" and data[offset_conf] != "\xBF":
                        offset_conf -= 1

                    if data[offset_conf] != "\xC7" and data[offset_conf] != "\xBE" and data[offset_conf] != "\xBF":
                        continue
                    if data[offset_conf] == "\xC7" and data[offset_conf + 1] != "\x85" and data[offset_conf + 1] != "\x45":
                        offset_conf -= 6

                    # get address
                    if data[offset_conf] == "\xC7" and data[offset_conf + 1] != "\x85":
                        (config_addr, ) = unpack("=I", data[offset_conf + 3:offset_conf + 7])
                    elif data[offset_conf] == "\xC7" and data[offset_conf + 1] == "\x85":
                        (config_addr, ) = unpack("=I", data[offset_conf + 6:offset_conf + 10])
                    else:
                        (config_addr, ) = unpack("=I", data[offset_conf + 1:offset_conf + 5])

                    if config_addr < vad_base_addr:
                        continue
                    config_addr -= vad_base_addr
                    config = data[config_addr:config_addr + config_size]
                    if len(config) > 0:
                        config_data.append(self.parse_config(config, config_size, config_addr))

                if str(hit) in ["Himawari", "Lavender", "Armadill", "zark20rk"]:
                    offset_conf += 6
                    if str(hit) in ["zark20rk"]:
                        offset_conf += 6
                    config_size = 880

                    # get address
                    (config_addr, ) = unpack("=I", data[offset_conf:offset_conf + 4])

                    if config_addr < vad_base_addr:
                        continue

                    config_addr -= vad_base_addr
                    config = data[config_addr:config_addr + config_size]
                    if len(config) > 0:
                        config_data.append(self.parse_config_himawari(config, config_size, config_addr))

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
