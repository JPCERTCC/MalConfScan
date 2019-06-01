# Detecting Emotet for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv emotetscan.py volatility/plugins/malware
# 3. python vol.py emotetconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
from struct import unpack, pack
from collections import OrderedDict
from socket import inet_ntoa

try:
    from Crypto.Util import asn1
    from Crypto.PublicKey import RSA
    has_crypto = True
except ImportError:
    has_crypto = False

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

emotet_sig = {
    'namespace1' : 'rule Emotet { \
                    strings: \
                       $v4a = { BB 00 C3 4C 84 } \
                       $v4b = { B8 00 C3 CC 84 } \
                       $v5a = { 69 01 6D 4E C6 41 05 39 30 00 00} \
                       $v5b = { 6D 4E C6 41 33 D2 81 C1 39 30 00 00 } \
                    condition: ($v4a and $v4b) or $v5a or $v5b}'
}

# MZ Header
MZ_HEADER = b"\x4D\x5A\x90\x00"

# Config pattern
CONFIG_PATTERNS = [re.compile("(........)(\x9A\x1F|\x90\x1F|\xBB\x01|\x50\x00|\xA8\x1B|\x2F\x10|\x50\xC3|\xDE\x03|\x2F\x10|\xE3\x03|\x14\x00|\x16\x00)(......)(\x9A\x1F|\x90\x1F|\xBB\x01|\x50\x00|\xA8\x1B|\x2F\x10|\x50\xC3|\xDE\x03|\x2F\x10|\xE3\x03|\x14\x00|\x16\x00)", re.DOTALL),
                   re.compile("\x00\x00\x00\x00(....)(\x9A\x1F|\x90\x1F|\xBB\x01|\x50\x00|\xA8\x1B|\x2F\x10|\x50\xC3|\xDE\x03|\x2F\x10|\xE3\x03|\x14\x00|\x16\x00)(......)(\x9A\x1F|\x90\x1F|\xBB\x01|\x50\x00|\xA8\x1B|\x2F\x10|\x50\xC3|\xDE\x03|\x2F\x10|\xE3\x03|\x14\x00|\x16\x00)", re.DOTALL)]


class emotetConfig(taskmods.DllList):
    """Parse the Emotet configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def extract_rsakey(self, data):
        pubkey = ""
        pemkey_match = re.findall('''\x30[\x00-\xFF]{100}\x02\x03\x01\x00\x01\x00\x00''',data)

        if pemkey_match:
            pemkey = pemkey_match[0][0:106]
            seq = asn1.DerSequence()
            seq.decode(pemkey)
            pemkey = RSA.construct((seq[0],seq[1]))
            pubkey = pemkey.exportKey()

        return pubkey

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=emotet_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                p_data = OrderedDict()
                for pattern in CONFIG_PATTERNS:
                    mc = re.search(pattern, data)
                    if mc:
                        try:
                            d = 4
                            i = 0
                            while 1:
                                ip = data[mc.start() + d + 3] + data[mc.start() + d + 2] + data[mc.start() + d + 1] + data[mc.start() + d]
                                port = unpack("=H", data[mc.start() + d + 4:mc.start() + d + 6])[0]
                                d += 8
                                if ip == "\x00\x00\x00\x00" and port == 0:
                                    break
                                else:
                                    p_data["IP " + str(i)] = str(inet_ntoa(ip)) + ":" + str(port)
                                    i += 1
                        except:
                            outfd.write("[!] Not found config data.\n")

                config_data.append({"RSA Public Key" : self.extract_rsakey(data)})
                config_data.append(p_data)

                yield task, vad_base_addr, end, hit, memory_model, config_data
                break

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, end, malname, memory_model, config_data in data:
            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.ImageFileName, task.UniqueProcessId))

            outfd.write("[Static IP Address list]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0}:{1}\n".format(id, param))
