# Detecting AgentTesla Keylogger for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv agentteslascan.py volatility/plugins/malware
# 3. python vol.py agentteslaconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
from base64 import b64decode
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    from Crypto.Cipher import AES
    has_crypto = True
except ImportError:
    has_crypto = False

agenttesla_sig = {
    'namespace1' : 'rule Agenttesla_type1 { \
                    strings: \
                       $type1ie = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb" \
                       $type1at = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb" \
                       $type1sql = "Not a valid SQLite 3 Database File" wide \
                    condition:  all of them}',
    'namespace2' : 'rule Agenttesla_type2 { \
                    strings: \
                       $type2db1 = "1.85 (Hash, version 2, native byte-order)" wide \
                       $type2db2 = "Unknow database format" wide \
                       $type2db3 = "SQLite format 3" wide \
                       $type2db4 = "Berkelet DB" wide \
                    condition: (uint16(0) == 0x5A4D) and 3 of them}'
}

# IV
IV = "@1B2c3D4e5F6g7H8"

# AES Key
KEY = "\x34\x88\x6D\x5B\x09\x7A\x94\x19\x78\xD0\xE3\x8b\x1b\x5c\xa3\x29\x60\x74\x6a\x5e\x5d\x64\x87\x11\xb1\x2c\x67\xaa\x5b\x3a\x8e\xbf"


class agentteslaConfig(taskmods.DllList):
    """Parse the Agenttesla configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def base64strings(self, data, n=18):
        for match in re.finditer(("(([0-9a-z-A-Z\+/]\x00){%s}([0-9a-z-A-Z\+/]\x00)*(=\x00){0,2})" % n).encode(), data):
            yield match.group(0)

    def remove_unascii(self, b):
        cleaned = ""
        for i in b:
            if ord(i) >= 0x20 and ord(i) < 0x7f:
                cleaned += i
        return cleaned

    def stringdecrypt_type1(self, a):
        string = b64decode(a)
        cleartext = AES.new(KEY[0:32], AES.MODE_CBC, IV).decrypt(string)
        return cleartext

    def stringdecrypt_type2(self, data):
        encdata = data[0x2050:]

        dlist = OrderedDict()
        offset = 0
        num = 0
        i = 16
        while True:
            key = encdata[offset:offset + 32]
            iv = encdata[offset + 32:offset + 48]
            enc_data =encdata[offset + 48:offset + 48 + i]

            if b"\x00\x00" in key and b"\x00\x00" in iv:
                break

            try:
                cleartext = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_data)
                if len(cleartext) and (ord(cleartext[-1]) <= 0x10 or self.remove_unascii(cleartext) % 16 == 0) and not (ord(cleartext[-2]) == 0x0d and ord(cleartext[-1]) == 0x0a):
                    dlist["Encoded string " + str(num)] = self.remove_unascii(cleartext).rstrip()
                    offset = offset + 48 + i
                    num += 1
                    i = 0
                else:
                    i += 16
            except:
                i += 16

        return dlist

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        if not has_crypto:
            debug.error("pycrypto must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=agenttesla_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []
                dlist = OrderedDict()
                if "type1" in str(hit):
                    for word in self.base64strings(data):
                        try:
                            dec = self.stringdecrypt_type1(word)
                            dec = self.remove_unascii(dec).rstrip()
                            dlist[word.strip().replace('\0', '')] = dec
                        except:
                            pass

                if "type2" in str(hit):
                    dlist = self.stringdecrypt_type2(data)

                config_data.append(dlist)

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
