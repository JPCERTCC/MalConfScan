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
    'namespace1' : 'rule Agenttesla { \
                    strings: \
                       $iestr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb" \
                       $atstr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb" \
                       $sqlitestr = "Not a valid SQLite 3 Database File" wide \
                    condition: all of them}'
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

    def strings(self, data, n=18):
        for match in re.finditer(("(([0-9a-z-A-Z\+/]\x00){%s}([0-9a-z-A-Z\+/]\x00)*(=\x00){0,2})" % n).encode(), data):
            yield match.group(0)

    def stringdecrypt(self, a):
        string = b64decode(a)
        cleartext = AES.new(KEY[0:32], AES.MODE_CBC, IV).decrypt(string)
        return cleartext

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
                dlist = {}
                for word in self.strings(data):
                    try:
                        dec = self.stringdecrypt(word)
                        dec = re.sub("([\x00,\x01,\x02,\x03,\x04,\x05,\x06,\x07,\x08,\x09,\x0a,\x0b,\x0c,\x0d,\x0e,\x0f,\x10]{1})", "\x00", dec)
                        dlist[word.strip().replace('\0', '')] = dec.strip().replace("\n", "").replace("\r", "")
                    except:
                        pass

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
