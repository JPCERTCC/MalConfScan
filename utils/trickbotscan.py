# Detecting TrickBot for Volatilitv
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv trickbotconfigallocate.py volatility/plugins/malware
# 3. python vol.py trickbotconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from struct import unpack, unpack_from

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

trickbot_sig = {
    'namespace1' : 'rule Trickbot { \
                    strings: \
                       $tagm1 = "<mcconf><ver>" wide \
                       $tagm2 = "</autorun></mcconf>" wide \
                       $tagc1 = "<moduleconfig><autostart>" wide \
                       $tagc2 = "</autoconf></moduleconfig>" wide \
                       $tagi1 = "<igroup><dinj>" wide \
                       $tagi2 = "</dinj></igroup>" wide \
                       $tags1 = "<servconf><expir>" wide \
                       $tags2 = "</plugins></servconf>" wide \
                       $tagl1 = "<slist><sinj>" wide \
                       $tagl2 = "</sinj></slist>" wide \
                    condition: all of ($tagm*) or all of ($tagc*) or all of ($tagi*) or all of ($tags*) or all of ($tagl*)}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("\x3C\x00\x6D\x00\x63\x00\x63\x00\x6F\x00\x6E\x00\x66\x00\x3E\x00\x3C\x00\x76\x00\x65\x00\x72\x00\x3E\x00(.*)\x3C\x00\x2F\x00\x6D\x00\x63\x00\x63\x00\x6F\x00\x6E\x00\x66\x00\x3E\x00", re.DOTALL),
                   re.compile("\x3C\x00\x6D\x00\x6F\x00\x64\x00\x75\x00\x6C\x00\x65\x00\x63\x00\x6F\x00\x6E\x00\x66\x00\x69\x00\x67\x00\x3E\x00\x3C\x00\x61\x00\x75\x00\x74\x00\x6F\x00\x73\x00\x74\x00\x61\x00\x72\x00\x74\x00\x3E\x00(.*)\x3C\x00\x2F\x00\x61\x00\x75\x00\x74\x00\x6F\x00\x63\x00\x6F\x00\x6E\x00\x66\x00\x3E\x00\x3C\x00\x2F\x00\x6D\x20\x6F\x00\x64\x00\x75\x00\x6C\x00\x65\x00\x63\x00\x6F\x00\x6E\x00\x66\x00\x69\x00\x67\x00\x3E\x00", re.DOTALL),
                   re.compile("\x3C\x00\x69\x00\x67\x00\x72\x00\x6F\x00\x75\x00\x70\x00\x3E\x00\x3C\x00\x64\x00\x69\x00\x6E\x00\x6A\x00\x3E\x00(.*)\x3C\x00\x2F\x00\x64\x00\x69\x00\x6E\x00\x6A\x00\x3E\x00\x3C\x00\x2F\x00\x69\x00\x67\x00\x72\x00\x6F\x00\x75\x00\x70\x00\x3E\x00", re.DOTALL),
                   re.compile("\x3C\x00\x73\x00\x65\x00\x72\x00\x76\x00\x63\x00\x6F\x00\x6E\x00\x66\x00\x3E\x00\x3C\x00\x65\x00\x78\x00\x70\x00\x69\x00\x72\x00\x3E\x00(.*)\x3C\x00\x2F\x00\x70\x00\x6C\x00\x75\x00\x67\x00\x69\x00\x6E\x00\x73\x00\x3E\x00\x3C\x00\x2F\x00\x73\x00\x65\x00\x72\x00\x76\x00\x63\x00\x6F\x00\x6E\x00\x66\x00\x3E\x00", re.DOTALL),
                   re.compile("\x3C\x00\x73\x00\x6C\x00\x69\x00\x73\x00\x74\x00\x3E\x00\x3C\x00\x73\x00\x69\x00\x6E\x00\x6A\x00\x3E\x00(.*)\x3C\x00\x2F\x00\x73\x00\x69\x00\x6E\x00\x6A\x00\x3E\x00\x3C\x00\x2F\x00\x73\x00\x6C\x00\x69\x00\x73\x00\x74\x00\x3E\x00", re.DOTALL)]


class trickbotConfig(taskmods.DllList):
    "Parse the TrickBot configuration"

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End
        return None

    def calculate(self):

        if not has_yara:
            debug.error('Yara must be installed for this plugin.')

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error('This command does not support the selected profile.')

        rules = yara.compile(sources=trickbot_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                memdata = proc_addr_space.get_available_addresses()

                config_data = []

                for m in memdata:

                    if m[1] <= 0x1000:
                        continue

                    data = proc_addr_space.zread(m[0], m[1])

                    for pattern in CONFIG_PATTERNS:
                        m = re.search(pattern, data)

                        if m:
                            offset = m.start()
                        else:
                            continue

                        p_data = OrderedDict()
                        xml_data = data[offset:m.end()]
                        root = ET.fromstring(xml_data)
                        i = 0
                        for e in root.getiterator():
                            if e.text is None:
                                if len(e.attrib) != 0:
                                    p_data[i] = e.tag + ": " + str(e.attrib)
                            else:
                                p_data[i] = e.tag + ": " + str(e.text)
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
                    outfd.write("{0:<4}: {1}\n".format(id, param))
