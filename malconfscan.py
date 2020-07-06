# MalConfScan: Detecting Malware Configuration for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.procdump as procdump
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.linux_yarascan as linux_yarascan
import re
import os
import pefile
from struct import unpack_from
from collections import OrderedDict
from importlib import import_module

PATTERNS = ["PUSH", "MOV", "CMP", "LEA"]

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False


class malconfScan(taskmods.DllList):
    """Detect infected processes and parse malware configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        osversion, memory_model = self.is_valid_profile(addr_space.profile)
        base = os.path.dirname(os.path.abspath(__file__))
        rules = yara.compile(base + "/yara/rule.yara")
        if osversion == "windows":

            for task in self.filter_tasks(tasks.pslist(addr_space)):
                scanner = malfind.VadYaraScanner(task=task, rules=rules)

                for hit, address in scanner.scan():

                    vad_base_addr, end = self.get_vad_base(task, address)

                    malname = str(hit).lower()
                    if str(hit) in ["Himawari", "Lavender", "Armadill", "zark20rk"]:
                        malname = "redleaves"
                    if str(hit) in "TSC_Loader":
                        malname = "tscookie"
                    if "Agenttesla" in str(hit):
                        malname = "agenttesla"

                    try:
                        module = import_module("volatility.plugins.malware.utils.{name}scan".format(name=malname))
                        module_cls = getattr(module, malname + "Config")
                        instance = module_cls(self._config)
                    except:
                        debug.error("Can't loading module volatility.plugins.malware.utils.{name}scan".format(name=malname))

                    for task, vad_base_addr, end, hit, memory_model, config_data in instance.calculate():
                        yield task, vad_base_addr, end, hit, memory_model, config_data
                    break
        elif osversion == "linux":
            debug.error("Please use linux_malconfscan.")
        else:
            debug.error("This command does not support the selected profile.")

    def render_text(self, outfd, data):

        delim = '-' * 70

        outfd.write("[+] Searching memory by Yara rules.\n")

        for task, start, end, malname, memory_model, config_data in data:
            outfd.write("[+] Detect malware by Yara rules.\n")
            outfd.write("[+]   Process Name      : {0}\n".format(task.ImageFileName))
            outfd.write("[+]   Process ID        : {0}\n".format(task.UniqueProcessId))
            outfd.write("[+]   Malware name      : {0}\n".format(malname))
            outfd.write("[+]   Base Address(VAD) : 0x{0:X}\n".format(start))
            outfd.write("[+]   Size              : 0x{0:X}\n".format(end - start + 1))

            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.ImageFileName, task.UniqueProcessId))

            outfd.write("[Config Info]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0:<22}: {1}\n".format(id, param))

class linux_malconfScan(linux_pslist.linux_pslist):
    """Detect infected processes and parse malware configuration for Linux"""

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

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        osversion, memory_model = self.is_valid_profile(addr_space.profile)
        base = os.path.dirname(os.path.abspath(__file__))
        rules = yara.compile(base + "/yara/rule.yara")

        if osversion == "linux":
            tasks = self.filter_tasks()
            for task in tasks:
                scanner = linux_yarascan.VmaYaraScanner(task = task, rules = rules)
                for hit, address in scanner.scan():

                    start, end = self.get_vma_base(task, address)

                    malname = str(hit).lower()

                    try:
                        module = import_module("volatility.plugins.malware.utils.{name}scan".format(name=malname))
                        module_cls = getattr(module, malname + "Config")
                        instance = module_cls(self._config)
                    except:
                        debug.error("Can't loading module volatility.plugins.malware.utils.{name}scan".format(name=malname))

                    for task, start, end, hit, memory_model, config_data in instance.calculate():
                        yield task, start, end, hit, memory_model, config_data
                    break
        elif osversion == "windows":
            debug.error("Please use malconfscan.")
        else:
            debug.error("This command does not support the selected profile.")

    def render_text(self, outfd, data):

        delim = '-' * 70

        outfd.write("[+] Searching memory by Yara rules.\n")

        for task, start, end, malname, memory_model, config_data in data:
            outfd.write("[+] Detect malware by Yara rules.\n")
            outfd.write("[+]   Process Name      : {0}\n".format(task.comm))
            outfd.write("[+]   Process ID        : {0}\n".format(task.pid))
            outfd.write("[+]   Malware name      : {0}\n".format(malname))
            outfd.write("[+]   Address           : 0x{0:X}\n".format(start))
            outfd.write("[+]   Size              : 0x{0:X}\n".format(end - start))

            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.comm, task.pid))

            outfd.write("[Config Info]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0:<22}: {1}\n".format(id, param))

class malstrScan(procdump.ProcDump, malfind.Malfind, vadinfo.VADDump):
    """Search strings with malicious space"""

    def __init__(self, config, *args, **kwargs):
        procdump.ProcDump.__init__(self, config, *args, **kwargs)
        config.add_option("FULLSCAN", short_option="a", default=False, action="store_true",
                          help="Search with parent memory spaces.")

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def Disassemble(self, data, start, pe, bits='32bit', stoponret=False):
        if not has_distorm3:
            raise StopIteration

        if bits == "32bit":
            mode = distorm3.Decode32Bits
        else:
            mode = distorm3.Decode64Bits

        for address, _, code, hex_data in distorm3.DecodeGenerator(start, data, mode):
            if stoponret and i.startswith("RET"):
                raise StopIteration
            yield address, code, len(hex_data)/2

    def detect_injection_proc(self, proc, space):
        detects = []
        for vad, address_space in proc.get_vads(vad_filter=proc._injection_filter):
            data = address_space.zread(vad.Start, vad.End + 1)
            vad_protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v())
            if self._is_vad_empty(vad, address_space):
                continue
            if obj.Object("_IMAGE_DOS_HEADER", offset=vad.Start, vm=address_space).e_magic != 0x5A4D:
                nt_magic = unpack_from("<H", data, 0x3c)[0]
                if nt_magic > 1 and nt_magic <= 0x100 and self._config.FULLSCAN:
                    data = "\x4d\x5a" + data[2:]
                    data = data[:nt_magic] + "\x50\x45" + data[nt_magic + 2:]
                else:
                    continue
            detects.append([vad.Start, vad.End, data, vad_protection])

        return detects

    def get_strings(self, data, n=5):
        # ascii
        for match in re.finditer(('([\x20-\x7e]{%s}[\x20-\x7e]*)' % n).encode(), data):
            yield match.start(), match.group(0)

        # unicode
        for match in re.finditer(('(([\x20-\x7e]\x00){%s}([\x20-\x7e]\x00)*)' % n).encode(), data):
            yield match.start(), match.group(0)

    def ascii_check(self, code):
        if (code >= "\x20" and code <= "\x7e") or code == "\x00" or code == "\x0a" or code == "\x0d":
            return False
        else:
            return True

    def search_strings(self, offset, data):
        string_data = []
        while 1:
            if self.ascii_check(data[offset]) or self.ascii_check(data[offset + 1]):
                string_data = []
                break

            string_data.append(data[offset])
            if data[offset + 1] != "\x00" or data[offset + 2] != "\x00":
                if data[offset - 1] != "\x00" or data[offset + 1] != "\x00":
                    string_data.append(data[offset + 1])
                    if data[offset + 2] == "\x00":
                        break
                if data[offset - 1] != "\x00" and data[offset + 1] == "\x00":
                    break
                offset += 2
            else:
                break

        return string_data

    def calculate(self):

        if not has_distorm3:
            debug.error("Distorm3 must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        osversion, memory_model = self.is_valid_profile(addr_space.profile)
        data = self.filter_tasks(tasks.pslist(addr_space))

        for proc in data:
            space = proc.get_process_address_space()
            if space == None:
                continue

            for start, end, memdata, protection in self.detect_injection_proc(proc, space):
                strings = {}

                pe = pefile.PE(data=memdata)
                if pe.FILE_HEADER.Machine in (pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64'], pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']):
                    mode = "64bit"
                else:
                    mode = "32bit"

                for curent_address, i, code_len in self.Disassemble(memdata, start, pe, bits=mode):
                    code = i.split(" ")
                    if code[0] in PATTERNS:
                        for ope in code:
                            if "0x" in ope:
                                string_addr = int(re.sub("[\],]", "", ope.split("0x")[1]), 16)
                                if mode == "32bit":
                                    string_rva = string_addr - start
                                else:
                                    string_rva = string_addr + curent_address + code_len - start
                                if string_rva > 0x1000 and string_rva < (end - start):
                                    if mode == "32bit":
                                        offset = unpack_from("<H", memdata, string_rva)[0]
                                    else:
                                        offset = unpack_from("<Q", memdata, string_rva)[0]

                                    if offset > start and offset < end:
                                        string_data = self.search_strings(offset - start, memdata)
                                        string = str("".join(string_data)).replace("\n", " ").replace("\r", " ")
                                        if len(string) > 1 and string != "\x00\x00":
                                            strings[offset] = string
                                            # print("0x{0:0>8X} -> 0x{1:0>8X}: {2}".format(string_addr, offset, string))
                                    else:
                                        string_data = self.search_strings(string_rva, memdata)
                                        string = str("".join(string_data)).replace("\n", " ").replace("\r", " ")
                                        if len(string) > 1 and string != "\x00\x00":
                                            strings[string_rva + start] = string
                                            # print("0x{0:0>8X}: {1}".format(string_addr, string))

                levels = {}
                if self._config.FULLSCAN:
                    for vad in proc.VadRoot.traverse():
                        if vad:
                            if vad.Start == start:
                                level = levels.get(vad.Parent.obj_offset, -1) + 1
                                levels[vad.obj_offset] = level
                            elif vad.Parent.obj_offset in levels:
                                level = levels.get(vad.Parent.obj_offset, -1) + 1
                                levels[vad.obj_offset] = level
                                if vad.Start > 0x70000000 and mode == "32bit":
                                    break
                                data = space.zread(vad.Start, vad.End - vad.Start)
                                for addr, word in self.get_strings(data):
                                    strings[vad.Start + addr] = word

                yield proc, start, end, memdata, protection, strings

    def render_text(self, outfd, data):

        delim = '-' * 70

        if self._config.FULLSCAN:
            outfd.write("[+] Searching for malicious memory space and parent memory spaces.\n")
        else:
            outfd.write("[+] Searching for malicious memory space.\n")

        for task, start, end, data, protection, strings in data:
            outfd.write("[+] Detect Process Hollowing space.\n")
            outfd.write("[+]   Process Name      : {0}\n".format(task.ImageFileName))
            outfd.write("[+]   Process ID        : {0}\n".format(task.UniqueProcessId))
            outfd.write("[+]   Base Address(VAD) : 0x{0:X}\n".format(start))
            outfd.write("[+]   Size              : 0x{0:X}\n".format(end - start + 1))
            outfd.write("[+]   Vad Protection    : {0}\n".format(protection))

            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.ImageFileName, task.UniqueProcessId))

            sort_strings = OrderedDict(sorted(strings.items()))
            for address, str_data in sort_strings.items():
                outfd.write("0x{0:0>8X}: {1}\n".format(address, str_data))

            outfd.write("\n")
