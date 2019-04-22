# Detecting Ramnit for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv ramnitscan.py volatility/plugins/malware
# 3. python vol.py ramnitconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import pefile
from struct import unpack, unpack_from
from socket import inet_ntoa
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

ramnit_sig = {
    'namespace1' : 'rule Ramnit { \
                    strings: \
                       $guid = "{%08X-%04X-%04X-%04X-%08X%04X}" \
                       $md5_magic_1 = "15Bn99gT" \
                       $md5_magic_2 = "1E4hNy1O" \
                       $init_dga = { C7 ?? ?? ?? ?? ?? FF FF FF FF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 75 ?? } \
                       $xor_secret = { 8A ?? ?? 32 ?? 88 ?? 4? 4? E2 ?? } \
                       $init_function = { FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 } \
                       $dga_rand_int = { B9 1D F3 01 00 F7 F1 8B C8 B8 A7 41 00 00 } \
                       $cookies = "cookies4.dat" \
                       $s3 = "pdatesDisableNotify" \
                       $get_domains = { a3 [4] a1 [4] 80 3? 00 75 ?? c7 05 [4] ff ff ff ff ff 35 [4] ff 35 [4] ff 35 [4] e8 } \
                       $add_tld = { 55 8B EC  83 ?? ?? 57 C7 ?? ?? 00 00 00 00 B? ?? ?? ?? ?? 8B ?? ?? 3B ?? ?? 75 ?? 8B ?? } \
                       $get_port = { 90 68 [4] 68 [4] FF 35 [4] FF 35 [4] E8 [4] 83 } \
                    condition: $init_dga and $init_function and 2 of ($guid, $md5_magic_*, $cookies, $s3) and any of ( $get_port, $add_tld, $dga_rand_int, $get_domains, $xor_secret)}'
}

# MZ Header
MZ_HEADER = b"\x4D\x5A\x90\x00"

# XOR key pattern
XOR_KEY_PATTERNS = [re.compile("\x68\x3C\x01\x00\x00\x68\x20", re.DOTALL)]

# Flag
FLAG = {0x0: "Disable", 0x1: "Enable"}


class ramnitConfig(taskmods.DllList):
    """Parse the Ramnit configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def xor(self, encoded, xor_key):
        count = 0
        decode = []
        key_len = len(xor_key)
        for n in range(len(encoded)):
            if count == 0:
                count = key_len - 1
            decode.append(chr(ord(encoded[n]) ^ ord(xor_key[count])))
            count -= 1

        return "".join(decode)

    def parse_config(self, pe, data, base):
        p_data = OrderedDict()
        p_data["DGA Damain No"]   = unpack_from("I", data, base)[0]
        p_data["DGA Damain Seed"] = unpack_from(">I", data, base + 4)[0]
        p_data["Magick Check"]    = FLAG[unpack_from("I", data, base + 8)[0]]
        p_data["Magick"]          = unpack_from(">I", data, base + 0xc)[0]
        p_data["Use IP Address"]  = FLAG[unpack_from("I", data, base + 0x10)[0]]
        p_data["IP Address"]      = inet_ntoa(data[base + 0x14:base + 0x18])
        p_data["Port"]            = unpack_from("I", data, base + 0x18)[0]
        key_len = unpack_from("I", data, base + 0x1c)[0]
        p_data["XOR key length"]  = key_len

        for pattern in XOR_KEY_PATTERNS:
            mk = re.search(pattern, data)

        if mk:
            (resource_name_rva, ) = unpack("=I", data[mk.start() - 4:mk.start()])
            rn_addr = pe.get_physical_by_rva(resource_name_rva - pe.NT_HEADERS.OPTIONAL_HEADER.ImageBase)
            xor_key = data[rn_addr:rn_addr + key_len]
        else:
            xor_key = ""
            outfd.write("[!] Not found XOR key.\n")

        domain_encoded_data       = data[base + 0x20:base + 0x15c].replace("\0","")
        botnet_encoded_data       = data[base + 0x15c:base + 0x1ca].replace("\0","")
        encoded_data_1            = data[base + 0x1ca:base + 0x240].replace("\0","")
        encoded_data_2            = data[base + 0x240:base + 0x2b6].replace("\0","")
        rc4_encoded_data          = data[base + 0x2b6:base + 0x2f1].replace("\0","")

        p_data["Hardcode Domain"] = self.xor(domain_encoded_data, xor_key)
        p_data["Botnet name"]     = self.xor(botnet_encoded_data, xor_key)
        p_data["Unknown 1"]       = self.xor(encoded_data_1, xor_key)
        p_data["Unknown 2"]       = self.xor(encoded_data_2, xor_key)
        p_data["RC4 Key"]         = self.xor(rc4_encoded_data, xor_key)

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=ramnit_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                # resource PE search
                dll_index = data.rfind(MZ_HEADER)
                dll_data = data[dll_index:]

                try:
                    pe = pefile.PE(data=dll_data)
                except:
                    outfd.write("[!] Can't mapped PE.\n")
                    continue

                for section in pe.sections:
                    if ".data" in section.Name:
                        data_address = section.PointerToRawData

                config_data.append(self.parse_config(pe, dll_data, data_address))

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
