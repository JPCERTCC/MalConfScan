# Detecting Datper for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv datperscan.py volatility/plugins/malware
# 3. python vol.py datperconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
import sys
import pefile
from struct import unpack, unpack_from
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

datper_sig = {
    'namespace1' : 'rule Datper { \
                    strings: \
                       $a1 = { E8 03 00 00 } \
                       $b1 = "|||" \
                       $c1 = "Content-Type: application/x-www-form-urlencoded" \
                       $push7530h64 = { C7 C1 30 75 00 00 } \
                       $push7530h = { 68 30 75 00 00 } \
                    condition: $a1 and $b1 and $c1 and ($push7530h64 or $push7530h)}'
}

CONFIG_PATTERNS = [
    re.compile("\xB8(....)(\xBA\xE8\x03\x00\x00)", re.DOTALL),             # mov eax, qword ptr config_offset;mov edx 0x3e8
    re.compile("\xB8(....)(\x75\x00\xBA\xE8\x03\x00\x00)", re.DOTALL),     # mov eax, qword ptr config_offset;jnz short $+2;mov edx 0x3e8
    re.compile("\x48\x8D\x0D(....)(\xC7\xC2\xE8\x03\x00\x00)", re.DOTALL)  # lea rax, qword ptr config_offset;mov edx 0x3e8
]

RC4KEY = ["d4n[6h}8o<09,d(21i`t4n$]hx%.h,hd",
          "B3uT16@qs\l,!GdSevH=Y(;7Ady$jl\e",
          "V7oT1@@qr\\t,!GOSKvb=p(;3Akb$rl\\a"
          ]

idx_list = {
    0: "ID",
    1: "URL",
    2: "Sleep time(s)",
    3: "Mutex",
    4: "Proxy server",
    5: "Proxy port",
    6: "Unknown",
    7: "Unknown",
    8: "Startup time(h)",
    9: "End time(h)",
    10: "Unknown",
    11: "User-Agent",
    12: "RSA key(e + modules)"
}

CONFSIZE = 0x3F8
config_delimiter = ["|||", "[|-]"]


class datperConfig(taskmods.DllList):
    """Parse the Datper configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    # Custom RC4 use sbox seed
    def custom_rc4(self, data, key, box_seed):
        x = 0
        box = range(256)
        if box_seed != 0:
            for i in range(256):
                box[i] = (i + box_seed) & 0xFF

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

    def get_config_data_64(self, data, pe):
        for pattern in CONFIG_PATTERNS:
            m = re.search(pattern, data)
            if m:
                #print("found pattern")
                rva_offset_config = pe.get_rva_from_offset(m.start(2)) + unpack("<L", data[m.start(1):m.start(1) + 4])[0]
                config = pe.get_memory_mapped_image()[rva_offset_config:rva_offset_config + CONFSIZE]
                return config
        return None

    def get_config_data_32(self, data, pe, start):
        for pattern in CONFIG_PATTERNS:
            m = re.search(pattern, data)
            if m:
                #print("found pattern")
                rva_offset_config = unpack("<L", data[m.start(1):m.start(1) + 4])[0]
                rva_config = rva_offset_config - start
                config = data[rva_config:rva_config + CONFSIZE]
                return config
        return None

    def decompress(self, data):
        if ord(data[0]) == 0x80:
            return data[1:]
        length = unpack("<H", data[:2])[0]
        if length > len(data[2:]):
            print("[!] invalid length")
            return ""
        data = data[2:2 + length]
        tmp = ""
        for i, c in enumerate(data):
            val = (((i >> 5) + (i << 7) + length + ~i) & 0xFF)
            tmp += chr(ord(c) ^ (((i >> 5) + (i << 7) + length + ~i) & 0xFF))

        tmp = map(ord, list(tmp))[1:]
        i = 0
        block_len = 16
        dec = ""
        try:
            while i < len(tmp):
                if block_len == 16:
                    block_flag = (tmp[i] << 8) + tmp[i + 1]
                    block_len = 0
                    i += 2

                if block_flag & (0x8000 >> block_len) != 0:
                    char_flag = (tmp[i + 1] >> 4) + (16 * tmp[i])
                    if char_flag != 0:
                        loop_count = (tmp[i + 1] & 0xF) + 3
                        for n in range(loop_count):
                            dec += dec[-char_flag]
                        i += 2
                    else:
                        loop_count = (tmp[i + 1] << 8) + tmp[i + 2] + 16
                        for n in range(loop_count):
                            #data += chr(tmp[i + 3])
                            pass
                        i += 4
                else:
                    dec += chr(tmp[i])
                    i += 1

                block_len += 1
        except:
            raise
            return ""
        return dec

    def decrypt(self, dec):
        decrypted_len = len(dec)
        decomp = []
        processed_len = 0
        while (decrypted_len > processed_len):
            enc_compressed_len = unpack("<H", dec[processed_len:processed_len + 2])[0]
            enc_compressed = dec[processed_len + 2:processed_len + 2 + enc_compressed_len]
            if enc_compressed_len > len(enc_compressed):
                break
            processed_len += enc_compressed_len + 2
            tmp = []
            for i in range(enc_compressed_len):
                xor_key = (i >> 5) & 0xff
                xor_key += (i << 7) & 0xff
                xor_key += enc_compressed_len
                xor_key += ~i
                xor_key = xor_key & 0xff
                tmp.append(chr(ord(enc_compressed[i]) ^ xor_key))
            compressed = "".join(tmp)
            decompressed = self.decompress(compressed)
            decomp.append(decompressed)
        return "".join(decomp)

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=datper_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                try:
                    pe = pefile.PE(data=data)
                except:
                    sys.exit("[!] could not parse as a PE file")

                config_size = CONFSIZE

                if pe.FILE_HEADER.Machine in (pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64'], pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']):
                    enc = self.get_config_data_64(data, pe)
                else:
                    enc = self.get_config_data_32(data, pe, vad_base_addr)

                dec = ""
                for key in RC4KEY:
                    for rc4key_seed in range(0xFF):
                        dec = self.custom_rc4(enc, key, rc4key_seed)
                        dec = self.decrypt(dec)
                        for dline in config_delimiter:
                            if dline in dec:
                                break
                        else:
                            continue
                        break
                    else:
                        continue
                    break

                if dec == "":
                    dec = self.decrypt(enc)
                    for dline in config_delimiter:
                        if dline in dec:
                            key = "NULL"
                            rc4key_seed = "NULL"
                            break

                p_data = OrderedDict()
                if dec != "":
                    p_data["RC4 key"]          = key
                    p_data["RC4 Sbox seed"]    = rc4key_seed
                    p_data["Config delimiter"] = dline
                    idx = 0
                    for e in (dec.split(dline)):
                        try:
                            p_data[idx_list[idx]] = e
                        except:
                            p_data["Unknown " + str(idx)] = e
                        idx += 1
                else:
                    outfd.write("[!] failed to decrypt\n")

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
                    outfd.write("{0:<16}: {1}\n".format(id, param))
