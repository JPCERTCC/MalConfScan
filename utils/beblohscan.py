# Detecting Bebloh(Shiotob, URLZone) for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv beblohscan.py volatility/plugins/malware
# 3. python vol.py beblohconfig -f images.mem --profile=Win7SP1x64

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

bebloh_sig = {
    'namespace1' : 'rule Bebloh { \
                    strings: \
                       $crc32f = { b8 EE 56 0b ca } \
                       $dga = "qwertyuiopasdfghjklzxcvbnm123945678" \
                       $post1 = "&vcmd=" \
                       $post2 = "?tver=" \
                    condition: all of them}'
}

# RSA key header
RSA_HEADER = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"

# Config pattern
CONFIG_PATTERNS = [re.compile("\x83\x45\x08\x02\xe8(....)", re.DOTALL)]


class beblohConfig(taskmods.DllList):
    """Parse the Bebloh configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def crc32(self, buf, value):
        table = []

        for i in range(256):
            v = i
            for j in range(8):
                v = (0xEDB88320 ^ (v >> 1)) if(v & 1) == 1 else (v >> 1)
            table.append(v)

        for c in buf:

            value = value ^ ord(c)
            value = table[value & 0xFF] ^ (value >> 8)

        return value

    def sum_of_characters(self, domain):
        return sum([ord(d) for d in domain[:-3]])

    def get_next_domain(self, domain, xor):
        qwerty = "qwertyuiopasdfghjklzxcvbnm123945678"

        sof = self.sum_of_characters(domain) ^ xor
        ascii_codes = [ord(d) for d in domain] + 100 * [0]
        old_hostname_length = len(domain) - 4
        for i in range(0, 66):
            for j in range(0, 66):
                edi = j + i
                if edi < 65:
                    p = (old_hostname_length * ascii_codes[j])
                    cl = p ^ ascii_codes[edi] ^ sof
                    ascii_codes[edi] = cl & 0xFF

        """
            calculate the new hostname length
            max: 255/16 = 15
            min: 10
        """
        cx = ((ascii_codes[2] * old_hostname_length) ^ ascii_codes[0]) & 0xFF
        hostname_length = int(cx / 16)  # at most 15
        if hostname_length < 10:
            hostname_length = old_hostname_length

        """
            generate hostname
        """
        for i in range(hostname_length):
            index = int(ascii_codes[i] / 8)  # max 31 --> last 3 chars of qwerty unreachable
            bl = ord(qwerty[index])
            ascii_codes[i] = bl

        hostname = ''.join([chr(a) for a in ascii_codes[:hostname_length]])

        """
            append .net or .com (alternating)
        """
        tld = '.com' if domain.endswith('.net') else '.net'
        domain = hostname + tld

        return domain

    def parse_config(self, data, base, rsa_key, dga_key):
        p_data = OrderedDict()
        p_data["RSA key"]         = rsa_key.encode("hex")
        p_data["Sleep count"]     = unpack_from("<I", data, base + 5)[0]
        p_data["Seed URL"]        = data[base + 9:base + 0x29].replace("\0", "")
        p_data["Sleep time"]      = unpack_from("<I", data, base + 0xf9)[0]
        p_data["Botid"]           = data[base + 0xfd:base + 0x10f].replace("\0", "")
        p_data["Registry subkey"] = data[base + 0x136:base + 0x160].replace("\0", "")

        site_check_flag = unpack_from("<I", data, base + 0xf9)[0]
        if site_check_flag != 0:
            site_check = "Enable"
        else:
            site_check = "Disable"

        p_data["Network Chack"]   = site_check
        p_data["Botnet"]          = data[base + 0x178:base + 0x188].replace("\0", "")
        p_data["Registry key"]    = data[base + 0x188:base + 0x194].replace("\0", "")

        domain = data[base + 9:base + 0x29].split("/")[0]

        for i in range(51):
            p_data["DGA " + str(i)] = domain
            domain = self.get_next_domain(domain, dga_key)

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=bebloh_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                rsa_key_index = data.find(RSA_HEADER)
                rsa_key = data[rsa_key_index:rsa_key_index + 0x94]

                dga_key = self.crc32(rsa_key, 0xCA0B56EE)

                for pattern in CONFIG_PATTERNS:
                    offset = re.search(pattern, data).start()

                while not (data[offset] == "\xBA" or data[offset] == "\xB8"):
                    offset += 1

                (config_addr, ) = unpack("=I", data[offset + 1:offset + 5])
                config_addr -= vad_base_addr

                config_data.append(self.parse_config(data, config_addr, rsa_key, dga_key))

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
