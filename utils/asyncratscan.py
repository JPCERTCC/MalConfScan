import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
from struct import unpack, pack
from base64 import b64decode
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    has_crypto = True
except ImportError:
    has_crypto = False

asyncrat_sig = {
    'namespace1': 'rule asyncrat { \
                    strings: \
                        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}\
                        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}\
                        $b2 = {09 50 00 6F 00 6E 00 67 00 00}\
                        $s1 = "pastebin" ascii wide nocase \
                        $s2 = "pong" wide\
                        $s3 = "Stub.exe" ascii wide\
                    condition:  ($salt and (2 of ($s*) or 1 of ($b*))) or (all of ($b*) and 2 of ($s*)) }'
}

CONFIG_PATTERNS = [
    b"\x00\x00\x00\x0D\x53\x00\x48\x00\x41\x00\x32\x00\x35\x00\x36\x00\x00"]

## format  "index" : ("position_in_storage_stream","field_name","encryption_method")
config_index = {
    1: (2,"Server", "aes"),
    2: (1,"Ports", "aes"),
    3: (3,"Version", "aes"),
    4: (4,"Autorun", "aes"),
    5: (5,"Install_Folder", ""),
    6: (6,"Install_File", "aes"),
    7: (7,"AES_key", "base64"),
    8: (8,"Mutex", "aes"),
    9: (11,"AntiDetection", "aes"),
    10: (12,"External_config_on_Pastebin", "aes"),
    11: (13,"BDOS", "aes"),
    12: (14,"HWID", ""),
    13: (15,"Startup_Delay", ""),
    14: (9,"Certificate", "aes"),
    15: (10,"ServerSignature", "aes")
}


class asyncratConfig(taskmods.DllList):
    """Parse the asyncrat configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def printable(self, data):
        if len(data) < 1:
            return data
        cleaned = ""

        for d in data:
            if 0x20 <= ord(d) and ord(d) <= 0x7F:
                cleaned += d

        return cleaned

    def storage_stream_us_parser(self, data):
        """
        parse storage_stream for unicode strings in .NET assembly.
        unicode_strings chunk patterns
            pat1: [size of unicode strings(1byte)][unicode strings][terminate code(0x00 or 0x01)]
            pat2: [size of unicode strings(2byte)][unicode strings][terminate code(0x00 or 0x01)]
        """
        if len(data) < 2:
            return list()
        unicode_strings = list()

        while True:
            # first byte must be the size of unicode strings chunk.
            initial_byte = ord(data[0])
            if initial_byte == 0x00:
                break
            elif initial_byte < 0x80:
                size = initial_byte
                p = 1
            elif initial_byte >= 0x80:
                size = unpack(">H",pack("B",initial_byte-0x80)+data[1])[0]
                # size = int.from_bytes(bytes([data[0]-0x80, data[1]]), "big")
                p = 2

            if size < 0 or 0x7FFF < size or size > len(data)-3:
                debug.info("Invalid string size found in stroage stream.")
                break
            try:
                unicode_strings.append(
                    data[p:size + p - 1].decode().replace("\x00", ""))
            except UnicodeDecodeError:
                debug.info("Invalid unicode byte(s) found in storage stream.")
                pass
            # check the termination code.
            termination_byte = ord(data[size + p - 1])
            if termination_byte == 0x00 or termination_byte == 0x01:
                # goto next block
                data = data[size + p:]
                continue
            else:
                debug.info("Invalid termination code: {}".format(termination_byte))
                break

        return unicode_strings

    def parse_config(self, unicode_strings):

        if len(unicode_strings) < 7:
            debug.info("unicode strings list is too short.")
            return OrderedDict()

        config = OrderedDict()

        key = b64decode(unicode_strings[7])
        salt = "BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941".decode("hex")
        aes_key = PBKDF2(key, salt, 32, 50000)

        for _ , params in config_index.items():
            pos, field, enc_type = params
            if enc_type == "aes" and len(unicode_strings[pos]) > 48:
                enc_data = b64decode(unicode_strings[pos])
                # hmac = enc_data[:32]
                aes_iv = enc_data[32:48]
                cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                value = self.printable(cipher.decrypt(enc_data[48:]))
            elif enc_type == "base64":
                value = self.printable(b64decode(unicode_strings[pos]))
            else:
                value = unicode_strings[pos]
            config[field] = value
        return config

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        if not has_crypto:
            debug.error("pycrypto must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=asyncrat_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():
                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(
                    vad_base_addr, end - vad_base_addr)

                config_data = []
                dlist = OrderedDict()

                for pattern in CONFIG_PATTERNS:
                    m = data.find(pattern)
                    if m > 0:
                        unicode_strings = self.storage_stream_us_parser(
                            data[m + 3:])
                        dlist = self.parse_config(unicode_strings)
                        break
                    else:
                        debug.info(
                            "Asyncrat configuration signature not found.")

                config_data.append(dlist)

                yield task, vad_base_addr, end, hit, memory_model, config_data
                break

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, end, malname, memory_model, config_data in data:
            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(
                task.ImageFileName, task.UniqueProcessId))

            outfd.write("[Config Info]\n")
            for p_data in config_data:
                for id, param in p_data.items():
                    outfd.write("{0:<25}: {1}\n".format(id, param))
