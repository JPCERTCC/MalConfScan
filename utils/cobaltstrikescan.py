# Detecting CobaltStrike for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. locate "cobaltstrikescan.py" in [Volatility_Plugins_Directory]
#  ex) mv cobaltstrikescan.py /usr/lib/python2.7/dist-packages/volatility/plugins/malware
# 2. python vol.py cobaltstrikeconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
from struct import unpack, unpack_from
from socket import inet_ntoa
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

cobaltstrike_sig = {
    'namespace1' : 'rule CobaltStrike { \
                    strings: \
                       $v1 = { 73 70 72 6E 67 00} \
                       $v2 = { 69 69 69 69 69 69 69 69} \
                    condition: $v1 and $v2}'
}

CONF_PATTERNS = [{
    'pattern': '\x69\x68\x69\x68\x69',
    'cfg_size': 0x1000,
    'cfg_info': [['\x00\x01\x00\x01\x00\x02', 'BeaconType', 0x2], ['\x00\x02\x00\x01\x00\x02', 'Port', 0x2], ['\x00\x03\x00\x02\x00\x04', 'Polling(ms)', 0x4],
                 ['\x00\x04\x00\x02\x00\x04', 'Unknown1', 0x4], ['\x00\x05\x00\x01\x00\x02', 'Jitter', 0x2], ['\x00\x06\x00\x01\x00\x02', 'Maxdns', 0x2],
                 ['\x00\x07\x00\x03\x01\x00', 'Unknown2', 0x100], ['\x00\x08\x00\x03\x01\x00', 'C2Server', 0x100], ['\x00\x09\x00\x03\x00\x80', 'UserAgent', 0x80],
                 ['\x00\x0a\x00\x03\x00\x40', 'HTTP_Method2_Path', 0x40], ['\x00\x0b\x00\x03\x01\x00', 'Unknown3', 0x100], ['\x00\x0c\x00\x03\x01\x00', 'Header1', 0x100],
                 ['\x00\x0d\x00\x03\x01\x00', 'Header2', 0x100], ['\x00\x0e\x00\x03\x00\x40', 'Injection_Process', 0x40], ['\x00\x0f\x00\x03\x00\x80', 'PipeName', 0x80],
                 ['\x00\x10\x00\x01\x00\x02', 'Year', 0x2], ['\x00\x11\x00\x01\x00\x02', 'Month', 0x2], ['\x00\x12\x00\x01\x00\x02', 'Day', 0x2],
                 ['\x00\x13\x00\x02\x00\x04', 'DNS_idle', 0x4], ['\x00\x14\x00\x02\x00\x04', 'DNS_sleep(ms)', 0x2], ['\x00\x1a\x00\x03\x00\x10', 'Method1', 0x10],
                 ['\x00\x1b\x00\x03\x00\x10', 'Method2', 0x10], ['\x00\x1c\x00\x02\x00\x04', 'Unknown4', 0x4], ['\x00\x1d\x00\x03\x00\x40', 'Spawnto_x86', 0x40],
                 ['\x00\x1e\x00\x03\x00\x40', 'Spawnto_x64', 0x40], ['\x00\x1f\x00\x01\x00\x02', 'Unknown5', 0x2], ['\x00\x20\x00\x03\x00\x80', 'Proxy_HostName', 0x80],
                 ['\x00\x21\x00\x03\x00\x40', 'Proxy_UserName', 0x40], ['\x00\x22\x00\x03\x00\x40', 'Proxy_Password', 0x40], ['\x00\x23\x00\x01\x00\x02', 'Proxy_AccessType', 0x2],
                 ['\x00\x24\x00\x01\x00\x02', 'create_remote_thread', 0x2]]
}]

BEACONTYPE = {0x0: "0 (HTTP)", 0x1: "1 (Hybrid HTTP and DNS)", 0x8: "8 (HTTPS)"}
ACCESSTYPE = {0x0: "0 (not use)", 0x1: "1 (use direct connection)", 0x2: "2 (use IE settings)", 0x4: "4 (use proxy server)"}


class cobaltstrikeConfig(taskmods.DllList):

    """Detect processes infected with CobaltStrike malware"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def decode_config(self, cfg_blob):
        return "".join(chr(ord(cfg_offset) ^ 0x69) for cfg_offset in cfg_blob)

    def parse_config(self, cfg_blob, nw):

        p_data = OrderedDict()

        for pattern, name, size in nw['cfg_info']:
            if name.count('Port'):
                port = unpack_from('>H', cfg_blob, 0xE)[0]
                p_data[name] = port
                continue

            offset = cfg_blob.find(pattern)
            if offset == -1:
                p_data[name] = ""
                continue

            config_data = cfg_blob[offset + 6:offset + 6 + size]
            if name.count('Unknown'):
                p_data[name] = repr(config_data)
                continue

            if size == 2:
                if name.count('BeaconType'):
                    p_data[name] = BEACONTYPE[unpack('>H', config_data)[0]]
                elif name.count('AccessType'):
                    p_data[name] = ACCESSTYPE[unpack('>H', config_data)[0]]
                elif name.count('create_remote_thread'):
                    if unpack('>H', config_data)[0] != 0:
                        p_data[name] = "Enable"
                    else:
                        p_data[name] = "Disable"
                else:
                    p_data[name] = unpack('>H', config_data)[0]
            elif size == 4:
                if name.count('DNS_idle'):
                    p_data[name] = inet_ntoa(config_data)
                else:
                    p_data[name] = unpack('>I', config_data)[0]
            else:
                if name.count('Header'):
                    cfg_offset = 3
                    flag = 0
                    while 1:
                        if cfg_offset > 255:
                            break
                        else:
                            if config_data[cfg_offset] != '\x00':
                                if config_data[cfg_offset + 1] != '\x00':
                                    if flag:
                                        name = name + "+"
                                    p_data[name] = config_data[(cfg_offset + 1):].split('\x00')[0]
                                    cfg_offset = config_data[cfg_offset:].find('\x00\x00\x00') + cfg_offset - 1
                                    flag += 1
                                else:
                                    cfg_offset += 4
                                    continue
                            else:
                                cfg_offset += 4
                                continue
                else:
                    p_data[name] = config_data

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=cobaltstrike_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []

                for nw in CONF_PATTERNS:
                    cfg_addr = data.find(nw['pattern'])
                    if cfg_addr != -1:
                        break
                    else:
                        continue

                cfg_blob = data[cfg_addr:cfg_addr + nw['cfg_size']]
                config_data.append(self.parse_config(self.decode_config(cfg_blob), nw))

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
                    outfd.write("{0:<22}: {1}\n".format(id, param))
