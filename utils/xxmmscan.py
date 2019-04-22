# Detecting xxmm config for Volatilitv
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv xxmmconfig.py volatility/plugins/malware
# 3. python vol.py xxmmconfig -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import re
from struct import unpack, unpack_from

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

xxmm_sig = {
    'namespace1' : 'rule xxmm { \
                    strings: \
                       $v1 = "setupParameter:" \
                       $v2 = "loaderParameter:" \
                       $v3 = "parameter:" \
                    condition: all of them}'
}

DATA_TYPE = {0x10001: 'ASCII',
             0x104DB: 'UTF-16LE',
             0x104DC: 'UTF-16LE',
             0x104DE: 'ASCII',
             0x104DF: 'UTF-16LE',
             0x104E0: 'UTF-16LE',
             0x104E1: 'ASCII',
             0x104E2: 'ASCII',
             0x104E3: 'ASCII',
             0x104E4: 'ASCII',
             0x104E5: 'UTF-16LE',
             0x104E6: 'UTF-16LE',
             0x104E7: 'UTF-16LE',
             0x104E8: 'UTF-16LE',
             0x104E9: 'UTF-16LE',
             0x104EA: 'UTF-16LE',
             0x10502: 'ASCII',
             0x10515: 'UTF-16LE',
             0x10516: 'UTF-16LE',
             0x10517: 'UTF-16LE',
             0x10518: 'ASCII',
             0x10519: 'UTF-16LE',
             0x1051A: 'UTF-16LE',
             0x1051B: 'UTF-16LE',
             0x1051C: 'UTF-16LE',
             0x1051D: 'UTF-16LE',
             0x1051E: 'UTF-16LE',
             0x1051F: 'UTF-16LE',
             0x10522: 'UTF-16LE',
             0x10525: 'UTF-16LE',
             0x10534: 'UTF-16LE',
             0x10535: 'UTF-16LE',
             0x1053C: 'ASCII',
             0x20520: 'DWORD',
             0x20521: 'DWORD',
             0x20523: 'DWORD',
             0x20524: 'DWORD',
             0x20526: 'DWORD',
             0x20535: 'DWORD',
             0x40500: 'BYTE',
             0x40501: 'BYTE',
             0x80503: 'BYTE',
             0x80514: 'BYTE',
             0x8052A: 'BYTE'}


class xxmmConfig(taskmods.DllList):
    "Parse the xxmm configuration"

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End
        return None

    def extract_param(self, conf_data, offset):
        l = unpack_from('>I', conf_data, offset)[0]
        if 8 <= l <= len(conf_data[offset:]):
            idnum = unpack_from('>I', conf_data, offset + 0x4)[0]
            s = conf_data[offset + 0x8:offset + l]
        else:
            return None, None, None
        return l, idnum, s

    def calculate(self):

        if not has_yara:
            debug.error('Yara must be installed for this plugin.')

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error('This command does not support the selected profile.')

        rules = yara.compile(sources=xxmm_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                memdata = proc_addr_space.get_available_addresses()

                config_data = []

                for m in memdata:
                    if 0x2000 < m[1]:
                        continue
                    p_data = {}

                    data = proc_addr_space.zread(m[0], m[1])
                    offset = 0
                    p_data['param'] = []
                    while(True):
                        param = {}
                        l, param['id'], param['data'] = self.extract_param(data, offset)
                        if l == None:
                            if len(p_data['param']) == 1 and p_data['param'][0]['type'] == 'Unknown':
                                offset = 0
                                break
                            for c in data[offset:]:
                                if ord(c) != 0x00:
                                    offset = 0
                                    break
                            break
                        offset += l
                        if param['id'] in DATA_TYPE.keys():
                            param['type'] = DATA_TYPE[param['id']]
                        else:
                            param['type'] = 'Unknown'
                        p_data['param'].append(param)
                    if offset == 0:
                        continue
                    p_data['offset'] = m[0]
                    p_data['length'] = offset
                    config_data.append(p_data)
                yield task, vad_base_addr, end, hit, memory_model, config_data
                break

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, end, malname, memory_model, config_data in data:
            self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, start)
            outfd.write("{0}\n".format(delim))
            outfd.write("Process: {0} ({1})\n\n".format(task.ImageFileName, task.UniqueProcessId))

            for p_data in config_data:
                outfd.write(' Offset: %8Xh\n' % p_data['offset'])
                outfd.write(' Length: %8Xh\n' % p_data['length'])
                for param in p_data['param']:
                    outfd.write('  ID:%6Xh  Data(%s): ' % (param['id'], param['type']))
                    if param['type'] in {'ASCII', 'UTF-16LE'}:
                        outfd.write('%s\n' % param['data'])
                    elif param['type'] == 'DWORD':
                        outfd.write('%d\n' % unpack('>I', param['data'])[0])
                    elif param['type'] in {'BYTE', 'Unknown'}:
                        for c in param['data']:
                            outfd.write('%X ' % ord(c))
                        outfd.write('\n')
                    else:
                        debug.error('Invalid type found.')
                outfd.write('%s\n' % ('-' * 10))
