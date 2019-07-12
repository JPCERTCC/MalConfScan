# Detecting Nanocore RAT for Volatilitv
#
# Based on the script below:
# https://github.com/kevthehermit/RATDecoders/blob/master/decoders/NanoCore.py
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv nanocoreconfigallocate.py volatility/plugins/malware
# 3. python vol.py nanocoreconfig -f images.mem --profile=Win7SP1x64

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

nanocore_sig = {
    'namespace1' : 'rule Nanocore { \
                    strings: \
                       $v1 = "NanoCore Client" \
                       $v2 = "PluginCommand" \
                       $v3 = "CommandType" \
                    condition: all of them}'
}

# Config pattern
CONFIG_PATTERNS = [re.compile("Version.\x07(.*?)\x0cMutex", re.DOTALL)]

MODE = {0x0: "Disable", 0x01: "Enable"}


class nanocoreConfig(taskmods.DllList):
    "Parse the Nanocore configuration"

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End
        return None

    def parse_config(self, data):

        p_data = OrderedDict()

        p_data['Version']             = re.search('Version..(.*?)\x0c', data).group()[8:16]
        p_data['Mutex']               = re.search('Mutex(.*?)\x0c', data).group()[6:-1].encode('hex')
        p_data['Group']               = re.search('DefaultGroup\x0c(.*?)\x0c', data).group()[14:-1]
        p_data['Domain1']             = re.search('PrimaryConnectionHost\x0c(.*?)Back', data, re.DOTALL).group()[23:-6]
        p_data['Domain2']             = re.search('BackupConnectionHost\x0c(.*?)\x0c', data).group()[22:-1]
        p_data['Port']                = unpack("<H", re.search('ConnectionPort...', data, re.DOTALL).group()[15:])[0]
        try:
            p_data['KeyboardLogging']     = MODE[ord(re.search('KeyboardLogging(.*?)\x0c', data).group()[16:-1])]
        except:
            pass
        p_data['RunOnStartup']        = MODE[ord(re.search('RunOnStartup(.*?)\x0c', data).group()[13:-1])]
        p_data['RequestElevation']    = MODE[ord(re.search('RequestElevation(.*?)\x0c', data).group()[17:-1])]
        p_data['BypassUAC']           = MODE[ord(re.search('BypassUserAccountControl(.*?)\x0c', data).group()[25:-1])]
        p_data['ClearZoneIdentifier'] = MODE[ord(re.search('ClearZoneIdentifier(.*?)\x0c', data).group()[20:-1])]
        p_data['ClearAccessControl']  = MODE[ord(re.search('ClearAccessControl(.*?)\x0c', data).group()[19:-1])]
        p_data['SetCriticalProcess']  = MODE[ord(re.search('SetCriticalProcess(.*?)\x0c', data).group()[19:-1])]
        p_data['PreventSystemSleep']  = MODE[ord(re.search('PreventSystemSleep(.*?)\x0c', data).group()[19:-1])]
        p_data['ActivateAwayMode']    = MODE[ord(re.search('ActivateAwayMode(.*?)\x0c', data).group()[17:-1])]
        p_data['EnableDebugMode']     = MODE[ord(re.search('EnableDebugMode(.*?)\x0c', data).group()[16:-1])]
        p_data['RunDelay']            = unpack("<i", re.search('RunDelay(.*?)\x0c', data).group()[9:-1])[0]
        p_data['ConnectDelay']        = unpack("<i", re.search('ConnectDelay(.*?)\x0c', data).group()[13:-1])[0]
        p_data['RestartDelay']        = unpack("<i", re.search('RestartDelay(.*?)\x0c', data).group()[13:-1])[0]
        p_data['TimeoutInterval']     = unpack("<i", re.search('TimeoutInterval(.*?)\x0c', data).group()[16:-1])[0]
        p_data['KeepAliveTimeout']    = unpack("<i", re.search('KeepAliveTimeout(.*?)\x0c', data).group()[17:-1])[0]
        p_data['MutexTimeout']        = unpack("<i", re.search('MutexTimeout(.*?)\x0c', data).group()[13:-1])[0]
        p_data['LanTimeout']          = unpack("<i", re.search('LanTimeout(.*?)\x0c', data).group()[11:-1])[0]
        p_data['WanTimeout']          = unpack("<i", re.search('WanTimeout(.*?)\x0c', data).group()[11:-1])[0]
        p_data['BufferSize']          = re.search('BufferSize(.*?)\x0c', data).group()[11:-1].encode('hex')
        p_data['MaxPacketSize']       = re.search('MaxPacketSize(.*?)\x0c', data).group()[14:-1].encode('hex')
        p_data['GCThreshold']         = re.search('GCThreshold(.*?)\x0c', data).group()[12:-1].encode('hex')
        try:
            p_data['UseCustomDNS']    = MODE[ord(re.search('UseCustomDnsServer(.*?)\x0c', data).group()[19:-1])]
            p_data['PrimaryDNSServer']= re.search('PrimaryDnsServer\x0c(.*?)\x0c', data).group()[18:-1]
            p_data['BackupDNSServer'] = re.search('BackupDnsServer\x0c(.*?)(\x04|\x0c)', data).group()[16:-1]
        except:
            pass

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error('Yara must be installed for this plugin.')

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error('This command does not support the selected profile.')

        rules = yara.compile(sources=nanocore_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)
            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                memdata = proc_addr_space.get_available_addresses()

                config_data = []

                for m in memdata:
                    if m[1] < 0x100000:
                        continue

                    data = proc_addr_space.zread(m[0], m[1])

                    for pattern in CONFIG_PATTERNS:
                        m = re.search(pattern, data)

                    if m:
                        offset = m.start()
                    else:
                        continue

                    config_data.append(self.parse_config(data[offset: offset + 0x1000]))

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
                    outfd.write("{0:<20}: {1}\n".format(id, param))
