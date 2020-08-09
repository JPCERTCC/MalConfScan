# Detecting nanocore for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] nanocorescan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] nanocorescan -pid [PID]

from . import basescan

import logging
import re
from collections import OrderedDict
from struct import unpack

from volatility.plugins.windows import vaddump

try:
    """import crypto libs here"""
    has_crypto = True
except ImportError:
    has_crypto = False

# logger for volatility
vollog = logging.getLogger(__name__)


class nanocoreConfig(basescan.baseConfig):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            'namespace1': 'rule Nanocore { \
                    strings: \
                       $v1 = "NanoCore Client" \
                       $v2 = "PluginCommand" \
                       $v3 = "CommandType" \
                    condition: all of them}'
        }
        self._config_sig = [re.compile(b"Version.\x07(.*?)\x0cMutex", re.DOTALL)]  # signature for searching configuration data
        self.mode = {0x0: "Disable", 0x01: "Enable"}

    def parse_config(self, data):
        p_data = OrderedDict()

        p_data['Version'] = re.search(b'Version..(.*?)\x0c', data).group()[8:16].decode()
        p_data['Mutex'] = re.search(b'Mutex(.*?)\x0c', data).group()[6:-1].hex()
        p_data['Group'] = re.search(b'DefaultGroup\x0c(.*?)\x0c', data).group()[14:-1].decode()
        p_data['Domain1'] = re.search(b'PrimaryConnectionHost\x0c(.*?)Back', data, re.DOTALL).group()[23:-6].decode()
        p_data['Domain2'] = re.search(b'BackupConnectionHost\x0c(.*?)\x0c', data).group()[22:-1].decode()
        p_data['Port'] = unpack("<H", re.search(b'ConnectionPort...', data, re.DOTALL).group()[15:])[0]
        try:
            p_data['KeyboardLogging'] = self.mode[ord(re.search(b'KeyboardLogging(.*?)\x0c', data).group()[16:-1])]
        except BaseException:
            pass
        p_data['RunOnStartup'] = self.mode[ord(re.search(b'RunOnStartup(.*?)\x0c', data).group()[13:-1])]
        p_data['RequestElevation'] = self.mode[ord(re.search(b'RequestElevation(.*?)\x0c', data).group()[17:-1])]
        p_data['BypassUAC'] = self.mode[ord(re.search(b'BypassUserAccountControl(.*?)\x0c', data).group()[25:-1])]
        p_data['ClearZoneIdentifier'] = self.mode[ord(re.search(b'ClearZoneIdentifier(.*?)\x0c', data).group()[20:-1])]
        p_data['ClearAccessControl'] = self.mode[ord(re.search(b'ClearAccessControl(.*?)\x0c', data).group()[19:-1])]
        p_data['SetCriticalProcess'] = self.mode[ord(re.search(b'SetCriticalProcess(.*?)\x0c', data).group()[19:-1])]
        p_data['PreventSystemSleep'] = self.mode[ord(re.search(b'PreventSystemSleep(.*?)\x0c', data).group()[19:-1])]
        p_data['ActivateAwayMode'] = self.mode[ord(re.search(b'ActivateAwayMode(.*?)\x0c', data).group()[17:-1])]
        p_data['EnableDebugMode'] = self.mode[ord(re.search(b'EnableDebugMode(.*?)\x0c', data).group()[16:-1])]
        p_data['RunDelay'] = unpack("<i", re.search(b'RunDelay(.*?)\x0c', data).group()[9:-1])[0]
        p_data['ConnectDelay'] = unpack("<i", re.search(b'ConnectDelay(.*?)\x0c', data).group()[13:-1])[0]
        p_data['RestartDelay'] = unpack("<i", re.search(b'RestartDelay(.*?)\x0c', data).group()[13:-1])[0]
        p_data['TimeoutInterval'] = unpack("<i", re.search(b'TimeoutInterval(.*?)\x0c', data).group()[16:-1])[0]
        p_data['KeepAliveTimeout'] = unpack("<i", re.search(b'KeepAliveTimeout(.*?)\x0c', data).group()[17:-1])[0]
        p_data['MutexTimeout'] = unpack("<i", re.search(b'MutexTimeout(.*?)\x0c', data).group()[13:-1])[0]
        p_data['LanTimeout'] = unpack("<i", re.search(b'LanTimeout(.*?)\x0c', data).group()[11:-1])[0]
        p_data['WanTimeout'] = unpack("<i", re.search(b'WanTimeout(.*?)\x0c', data).group()[11:-1])[0]
        p_data['BufferSize'] = re.search(b'BufferSize(.*?)\x0c', data).group()[11:-1].hex()
        p_data['MaxPacketSize'] = re.search(b'MaxPacketSize(.*?)\x0c', data).group()[14:-1].hex()
        p_data['GCThreshold'] = re.search(b'GCThreshold(.*?)\x0c', data).group()[12:-1].hex()
        try:
            p_data['UseCustomDNS'] = self.mode[ord(re.search(b'UseCustomDnsServer(.*?)\x0c', data).group()[19:-1])]
            p_data['PrimaryDNSServer'] = re.search(b'PrimaryDnsServer\x0c(.*?)\x0c', data).group()[18:-1]
            p_data['BackupDNSServer'] = re.search(b'BackupDnsServer\x0c(.*?)(\x04|\x0c)', data).group()[16:-1]
        except BaseException:
            pass

        return p_data

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        """process dump data will be passed as data"""
        config_data = OrderedDict()
        for top_addr, size in self.get_vad_maps(self._target_proc):
            if size < 0x100000:
                continue
            vad = self.get_vad_base(self._target_proc, top_addr)
            ex_data = vaddump.VadDump.vad_dump(context=self.context, layer_name=self._target_proc.add_process_layer(), vad=vad)
            for pattern in self._config_sig:
                m = re.search(pattern, ex_data)
            if m:
                break

        config_data = self.parse_config(ex_data)

        return config_data
