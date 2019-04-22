# Detecting PlugX for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv plugxscan.py volatility/plugins/malware
# 3. python vol.py [ plugxscan | plugxconfig ] -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
from struct import unpack, unpack_from
from socket import inet_ntoa
from collections import OrderedDict

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

plugx_sig = {
    'namespace1' : 'rule plugx { \
                    strings: \
                       $v1 = { 47 55 4c 50 00 00 00 00 } \
                       $v2a = { 68 40 25 00 00 } \
                       $v2c = { 68 58 2D 00 00 } \
                       $v2b = { 68 a0 02 00 00 } \
                       $v2d = { 68 a4 36 00 00 } \
                       $v2e = { 8D 46 10 68 } \
                       $v2f = { 68 24 0D 00 00 } \
                       $v2g = { 68 a0 02 00 00 } \
                       $v2h = { 68 e4 0a 00 00 } \
                    condition: $v1 at 0 or ($v2a and $v2b) or ($v2c and $v2b) or ($v2d and $v2b) or ($v2d and $v2e) or ($v2f and $v2g) or ($v2h and $v2g)}'
}

FLAG_ENABLE        = 0xFFFFFFFF

HKEY_CLASSES_ROOT  = 0x80000000
HKEY_CURRENT_USER  = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002


class plugxConfig(taskmods.DllList):
    """Parse the PlugX configuration"""

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start, vad.End

        return None

    def parse_config(self, cfg_blob, cfg_sz, cfg_addr, vinfo):
        p_data = OrderedDict()

        # config parsing
        SleepTime = unpack_from('>I', cfg_blob, 0x34)[0]
        NetworkFlag = unpack_from('<672B', cfg_blob, 0x3c)
        ServerURL = unpack_from('<128s128s128s128s', cfg_blob, 0x3fc)
        if cfg_sz == 0x1d18:
            InstallFolder = unpack_from('<512s', cfg_blob, 0x910)[0]
            ServiceName = unpack_from('<512s', cfg_blob, 0xb10)[0]
            ServiceDisplayName = unpack_from('<512s', cfg_blob, 0xd10)[0]
            InjectionProcess = unpack_from('<512s', cfg_blob, 0x1518)[0]
            ServerID1 = unpack_from('<512s', cfg_blob, 0x1718)[0]
            ServerID2 = unpack_from('<512s', cfg_blob, 0x1918)[0]
            Mutex = unpack_from('<256s', cfg_blob, 0x1b18)[0]
            RunKey = unpack_from('<512s', cfg_blob, 0x1114)[0]
            RunKeyValu = unpack_from('<512s', cfg_blob, 0x1314)[0]
        elif cfg_sz == 0x1510 or cfg_sz == 0x150c:
            InstallFolder = unpack_from('<512s', cfg_blob, 0x90c)[0]
            ServiceName = unpack_from('<512s', cfg_blob, 0xb0c)[0]
            ServiceDisplayName = unpack_from('<512s', cfg_blob, 0xd0c)[0]
            ServerID1 = unpack_from('<512s', cfg_blob, 0x110c)[0]
            ServerID2 = unpack_from('<512s', cfg_blob, 0x130c)[0]

        ServerData = [[0] * 3] * 4
        proxy = [[0] * 5] * 4
        if unpack_from('<I', cfg_blob, 0xc)[0] == FLAG_ENABLE:
            DLLremove_flag = 'Enable'
        else:
            DLLremove_flag = 'Disable'

        if unpack_from('<I', cfg_blob, 0x28)[0] == FLAG_ENABLE:
            FileDelete_flag = 'Enable'
        else:
            FileDelete_flag = 'Disable'

        if unpack_from('<I', cfg_blob, 0x2c)[0] == FLAG_ENABLE:
            KeyLog_flag = 'Enable'
        else:
            KeyLog_flag = 'Disable'

        (dns1, dns2, dns3, dns4) = unpack_from("<4L", cfg_blob, 0x2dc)
        custom_dns = cfg_blob[0x2dc:0x2ec]

        for i in xrange(4):
            if unpack_from('<B', cfg_blob, 0x2ec + (i * 68))[0] != 0x0:
                ServerData[i] = unpack_from('<HH64s', cfg_blob, 0x2ec + (i * 68))

        for i in xrange(4):
            proxy[i] = unpack_from('<2H64s64s64s', cfg_blob, 0x5fc + (i * 196))

        if unpack_from('>B', cfg_blob, 0x90c)[0] == 0:
            AutorunSetup = 'Service setup'
        elif unpack_from('>B', cfg_blob, 0x90c)[0] == 1:
            AutorunSetup = 'Run Registry'
        elif unpack_from('>B', cfg_blob, 0x90c)[0] == 2:
            AutorunSetup = 'Disable'

        if unpack_from('<I', cfg_blob, 0x1110)[0] == HKEY_CLASSES_ROOT:
            RegistrySubkey = 'HKEY_CLASSES_ROOT'
        elif unpack_from('<I', cfg_blob, 0x1110)[0] == HKEY_CURRENT_USER:
            RegistrySubkey = 'HKEY_CURRENT_USER'
        elif unpack_from('<I', cfg_blob, 0x1110)[0] == HKEY_LOCAL_MACHINE:
            RegistrySubkey = 'HKEY_LOCAL_MACHINE'
        else:
            RegistrySubkey = unpack_from('<I', cfg_blob, 0x1110)[0]

        if cfg_sz > 0x1510:
            if unpack_from('>B', cfg_blob, 0x1514)[0] == 0:
                InjectionFlag = 'Enable'
            else:
                InjectionFlag = 'Disable'

        CnCDay = 'Everyday'
        for x in xrange(672):
            if NetworkFlag[x] == 0x0:
                CnCDay = 'Network Activity Flag Enable(Check config file!)'

        # config write file
        p_data["Version"] = 1
        p_data["Version Info"] = vinfo
        p_data["Config Size"] = "0x{0:X}".format(cfg_sz)
        p_data["Delete DLL list"] = DLLremove_flag
        p_data["File Delete"] = FileDelete_flag
        p_data["Key Logger"] = KeyLog_flag
        p_data["Sleep Time"] = SleepTime
        p_data["Network Activity"] = CnCDay
        if dns1 not in (0, 0xffffffff):
            p_data["Custom DNS 1"] = inet_ntoa(custom_dns[:4])
        if dns2 not in (0, 0xffffffff):
            p_data["Custom DNS 2"] = inet_ntoa(custom_dns[4:8])
        if dns3 not in (0, 0xffffffff):
            p_data["Custom DNS 3"] = inet_ntoa(custom_dns[8:12])
        if dns4 not in (0, 0xffffffff):
            p_data["Custom DNS 4"] = inet_ntoa(custom_dns[12:16])

        for z in xrange(4):
            if ServerData[z][0]:
                p_data["Server  {0}".format(z + 1)] = "{0}:{1} (Type {2})".format(ServerData[z][2].replace('\0', ''), ServerData[z][1], ServerData[z][0])

        for y in xrange(4):
            if ServerURL[y]:
                p_data["Server URL {0}".format(y + 1)] = ServerURL[y].replace('\0', '')

        for k in xrange(4):
            if proxy[k][1] != 0:
                p_data["Proxy {0}".format(k + 1)] = "{0}:{1}".format(proxy[k][2].replace('\0', ''), proxy[k][1])
                if proxy[k][3] != '\x00':
                    p_data["Proxy credentials {0}".format(k + 1)] = "{0}:{1}".format(proxy[k][3].replace('\0', ''), proxy[k][4].replace('\0', ''))

        p_data["Install Folder"] = InstallFolder.replace('\0', '')
        p_data["Service Name"] = ServiceName.replace('\0', '')
        p_data["Service Display Name"] = ServiceDisplayName.replace('\0', '')
        p_data["Server ID1"] = ServerID1.replace('\0', '')
        p_data["Server ID2"] = ServerID2.replace('\0', '')
        if cfg_sz == 0x1d18:
            p_data["Auto Start"] = AutorunSetup
            p_data["Registry Subkey"] = RegistrySubkey.replace('\0', '')
            p_data["Registry Key"] = RunKey.replace('\0', '')
            p_data["Registry Value"] = RunKeyValu.replace('\0', '')
            p_data["Injection"] = InjectionFlag
            p_data["Injection Process"] = InjectionProcess.replace('\0', '')
            p_data["Mutex"] = Mutex.replace('\0', '')

        return p_data

    def parse_config2(self, cfg_blob, cfg_sz, cfg_addr, vinfo):
        p_data = OrderedDict()

        # config parsing
        SleepTime = unpack_from('>I', cfg_blob, 0x34)[0]
        NetworkFlag = unpack_from('>672B', cfg_blob, 0x3c)
        ServerURL = unpack_from('<128s128s128s128s', cfg_blob, 0x3fc)
        InstallFolder = unpack_from('<512s', cfg_blob, 0x910)[0]
        ServiceName = unpack_from('<512s', cfg_blob, 0xb10)[0]
        ServiceDisplayName = unpack_from('<512s', cfg_blob, 0xd10)[0]
        InjectionProcess1 = unpack_from('<512s', cfg_blob, 0x1518)[0]
        InjectionProcess2 = unpack_from('<512s', cfg_blob, 0x1718)[0]
        InjectionProcess3 = unpack_from('<512s', cfg_blob, 0x1918)[0]
        InjectionProcess4 = unpack_from('<512s', cfg_blob, 0x1B18)[0]
        if cfg_sz == 0x2540:
            ServerID1 = unpack_from('<512s', cfg_blob, 0x1d18)[0]
            ServerID2 = unpack_from('<512s', cfg_blob, 0x1f18)[0]
            Mutex = unpack_from('<256s', cfg_blob, 0x2118)[0]
            ScreenCapFolder = unpack_from('<512s', cfg_blob, 0x2330)[0]
        else:
            ServerID1 = unpack_from('<512s', cfg_blob, 0x251c)[0]
            ServerID2 = unpack_from('<512s', cfg_blob, 0x271c)[0]
            Mutex = unpack_from('<256s', cfg_blob, 0x291c)[0]
            ScreenCapFolder = unpack_from('<512s', cfg_blob, 0x2b34)[0]
        RunKey = unpack_from('<512s', cfg_blob, 0x1114)[0]
        RunKeyValu = unpack_from('<512s', cfg_blob, 0x1314)[0]

        ServerData = [[0] * 3] * 4
        proxy = [[0] * 5] * 4
        if unpack_from('<I', cfg_blob, 0xc)[0] == FLAG_ENABLE:
            DLLremove_flag = 'Enable'
        else:
            DLLremove_flag = 'Disable'

        if unpack_from('<I', cfg_blob, 0x28)[0] == FLAG_ENABLE:
            FileDelete_flag = 'Enable'
        else:
            FileDelete_flag = 'Disable'

        if unpack_from('<I', cfg_blob, 0x2c)[0] == FLAG_ENABLE:
            KeyLog_flag = 'Enable'
        else:
            KeyLog_flag = 'Disable'

        (dns1, dns2, dns3, dns4) = unpack_from("<4L", cfg_blob, 0x2dc)
        custom_dns = cfg_blob[0x2dc:0x2ec]

        for i in xrange(4):
            if unpack_from('<B', cfg_blob, 0x2ec + (i * 68))[0] != 0x0:
                ServerData[i] = unpack_from('<HH64s', cfg_blob, 0x2ec + (i * 68))

        for i in xrange(4):
            proxy[i] = unpack_from('<2H64s64s64s', cfg_blob, 0x5fc + (i * 196))

        if unpack_from('>B', cfg_blob, 0x90c)[0] == 0:
            AutorunSetup = 'Run Registry or Service setup'
        elif unpack_from('>B', cfg_blob, 0x90c)[0] == 1:
            AutorunSetup = 'Service setup'
        elif unpack_from('>B', cfg_blob, 0x90c)[0] == 2:
            AutorunSetup = 'Run Registry'
        elif unpack_from('>B', cfg_blob, 0x90c)[0] == 3:
            AutorunSetup = 'Disable'

        if unpack_from('<I', cfg_blob, 0x1110)[0] == HKEY_CLASSES_ROOT:
            RegistrySubkey = 'HKEY_CLASSES_ROOT'
        elif unpack_from('<I', cfg_blob, 0x1110)[0] == HKEY_CURRENT_USER:
            RegistrySubkey = 'HKEY_CURRENT_USER'
        elif unpack_from('<I', cfg_blob, 0x1110)[0] == HKEY_LOCAL_MACHINE:
            RegistrySubkey = 'HKEY_LOCAL_MACHINE'
        else:
            RegistrySubkey = unpack_from('<I', cfg_blob, 0x1110)[0]

        if unpack_from('>B', cfg_blob, 0x1514)[0] == 0:
            InjectionFlag = 'Enable'
        else:
            InjectionFlag = 'Disable'

        if cfg_sz == 0x2540:
            if unpack_from('>B', cfg_blob, 0x2318)[0] == 0:
                ScCapFlug = 'Disable'
            else:
                ScCapFlug = 'Enable'
        else:
            if unpack_from('>B', cfg_blob, 0x2b1c)[0] == 0:
                ScCapFlug = 'Disable'
            else:
                ScCapFlug = 'Enable'

        CnCDay = 'Everyday'
        for x in xrange(672):
            if NetworkFlag[x] == 0x0:
                CnCDay = 'Network Activity Flag Enable(Check config file!)'

        # config write file
        p_data["Version"] = 2
        p_data["Version Info"] = vinfo
        p_data["Config Size"] = "0x{0:X}".format(cfg_sz)
        p_data["Delete DLL list"] = DLLremove_flag
        p_data["File Delete"] = FileDelete_flag
        p_data["Key Logger"] = KeyLog_flag
        p_data["Sleep Time"] = SleepTime
        p_data["Network Activity"] = CnCDay
        if dns1 not in (0, 0xffffffff):
            p_data["Custom DNS 1"] = inet_ntoa(custom_dns[:4])
        if dns2 not in (0, 0xffffffff):
            p_data["Custom DNS 2"] = inet_ntoa(custom_dns[4:8])
        if dns3 not in (0, 0xffffffff):
            p_data["Custom DNS 3"] = inet_ntoa(custom_dns[8:12])
        if dns4 not in (0, 0xffffffff):
            p_data["Custom DNS 4"] = inet_ntoa(custom_dns[12:16])

        for z in xrange(4):
            if ServerData[z][0]:
                p_data["Server  {0}".format(z + 1)] = "{0}:{1} (Type {2})".format(ServerData[z][2].replace('\0', ''), ServerData[z][1], ServerData[z][0])

        for y in xrange(4):
            if ServerURL[y]:
                p_data["Server URL {0}".format(y + 1)] = ServerURL[y].replace('\0', '')

        for k in xrange(4):
            if proxy[k][1] != 0:
                p_data["Proxy {0}".format(k + 1)] = "{0}:{1}".format(proxy[k][2].replace('\0', ''), proxy[k][1])
                if proxy[k][3] != '\x00':
                    p_data["Proxy credentials {0}".format(k + 1)] = "{0}:{1}".format(proxy[k][3].replace('\0', ''), proxy[k][4].replace('\0', ''))

        p_data["Auto Start"]            = AutorunSetup
        p_data["Install Folder"]        = InstallFolder.replace('\0', '')
        p_data["Service Name"]          = ServiceName.replace('\0', '')
        p_data["Service Display Name"]  = ServiceDisplayName.replace('\0', '')
        p_data["Registry Subkey"]       = RegistrySubkey
        p_data["Registry Key"]          = RunKey.replace('\0', '')
        p_data["Registry Value"]        = RunKeyValu.replace('\0', '')
        p_data["Injection"]             = InjectionFlag
        p_data["Injection Process1"]    = InjectionProcess1.replace('\0', '')
        p_data["Injection Process2"]    = InjectionProcess2.replace('\0', '')
        p_data["Injection Process3"]    = InjectionProcess3.replace('\0', '')
        p_data["Injection Process4"]    = InjectionProcess4.replace('\0', '')
        p_data["Server ID1"]            = ServerID1.replace('\0', '')
        p_data["Server ID2"]            = ServerID2.replace('\0', '')
        p_data["Mutex"]                 = Mutex.replace('\0', '')
        p_data["Screen Capture"]        = ScCapFlug
        p_data["Screen Capture Folder"] = ScreenCapFolder.replace('\0', '')

        return p_data

    def parse_config3(self, cfg_blob, cfg_sz, cfg_addr, vinfo):
        p_data = OrderedDict()

        # config parsing
        timer1 = unpack_from('4B', cfg_blob, 0x28)
        SleepTime1 = ""
        if timer1[0] != 0:
            SleepTime1 += "%d days, " % timer1[0]
        if timer1[1] != 0:
            SleepTime1 += "%d hours, " % timer1[1]
        if timer1[2] != 0:
            SleepTime1 += "%d mins, " % timer1[2]
        SleepTime1 += "%d secs" % timer1[3]

        timer2 = unpack_from('4B', cfg_blob, 0x2c)
        SleepTime2 = ""
        if timer2[0] != 0:
            SleepTime2 += "%d days, " % timer2[0]
        if timer2[1] != 0:
            SleepTime2 += "%d hours, " % timer2[1]
        if timer2[2] != 0:
            SleepTime2 += "%d mins, " % timer2[2]
        SleepTime2 += "%d secs" % timer2[3]

        NetworkFlag = unpack_from('>672B', cfg_blob, 0x30)
        ServerURL = unpack_from('<128s128s128s128s128s128s128s128s128s128s128s128s128s128s128s128s', cfg_blob, 0x720)
        InstallFolder = unpack_from('<512s', cfg_blob, 0x1234)[0]
        ServiceName = unpack_from('<512s', cfg_blob, 0x1434)[0]
        ServiceDisplayName = unpack_from('<512s', cfg_blob, 0x1634)[0]
        ServiceComment = unpack_from('<512s', cfg_blob, 0x1834)[0]
        InjectionProcess1 = unpack_from('<512s', cfg_blob, 0x1e3c)[0]
        InjectionProcess2 = unpack_from('<512s', cfg_blob, 0x203c)[0]
        InjectionProcess3 = unpack_from('<512s', cfg_blob, 0x223c)[0]
        InjectionProcess4 = unpack_from('<512s', cfg_blob, 0x243c)[0]
        BypassProcess1 = unpack_from('<512s', cfg_blob, 0x2640)[0]
        BypassProcess2 = unpack_from('<512s', cfg_blob, 0x2840)[0]
        BypassProcess3 = unpack_from('<512s', cfg_blob, 0x2a40)[0]
        BypassProcess4 = unpack_from('<512s', cfg_blob, 0x2c40)[0]
        ServerID1 = unpack_from('<512s', cfg_blob, 0x2e40)[0]
        ServerID2 = unpack_from('<512s', cfg_blob, 0x3040)[0]
        Mutex = unpack_from('<256s', cfg_blob, 0x3240)[0]
        ScreenCapFolder = unpack_from('<512s', cfg_blob, 0x3458)[0]
        RunKey = unpack_from('<512s', cfg_blob, 0x1a38)[0]
        RunKeyValu = unpack_from('<512s', cfg_blob, 0x1c38)[0]

        ServerData = [[0] * 3] * 16
        proxy = [[0] * 5] * 6
        if unpack_from('<I', cfg_blob, 0x0)[0] == FLAG_ENABLE:
            DLLremove_flag = 'Enable'
        else:
            DLLremove_flag = 'Disable'

        if unpack_from('<I', cfg_blob, 0x14)[0] == FLAG_ENABLE:
            FileDelete_flag = 'Enable'
        else:
            FileDelete_flag = 'Disable'

        if unpack_from('<I', cfg_blob, 0x18)[0] == FLAG_ENABLE:
            KeyLog_flag = 'Enable'
        else:
            KeyLog_flag = 'Disable'

        if unpack_from('<I', cfg_blob, 0x20)[0] == 0:
            Unknown_flag = 'Disable'
        else:
            Unknown_flag = 'Enable'

        if unpack_from('<I', cfg_blob, 0x263c)[0] == 0:
            BypassProcess_flag = 'Disable'
        else:
            BypassProcess_flag = 'Enable'

        (dns1, dns2, dns3, dns4) = unpack_from("<4L", cfg_blob, 0x2d0)
        custom_dns = cfg_blob[0x2d0:0x2e0]

        for i in xrange(16):
            if unpack_from('<B', cfg_blob, 0x2e0 + (i * 68))[0] != 0x0:
                ServerData[i] = unpack_from('<HH64s', cfg_blob, 0x2e0 + (i * 68))

        for i in xrange(4):
            proxy[i] = unpack_from('<2H64s64s64s', cfg_blob, 0xf20 + (i * 196))

        if unpack_from('>B', cfg_blob, 0x1230)[0] == 0:
            AutorunSetup = 'Run Registry or Service setup'
        elif unpack_from('>B', cfg_blob, 0x1230)[0] == 1:
            AutorunSetup = 'Service setup'
        elif unpack_from('>B', cfg_blob, 0x1230)[0] == 2:
            AutorunSetup = 'Run Registry'
        elif unpack_from('>B', cfg_blob, 0x1230)[0] == 3:
            AutorunSetup = 'Disable'

        if unpack_from('<I', cfg_blob, 0x1a34)[0] == HKEY_CLASSES_ROOT:
            RegistrySubkey = 'HKEY_CLASSES_ROOT'
        elif unpack_from('<I', cfg_blob, 0x1a34)[0] == HKEY_CURRENT_USER:
            RegistrySubkey = 'HKEY_CURRENT_USER'
        elif unpack_from('<I', cfg_blob, 0x1a34)[0] == HKEY_LOCAL_MACHINE:
            RegistrySubkey = 'HKEY_LOCAL_MACHINE'
        else:
            RegistrySubkey = unpack_from('<I', cfg_blob, 0x1110)[0]

        if unpack_from('>B', cfg_blob, 0x1e38)[0] == 0:
            InjectionFlag = 'Disable'
        else:
            InjectionFlag = 'Enable'

        if unpack_from('>B', cfg_blob, 0x3440)[0] == 0:
            ScCapFlug = 'Disable'
        else:
            ScCapFlug = 'Enable'

        CnCDay = 'Everyday'
        for x in xrange(672):
            if NetworkFlag[x] == 0x0:
                CnCDay = 'Network Activity Flag Enable(Check config file!)'

        IPscanValu1 = unpack_from('<I', cfg_blob, 0x3658)[0]
        IPscanValu2 = unpack_from('<I', cfg_blob, 0x3660)[0]
        IPscanValu3 = unpack_from('<I', cfg_blob, 0x3668)[0]
        IPscanValu4 = unpack_from('<I', cfg_blob, 0x3670)[0]
        IPscanPort1 = unpack_from('<H', cfg_blob, 0x365c)[0]
        IPscanPort2 = unpack_from('<H', cfg_blob, 0x3664)[0]
        IPscanPort3 = unpack_from('<H', cfg_blob, 0x366c)[0]
        IPscanPort4 = unpack_from('<H', cfg_blob, 0x3674)[0]
        (ip1, ip2, ip3, ip4) = unpack_from("<4L", cfg_blob, 0x367c)
        scanip = cfg_blob[0x367c:0x369c]

        if unpack_from('<I', cfg_blob, 0x3678)[0] == 0:
            IPscan_flag = 'Disable'
        else:
            IPscan_flag = 'Enable'

        # config write file
        p_data["Version"] = 3
        p_data["Version Info"] = vinfo
        p_data["Config Size"] = "0x{0:X}".format(cfg_sz)
        p_data["Delete DLL list"] = DLLremove_flag
        p_data["File Delete"] = FileDelete_flag
        p_data["Key Logger"] = KeyLog_flag
        p_data["Unknown Flag"] = Unknown_flag
        p_data["Sleep Time1"] = SleepTime1
        p_data["Sleep Time2"] = SleepTime2
        p_data["Network Activity"] = CnCDay
        if dns1 not in (0, 0xffffffff):
            p_data["Custom DNS 1"] = inet_ntoa(custom_dns[:4])
        if dns2 not in (0, 0xffffffff):
            p_data["Custom DNS 2"] = inet_ntoa(custom_dns[4:8])
        if dns3 not in (0, 0xffffffff):
            p_data["Custom DNS 3"] = inet_ntoa(custom_dns[8:12])
        if dns4 not in (0, 0xffffffff):
            p_data["Custom DNS 4"] = inet_ntoa(custom_dns[12:16])

        for z in xrange(16):
            if ServerData[z][0]:
                p_data["Server  {0}".format(z + 1)] = "{0}:{1} (Type {2})".format(ServerData[z][2].replace('\0', ''), ServerData[z][1], ServerData[z][0])

        for y in xrange(16):
            if ServerURL[y]:
                p_data["Server URL {0}".format(y + 1)] = ServerURL[y].replace('\0', '')

        for k in xrange(4):
            if proxy[k][1] != 0:
                p_data["Proxy {0}".format(k + 1)] = "{0}:{1}".format(proxy[k][2].replace('\0', ''), proxy[k][1])
                if proxy[k][3] != '\x00':
                    p_data["Proxy credentials {0}".format(k + 1)] = "{0}:{1}".format(proxy[k][3].replace('\0', ''), proxy[k][4].replace('\0', ''))

        p_data["Auto Start"] = AutorunSetup
        p_data["Install Folder"] = InstallFolder.replace('\0', '')
        p_data["Service Name"] = ServiceName.replace('\0', '')
        p_data["Service Display Name"] = ServiceDisplayName.replace('\0', '')
        p_data["Service Comment"] = ServiceComment.replace('\0', '')
        p_data["Registry Subkey"] = RegistrySubkey
        p_data["Registry Key"] = RunKey.replace('\0', '')
        p_data["Registry Value"] = RunKeyValu.replace('\0', '')
        p_data["Injection"] = InjectionFlag
        p_data["Injection Process1"] = InjectionProcess1.replace('\0', '')
        p_data["Injection Process2"] = InjectionProcess2.replace('\0', '')
        p_data["Injection Process3"] = InjectionProcess3.replace('\0', '')
        p_data["Injection Process4"] = InjectionProcess4.replace('\0', '')
        p_data["UACBypass"] = BypassProcess_flag
        p_data["UACBypass Process1"] = BypassProcess1.replace('\0', '')
        p_data["UACBypass Process2"] = BypassProcess2.replace('\0', '')
        p_data["UACBypass Process3"] = BypassProcess3.replace('\0', '')
        p_data["UACBypass Process4"] = BypassProcess4.replace('\0', '')
        p_data["Server ID1"] = ServerID1.replace('\0', '')
        p_data["Server ID2"] = ServerID2.replace('\0', '')
        p_data["Mutex"] = Mutex.replace('\0', '')
        p_data["Screen Capture"] = ScCapFlug
        p_data["Screen Capture Folder"] = ScreenCapFolder.replace('\0', '')
        p_data["IP Scan"] = IPscan_flag
        if IPscan_flag == "Enable":
            p_data["IP Scan value 1"] = IPscanValu1
            p_data["IP Scan port 1"] = IPscanPort1
            p_data["IP Scan value 2"] = IPscanValu2
            p_data["IP Scan port 2"] = IPscanPort2
            p_data["IP Scan value 3"] = IPscanValu3
            p_data["IP Scan port 3"] = IPscanPort3
            p_data["IP Scan value 4"] = IPscanValu4
            p_data["IP Scan port 4"] = IPscanPort4

        if ip1 not in (0, 0xffffffff):
            p_data["Scan IP 1"] = "{0} - {1}".format(inet_ntoa(scanip[:4]), (inet_ntoa(scanip[16:20])))
        if ip2 not in (0, 0xffffffff):
            p_data["Scan IP 2"] = "{0} - {1}".format(inet_ntoa(scanip[4:8]), (inet_ntoa(scanip[20:24])))
        if ip3 not in (0, 0xffffffff):
            p_data["Scan IP 3"] = "{0} - {1}".format(inet_ntoa(scanip[8:12]), (inet_ntoa(scanip[24:28])))
        if ip4 not in (0, 0xffffffff):
            p_data["Scan IP 4"] = "{0} - {1}".format(inet_ntoa(scanip[12:16]), (inet_ntoa(scanip[28:32])))

        return p_data

    def parse_config_winnti(self, cfg_blob, cfg_sz, cfg_addr, vinfo):
        p_data = OrderedDict()

        # config parsing
        SleepTime = unpack_from('>I', cfg_blob, 0x0c)[0]
        NetworkFlag = unpack_from('<672B', cfg_blob, 0x14)

        if cfg_sz == 0xd24:
            InstallDll = unpack_from('<32s', cfg_blob, 0xae4)[0]
            InstallData = unpack_from('<32s', cfg_blob, 0xb04)[0]
            ServiceName = unpack_from('<32s', cfg_blob, 0xb24)[0]
            ServiceDisplayName = unpack_from('<256s', cfg_blob, 0xc24)[0]

        ServerData = [[0] * 3] * 4
        if unpack_from('<I', cfg_blob, 0xc)[0] == FLAG_ENABLE:
            unknown_flag = 'Enable'
        else:
            unknown_flag = 'Disable'

        (dns1, dns2, dns3, dns4) = unpack_from("<4L", cfg_blob, 0x2b4)
        custom_dns = cfg_blob[0x2b4:0x2c4]

        for i in xrange(4):
            if unpack_from('<B', cfg_blob, 0x2c4 + (i * 68))[0] != 0x0:
                ServerData[i] = unpack_from('<HH64s', cfg_blob, 0x2c4 + (i * 68))

        CnCDay = 'Everyday'
        for x in xrange(672):
            if NetworkFlag[x] == 0x0:
                CnCDay = 'Network Activity Flag Enable(Check config file!)'

        # config write file
        p_data["Version"] = "winnti"
        p_data["Version Info"] = vinfo
        p_data["Config Size"] = "0x{0:X}".format(cfg_sz)
        p_data["Unknown Flag"] = unknown_flag
        p_data["Sleep Time"] = SleepTime
        p_data["Network Activity"] = CnCDay
        if dns1 not in (0, 0xffffffff):
            p_data["Custom DNS 1"] = inet_ntoa(custom_dns[:4])
        if dns2 not in (0, 0xffffffff):
            p_data["Custom DNS 2"] = inet_ntoa(custom_dns[4:8])
        if dns3 not in (0, 0xffffffff):
            p_data["Custom DNS 3"] = inet_ntoa(custom_dns[8:12])
        if dns4 not in (0, 0xffffffff):
            p_data["Custom DNS 4"] = inet_ntoa(custom_dns[12:16])

        for z in xrange(4):
            if ServerData[z][0]:
                p_data["Server  {0}".format(z + 1)] = "{0}:{1} (Type {2})".format(ServerData[z][2].replace('\0', ''), ServerData[z][1], ServerData[z][0])

        if cfg_sz == 0xd24:
            p_data["Install DLL"] = InstallDll.replace('\0', '')
            p_data["Install Data"] = InstallData.replace('\0', '')
            p_data["Service Name"] = ServiceName.replace('\0', '')
            p_data["Service Display Name"] = ServiceDisplayName.replace('\0', '')

        return p_data

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os, memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources=plugx_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task=task, rules=rules)

            for hit, address in scanner.scan():

                vad_base_addr, end = self.get_vad_base(task, address)
                proc_addr_space = task.get_process_address_space()
                data = proc_addr_space.zread(vad_base_addr, end - vad_base_addr)

                config_data = []
                offset1 = data.find("\xFF\x68\xa0\x02\x00\x00\x47\x57\x68")  # push 0x2a0
                offset2 = data.find("\x00\x68\xa0\x02\x00\x00\x50")  # push 0x2a0
                offset3 = data.find("\xF6\x68\xa0\x02\x00\x00\x46\x56\x68")  # push 0x2a0
                offset4 = data.find("\xDB\x68\xa0\x02\x00\x00\x43\x53\x68")  # push 0x2a0
                offset5 = data.find("\x83\xc4\x0c\x68\x10\x27\x00\x00")  # push 2710h # Config 0x36A4
                offset6 = data.find("\x00\x68\xa0\x02\x00\x00\xB0")  # push 0x2a0

                if offset1 > 0:
                    offset = offset1
                elif offset2 > 0:
                    offset = offset2
                elif offset3 > 0:
                    offset = offset3
                elif offset4 > 0:
                    offset = offset4
                elif offset5 > 0:
                    offset = offset5
                elif offset6 > 0:
                    offset = offset6
                else:
                    continue

                while not (data[offset] == "\x68" and (data[offset + 5] == "\xe8" or data[offset + 6] == "\xe8")) and offset > 0:
                    offset -= 1
                if data[offset] != "\x68":
                    continue

                # Now were at:
                # push 0xxxxxx <- config address
                # call 0xxxxxx
                (config_addr, ) = unpack("=I", data[offset + 1:offset + 5])

                # Find previous push imm
                offset -= 1
                while not data[offset] == "\x68":
                    offset -= 1
                if data[offset] != "\x68":
                    continue

                # Version info
                info_start = data.find('\\work\\')
                if info_start > 0:
                    info_end = data.find('\\', info_start + 6)
                    version_info = data[info_start + 6: info_end]
                else:
                    version_info = "Null"

                (config_size, ) = unpack("=I", data[offset + 1:offset + 5])

                config_addr -= vad_base_addr
                if config_size == 0x1510:
                    config_addr = config_addr + 4

                config_blob = data[config_addr:config_addr + config_size]
                if config_size == 0xd24 or config_size == 0xae4:
                    config_data.append(self.parse_config_winnti(config_blob, config_size, config_addr, version_info))
                elif config_size == 0x2540:
                    config_data.append(self.parse_config2(config_blob, config_size, config_addr, version_info))
                elif config_size == 0x2d58:
                    config_data.append(self.parse_config2(config_blob, config_size, config_addr, version_info))
                elif config_size == 0x36A4:
                    config_data.append(self.parse_config3(config_blob, config_size, config_addr, version_info))
                else:
                    config_data.append(self.parse_config(config_blob, config_size, config_addr, version_info))

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
                    outfd.write("{0:<25}: {1}\n".format(id, param))
