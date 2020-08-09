import logging
import sys
from typing import Iterable, Tuple
from collections import OrderedDict

from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.plugins import yarascan
from volatility.plugins.windows import pslist
from volatility.plugins.windows import vaddump

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    """Import cypto modules here"""
    has_crypto = True
except ImportError:
    has_crypto = False

# logger for volatility
vollog = logging.getLogger(__name__)

outfd = sys.stdout
delim = '-' * 70


class baseConfig(interfaces.plugins.PluginInterface):
    """Base class for MalConfScan utils."""

    def __init__(self, *args, **kwargs) -> None:
        self._target_proc = None
        super().__init__(*args, **kwargs)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Memory layer for the kernel',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols", description="Windows kernel symbols"),
                requirements.ListRequirement(name='pid',
                                             description='Filter on specific process IDs',
                                             element_type=int,
                                             optional=True),
                requirements.PluginRequirement(name='pslist', plugin=pslist.PsList, version=(1, 0, 0)),
                requirements.PluginRequirement(name='vaddump', plugin=vaddump.VadDump, version=(1, 1, 0))
                ]

    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.
        Args:
            task: The EPROCESS object of which to traverse the vad tree
        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    @staticmethod
    def get_vad_base(task: interfaces.objects.ObjectInterface, address: int) -> interfaces.objects.ObjectInterface:
        """Get the VAD address block which contains the second argument address."""
        for vad in task.get_vad_root().traverse():
            end = vad.get_end()
            start = vad.get_start()
            if start <= address and address <= end:
                return vad

    @staticmethod
    def remove_00_bytes(data: bytes) -> bytes:
        """remove 0x00 from data"""
        _tmp = bytes()
        for b in data:
            if b != 0:
                _tmp += b.to_bytes(1, "little")
        return _tmp

    @staticmethod
    def remove_unascii(data: bytes) -> str:
        """remove non-ascii bytes from bytes"""
        if len(data) < 1:
            return data
        cleaned = ""
        for d in data:
            if 0x20 <= d and d <= 0x7F:
                cleaned += chr(d)
        return cleaned

    def main_process(self) -> (int, str, str, int, int, int, OrderedDict):
        layer = self.context.layers[self.config['primary']]
        rules = yara.compile(sources=self._yara_sig)  # rename signature name
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        if layer.metadata.get('os', None) in ['Windows', 'Unknown']:

            # scan each process and find the memory block which contains malicious code
            for task in pslist.PsList.list_processes(context=self.context,
                                                     layer_name=self.config['primary'],
                                                     symbol_table=self.config['nt_symbols'],
                                                     filter_func=filter_func):
                layer_name = task.add_process_layer()
                layer = self.context.layers[layer_name]

                for offset, hit, _, value in layer.scan(context=self.context,
                                                        scanner=yarascan.YaraScanner(rules=rules),
                                                        sections=self.get_vad_maps(task)):
                    vad = self.get_vad_base(task, offset)
                    vad_base_addr, end = vad.get_start(), vad.get_end()  # get VAD memory block address
                    image_filename = task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count, errors='replace')
                    pid = task.UniqueProcessId
                    data = vaddump.VadDump.vad_dump(context=self.context, layer_name=task.add_process_layer(), vad=vad)
                    self._target_proc = task
                    config_data = self.extract_config(data, hit, vad_base_addr)
                    yield (pid, image_filename, hit, vad_base_addr, end, config_data)
                    break

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        """[INFO]: this method would be overrided by each scanner"""
        raise NotImplementedError("extract_config method has not been implemented.")

    def render_cli_text(self, pid, image_filename, malname, start, end, config_data) -> None:
        """CLI render method for malconfscan."""
        outfd.write("[+] Detect malware by Yara rules.\n")
        outfd.write("[+]   Process Name      : {0}\n".format(image_filename))
        outfd.write("[+]   Process ID        : {0}\n".format(pid))
        outfd.write("[+]   Malware name      : {0}\n".format(malname))
        outfd.write("[+]   Base Address(VAD) : 0x{0:X}\n".format(start))
        outfd.write("[+]   Size              : 0x{0:X}\n".format(end - start + 1))

        outfd.write("{0}\n".format(delim))
        outfd.write("Process: {0} ({1})\n\n".format(image_filename, pid))

        outfd.write("[Config Info]\n")
        for id, param in config_data.items():
            outfd.write("{0:<22}: {1}\n".format(id, param))

        return

    def _generator(self):
        pass

    def footer_message(self):
        yield (0, ("", ""))

    def run(self) -> renderers.TreeGrid:
        if not has_yara:
            vollog.info("Python yara module not found, plugin (and dependent plugins) not available")
            raise ImportError
        if not has_crypto:
            vollog.info("Python pycrypto module not found, plugin (and dependent plugins) not available")
            raise ImportError

        outfd.write("\n[+] Searching memory by Yara rules.\n")

        for pid, image_filename, malname, start, end, config_data in self.main_process():
            self.render_cli_text(pid, image_filename, malname, start, end, config_data)

        return renderers.TreeGrid([("SCAN FINISHED.", str), ("THANK YOU.", str)], self.footer_message())  # return mock message.
