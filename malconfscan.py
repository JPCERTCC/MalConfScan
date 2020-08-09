# MalConfScan: Detecting Malware Configuration for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#

import logging
import os
import sys
from importlib import import_module
from typing import Iterable, Tuple
from collections import OrderedDict
from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.plugins import yarascan
from volatility.plugins.windows import pslist


vollog = logging.getLogger(__name__)
outfd = sys.stdout
delim = '-' * 70

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

try:
    from tqdm import tqdm
    has_tqdm = True
except ImportError:
    has_tqdm = False


class malconfScan(interfaces.plugins.PluginInterface):
    """Detect infected processes and parse malware configuration"""

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

    def render_cli_text(self, pid, image_filename, malname, start, end, config_data) -> None:
        """CLI render method for malconfscan."""
        outfd.write("\n" + delim + "\n")
        # outfd.write("[+] Detect malware by Yara rules.\n")
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

    def main_process(self) -> (int, str, str, int, int, int, OrderedDict):
        layer = self.context.layers[self.config['primary']]
        base = os.path.dirname(os.path.abspath(__file__))
        rules = yara.compile(base + "/yara/rule.yara")
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        if layer.metadata.get('os', None) in ['Windows', 'Unknown']:
            tasks = list(pslist.PsList.list_processes(context=self.context,
                                                      layer_name=self.config['primary'],
                                                      symbol_table=self.config['nt_symbols'],
                                                      filter_func=filter_func))
            # progress bar
            if has_tqdm:
                progress_bar = tqdm(total=len(tasks))
                progress_bar.set_description('MalConfScan progress')

            for task in tasks:
                layer_name = task.add_process_layer()
                layer = self.context.layers[layer_name]
                vollog.info("Scaning: pid: {}  process name: {}".format(task.UniqueProcessId, task.ImageFileName.cast("string", max_length=task.ImageFileName.vol.count, errors='replace')))
                for offset, hit, name, value in layer.scan(context=self.context,
                                                           scanner=yarascan.YaraScanner(rules=rules),
                                                           sections=self.get_vad_maps(task)):

                    malname = str(hit).lower()
                    if str(hit) in ["Himawari", "Lavender", "Armadill", "zark20rk"]:
                        malname = "redleaves"
                    if str(hit) in "TSC_Loader":
                        malname = "tscookie"
                    if "Agenttesla" in str(hit):
                        malname = "agenttesla"

                    sys.path += [os.path.dirname(os.path.abspath(__file__))]
                    try:
                        module = import_module("utils.{name}scan".format(name=malname))
                        module_cls = getattr(module, malname + "Config")
                        self.context.config["plugins.malconfScan.pid"] = [task.UniqueProcessId]  # overwrite pid argument with detected proc_id
                        instance = module_cls(self.context, self.config_path)
                    except ModuleNotFoundError:
                        instance = None
                        vollog.error("Can't loading module utils.{name}scan".format(name=malname))

                    if instance:
                        for pid, image_filename, malname, start, end, config_data in instance.main_process():
                            yield pid, image_filename, malname, start, end, config_data
                        break

                # update progress bar
                if has_tqdm:
                    progress_bar.update(1)
            else:
                if has_tqdm:
                    progress_bar.close()

        elif layer.metadata.get('os', None) in "linux":
            vollog.error("Please use linux_malconfscan.")
        else:
            vollog.error("This command does not support the selected profile.")

    def _generator(self):
        pass

    def footer_message(self):
        yield (0, ("", ""))

    def run(self) -> renderers.TreeGrid:
        if not has_yara:
            vollog.info("Python yara module not found, plugin (and dependent plugins) not available")
            raise ImportError

        outfd.write("\n\n[+] Searching memory by Yara rules.\n")

        result = []

        for pid, image_filename, malname, start, end, config_data in self.main_process():
            result.append((pid, image_filename, malname, start, end, config_data))

        outfd.write("[+] Yara rules detected {} malicious process(es).\n".format(len(result)))

        for pid, image_filename, malname, start, end, config_data in result:
            self.render_cli_text(pid, image_filename, malname, start, end, config_data)

        return renderers.TreeGrid([("SCAN FINISHED.", str), ("THANK YOU.", str)], self.footer_message())  # return mock message.
