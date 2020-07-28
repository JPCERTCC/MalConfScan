# Detecting ***** for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/MalConfScan/
#
# How to use
# scan all processes:
# $ python3 vol.py -f images.mem -p [plugin_directory] *****scan
# specifiy scaning process with PID:
# $ python3 vol.py -f images.mem -p [plugin_directory] *****scan -pid [PID]

from . import basescan

import logging
from collections import OrderedDict

try:
    """import crypto libs here"""
    has_crypto = True
except ImportError:
    has_crypto = False

# logger for volatility
vollog = logging.getLogger(__name__)


class templateConfig(basescan.baseConfig):
    """please rename class name the same name as [yara_rule_name]Config."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._yara_sig = {
            'namespace1': 'rule asyncrat { \
                strings: \
                    $b1 = {DE AD BE EF}\
                    $s1 = "this is sample rule" ascii wide nocase \
                condition: all of them} '
        }
        self._config_sig = [b"some signature will come here"]  # signature for searching configuration data
        self._config_index = {}

    def extract_config(self, data: bytes, malname: str, vad_base_addr: int) -> OrderedDict:
        """process dump data will be passed as data"""
        config_data = OrderedDict()

        ###
        # Write config extraction logic here.
        ###

        return config_data
