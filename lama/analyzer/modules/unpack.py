"""
Unpack Docker class

"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import os
import json

from html import escape

from lama.utils.type import Type
from lama.input.input import Input
from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule


class UnpackDocker(DockerModule):
    """UnpackDockerDocker class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "Unpack"

    def __init__(self, malware, local_path):
        super().__init__("Unpack", malware, local_path, "unpack")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_unpack = self.json_decode(self._result)
        if not json_unpack:
            return

        if "res" in json_unpack and json_unpack["res"] == "ok":
            for path, subdirs, files in os.walk(self._out_tmp_path):
                for name in files:
                    file_path = os.path.join(path, name)
                    extract_malware = self.malware.add_extract_malware_path(self.module_cls_name, file_path, name)
                    Input.analyse_malware(extract_malware)

        if "error" in json_unpack:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="error",
                                          content_type=Type.BASE64,
                                          content=json_unpack["error"],
                                          score=-1)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        for item in content:
            if item.name == "error":
                html += "<b>Error : </b>{}".format(escape(item.content))
            else:
                html += "LAMA PARSE ERROR"
        html += "</div>"
        return html
