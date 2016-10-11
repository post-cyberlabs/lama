"""
OletoolsMRaptor Docker class

This module allow to annalyze ole files with oletools.
OletoolsMRaptor is on a Docker container
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import json
import base64

from html import escape

from lama.utils.type import Type
from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule


class OletoolsMRaptor(DockerModule):
    """OletoolsMRaptor class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "Oletools Mraptor"

    def __init__(self, malware, local_path):
        super().__init__("Oletools MRaptor", malware, local_path, "oletools-mraptor")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """

        if not self._result:
            return

        json_ole = self.json_decode(self._result)
        if not json_ole:
            return

        if 'returncode' in json_ole:
            returncode = json_ole['returncode']
            if returncode == 0:
                # No macro
                score = 1
            elif returncode == 1:
                # Not MS Office
                score = 0
            elif returncode == 2:
                # Macro OK
                score = 1
            elif returncode == 10:
                # error
                score = 0
            elif returncode == 20:
                # SUSPICIOUS
                score = 5
            else:
                # Other ???
                score = 0

            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="returncode",
                                          content_type=Type.INTEGER,
                                          content=returncode,
                                          score=score)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

        if 'out' in json_ole:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="out",
                                          content_type=Type.JSON,
                                          content=json_ole['out'],
                                          score=0)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"

        for item in content:
            if item.name == "out":
                out = base64.b64decode(item.content)
                html += "<label class=\"label label-info\">out</label><pre>{}</pre>".format(escape(out.decode("utf-8")))

            if item.name == "returncode":
                html += "<label class=\"label label-info\">Return code : {}</label><br/>".format(escape(item.content))

        html += "</div>"
        return html
