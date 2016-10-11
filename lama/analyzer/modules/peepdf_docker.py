"""
PeePDF Docker class

This module allow to annalyze PDf with PeePDF.
PeePDF is on a Docker container
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


class PeePDFDocker(DockerModule):
    """PeePDFDocker class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "PeePDF"

    def __init__(self, malware, local_path):
        super().__init__("PeePDF", malware, local_path, "peepdf")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_peepedf = self.json_decode(self._result)
        if not json_peepedf:
            return

        if 'js' in json_peepedf:
            for i, js in enumerate(json_peepedf['js']):
                indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                              name="js",
                                              content_type=Type.JS,
                                              content=js,
                                              score=5)
                self._malware.get_module_status(self.module_cls_name
                                                ).add_indicator(indicator)

        if 'uris' in json_peepedf:
            for js in json_peepedf['uris']:
                indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                              name="uris",
                                              content_type=Type.URL,
                                              content=js,
                                              score=4)
                self._malware.get_module_status(self.module_cls_name
                                                ).add_indicator(indicator)

        if 'error' in json_peepedf:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="error",
                                          content_type=Type.BASE64,
                                          content=json_peepedf["error"],
                                          score=-1)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        for item in content:
            if item.name == "uris":
                html += "<label class=\"label label-warning\">URI</label> <pre>{}</pre>".format(escape(base64.b64decode(item.content).decode("utf-8")))
            elif item.name == "js":
                html += "<label class=\"label label-important\">Java Script</label><pre>{}</pre>".format(escape(base64.b64decode(item.content).decode("utf-8")))
            elif item.name == "error":
                html += "<b>Error : </b>{}".format(escape(base64.b64decode(item.content).decode("utf-8")))
            else:
                html += "LAMA PARSE ERROR"
        html += "</div>"
        return html
