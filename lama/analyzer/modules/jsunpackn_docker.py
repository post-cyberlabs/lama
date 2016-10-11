"""
Jsunpackn Docker class

This module allow to annalyze PDf with jsunpack-n.
Jsunpack-n is on a Docker container
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
from lama.input.input import Input
from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule


class JsunpacknDocker(DockerModule):
    """JsunpacknDocker class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "JS Unpack-n"

    def __init__(self, malware, local_path):
        super().__init__("JS Unpack-n", malware, local_path, "jsunpackn")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_jsunpackn = self.json_decode(self._result)
        if not json_jsunpackn:
            return

        if 'info' in json_jsunpackn:
            info = json_jsunpackn['info']
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="info",
                                          content_type=Type.STRING,
                                          content=info,
                                          score=0)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)
        if 'sources' in json_jsunpackn:
            for source in json_jsunpackn['sources']:
                indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                              name="source",
                                              content_type=Type.BASE64,
                                              content=source,
                                              score=4)
                self._malware.get_module_status(self.module_cls_name
                                                ).add_indicator(indicator)
                extract_malware = self.malware.add_extract_malware(self.module_cls_name,
                                                                   base64.b64decode(source))
                Input.analyse_malware(extract_malware)

        if 'error' in json_jsunpackn:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="error",
                                          content_type=Type.STRING,
                                          content=json_jsunpackn["error"],
                                          score=-1)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        for item in content:
            if item.name == "info":
                html += "<label class=\"label label-info\">Info</label> <pre>{}</pre>".format(escape(item.content))
            elif item.name == "source":
                html += "<label class=\"label label-warning\">Source</label><pre>{}</pre>".format(escape(base64.b64decode(item.content).decode("utf-8")))
            elif item.name == "error":
                html += "<b>Error : </b>{}".format(escape(item.content))
            else:
                html += "LAMA PARSE ERROR"
        html += "</div>"
        return html
