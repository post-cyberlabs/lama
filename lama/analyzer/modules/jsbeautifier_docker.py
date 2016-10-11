"""
JsBeautifier Docker class

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
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule
from lama.models.indicator import Indicator


class JsBeautifierDocker(DockerModule):
    """JsBeautifierDocker class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "JS Beautifier"

    def __init__(self, malware, local_path):
        super().__init__("JS Beautifier", malware, local_path, "jsbeautifier")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_jsbeautify = self.json_decode(self._result)
        if not json_jsbeautify:
            return

        if 'code' in json_jsbeautify:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="code",
                                          content_type=Type.BASE64,
                                          content=json_jsbeautify["code"],
                                          score=0)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)
        if 'error' in json_jsbeautify:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="error",
                                          content_type=Type.BASE64,
                                          content=json_jsbeautify["error"],
                                          score=-1)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        for item in content:
            if item.name == "code":
                html += "<label class=\"label label-info\">Code</label> <pre>{}</pre>".format(escape(base64.b64decode(item.content).decode('utf-8')))
            elif item.name == "error":
                html += "<label class=\"label label-inverse\">Error</label> <pre>{}</pre>".format(escape(base64.b64decode(item.content).decode('utf-8')))
            else:
                html += "LAMA PARSE ERROR"
        html += "</div>"
        return html
