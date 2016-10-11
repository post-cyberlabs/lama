"""
JsHtmlExtract Docker class

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


class JsHtmlExtract(DockerModule):
    """JsHtmlExtract class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "JS HTML Extractor"

    def __init__(self, malware, local_path):
        super().__init__("JS HTML Extractor", malware, local_path, "js-html-extract")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_jsextract = self.json_decode(self._result)
        if not json_jsextract:
            return

        if 'code' in json_jsextract:
            for i, c in enumerate(json_jsextract['code']):
                if bool(c[0] and c[0].strip()):
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="code_header",
                                                  content_type=Type.BASE64,
                                                  content=base64.b64encode(bytes(c[0], "utf-8")).decode('utf-8'),
                                                  option=i,
                                                  score=0)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(indicator)

                if bool(c[1] and c[1].strip()):
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="code_body",
                                                  content_type=Type.BASE64,
                                                  content=base64.b64encode(bytes(c[1], "utf-8")).decode('utf-8'),
                                                  option=i,
                                                  score=0)
                    extract_malware = self.malware.add_extract_malware(self.module_cls_name, c[1])
                    Input.analyse_malware(extract_malware)

                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        html_parts = dict()
        for item in content:
            if item.name == "code_header" or item.name == "code_body" and item.option not in html_parts:
                html_parts[item.option] = {'header': None, 'body': None}

            if item.name == "code_header":
                html_parts[item.option]['header'] = "<label class=\"label label-info\">Code Header</label> <pre>{}</pre>".format(escape(base64.b64decode(item.content).decode('utf-8')))
            elif item.name == "code_body":
                html_parts[item.option]['body'] = "<label class=\"label label-info\">Code Body</label> <pre>{}</pre>".format(escape(base64.b64decode(item.content).decode('utf-8')))
            elif item.name == "error":
                html += "<label class=\"label label-inverse\">Error</label> <pre>{}</pre>".format(escape(base64.b64decode(item.content).decode('utf-8')))
            else:
                html += "LAMA PARSE ERROR<br/>"

        for i in sorted(html_parts):
            html += "<h6>Script " + i + "</h6>"
            if html_parts[i]['header']:
                html += html_parts[i]['header']
            if html_parts[i]['body']:
                html += html_parts[i]['body']
        html += "</div>"
        return html
