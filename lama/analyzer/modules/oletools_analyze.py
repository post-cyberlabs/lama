"""
OletoolsAnalyze Docker class

This module allow to annalyze ole files with oletools.
OletoolsAnalyze is on a Docker container
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
import validators

from html import escape

from lama.utils.type import Type
from lama.input.input import Input
from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule


class OletoolsAnalyze(DockerModule):
    """OletoolsAnalyze class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "Oletools Analyze"

    def __init__(self, malware, local_path):
        super().__init__("Oletools Analyze", malware, local_path, "oletools-analyze")

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

        for item in json_ole:
            if "IOC" in item["type"]:
                score = 7
                if "URL" in item['description'] and validators.url(item['keyword']):
                    extract_malware = self.malware.add_extract_malware(
                        self.module_cls_name, item['keyword'], Type.get_label(Type.URL))
                    Input.analyse_malware(extract_malware)
            elif "AutoExec" in item["type"]:
                score = 7
            elif "Suspicious" in item["type"]:
                score = 5
            elif "VBA string" in item["type"]:
                score = 3
            elif "Hex String" in item["type"]:
                score = 1
            else:
                score = -1

            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="item",
                                          content_type=Type.JSON,
                                          content=json.dumps(item),
                                          score=score)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        html_type = {'important': "",
                     'warning': "",
                     'info': "",
                     'inverse': ""}

        for item in content:
            if item.name == "item":
                decoded_content = json.loads(item.content)
                score = item.score

                if score >= 5:
                    type_label = "important"
                elif score >= 2:
                    type_label = "warning"
                elif score > 0:
                    type_label = "info"
                else:
                    type_label = "inverse"

                html_type[type_label] += "<label class=\"label label-{}\">{}</label> -> <b>{}</b><pre>{}</pre>".format(
                    type_label,
                    escape(decoded_content["type"]),
                    escape(decoded_content["keyword"]),
                    escape(decoded_content["description"])
                )
            else:
                html += "LAMA PARSE ERROR ({})".format(item.name)

        html += html_type['important']
        html += html_type['warning']
        html += html_type['info']
        html += html_type['inverse']
        html += "</div>"
        return html
