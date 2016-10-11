"""
OletoolsExctract Docker class

This module allow to annalyze ole files with oletools.
OletoolsExctract is on a Docker container
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

from html import escape

from lama.utils.type import Type
from lama.input.input import Input
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule
from lama.models.indicator import Indicator


class OletoolsExctract(DockerModule):
    """OletoolsExctract class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "Oletools Extract"

    def __init__(self, malware, local_path):
        super().__init__("Oletools Extract", malware, local_path, "oletools-extract")

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
            if 'type' in item and (
                item['type'] == 'MHTML' or
                    item['type'] == 'OLE'):
                if 'analysis' in item and item['analysis']:
                    for analyse in item['analysis']:
                        if "IOC" in analyse["type"]:
                            score = 7
                        elif "AutoExec" in analyse["type"]:
                            score = 7
                        elif "Suspicious" in analyse["type"]:
                            score = 5
                        elif "VBA string" in analyse["type"]:
                            score = 3
                        elif "Hex String" in analyse["type"]:
                            score = 1
                        else:
                            score = -1

                        indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                      name="analysis",
                                                      content_type=Type.JSON,
                                                      content=json.dumps(analyse),
                                                      score=score)
                        self._malware.get_module_status(self.module_cls_name
                                                        ).add_indicator(
                                                            indicator)
                if 'macros' in item:
                    for analyse in item['macros']:
                        indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                      name="macros",
                                                      content_type=Type.JSON,
                                                      content=json.dumps(analyse),
                                                      score=3)
                        self._malware.get_module_status(self.module_cls_name
                                                        ).add_indicator(
                                                            indicator)
                        extract_malware = self.malware.add_extract_malware(
                            self.module_cls_name, analyse['code'])
                        Input.analyse_malware(extract_malware)

    def html_report(content):
        html = "<div>"

        html_type = {'important': "",
                     'warning': "",
                     'info': "",
                     'inverse': ""}
        for item in content:
            if item.name == "analysis":
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
            elif item.name == 'macros':
                decoded_content = json.loads(item.content)
                html += "<label class=\"label label-info\">Source</label> : <b>{}</b><pre>{}</pre>".format(escape(decoded_content['vba_filename']),
                                                                                                           escape(decoded_content['code']))
            else:
                html += "LAMA PARSE ERROR"

        html += html_type['important']
        html += html_type['warning']
        html += html_type['info']
        html += html_type['inverse']
        html += "</div>"
        return html
