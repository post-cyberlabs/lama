"""
URL Analyzer Docker class

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
import logging
from lama.input.input import Input
from lama.utils.type import Type
from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule


class UrlAnalyzerDocker(DockerModule):
    """UrlAnalyzerDocker class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "URL Analyzer"

    def __init__(self, malware, local_path):
        super().__init__("JS Unpack-n", malware, local_path, "url_analyzer")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_urls = self.json_decode(self._result)
        if not json_urls:
            return

        if 'urls' in json_urls:
            for url in json_urls['urls']:
                if 'path' in json_urls['urls'][url]:
                    path = json_urls['urls'][url]['path']
                    if path.startswith("/lama/out/"):
                        path = path[10:]
                    file_path = os.path.join(self._out_tmp_path, path)
                    path, name = os.path.split(file_path)
                    extract_malware = self.malware.add_extract_malware_path(self.module_cls_name, file_path, name)
                    Input.analyse_malware(extract_malware)
                if 'error' in json_urls['urls'][url]:
                    content = "{} : {}".format(url, json_urls['urls'][url]['error'])
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="error",
                                                  content_type=Type.STRING,
                                                  content=content,
                                                  score=-1)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(indicator)

        if 'error' in json_urls:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="error",
                                          content_type=Type.STRING,
                                          content=json_urls["error"],
                                          score=-1)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)


    # def html_report(content):
    #     html = "<div>"
    #     for item in content:
    #         if item.name == "info":
    #             html += "<label class=\"label label-info\">Info</label> <pre>{}</pre>".format(escape(item.content))
    #         elif item.name == "source":
    #             html += "<label class=\"label label-warning\">Source</label><pre>{}</pre>".format(escape(base64.b64decode(item.content).decode("utf-8")))
    #         elif item.name == "error":
    #             html += "<b>Error : </b>{}".format(escape(item.content))
    #         else:
    #             html += "LAMA PARSE ERROR"
    #     html += "</div>"
    #     return html
