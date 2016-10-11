"""
DockerModuleExample class

"""
import os

from html import escape

from lama.utils.type import Type
from lama.input.input import Input
from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule


class DockerModuleExample(DockerModule):
    """DockerModuleExample class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "DockerModuleExample"

    def __init__(self, malware, local_path):
        super().__init__("DockerModuleExample", malware, local_path, "container_name")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_res = self.json_decode(self._result)
        if not json_res:
            return

        if "file" in json_res:
            name = "file"
            path = json_res['file']
            file_path = os.path.join(path, name)
            extract_file = self.malware.add_extract_malware_path(self.module_cls_name, file_path, name)
            Input.analyse_malware(extract_file)

        if "key1" in json_res:
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="key1",
                                          content_type=Type.STRING,
                                          content=json_res["key1"],
                                          score=0)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        for item in content:
            if item.name == "key1":
                html += "Key1 : {}".format(escape(item.content))
            else:
                # Error
                pass
        html += "</div>"
        return html
