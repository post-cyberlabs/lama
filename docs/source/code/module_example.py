"""
Example Module class

"""

from html import escape

from lama.utils.type import Type
from lama.analyzer.module import Module
from lama.models.indicator import Indicator
from lama.models.module_status import ModuleStatus


class ExampleModule(Module):
    """
    ExampleModule class

    Args :
        **malware** (Malware) : Malware to be analyzed.
    """

    _module_name = "ExampleModule"

    def __init__(self, malware, local_path):
        super().__init__("Example", malware, local_path)
        self._param_local1 = 10
        self.malware.set_module_status(self.module_cls_name,
                                       ModuleStatus.MODULE_NOT_ANALYZED)

    def check_elem(self):
        """
        (Override super)
        Check if the analysis is finished.
        """
        return False

    @Module.dec_analyze
    def analyze(self):
        """
        Static analyze method. (Override super)
        """
        return True

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                      name="name1",
                                      content_type=Type.STRING,
                                      content="content1",
                                      score=0)
        self._malware.get_module_status(self.module_cls_name
                                        ).add_indicator(indicator)

    # Optionnal
    def html_report(content):
        html = "<div>"
        for item in content:
            if item.name == "name1":
                html += "Name1 : {}".format(escape(item.content))
            else:
                # Error
                pass
        html += "</div>"
        return html
