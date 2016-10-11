"""
peframe Docker class

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

from lama.utils.file import File
from lama.utils.type import Type
from lama.utils.ftp import LamaFtp
from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule


class Peframe(DockerModule):
    """peframe class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "PEFrame"

    def __init__(self, malware, local_path):
        super().__init__("PEframe", malware, local_path, "peframe")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        if not self._result:
            return

        json_pe = self.json_decode(self._result)
        if not json_pe:
            return

        tmp_result_file = File.create_tmp_file("peframe.txt", self._result)
        remote_path = LamaFtp.upload_from_module(local_path=tmp_result_file+"/peframe.txt",
                                                 analysis_uid=self.malware.analysis_uid,
                                                 malware_uid=self.malware.uid,
                                                 module_cls_name=self.module_cls_name,
                                                 remote_path="",
                                                 remote_name="peframe.txt")

        indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                      name="result_json",
                                      content_type=Type.FILE,
                                      content=remote_path,
                                      score=0)
        self._malware.get_module_status(self.module_cls_name
                                        ).add_indicator(
                                            indicator)

        # ip_found
        if "ip_found" in json_pe:
            for ip in json_pe['ip_found']:
                indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                              name="ip",
                                              content_type=Type.IP,
                                              content=ip,
                                              score=3)
                self._malware.get_module_status(self.module_cls_name
                                                ).add_indicator(
                                                    indicator)

        # url_found
        if "url_found" in json_pe:
            for url in json_pe['url_found']:
                indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                              name="url",
                                              content_type=Type.URL,
                                              content=url,
                                              score=2)
                self._malware.get_module_status(self.module_cls_name
                                                ).add_indicator(
                                                    indicator)

        # url_found
        if "file_found" in json_pe:
            file_found = json_pe['file_found']

            # file_found->WebPage
            if "Web Page" in file_found:
                for webpage in file_found['Web Page']:
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="webpage",
                                                  content_type=Type.URL,
                                                  content=webpage,
                                                  score=1)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)

        # pe_info
        if "pe_info" in json_pe and json_pe['pe_info']:
            pe_info = json_pe['pe_info']

            # pe_info->sections_info
            if "sections_info" in pe_info:
                for section in pe_info['sections_info']:
                    score = 3 if section['suspicious'] else 0
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="section_info",
                                                  content_type=Type.STRING,
                                                  content=section['name'],
                                                  score=score)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)

            # pe_info->detected
            if "detected" in pe_info:
                for detected in pe_info['detected']:
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="detected",
                                                  content_type=Type.STRING,
                                                  content=detected,
                                                  score=4)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)


            # pe_info->packer_info
            if "packer_info" in pe_info:
                for pack_info in pe_info['packer_info']:
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="packer_info",
                                                  content_type=Type.STRING,
                                                  content=pack_info,
                                                  score=0)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)

            # pe_info->directories
            if "directories" in pe_info:
                for directorie in pe_info['directories']:
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="directories",
                                                  content_type=Type.STRING,
                                                  content=directorie,
                                                  score=0)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)

            # pe_info->apialert_info
            if "apialert_info" in pe_info:
                for api in pe_info['apialert_info']:
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="apialert_info",
                                                  content_type=Type.STRING,
                                                  content=api,
                                                  score=0)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)

            # pe_info->antidbg_info
            if "antidbg_info" in pe_info:
                for antidbg in pe_info['antidbg_info']:
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="antidbg_info",
                                                  content_type=Type.STRING,
                                                  content=antidbg,
                                                  score=3)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)

            # pe_info->antivm_info
            if "antivm_info" in pe_info:
                for antidbg in pe_info['antivm_info']:
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="antivm_info",
                                                  content_type=Type.STRING,
                                                  content=antidbg,
                                                  score=4)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(
                                                        indicator)

    def html_report(content):
        html = "<div>"
        html_info = ""
        html_warning = ""
        html_part = dict()
        section_info_label = "info"
        content.sort(key=lambda item: item.score)
        for item in reversed(content):

            if item.name not in html_part:
                html_part[item.name] = ""
            if item.name == "section_info":
                label = "OK"
                if item.score > 1:
                    section_info_label = "warning"
                    label = "Suspicious"
                html_part[item.name] += "<li>{} : {}</li>".format(escape(item.content), label)
            elif item.name == "result_json":
                html += "<label class=\"label\">PEFrame result json : </label> <a href=\"/file?path={}\">peframe.txt</a><br />".format(item.content)
            else:
                html_part[item.name] += "<li>{}</li>".format(escape(item.content))

        for k in sorted(html_part):
            html_part[k] = "<ul>{}</ul>".format(html_part[k])
            if k == "ip":
                html_warning += "<label class=\"label label-warning\">IP</label>{}".format(html_part[k])
            elif k == "detected":
                html_warning += "<label class=\"label label-warning\">Detected</label>{}".format(html_part[k])
            elif k == "antidbg_info":
                html_warning += "<label class=\"label label-warning\">Anti Debug</label>{}".format(html_part[k])
            elif k == "antivm_info":
                html_warning += "<label class=\"label label-warning\">Anti VM</label>{}".format(html_part[k])
            elif k == "url":
                html_info += "<label class=\"label label-info\">URL</label>{}".format(html_part[k])
            elif k == "webpage":
                html_info += "<label class=\"label label-info\">Web Page</label>{}".format(html_part[k])
            elif k == "packer_info":
                html_info += "<label class=\"label label-info\">Packer info</label>{}".format(html_part[k])
            elif k == "directories":
                html_info += "<label class=\"label label-info\">Directories</label>{}".format(html_part[k])
            elif k == "apialert_info":
                html_info += "<label class=\"label label-info\">API alert info</label>{}".format(html_part[k])
            elif k == "section_info":
                if section_info_label == "info":
                    html_info += "<label class=\"label label-{}\">Section info</label>{}".format(section_info_label, html_part[k])
                else:
                    html_warning += "<label class=\"label label-{}\">Section info</label>{}".format(section_info_label, html_part[k])

        html += html_warning
        html += html_info

        html += "</div>"
        return html
