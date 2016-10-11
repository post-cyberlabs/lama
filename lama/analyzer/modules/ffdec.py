"""
Ffdec Docker class

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
import base64

from html import escape

from lama.models.indicator import Indicator
from lama.analyzer.module import Module
from lama.analyzer.docker_module import DockerModule
from lama.utils.type import Type
from lama.utils.ftp import LamaFtp


class FfdecDocker(DockerModule):
    """FfdecDocker class

    Args :
        **malware** (malware) : Malware which will be analyzed
    """

    _module_name = "Ffdec"

    def __init__(self, malware, local_path):
        super().__init__("Ffdec Docker", malware, local_path, "ffdec")

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """

        # save all scipts
        script_dir = os.path.join(self._out_tmp_path, "extract", "scripts")
        for path, subdirs, files in os.walk(script_dir):
            for name in files:
                script_path = os.path.join(path, name)
                with open(script_path, 'r') as script_file:
                    script_content = script_file.read()
                    # convert script to b64
                    codeb64 = base64.b64encode(bytes(script_content,
                                                     "utf-8")).decode('utf-8')
                    script_dict = dict()
                    script_dict['filename'] = script_path.replace(script_dir,
                                                                  "")[1:]
                    script_dict['code'] = codeb64
                    indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                                  name="script",
                                                  content_type=Type.BASE64,
                                                  content=json.dumps(script_dict),
                                                  score=0)
                    self._malware.get_module_status(self.module_cls_name
                                                    ).add_indicator(indicator)

        tar_path = os.path.join(self._out_tmp_path, "out.tar.gz")
        remote_tar_path = LamaFtp.upload_from_module(tar_path,
                                                     self.malware.analysis_uid,
                                                     self.malware.uid,
                                                     self.module_cls_name)

        indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                      name="tar",
                                      content_type=Type.FILE,
                                      content=remote_tar_path,
                                      score=0)
        self._malware.get_module_status(self.module_cls_name
                                        ).add_indicator(indicator)

    def html_report(content):
        html = ""
        html_tar = ""
        html_err = ""
        for item in content:
            if item.name == "script":
                json_decode = json.loads(item.content)
                html += "<label class=\"label\">Script</label> {} <pre>{}</pre>".format(escape(json_decode['filename']), escape(base64.b64decode(json_decode['code']).decode('utf-8')))
            elif item.name == "tar":
                archive_name = os.path.basename(item.content)
                html_tar += "<label class=\"label\">Exctact files : </label> <a href=\"/file?path={}\">{}</a><br />".format(item.content, archive_name)
            else:
                html_err += "LAMA PARSE ERROR"
        html = "<div>{}{}{}</div>".format(html_tar, html, html_err)
        return html
