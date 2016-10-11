"""
IRMA Module class

This class is a implementation of Module for IRMA
It interfaced with IRMA API.
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
import logging
import requests
import configparser
import urllib.parse

from html import escape

from lama.utils.type import Type
from lama.analyzer.module import Module
from lama.models.indicator import Indicator
from lama.models.module_status import ModuleStatus


class IrmaModule(Module):
    """
    IrmaModule class

    Args :
        **malware** (Malware) : Malware to be analyzed.

    Attributes :
        **_scan_id** (int list) : Analysis id.

        **_result_id** (int list) : Result id.
    """

    _module_name = "IRMA"

    _time_cicle = 10

    config = configparser.ConfigParser()
    config.read('lama/conf/modules.conf')
    json_decoder = json.JSONDecoder()

    hostname = config.get("IrmaModule", "host", fallback="localhost")
    URL = "http://{}/api/v1.1".format(hostname)

    def __init__(self, malware, local_path):
        super().__init__("IRMA", malware, local_path)
        self._scan_id = None
        self._result_id = None
        self.malware.set_module_status(self.module_cls_name,
                                       ModuleStatus.MODULE_NOT_ANALYZED)

    def check_elem(self):
        """
        (Override super)
        Check if the analysis is finished.
        It's finished if all of task are finished.
        """
        # send request for result
        if not self._scan_id:
            return False
        request_str = "{}/scans/{}".format(IrmaModule.URL,
                                           self._scan_id)
        logging.debug(request_str)
        request = requests.get(request_str)
        json_res = IrmaModule.json_decoder.decode(request.text)
        # get finished/total probes
        probes_total = json_res['probes_total']
        probes_finished = json_res['probes_finished']
        # get status of task
        status = json_res['status']
        # define in IRMA code (50 = finish)
        if status is not 50:
            logging.info("Malware {} on IRMA : {}/{}.".format(
                                                        self.malware.uid,
                                                        probes_finished,
                                                        probes_total))
            return False
        else:
            # all tasks finished.
            logging.info("Malware {} finished.".format(self.malware.uid))
            self.malware.set_module_status(self.module_cls_name,
                                           ModuleStatus.MODULE_FINISH)
            return True

    @Module.dec_analyze
    def analyze(self):
        """
        Static analyze method. (Override super)
        Run analysis in IRMA with malware.
        """
        # create scan
        request_str = "{}/scans".format(IrmaModule.URL)
        logging.debug(request_str)
        request = requests.post(request_str)

        json_res = IrmaModule.json_decoder.decode(request.text)
        # get generated scan id
        self._scan_id = json_res['id']
        self.malware.add_options_module_status(self.module_cls_name,
                                               str(self._scan_id))

        with open(self.local_path, "rb") as sample:
            # open file, and add into multipart_file.
            postfile = dict()
            filepath = self.local_path.encode("utf8")
            dec_filepath = urllib.parse.quote(filepath)
            postfile[dec_filepath] = sample.read()

            # send request
            request_str = "{}/scans/{}/files".format(IrmaModule.URL,
                                                     self._scan_id)
            logging.debug(request_str)
            request = requests.post(request_str, files=postfile)
            # get result id
            json_res = IrmaModule.json_decoder.decode(request.text)
            self._result_id = json_res['results'][0]['result_id']

        # force to sumbit
        params = {'force': True}
        # launch scan
        request_str = "{}/scans/{}/launch".format(IrmaModule.URL,
                                                  self._scan_id)
        logging.debug(request_str)

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        request = requests.post(request_str, data=json.dumps(params),
                                headers=headers)
        # get analysis id
        json_res = IrmaModule.json_decoder.decode(request.text)
        return True

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        # get results
        request_str = "{}/results/{}".format(IrmaModule.URL,
                                             self._result_id)
        logging.debug(request_str)
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        request = requests.get(request_str, headers=headers)
        json_res = IrmaModule.json_decoder.decode(request.text)
        for res in json_res['probe_results']:
            # add result for each probe
            if res['status'] == 1:
                score = 10
            elif res['status'] == 0:
                score = 0
            else:
                score = -1
            indicator = Indicator.factory(module_cls_name=self.module_cls_name,
                                          name="probe_results",
                                          content_type=Type.JSON,
                                          content=json.dumps(res),
                                          score=score)
            self._malware.get_module_status(self.module_cls_name
                                            ).add_indicator(indicator)

    def html_report(content):
        html = "<div>"
        content.sort(key=lambda item: json.loads(item.content)['name'])
        for item in content:
            html += "<div>"
            decode_content = json.loads(item.content)
            html += "<b>{} : </b>".format(escape(decode_content['name']))
            if decode_content['status'] is 0:
                html += "<label class=\"label label-success\">OK</label>"
            elif decode_content['status'] is 1:
                html += "<label class=\"label label-important\">Detected</label>"
            else:
                if isinstance(decode_content['error'], dict):
                    for err in decode_content['error']:
                        html += "<label class=\"label label-warning\">Error</label> {}: <pre>{}</pre>".format(escape(err),
                                                                                                              escape((decode_content['error'][err])))
                elif isinstance(decode_content['error'], str):
                       html += "<label class=\"label label-warning\">Error</label> <pre>{}</pre>".format(escape(decode_content['error']))
            html += "</div>"
        html += "</div>"
        return html

    def __str__(self):
        return (
            "{}\n"
            "Tasks \t{}\n"
            .format(
                super().__str__(),
                self._tasks_id)
        )
