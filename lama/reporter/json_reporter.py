"""
Json Reporter Class

This class allow to create a report in JSON.
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
from lama.analyzer.module import Module


class JsonReporter(object):

    @staticmethod
    def make_report(analysis):
        """
        Method to report in json format.

        Args :
            **analysis** (Analysis) : Analysis to report
        """

        report = dict()
        report["uid"] = analysis.uid
        report["create_date"] = str(analysis.start_date)
        report["end_date"] = str(analysis.end_date)
        malwares_tab = []
        for malware in analysis.malwares:
            malwares_tab.append(JsonReporter._make_malware_report(malware))

        report["malware"] = malwares_tab
        res = [report]
        return json.dumps(res, indent=1)

    def _make_malware_report(malware):
        malware_dict = dict()
        malware_dict['info'] = dict()
        malware_dict['info']["uid"] = malware.uid
        malware_dict['info']["name"] = malware.name
        malware_dict['info']["path"] = malware.path
        malware_dict['info']["md5"] = malware.md5
        malware_dict['info']["sha1"] = malware.sha1
        malware_dict['info']["mime"] = malware.mime
        malware_dict['info']["size"] = malware.size

        malware_dict["module_status"] = \
            JsonReporter._make_module_status_report(
                                            malware.module_status)

        extract_malware_tab = []
        for extract_malware in malware._extract_malware:
            extract_malware_tab.append(JsonReporter._make_malware_report(
                                            extract_malware))
        malware_dict["extract_malware"] = extract_malware_tab

        return malware_dict

    def _make_indicator_report(indicators):
        indicators_tab = []
        for indicator in indicators:
            # check if module is present
            indicator_dict = dict()

            # check if module have 'json_report' function
            indicator_class = Module.get_module_by_name(indicator.module_cls_name)
            json_report_fct = getattr(indicator_class, "json_report", None)
            if callable(json_report_fct):
                indicator_dict = json_report_fct(indicator.name,
                                                 indicator.content)
            else:
                # default json report
                logging.debug("{} have no json_report function."
                              .format(indicator.module_cls_name))
                indicator_dict["module_cls_name"] = indicator.module_cls_name
                indicator_dict["name"] = indicator.name
                indicator_dict["content_type"] = indicator.content_type
                indicator_dict["content"] = indicator.content
                indicator_dict["score"] = indicator.score
                indicator_dict["option"] = indicator.option
            indicators_tab.append(indicator_dict)
        return indicators_tab

    def _make_module_status_report(module_status):
        module_status_tab = []
        for ms in module_status:
            ms_dict = dict()
            ms_dict["module_cls_name"] = ms.module_cls_name
            ms_dict["status"] = ms.status
            ms_dict["options"] = ms.options
            ms_dict["start_analyze_date"] = \
                str(ms.start_analyze_date)
            ms_dict["end_analyze_date"] = \
                str(ms.end_analyze_date)

            ms_dict["indicators"] = JsonReporter._make_indicator_report(
                                                 ms.indicators)
            module_status_tab.append(ms_dict)
        return module_status_tab
