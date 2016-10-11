"""
Cuckoo Modified Module class

This class is a implementation of Module for Cuckoo Modified
It interfaced with Cuckoo API.
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import time
import json
import logging
import requests
import configparser

from lama.analyzer.module import Module
from lama.analyzer.modules.cuckoo_modified_module.cuckoo_html import CuckooModifiedHtml
from lama.analyzer.modules.cuckoo_modified_module.cuckoo_parser import CuckooModifiedParser
from lama.models.module_status import ModuleStatus


class CuckooModifiedModule(Module):
    """
    CuckooModifiedModule class

    Args :
        **malware** (Malware) : Malware to be analyzed.

        **local_path** (PATH) : Path of malware on the machine

    Attributes :
        **_tasks_id** (int list) : Contains analysis id of Cuckoo.
    """

    _module_name = "CuckooModified"
    """Module name"""

    _time_cicle = 20
    """"""

    config = configparser.ConfigParser()
    config.read('lama/conf/modules.conf')
    json_decoder = json.JSONDecoder()

    host = config.get("CuckooModifiedModule", "host", fallback="localhost")
    port = config.get("CuckooModifiedModule", "port", fallback="8090")
    URL = "http://{}:{}".format(host, port)

    def __init__(self, malware, local_path):
        super().__init__("Cuckoo Modified", malware, local_path)
        self._tasks_id = []
        time.sleep(3)
        self.malware.set_module_status(self.module_cls_name,
                                       ModuleStatus.MODULE_NOT_ANALYZED)

    def add_task_id(self, task_id):
        """
        Add task from cuckoo in _tasks_id list.
        """
        self._tasks_id.append(task_id)

    def check_elem(self):
        """
        (Override super)
        Check if the analysis is finished.
        It's finished if all of task are finished.
        """
        if not len(self._tasks_id):
            return False
        nb_finish = 0
        for task_id in self._tasks_id:
            # send request
            request_str = CuckooModifiedModule.URL+"/tasks/view/"+str(task_id)
            logging.debug(request_str)
            request = requests.get(request_str)
            json_res = CuckooModifiedModule.json_decoder.decode(request.text)
            # get status of task
            status = json_res["task"]["status"]
            if status == "reported":
                nb_finish += 1
        if nb_finish == len(self._tasks_id):
            # all tasks finished.
            logging.info("Malware {} finished.".format(self.malware.uid))
            self.malware.set_module_status(self.module_cls_name,
                                           ModuleStatus.MODULE_FINISH)
            return True
        else:
            logging.info("Malware {} on Cuckoo : {}/{}."
                         .format(self.malware.uid,
                                 nb_finish, len(self._tasks_id)))
            return False

    @Module.dec_analyze
    def analyze(self):
        """
        Static analyze method. (Override super)
        Run analysis for each VM in Cuckoo with malware.
        """

        machines_name = CuckooModifiedModule._list_machines()
        for machine_name in machines_name:
            tasks_id = CuckooModifiedModule._analyze_machine_id(self.local_path,
                                                                self.malware,
                                                                machine_name)
            for task_id in tasks_id:
                self.add_task_id(task_id)
        options = ",".join([str(t) for t in self._tasks_id])
        self.malware.add_options_module_status(self.module_cls_name,
                                               options)
        return True

    @Module.dec_parse_result
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        for task_id in self._tasks_id:
            parser = CuckooModifiedParser(self.malware,
                                          self.module_cls_name,
                                          task_id,
                                          CuckooModifiedModule.URL)
            parser.parse_result()

    def html_report(content):
        return CuckooModifiedHtml.make_html(content)

    @staticmethod
    def _analyze_machine_id(local_path, malware, machine_name):
        """
        Fonction to run analysis on one VM.
        """
        with open(local_path, "rb") as sample:
            # open file, and add into multipart_file.
            multipart_file = {"file": (malware.name, sample),
                              "machine": str(machine_name)}
            # send request
            request_str = CuckooModifiedModule.URL+"/tasks/create/file"
            logging.debug(request_str)
            request = requests.post(request_str, files=multipart_file)
            # get analysis id
            task = CuckooModifiedModule.json_decoder.decode(request.text)
            task_id = task["task_ids"]
            return task_id

    @staticmethod
    def _list_machines(platform=None):
        """
        Function who list all machine.
        It's possible to filter with a platform name.
        """
        # send request
        request_str = CuckooModifiedModule.URL+"/machines/list"
        logging.debug(request_str)
        request = requests.get(request_str)
        machines = CuckooModifiedModule.json_decoder.decode(request.text)
        machines_name = []
        # get all machine for provided platform
        for machine in machines["machines"]:
            if not platform or machine["platform"] == platform:
                machines_name.append(machine["name"])
        return machines_name

    def __str__(self):
        return (
            "{}\n"
            "Tasks \t{}\n"
            .format(
                super().__str__(),
                self._tasks_id)
        )
