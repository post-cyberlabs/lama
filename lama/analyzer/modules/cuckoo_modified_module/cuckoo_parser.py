"""
CuckooModified Parser class

This class parse results from CuckooModified and store them in Database.
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
import tarfile

from PIL import Image

from lama.utils.file import File
from lama.utils.type import Type
from lama.utils.ftp import LamaFtp
from lama.input.input import Input
from lama.models.indicator import Indicator


class CuckooModifiedParser(object):
    """CuckooModifiedParser class

        Args:
            **malware** (Malware) : Scanned malware.

            **module_cls_name** (Struing) : Name of current module

            **task_id** (Integer) : Task analysis on Cuckoo

            **cuckoo_url** (URL) : URL of Cuckoo

            **all_result** (Boolean) : If false, save on DB only parsed indocators.
    """

    def __init__(self, malware, module_cls_name, task_id,
                 cuckoo_url, all_result=False):
        self.json_decoder = json.JSONDecoder()
        self._malware = malware
        self._module_cls_name = module_cls_name
        self._task_id = task_id
        self._all = all_result
        self._ms = malware.get_module_status(self._module_cls_name)
        self._cuckoo_url = cuckoo_url

    def parse_result(self):
        """
        Main function to parse results
        Add indicator in malware.
        """
        # download full archive
        tar_url = "{}/tasks/report/{}/all".format(self._cuckoo_url,
                                                  self._task_id)
        folder_path = File.download_to_tmp(tar_url, "all.tar.gz")

        # send archive to FTP server
        tar_path = LamaFtp.upload_from_module(folder_path+"/all.tar.gz",
                                              self._malware.analysis_uid,
                                              self._malware.uid,
                                              self._module_cls_name,
                                              remote_path=str(
                                                  self._task_id)+"/all")

        # add indicator
        indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                      name="all",
                                      content_type=Type.FILE,
                                      content=tar_path,
                                      score=0,
                                      option=self._task_id)
        self._ms.add_indicator(indicator)

        # untar and analyze report.json
        tar = tarfile.open(folder_path+"/all.tar.gz")
        extract_path = folder_path+"/extract"
        os.mkdir(extract_path)
        tar.extractall(extract_path)
        json_report_file = open(extract_path+"/reports/report.json", "r")
        self._json_input = json_report_file.read()

        self._json_cuckoo = self.json_decoder.decode(self._json_input)

        # TODO move on submodule JSON ?
        if "info" in self._json_cuckoo:
            self.parse_info()
        if "target" in self._json_cuckoo:
            self.parse_target()
        if "strings" in self._json_cuckoo:
            self.parse_strings()
        if "signatures" in self._json_cuckoo:
            self.parse_signatures()
        if "buffer" in self._json_cuckoo:
            self.parse_buffer()
        if "network" in self._json_cuckoo:
            self.parse_network()
        if "behavior" in self._json_cuckoo:
            self.parse_process()

        # upload screenshots/pcap to FTP server
        self._get_screenshots(extract_path)
        self._get_files(extract_path)
        self._get_pcap(extract_path)

        # remove extracts files
        File.remove_tmp_dir(folder_path)

    def _get_screenshots(self, extract_path):
        """
        Retreive snapshot and upload it on FTP server
        """
        shots_path = os.path.join(extract_path, "shots")
        screenshots_path = []
        for f in os.listdir(shots_path):
            img_path = shots_path+"/"+f
            # resize
            img = Image.open(img_path)
            basewidth = 500
            wpercent = (basewidth/float(img.size[0]))
            hsize = int((float(img.size[1])*float(wpercent)))
            img = img.resize((basewidth, hsize), Image.ANTIALIAS)
            img.save(img_path)
            # send
            path = LamaFtp.upload_from_module(img_path,
                                              self._malware.analysis_uid,
                                              self._malware.uid,
                                              self._module_cls_name,
                                              remote_path=("{}/screenshots").format(self._task_id))
            screenshots_path.append(path)

        indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                      name="screenshots",
                                      content_type=Type.FILE,
                                      content=",".join(screenshots_path),
                                      score=0,
                                      option=self._task_id)
        self._ms.add_indicator(indicator)

    def _get_files(self, extract_path):
        """
        Retreive files and upload it on FTP server
        """
        files = os.path.join(extract_path, "files")
        files_path = []
        for f in os.listdir(files):
            file_path = files+"/"+f
            # send
            ftp_file_path = LamaFtp.upload_from_module(file_path,
                                                       self._malware.analysis_uid,
                                                       self._malware.uid,
                                                       self._module_cls_name,
                                                       remote_path=("{}/files").format(self._task_id))
            files_path.append(ftp_file_path)
            extract_file = self._malware.add_extract_malware_path(self._module_cls_name, file_path, f)
            Input.analyse_malware(extract_file)

        indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                      name="files",
                                      content_type=Type.FILE,
                                      content=",".join(files_path),
                                      score=0,
                                      option=self._task_id)
        self._ms.add_indicator(indicator)

    def _get_pcap(self, extract_path):
        """
        Retreive PCAP and upload it on FTP server
        """
        if os.path.isfile(extract_path+"/dump.pcap"):
            pcap_path = LamaFtp.upload_from_module(extract_path+"/dump.pcap",
                                                   self._malware.analysis_uid,
                                                   self._malware.uid,
                                                   self._module_cls_name,
                                                   remote_path=str(
                                                       self._task_id)+"/pcap")

            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="pcap",
                                          content_type=Type.FILE,
                                          content=pcap_path,
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)

    def parse_info(self):
        """
        Parse info part
        """
        if self._all:
            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="_info",
                                          content_type=Type.JSON,
                                          content=json.dumps(
                                              self._json_cuckoo["info"]),
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)
        # SCORE
        indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                      name="malscore",
                                      content_type=Type.INTEGER,
                                      content=str(self._json_cuckoo['malscore']),
                                      score=self._json_cuckoo['malscore'],
                                      option=self._task_id)
        self._ms.add_indicator(indicator)

        indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                      name="malfamily",
                                      content_type=Type.STRING,
                                      content=str(self._json_cuckoo['malfamily']),
                                      score=0,
                                      option=self._task_id)
        self._ms.add_indicator(indicator)
        # MACHINE LABEL
        indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                      name="machine_label",
                                      content_type=Type.INTEGER,
                                      content=str(self._json_cuckoo["info"]['machine']['label']),
                                      score=0,
                                      option=self._task_id)
        self._ms.add_indicator(indicator)
        self._ms.add_indicator(indicator)

    def parse_target(self):
        """
        Parse target part
        """
        if self._all:
            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="_target",
                                          content_type=Type.JSON,
                                          content=json.dumps(
                                              self._json_cuckoo["target"]),
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)

    def parse_strings(self):
        """
        Parse string part
        """
        if self._all:
            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="_strings",
                                          content_type=Type.JSON,
                                          content=json.dumps(
                                              self._json_cuckoo["strings"]),
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)

    def parse_network(self):
        """
        Parse network part
        """
        indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                      name="network",
                                      content_type=Type.JSON,
                                      content=json.dumps(
                                          self._json_cuckoo["network"]),
                                      score=0,
                                      option=self._task_id)
        self._ms.add_indicator(indicator)

    def parse_buffer(self):
        """
        Parse buffer part
        """
        if self._all:
            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="_buffer",
                                          content_type=Type.JSON,
                                          content=json.dumps(
                                              self._json_cuckoo["buffer"]),
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)

        for buff in self._json_cuckoo['buffer']:
            if len(buff['yara']):
                indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                              name="buff_yara",
                                              content_type=Type.JSON,
                                              content=json.dumps(buff['yara']),
                                              score=0,
                                              option=self._task_id)
                self._ms.add_indicator(indicator)

    def parse_signatures(self):
        """
        Parse signatures part
        """
        if self._all:
            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="_signatures",
                                          content_type=Type.JSON,
                                          content=json.dumps(
                                              self._json_cuckoo["signatures"]),
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)

        for sign in self._json_cuckoo['signatures']:

            signature = {"description": sign['description'],
                         "severity": sign['severity'],
                         "name": sign['name']
                         }

            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="signature",
                                          content_type=Type.STRING,
                                          content=json.dumps(signature),
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)

    def parse_process(self):
        if 'processtree' in self._json_cuckoo['behavior']:
            proc = self._json_cuckoo['behavior']['processtree']
            indicator = Indicator.factory(module_cls_name=self._module_cls_name,
                                          name="process",
                                          content_type=Type.STRING,
                                          content=json.dumps(proc),
                                          score=0,
                                          option=self._task_id)
            self._ms.add_indicator(indicator)
