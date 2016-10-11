"""
Docker Module class

This abstract module allow to create submodule with Docker container.
It run the given container with malware to analyze this.
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
import shutil
import logging
import tempfile

from sidomo import Container

from lama.analyzer.module import Module
from lama.analyzer.sync_module import SyncModule
from lama.models.module_status import ModuleStatus


class DockerModule(SyncModule):
    """DockerModule class

    Args :
        **module_cls_name** (string) : Name of submodule.

        **malware** (malware) : Malware who is analyzed.

        **local_path** (PATH) : Path of malware on the machine

        **docker_name** (string) : Name of container for the submodule.

    Attributes :
        **_docker_name** (String) : Name of the folder with Dockerfile, Script.py and optionnal other files

        **_result** (String) : Result from the Docker execution. It will be parsed.
    """

    def __init__(self, module_cls_name, malware, local_path, docker_name):
        super().__init__(module_cls_name, malware, local_path)
        self._docker_name = docker_name
        self.malware.set_module_status(self.module_cls_name,
                                       ModuleStatus.MODULE_NOT_ANALYZED)
        self._result = ""

    def __str__(self):
        return (
            "{}\n"
            "Docker name : {}"
            .format(super().__str__(), self._docker_name)
        )

    @Module.dec_analyze
    def analyze(self):
        """
        Static run_analyze method. (Override super)
        Run analysis on the container.
        """
        if "/" not in self._docker_name:
            # Containers starts with 'lama/'
            container_name = "lama/"+self._docker_name
        else:
            container_name = self._docker_name
        # tmp out folder
        self._out_tmp_path = tempfile.mkdtemp(prefix="docker_"+self.module_cls_name+"_")
        # Connect volume for malware sharing
        volumes = [self.local_path+":/lama/sample:ro",
                   self._out_tmp_path+":/lama/out"]
        try:
            logging.debug("Starting container {}".format(container_name))
            # open container
            with Container(container_name, volumes=volumes, cleanup=True) as c:
                # get result
                for line in c.run('python /lama/script.py'):
                    self._result += line.decode("utf-8")
            logging.debug("Stopping container {}".format(container_name))
        except:
            # if the given docker_name is wrong
            logging.error("Wrong container name '{}', "
                          "check with 'docker images'."
                          .format(container_name))
            return False

        self.malware.set_module_status(self.module_cls_name,
                                       ModuleStatus.MODULE_FINISH)
        return True

    def json_decode(self, encoded_json):
        json_decoder = json.JSONDecoder()
        try:
            return json_decoder.decode(encoded_json)
        except:
            logging.debug("JSON error from {} container \n==\n {} \n==\n".format(self.module_cls_name, encoded_json))
            return None

    def clean(self):
        """
        Remove shared folder with the container after analysis.
        """
        shutil.rmtree(self._out_tmp_path)
