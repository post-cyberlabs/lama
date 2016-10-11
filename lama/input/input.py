""" Input class

This class allow to initialize an analysis.
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
import logging

import lama.models.malware
import lama.models.analysis

from lama.utils.file import File
from lama.utils.ftp import LamaFtp
from lama.utils.queue import Queue


class Input(object):
    """
    Input class

    Args :
        **paths** (list(dict[name, path])): Contains all paths of file \
                                            which will be analyzed.

        **urls** (list) : Contains URL which will be analyzed.

    Attributes :
        **_analysis** (Analysis): Analysis object created for given paths and urls.
    """

    def __init__(self, paths=None, urls=None):
        """
        Init Input whose init analysis with provide paths or urls.
        If it's a url, it will be check and save into a file.
        The malware file is send on the FTP server and the analysis is persited on DB.
        """
        # Create an Analysis
        self._analysis = lama.models.analysis.Analysis.factory()
        res = self._analysis.persist()
        if not res:
            # TODO handle error
            logging.debug("Error persist analysis")
        if paths:
            for p in paths:
                m = lama.models.malware.Malware.empty_malware()
                name = os.path.basename(p)

                remote_dir = "{}/{}".format(str(self._analysis.uid),
                                            str(m.uid))
                new_name = m.factory(p, remote_dir, name)
                self._analysis.add_malware(m)
                res = m.persist()
                if not res:
                    # TODO handle error
                    logging.debug("Error persist malware")
                LamaFtp.upload(p, remote_dir, new_name)
        if urls:
            for url in urls:
                url = url.strip()
                if len(url):
                    name = "url.txt"
                    tmp_result_file = File.create_tmp_file(name, url)
                    path = os.path.join(tmp_result_file, name)
                    m = lama.models.malware.Malware.empty_malware()
                    remote_dir = "{}/{}".format(str(self._analysis.uid),
                                                str(m.uid))
                    new_name = m.factory(path, remote_dir, name)
                    self._analysis.add_malware(m)
                    m.mime = "URL"
                    res = m.persist()
                    if not res:
                        # TODO handle error
                        logging.debug("Error persist malware")
                    LamaFtp.upload(path, remote_dir, new_name)

        self._analysis.persist()

    def analyze(self):
        """
        Run the current analysis.
        It send all malware into a queue for waiting \
        analysis by the analysis module
        """
        logging.info("Run analysis {}.".format(self._analysis.uid))
        # self._analysis.analyze()
        for m in self._analysis.malwares:
            Input.analyse_malware(m)
        return self._analysis.uid

    @staticmethod
    def analyse_malware(malware):
        """
        Send malware queue id on analysis_queue.

        Args :
            **malware** (malware) : malware which will be analyzed.
        """
        Queue.publish_queue("analysis_queue", malware.get_queue_uid())

    @staticmethod
    def get_by_analysis_uid(uid):
        """
        Static method whose return analysis with provided uid.

        Args:
            **uid** (int): Uid of searched analysis.
        """
        analysis = lama.models.analysis.Analysis.find_by_id(uid)
        return analysis

    def get_remote_file(remote_file_path):
        """
        Function who download file from FTP server.
        """
        local_path = LamaFtp.download_to_tmp(remote_file_path)
        return local_path

    def get_all_analysis(offset=0, limit=None, children=False):
        return lama.models.analysis.Analysis.get_all_analysis(offset=offset, limit=limit, children=children)

    def delete_analysis(analysis_uid):
        lama.models.analysis.Analysis.delete(analysis_uid)
        LamaFtp.remove(analysis_uid)

    def flush():
        lama.models.analysis.Analysis.flush()
        LamaFtp.flush()
