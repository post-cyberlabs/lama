"""
FTP file

This class manages the FTP server
It can connect, send and download files from the FTP server.
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
import ftplib
import ftputil
import logging
import tempfile
import configparser


# session factory for SSL connexion
class FTPTLSSession(ftplib.FTP_TLS):

    def __init__(self, host, user, password):
        ftplib.FTP_TLS.__init__(self)
        self.connect(host, 21)
        self.login(user, password)
        # Set up encrypted data connection.
        self.prot_p()


class LamaFtp(object):

    host = None
    root_dir = None
    user = None
    password = None

    def init():
        # get informations for connexion
        config = configparser.ConfigParser()
        config.read('lama/conf/project.conf')
        try:
            LamaFtp.host = config["FTP"]["host"]
            LamaFtp.root_dir = config["FTP"]["root_dir"]
            LamaFtp.user = config["FTP"]["user"]
            LamaFtp.password = config["FTP"]["password"]
        except KeyError as e:
            logging.error("Error project.conf[FTP] : {} missing.".format(str(e)))
            exit(1)

    def create_ftp():
        pass

    def _get_session():
        """
        Return a session to FTP connexion.
        """
        if not LamaFtp.host:
            LamaFtp.init()
        ftp_host = ftputil.FTPHost(LamaFtp.host, LamaFtp.user, LamaFtp.password,
                                   session_factory=FTPTLSSession)
        ftp_host.makedirs(LamaFtp.root_dir)
        ftp_host.chdir(LamaFtp.root_dir)
        return ftp_host

    def check_remote_dir(remote_dir):
        """
        Check if the remote directory exists.

        Args :
            **remote_dir** (String) : directory to be tested.
        """
        ftp_host = LamaFtp._get_session()
        return ftp_host.path.isdir(remote_dir)

    def check_remote_file(remote_file):
        """
        Check if the remote file exists.

        Args :
            **remote_file** (String) : File to be tested.
        """
        ftp_host = LamaFtp._get_session()
        return ftp_host.path.isfile(remote_file)

    def upload(local_path, remote_dir, remote_name):
        """
        Upload a file.

        Args :
            **local_path** (String) : Path of local file to send.

            **remote_dir** (String) : Remote direcory of file.

            **remote_name** (String) : Remote name of file.
        """
        ftp_host = LamaFtp._get_session()
        ftp_host.makedirs(remote_dir)
        ftp_host.upload(local_path, os.path.join(remote_dir, remote_name))

    def upload_from_module(local_path, analysis_uid, malware_uid,
                           module_cls_name, remote_path="", remote_name=None):
        """
        Upload a file from a module.
        It set the âth automaticaly to respect the folder architecture.

        The remote path will be : analysis uid / malware uid / module classe name / remote path / remote name

        Args :
            **local_path** (String) : Path of local file to send.

            **analysis_uid** (Integer) : Uid of analysis.

            **malware_uid** (Integer) : Uid of malware.

            **module_cls_name** (String) : Module class name.

            **remote_dir** (String) : Remote direcory of file

            **remote_name** (String) : Remote name of file.
            """
        if not remote_name:
            remote_name = os.path.basename(local_path)
        remote_dir = os.path.join(str(analysis_uid),
                                  str(malware_uid),
                                  module_cls_name,
                                  remote_path)
        LamaFtp.upload(local_path, remote_dir, remote_name)
        return os.path.join(remote_dir, remote_name)

    def download(remote_path, local_path, name):
        """
        Download a file from FTP server.

        Args :
            **remote_path** (String) : Remote direcory of file.

            **local_path** (String) : Path of local file to send.

            **name** (String) : Name of file.
        """
        if LamaFtp.check_remote_file(remote_path):
            ftp_host = LamaFtp._get_session()
            ftp_host.download(remote_path, local_path+"/"+name)
            return True
        else:
            return False

    def download_to_tmp(remote_path):
        """
        Download a file from FTP server to a temporary directory.

        Args :
            **remote_path** (String) : Remote direcory of file.
        """
        local_tmp_path = tempfile.mkdtemp(prefix="lama_")
        name = os.path.basename(remote_path)

        if LamaFtp.download(remote_path, local_tmp_path, name):
            return local_tmp_path, name
        else:
            return None, None

    def remove(analysis_uid):
        ftp_host = LamaFtp._get_session()
        ftp_host.rmtree(str(analysis_uid))

    def flush():
        ftp_host = LamaFtp._get_session()
        ftp_host.rmtree(LamaFtp.root_dir+"/*")
