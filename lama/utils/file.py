"""
File class

This class maanages files on the local machine with creation of temporary directory or file
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
import shutil
import tempfile
import configparser
import urllib.request

config = configparser.ConfigParser()
config.read('lama/conf/project.conf')


class File(object):

    @staticmethod
    def create_tmp_dir(prefix="lama_"):
        """
        Create a temporary directory

        Args :
            **prefix** (String) : Prefix of temporary folder, by default "lama\_"
        """
        local_tmp_path = tempfile.mkdtemp(prefix=prefix)
        return local_tmp_path

    @staticmethod
    def download_to_tmp(url, name):
        """
        Download a file to a temporary directory

        Args :
            **url** (URL) : URL of ressource

            **name** (String) : Name of temporary file
        """
        local_tmp_path = File.create_tmp_dir("lama_tmp_url_")
        local_filename = os.path.join(local_tmp_path, name)
        urllib.request.urlretrieve(url, local_filename)
        return local_tmp_path

    @staticmethod
    def create_tmp_binary_file(name, content):
        """
        Create a temporary binary file.

        Args :
            **name** (String) : Name of temporary file.

            **content** (bytes) : Content of file.
        """
        local_tmp_path = File.create_tmp_dir("lama_tmp_binary")
        file_path = os.path.join(local_tmp_path, name)
        new_file = open(file_path, 'wb')
        new_file.write(content)
        new_file.close()
        return local_tmp_path

    @staticmethod
    def create_tmp_file(name, content):
        """
        Create a temporary file.

        Args :
            **name** (String) : Name of temporary file.

            **content** (String) : Content of file.
        """
        local_tmp_path = File.create_tmp_dir("lama_tmp_")
        file_path = os.path.join(local_tmp_path, name)
        new_file = open(file_path, 'w')
        content_str = content
        if type(content_str) is bytes:
            content_str = content_str.decode('utf-8')
        new_file.write(content_str)
        new_file.close()
        return local_tmp_path

    @staticmethod
    def remove_tmp_dir(path):
        """
        Remove a temporary directory.
        """
        if "lama_" in path:
            shutil.rmtree(path)
