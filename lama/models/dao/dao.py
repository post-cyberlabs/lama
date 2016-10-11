"""
LamaDAO class

This class is for DAO design pattern.
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


from abc import ABCMeta, abstractmethod


class LamaDAO(metaclass=ABCMeta):

    @abstractmethod
    def create():
        """
        This method create an instance on DB.
        """
        pass

    @abstractmethod
    def read():
        """
        This method find an instance in DB by uid.
        """
        pass

    @abstractmethod
    def update():
        """
        This method update an instance in DB.
        """
        pass

    @abstractmethod
    def delete():
        """
        This method delete instance in DB.
        """
        pass
