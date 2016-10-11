""" Class Analyzer

This class manage all enabled analysis module for this local machine.
It load all module, init them and stop at the end.
A white_list and black_list are read from the conf/project.conf file.
If lists are empty, all modules are loaded.
If white_list is not empty, only these modules are loaded.
If white_list is empty and not black_list, all module are loaded except these on the black list

This class create a thread to informs the dispatcher of enabled module.
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
import logging
import configparser

from threading import Thread, currentThread

# keep for init all Module when import is executed
from lama.analyzer.modules import *
from lama.analyzer.module import Module
from lama.utils.queue import Queue



class Analyzer(object):
    """
    Analyzer class

    For runing Analyzer, just run the static method run_analyzer.

    Attributes:
        **_modules** (static Module dict(dict())) : Contains all modules.
    """

    config = configparser.ConfigParser()
    config.read('lama/conf/project.conf')

    _modules = None

    @staticmethod
    def run_analyzer():
        """
        Static method to run the analyzer.
        It fetch all modules and init them.
        """
        # create a dict of availables module : name->cls
        Analyzer._modules = {}
        available_modules = dict([(m.__name__, m) for m in Module])

        logging.info("Available modules : {}."
                     .format(", ".join([m for m in available_modules])))

        # check config file
        # only use white listed modules
        if 'white_list' in Analyzer.config["MODULES"]:
            selected_modules = []
            # load selecting modules
            given_modules = [m.strip()
                             for m in Analyzer.config['MODULES']['white_list'].split(",")]
            for mod in given_modules:
                if mod in available_modules:
                    selected_modules.append(available_modules[mod])
                else:
                    logging.info("Module {} not found.".format(mod))
        # don't use black listed modules
        elif 'black_list' in Analyzer.config["MODULES"]:
            selected_modules = []
            # load selecting modules
            black_modules = [m.strip()
                             for m in Analyzer.config['MODULES']['black_list'].split(",")]
            for mod in available_modules:
                if mod not in black_modules:
                    selected_modules.append(available_modules[mod])
        # if no white/black list in config -> use all available
        else:
            selected_modules = [available_modules[m]
                                for m in available_modules]

        logging.info("Selected modules : {}."
                     .format(", ".join([m.__name__
                                        for m in selected_modules])))
        # check if at least one module is selected
        if len(selected_modules) is 0:
            logging.error("No module selected.")
            exit(1)

        # Iterate over subclasses
        for module_cls in selected_modules:
            # Add subclass in _modules list
            # Analyzer._modules.append(module_cls)
            module_cls_name = module_cls.__name__
            Analyzer._modules[module_cls_name] = {'mime_type': None}
            Analyzer._modules[module_cls_name]['mime_type'] = module_cls.get_mime_type()
            # Run module (check thread)
            module_cls.init()
        # start publish enabled modules
        Analyzer.run_send_module_cls_name_thread()

    @staticmethod
    def run_send_module_cls_name_thread():
        """
        Create the send module class name thread.
        """
        Analyzer._is_send_module_cls_name_check = True
        Analyzer._send_module_cls_name_thread = Thread(
            target=Analyzer._send_module_cls_name_thread_callback)
        Analyzer._send_module_cls_name_thread.deamon = True
        Analyzer._send_module_cls_name_thread.start()
        logging.info("Running send module name thread.")

    @staticmethod
    def _send_module_cls_name_thread_callback():
        """
        Callback of send module class name thread.
        For each module enabled, it send the name and mime types compatibles for the module.
        It publish each two second.
        """
        thread_id = currentThread().ident
        while(Analyzer._is_send_module_cls_name_check):
            for mod in Analyzer._modules:
                body = "{}:{}:{}".format(mod,
                                         ",".join(Analyzer._modules[mod]['mime_type']['type'])
                                         , ",".join(Analyzer._modules[mod]['mime_type']['notype'])
                                         )
                Queue.publish_queue("module_list",
                                    body,
                                    thread_id=thread_id)
            time.sleep(2)

    @staticmethod
    def stop_analyzer():
        """
        Function for stopping the analyzer.
        """
        logging.info("Stop analyzer.")
        for module_cls in Analyzer._modules:
            module_cls.stop()
        Queue.stop_consuming_all()
