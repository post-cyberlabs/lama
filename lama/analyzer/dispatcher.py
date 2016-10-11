""" Class Dispatcher

This class is the switch of the plateforme.
It send requested malware analysis to modules compatibles with it.

The analysis_queue is the entry point for asking analysis.
And for each module, if the malware is compatible; the dispatcher send it on a queue with the name of the module.

The dispatcher have a queue for automated reporting.
When an analysis is finished, the dispatcher run function for automated reporting (like send a mail)

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

from threading import Thread, currentThread
from datetime import datetime, timedelta

from lama.utils.queue import Queue
from lama.utils.common import compatible_mime_set

from lama.models.malware import Malware
from lama.models.analysis import Analysis

from lama.reporter.reporter import Reporter


class Dispatcher(object):
    """
    Dispatcher module

    Attributes:
        **_modules** (dict) : Dict with modules and compatibles mime type

        **_report_check_list** (set) : Set of running analysis uid.
    """
    _modules = None
    _report_check_list = set()

    def dispatch():
        """
        First function for dispatcher.
        Init the check report function.
        Init the remote module function.
        Consume the analysis_queue for malware submission.
        Check the state of each module, if a module don't send these informations since 5second, it will be remove from the module list.
        """
        Dispatcher._check_report()
        Dispatcher._modules = dict()
        Dispatcher._get_remote_module_thread()
        while True:
            Queue.consume_queue("analysis_queue",
                                Dispatcher._dispatcher_callback,
                                time_limit=5, loop=False)
            dt = timedelta(seconds=5)
            mods = Dispatcher._modules
            now = datetime.now()
            Dispatcher._modules = {m: mods[m] for m in mods
                                   if now - mods[m]['datetime'] < dt}
            logging.debug("Modules : {}".format(",".join(Dispatcher._modules)))

    @staticmethod
    def _dispatcher_callback(ch, method, properties, body):
        """
        RMQ callback method for receive message in queue.
        This medhod call analyze method for each compatible module with malware
        """
        # get the queue_if of current malware
        body = body.decode('utf-8')
        # get malware from DB
        malware = Malware.find_by_queue_uid(body)
        Dispatcher._report_check_list.add(malware.analysis_uid)
        if malware:
            for module in Dispatcher._modules:
                # for each module, it analyzes the malware
                if compatible_mime_set(malware.mime, Dispatcher._modules[module]['mime_type']) and not compatible_mime_set(malware.mime, Dispatcher._modules[module]['no_mime_type']):
                    Queue.publish_queue(module, malware.get_queue_uid())
                    malware.add_nb_module()
            res = malware.persist()
            if not res:
                # TODO handle error
                logging.debug("Error persist malware")

    @staticmethod
    def _get_remote_module_thread():
        """
        Init the remote module thread
        """
        Dispatcher._is_send_module_cls_name_check = True
        Dispatcher._send_module_cls_name_thread = Thread(
                        target=Dispatcher._get_remote_module_callback)
        Dispatcher._send_module_cls_name_thread.deamon = True
        Dispatcher._send_module_cls_name_thread.start()
        logging.info("Running getting module name thread.")

    @staticmethod
    def _get_remote_module_callback():
        """
        Remote module thread callback.
        Init a RMQ callback
        """
        thread_id = currentThread().ident
        Queue.consume_queue("module_list",
                            Dispatcher._get_remote_module_callback_queue,
                            thread_id=thread_id)

    @staticmethod
    def _get_remote_module_callback_queue(ch, method, properties, body):
        """
        RMQ callback for receive enables module from module_list.
        For each module, the name with mie types is saved on a list.
        And the time is save to prevent dead module.
        """
        body = body.decode('utf-8')
        mod_name, mime_types, no_mime_types = body.split(':')
        if mod_name not in Dispatcher._modules:
            Dispatcher._modules[mod_name] = {'datetime': None,
                                             'mime_type': set(),
                                             'no_mime_type': set()}
        Dispatcher._modules[mod_name]['datetime'] = datetime.now()
        lst = mime_types.split(',')
        Dispatcher._modules[mod_name]['mime_type'].update(lst)
        no_lst = no_mime_types.split(',')
        Dispatcher._modules[mod_name]['no_mime_type'].update(no_lst)

    @staticmethod
    def _check_report():
        """
        Create a thread for check end of analysis
        """
        Dispatcher._check_report = True
        Dispatcher._check_report_thread = Thread(
                        target=Dispatcher._check_report_callback)
        Dispatcher._check_report_thread.deamon = True
        Dispatcher._check_report_thread.start()
        logging.info("Running getting module name thread.")

    @staticmethod
    def _check_report_callback():
        """
        Callback for end analysis thread.
        If an analysis is finished, it will be remove frome the list and set as finish.
        Next the analysis is send to the reporter for automated reporting.
        """
        while Dispatcher._check_report:
            lst = Dispatcher._report_check_list.copy()
            for uid in lst:
                analysis = Analysis.find_by_uid(uid)
                if analysis.is_finish():
                    Dispatcher._report_check_list.remove(uid)
                    analysis.finish()
                    Reporter.make_automated_report(analysis)
            time.sleep(1)

    @staticmethod
    def stop_dispatch():
        """
        Stop the dispatcher.
        """
        Dispatcher._check_report = False
