"""
Module class

This is a abstract module.
It's composed of two parts.

This class autoregister all of these subclass.

Two threads are created :
- The first is a check thread, it allow to check if the current analysis is finished or not.
- The second thread is a submit thread, it allow to run the analysis and then run the parse results functions.

"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import abc
import time
import logging
import configparser

from threading import Thread, currentThread

from lama.utils.queue import Queue
from lama.models.malware import Malware
from lama.models.module_status import ModuleStatus


class RegisterModulesClasses(type):
    """
    RegisterModulesClasses class

    This class allow to register all submodule for automatical instantiation.
    """
    def __init__(cls, name, bases, nmspc):
        super(RegisterModulesClasses, cls).__init__(name, bases, nmspc)
        if not hasattr(cls, '_registry'):
            cls._registry = set()
        cls._registry.add(cls)
        cls._registry -= set(bases)
    # Metamethods, called on class objects:

    def __iter__(cls):
        return iter(cls._registry)


class ABCRegisterModulesClasses(RegisterModulesClasses, abc.ABCMeta):
    """
    ABCRegisterModulesClasses class

    Use for merge RegisterModulesClasses and ABCMeta into on class.
    Module class inherit from it.
    """
    pass


class Module(Thread, metaclass=ABCRegisterModulesClasses):

    """
    Module class

    This abstract class is a template for submodule.

    Args :
        **name** (string) : Name of submodule.

        **malware** (Malware) : Malware who is analyzed.

        **local_path** (PATH) : Path of malware on the machine

        **checker** (boolean) : If true, the check thread is activated.

    Attributes :
        **_name** (string) : Name of submodule.

        **_malware** (Malware) : Malware who is analyzed.

        **_local_path** (PATH) : Path of malware on the machine

        **_checker** (boolean) : If true, the check thread is activated.

        **_module_cls_name** (String) : Name of the module class
    """

    _module_name = "Module"
    """Module name"""

    _time_cicle = 1
    """
    Time of check cicle. If 1, all analysis are checked every second.
    For asynchrone module it's better to increase this value if the analysis take a long time (like cuckoo for exemple).
    """

    def __init__(self, name, malware, local_path, checker=True):
        super().__init__()
        self._name = name
        self._malware = malware
        self._local_path = local_path
        self._checker = checker
        self._module_cls_name = self.__class__.__name__

    @classmethod
    def get_mime_type(cls):
        """
        Return conpatible mime type for this module.
        It's loaded from conf/modules.conf file.
        Default it's all mime type ("*").
        """
        config = configparser.ConfigParser()
        config.read('lama/conf/modules.conf')
        # prepare the return dict
        res = {'type': None, 'notype': None}
        # get compatible types
        types = config.get(cls.__name__, "type", fallback=None)
        if types:
            res['type'] = [t.strip() for t in types.split(",")]
        else:
            res['type'] = ["*"]

        # get none compatible types
        notypes = config.get(cls.__name__, "notype", fallback=None)
        if notypes:
            res['notype'] = [t.strip() for t in notypes.split(",")]
        else:
            res['notype'] = []
        return res

    @staticmethod
    def get_module_by_name(name):
        """
        Return module class by name
        """
        for m in Module:
            if m.__name__ == name:
                return m
        return None

    @classmethod
    def init(cls):
        """
        Init the check and submit thread
        """
        cls.run_check_thread()
        cls.run_submit_thread()

    @classmethod
    def run_submit_thread(cls):
        """
        Create the submit thread
        """
        module_cls_name = cls.__name__
        cls._submit_thread = Thread(target=cls._submit_thread_callback)
        # cls._submit_thread.deamon = True
        cls._submit_thread.start()
        logging.info("Running listen queue thread ({}).".format(module_cls_name))

    @classmethod
    def _submit_thread_callback(cls):
        """
        Callback for submit thread.
        This function consume a RMQ queue with an other callback
        """
        # TODO add while with stop variable
        thread_id = currentThread().ident
        Queue.consume_queue(cls.__name__,
                            cls._submit_queue_callback,
                            thread_id=thread_id)

    @classmethod
    def _submit_queue_callback(cls, ch, method, properties, body):
        """
        Final callback for submit thread.
        It consume the queue with the same name than the module.
        On this queue, the malware queue id is send.
        When it consume, the malware is :

        1. Loaded from DB, downloaded on the local machine
        2. Downloaded on the machine
        3. (Added to checker list if needed)
        4. Run analyze
        5. Remove the copy on local machine
        6. Parse the result
        7. (Clean the module)
        """
        body = body.decode('utf-8')
        malware = Malware.find_by_queue_uid(body)
        if malware:
            # create current sub Module with malware
            local_dir = malware.download()
            local_path = local_dir+"/"+malware.name
            mod = cls(malware, local_path)
            logging.info("Module '{}' analyze malware '{}'."
                         .format(mod.name, malware.uid))
            if mod.need_checker():
                cls.add_to_checker(mod)
            res = mod.analyze()
            malware.delete_download(local_dir)
            if not mod.need_checker() and res:
                mod.parse_result()
            mod.clean()

    def clean(self):
        """
        Clean function if the module need to execute some post handling.
        For removing temporary file/folder for exemple
        """
        pass

    @classmethod
    def run_check_thread(cls):
        """
        Create the check thread
        """
        cls._is_running_check = True
        cls._check_thread = Thread(target=cls._check_thread_callback)
        cls._check_thread.deamon = True
        cls._check_thread.start()
        logging.info("Running check thread ({}).".format(cls.__name__))

    @classmethod
    def _check_thread_callback(cls):
        """
        For each item in _in_progress_list, it check if it's finished.
        The time is computed for analyze all item each _time_cicle time.
        When an analysis is finished, it run parsing function
        """
        cls._in_progress_list = []
        while(cls._is_running_check):
            len_list = len(cls._in_progress_list)
            if len_list:
                # get first item
                elem = cls._in_progress_list.pop(0)
                if not elem.check_elem():
                    # re-add into _in_progress_list
                    cls._in_progress_list.append(elem)
                else:
                    # run repporting
                    elem.parse_result()
            # sleep_time = 1/ number of task
            sleep_time = cls._time_cicle/len_list if len_list else cls._time_cicle
            time.sleep(sleep_time)

    @classmethod
    def stop(cls):
        """
        Function for stopping threads.
        """
        logging.info("Stopping threads ({}).".format(cls.__name__))
        cls._is_running_check = False
        cls._is_send_module_cls_name_check = False

    def need_checker(self):
        """
        Return true if the submodule need the checker thread
        """
        return self._checker

    @staticmethod
    def add_to_checker(self):
        """
        Static method who add current submodule instance in _in_progress_list.
        """
        self.__class__._in_progress_list.append(self)

    def dec_analyze(f):
        """
        Decorator for changing state of malware to 'MODULE_IN_PROGRESS'
        """
        def wrapper(*args):
            args[0].malware.set_module_status(args[0].__class__.__name__,
                                              ModuleStatus.MODULE_IN_PROGRESS)
            return f(*args)
        return wrapper

    @abc.abstractmethod
    def analyze(self):
        """
        Abstract analyze method

        This method is call for analyzing malware.
        It must be overiding by subclass and instanciate a submodule instance
        """
        raise NotImplementedError

    @abc.abstractmethod
    def check_elem(self):
        """
        Abstract check_elem method.
        It calls when thread check element.
        It must returning a boolean.
        """
        pass

    def dec_parse_result(f):
        """
        Decorator for changing state of malware to 'MODULE_REPORTED'
        """
        def wrapper(*args):
            res = f(*args)
            args[0].malware.set_module_status(args[0].__class__.__name__,
                                              ModuleStatus.MODULE_REPORTED)
            return res
        return wrapper

    @abc.abstractmethod
    def parse_result(self):
        """
        Abstract parse_result method.
        It calls when analyze is finished.
        It uptade malware with indicators.
        """
        pass

    def __str__(self):
        return (
            "Name \t{}"
            .format(self.name)
        )

    @property
    def name(self):
        """
        Return name of module
        """
        return self._name

    @property
    def local_path(self):
        """
        Return local path of module
        """
        return self._local_path

    @classmethod
    def module_name(cls):
        """
        Return the name of the module
        """
        if cls._module_name == "Module":
            return "<"+cls.__name__+">"
        else:
            return cls._module_name

    @property
    def module_cls_name(self):
        """
        Return class name of module
        """
        return self._module_cls_name

    @property
    def malware(self):
        """
        Return malware of module
        """
        return self._malware
