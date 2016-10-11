__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import abc


class RegisterReporterClasses(type):
    """
    RegisterModulesClasses class

    This class allow to register all submodule for automatical instantiation.
    """
    def __init__(cls, name, bases, nmspc):
        super(RegisterReporterClasses, cls).__init__(name, bases, nmspc)
        if not hasattr(cls, '_registry'):
            cls._registry = set()
        cls._registry.add(cls)
        cls._registry -= set(bases)
    # Metamethods, called on class objects:

    def __iter__(cls):
        return iter(cls._registry)


class ABCRegisterModulesClasses(RegisterReporterClasses, abc.ABCMeta):
    """
    ABCRegisterModulesClasses class

    Use for merge RegisterReporterClasses and ABCMeta into on class.
    Module class inherit from it.
    """
    pass


class AutomatedReporter(metaclass=ABCRegisterModulesClasses):

    @abc.abstractmethod
    def run(self):
        raise NotImplementedError
