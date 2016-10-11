__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import logging
import logging.handlers
from logging.config import dictConfig

DEFAULT_LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
}


# source
# http://stackoverflow.com/questions/4441842/python-logging-configuration-file
def configure_logging(logfile_path, debug=False, verbose=False):
    """
    Initialize logging defaults for Project.

    :param logfile_path: logfile used to the logfile
    :type logfile_path: string

    This function does:

    - Assign INFO and DEBUG level to logger file handler and console handler

    """
    dictConfig(DEFAULT_LOGGING)

    file_formatter = logging.Formatter(
        "[%(asctime)s] "
        "[%(levelname)s] "
        "[%(funcName)s():%(lineno)s] "
        "%(message)s",
        "%d/%m/%Y %H:%M:%S")

    console_formatter = logging.Formatter(
        "==> %(levelname)s, %(funcName)s(), line %(lineno)s : "
        "%(message)s")

    file_handler = logging.handlers.RotatingFileHandler(logfile_path,
                                                        maxBytes=10485760,
                                                        backupCount=300,
                                                        encoding='utf-8')

    console_handler = logging.StreamHandler()
    if debug:
        console_handler.setLevel(logging.DEBUG)
        file_handler.setLevel(logging.DEBUG)
    elif verbose:
        console_handler.setLevel(logging.INFO)
        file_handler.setLevel(logging.INFO)
    else:
        console_handler.setLevel(logging.WARN)
        file_handler.setLevel(logging.INFO)

    file_handler.setFormatter(file_formatter)
    console_handler.setFormatter(console_formatter)

    logging.root.setLevel(logging.DEBUG)
    logging.root.addHandler(file_handler)
    logging.root.addHandler(console_handler)
