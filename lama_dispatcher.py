#!/usr/bin/env python3


""" CLI

Usage:
    lama_dispatcher.py [-d] [-v]
    lama_dispatcher.py (-d | --debug)
    lama_dispatcher.py (-v | --verbose)
    lama_dispatcher.py (-h | --help)
    lama_dispatcher.py --version

Options:
    -d --debug                              Debug mode
    -v --verbose                            Verbose mode
    -h --help                               Show this message
    --version                               Show version

Examples:
    lama_dispatcher.py                        (Run dispatcher)

"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"

import sys
import os
import logging

from docopt import docopt

from lama.utils.ftp import LamaFtp
from lama.utils.database import Lamadb
from lama.utils.logging import configure_logging
from lama.analyzer.dispatcher import Dispatcher


def main():
    args = docopt(__doc__, version='0.1')
    debug = args["--debug"]
    verbose = args["--verbose"]
    if not os.path.exists("log"):
        os.makedirs("log")
    configure_logging("log/lama_dispatcher.log", debug=debug, verbose=verbose)
    cmd_line = "COMMAND : "+" ".join(sys.argv)
    logging.info(cmd_line)
    try:
        Lamadb.create_db()
        LamaFtp.create_ftp()
        Dispatcher.dispatch()
    except KeyboardInterrupt:
        Dispatcher.stop_dispatch()

if __name__ == "__main__":
    main()
