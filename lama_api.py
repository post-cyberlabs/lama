#!/usr/bin/env python3


""" CLI

Usage:
    lama_api.py [-d] [-v]
    lama_api.py (-d | --debug)
    lama_api.py (-v | --verbose)
    lama_api.py (-h | --help)
    lama_api.py --version

Options:
    -d --debug                              Debug mode
    -v --verbose                            Verbose mode
    -h --help                               Show this message
    --version                               Show version

Examples:
    lama_api.py                        (Run analyzer)

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
import sys
import logging

from docopt import docopt

from lama.input.web.api import run_api
from lama.analyzer.analyzer import Analyzer
from lama.utils.ftp import LamaFtp
from lama.utils.database import Lamadb
from lama.utils.logging import configure_logging


def main():
    args = docopt(__doc__, version='0.1')
    debug = args["--debug"]
    verbose = args["--verbose"]
    if not os.path.exists("log"):
        os.makedirs("log")
    configure_logging("log/lama_api.log", debug=debug, verbose=verbose)
    cmd_line = "COMMAND : "+" ".join(sys.argv)
    logging.info(cmd_line)
    try:
        Lamadb.create_db()
        LamaFtp.create_ftp()
        run_api(debug=debug)
    except KeyboardInterrupt:
        Analyzer.stop_analyzer()

if __name__ == "__main__":
    main()
