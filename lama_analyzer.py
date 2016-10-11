#!/usr/bin/env python3

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"

""" CLI

Usage:
    lama_analyzer.py [-d] [-v] [-p]
    lama_analyzer.py (-d | --debug)
    lama_analyzer.py (-v | --verbose)
    lama_analyzer.py (-h | --help)
    lama_analyzer.py --version

Options:
    -d --debug                              Debug mode
    -p --probe-mode                         Probe mode
    -v --verbose                            Verbose mode
    -h --help                               Show this message
    --version                               Show version

Examples:
    lama_analyzer.py                        (Run analyzer)

"""

import os
import sys
import logging

from docopt import docopt

from lama.utils.ftp import LamaFtp
from lama.utils.database import Lamadb
from lama.utils.logging import configure_logging
from lama.analyzer.analyzer import Analyzer


def main():
    args = docopt(__doc__, version='0.1')
    debug = args["--debug"]
    verbose = args["--verbose"]
    if not os.path.exists("log"):
        os.makedirs("log")
    configure_logging("log/lama_analyzer.log", debug=debug, verbose=verbose)
    cmd_line = "COMMAND : "+" ".join(sys.argv)
    logging.info(cmd_line)
    try:
        Lamadb.create_db()
        LamaFtp.create_ftp()
        Analyzer.run_analyzer()
    except KeyboardInterrupt:
        Analyzer.stop_analyzer()

if __name__ == "__main__":
    main()
