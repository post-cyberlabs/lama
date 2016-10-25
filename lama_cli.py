#!/usr/bin/env python3


""" CLI

Usage:
    lama_cli.py
    lama_cli.py [-p PATH ...] [-u URL ...] [-d] [-v]
    lama_cli.py [-r ID [-t TYPE]] [-d] [-v]
    lama_cli.py (-d | --debug)
    lama_cli.py (-v | --verbose)
    lama_cli.py (-h | --help)
    lama_cli.py --version

Options:
    -p PATH --path=PATH                     Add path for analysis
    -u URL --url=URL                        Add URL for analysis
    -r ID --result=ID                       ID of analysis
    -t TYPE --type=TYPE                     Type of report (json)
    -d --debug                              Debug mode
    -v --verbose                            Verbose mode
    -h --help                               Show this message
    --version                               Show version

Examples:
    lama_cli.py -p /PATH/TO/MALWARE         (Run analyse for selected file)
    lama_cli.py -g 1                        (View analysis 1)
    lama_cli.py -g 1 -t json                (View analysis 1 as Json)

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
import os.path
import logging
import validators

from docopt import docopt

from lama.input.input import Input
from lama.reporter.reporter import Reporter
from lama.utils.logging import configure_logging


def main():
    args = docopt(__doc__, version='0.1')
    debug = args["--debug"]
    verbose = args["--verbose"]
    if not os.path.exists("log"):
        os.makedirs("log")
    configure_logging("log/lama_cli.log", debug=debug, verbose=verbose)
    cmd_line = "COMMAND : "+" ".join(sys.argv)
    logging.info(cmd_line)
    # analysis
    paths = []
    urls = []
    if args["--path"] or args["--url"]:
        if args["--path"]:
            paths = args["--path"]
            for path in paths:
                if not os.path.isfile(path):
                    print("[X] "+path+" don't exists")
                    exit(1)
        if args["--url"]:
            urls = args["--url"]
            for url in urls:
                if not validators.url(url):
                    print("[X] "+url+" not valid")
                    exit(1)

        # run analysis
        inp = Input(paths, urls)
        analysis_id = inp.analyze()
        print("Analysis UID : {}".format(analysis_id))


    # view
    elif args["--result"]:
        # Get analysis id
        analysis_id = 0
        try:
            arg = args["--result"]
            analysis_id = int(arg)
        except ValueError:
            print("Invalid format."
                  "Value of the -r/--result option"
                  "must be an integer.See --help")
            exit(1)
        # Get report type
        if args["--type"]:
            report_type = args["--type"]
        else:
            report_type = "json"
        # Generate report
        report = Reporter.make_report(analysis_id, report_type)
        print(report)


if __name__ == "__main__":
    main()
