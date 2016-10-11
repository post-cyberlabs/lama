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
    lama_mail.py [-u USER] [-s SERVER] [-p PORT] [--password] [-d] [-v]
    lama_mail.py (-d | --debug)
    lama_mail.py (-v | --verbose)
    lama_mail.py (-h | --help)
    lama_mail.py --version

Options:
    -u USER --user=USER                     Mail user
    -s SERVER --server=SERVER               Server mail address
    -p PORT --port=PORT                     Server mail port
    --password                              Ask for password
    -d --debug                              Debug mode
    -v --verbose                            Verbose mode
    -h --help                               Show this message
    --version                               Show version

Examples:
    lama_mail.py -u jonh -s pop.doe.lu -p 110 --password      (Connect to mail server)

"""

import os
import sys
import os.path
import logging
import getpass
import configparser

from docopt import docopt

from lama.input.automated.mail import Mail
from lama.utils.logging import configure_logging


def main():
    args = docopt(__doc__, version='0.1')
    debug = args["--debug"]
    verbose = args["--verbose"]
    if not os.path.exists("log"):
        os.makedirs("log")
    configure_logging("log/lama_mail.log", debug=debug, verbose=verbose)
    cmd_line = "COMMAND : "+" ".join(sys.argv)
    logging.info(cmd_line)

    config = configparser.ConfigParser()
    config.read('lama/conf/project.conf')

    try:
        user = config["MAIL_INPUT"]["user"]
        password = config["MAIL_INPUT"]["password"]
        server = config["MAIL_INPUT"]["server"]
        port = config["MAIL_INPUT"]["port"]
    except KeyError as e:
        logging.error("Error project.conf[MAIL] : {} missing.".format(str(e)))
        exit(1)

    # overide params
    if args["--user"]:
        user = args["--user"]
    if args["--server"]:
        server = args["--server"]
    if args["--port"]:
        port = args["--port"]
    if args["--password"]:
        password = getpass.getpass("Enter password please : ")

    print(user, password, server, port)

    mail = Mail(user, password, server, port)
    mail.run()

if __name__ == "__main__":
    main()
