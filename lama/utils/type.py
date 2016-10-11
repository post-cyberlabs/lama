""" Type class

This class represant all type for indicators.
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


class Type(object):

    # simple type -> No analyze after
    STRING = 1
    INTEGER = 2

    JSON = 10
    STRING_ARRAY = 11
    BASE64 = 12
    # complexe type -> need analyze after
    FILE = 20
    BIN = 21
    PDF = 22
    DOC = 23
    JS = 24
    VBA = 25
    URL = 27
    IP = 28
    label = {STRING: "STRING",
             INTEGER: "INTEGER",
             FILE: "FILE",
             BIN: "BIN",
             PDF: "PDF",
             DOC: "DOC",
             JS: "JS",
             VBA: "VBA",
             JSON: "JSON",
             URL: "URL",
             }

    @staticmethod
    def get_label(t):
        return Type.label[t]
