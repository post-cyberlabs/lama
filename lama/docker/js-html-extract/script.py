__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import re
import json

result_dict = dict()

gdoc = open('/lama/sample', 'r').read()
scriptlis = re.findall(r'<script\s*([^>]*)\s*>(.*?)</script', gdoc, re.I|re.S)
result_dict['code'] = scriptlis

print(json.dumps(result_dict))
