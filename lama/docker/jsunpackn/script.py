__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import os
import base64
import json

result_dict = dict()

os.system('python /lama/jsunpack-n/jsunpackn.py /lama/sample -v > /dev/null')

try:
    decoded = open('/lama/jsunpack-n/temp/decoded.log', 'r')
except IOError as e:
    result_dict['error'] = str(e).decode('utf-8')
    print(json.dumps(result_dict))
    exit(0)

decoded_info = decoded.read()
result_dict['info'] = decoded_info
result_dict['sources'] = []
for line in decoded_info.split('\n'):
    if 'file:' in line:
        name = line.split(':')[1].strip()
        tmp_file = open('/lama/jsunpack-n/temp/files/'+name)
        tmp_file_str = tmp_file.read()
        result_dict['sources'].append(base64.b64encode(tmp_file_str))
        tmp_file.close()

print(json.dumps(result_dict))
