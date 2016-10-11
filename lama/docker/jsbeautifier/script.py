__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import jsbeautifier
import json
import base64

result_dict = dict()

try:
    res = jsbeautifier.beautify_file('/lama/sample')
    res = res.encode('utf-8')
    result_dict['code'] = base64.b64encode(res)
except (UnicodeDecodeError, UnicodeEncodeError) as e:
    result_dict['error'] = base64.b64encode(str(e))
except Exception as e:
    result_dict['error'] = base64.b64encode(str(e))

print(json.dumps(result_dict))
