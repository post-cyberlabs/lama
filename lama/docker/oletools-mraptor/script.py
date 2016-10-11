__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import subprocess
import json
import base64

result_dict = dict()
p = subprocess.Popen(['python',
                      '/lama/oletools/oletools/mraptor.py',
                      '/lama/sample'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     stdin=subprocess.PIPE)

out, err = p.communicate()
returncode = p.returncode
result_dict['out'] = base64.b64encode(out)
result_dict['returncode'] = returncode
print(json.dumps(result_dict))
