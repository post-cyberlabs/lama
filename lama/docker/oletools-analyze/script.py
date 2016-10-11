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
import subprocess

result_dict = dict()
p = subprocess.Popen(['python',
                      '/lama/oletools/oletools/olevba.py',
                      '/lama/sample',
                      '--deobf'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     stdin=subprocess.PIPE)
out, err = p.communicate()

part = 0
res = []
for line in out.split("\n"):
    match = re.match('\+\-+\+\-+\+\-+\+', line)

    if part == 2 and not match:
        parts = [l.strip() for l in line.split('|')]
        if len(parts[1]):
            res.append({'type': parts[1],
                        'keyword': parts[2],
                        'description': parts[3]})
        else:
            if len(parts[2]):
                res[-1]['keyword'] += parts[2]
            if len(parts[3]):
                res[-1]['description'] += parts[3]

    if re.match('\+\-*\+\-*\+\-*\+', line):
        part += 1

    elif part == 3:
        break


print(json.dumps(res))
