__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import json
import validators
import requests
import os

result_dict = dict()

try:
    urls = open('/lama/sample', 'r').read()
except Exception as e:
    result_dict['error'] = str(e)
    print(json.dumps(result_dict))
    exit(0)

result_dict['urls'] = dict()
for i, url in enumerate(urls.split("\n")):
    url = url.strip()
    result_dict['urls'][url] = dict()
    if len(url):
        if validators.url(url):
            try:
                r = requests.get(url, stream=True)
                # TODO find some things to change name
                name = "extract"
                path = "/lama/out/{}/".format(i)
                file_path = os.path.join(path, name)
                os.makedirs(path)
                with open(file_path, 'wb') as fd:
                    for chunk in r.iter_content(16384):
                        fd.write(chunk)
                result_dict['urls'][url]['path'] = file_path
            except Exception as e:
                result_dict['urls'][url]['error'] = str(e)
        else:
            result_dict['urls'][url]['error'] = "Not a valid URL."
# return result
print(json.dumps(result_dict))
os.system("chmod 777 -R /lama/out 2>/dev/null")
