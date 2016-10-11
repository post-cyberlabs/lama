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
import pexpect
import base64

result_dict = dict()
p = subprocess.Popen(['python',
                      '/lama/peepdf/peepdf.py',
                      '-j', '-i',
                      '/lama/sample'],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     stdin=subprocess.PIPE)
out, err = p.communicate()
# print(out)
try:
    info_json = json.loads(out)
except ValueError:
    result_dict['error'] = base64.b64encode(err)
    print(json.dumps(result_dict))
    exit(-1)

js_dict = info_json['peepdf_analysis']['advanced'][0]['version_info']['suspicious_elements']['actions']
js_objs = []
if js_dict:
    if "/JS" in js_dict:
        for index in js_dict['/JS']:
            js_objs.append(index)


child = pexpect.spawn('python /lama/peepdf/peepdf.py -ig /lama/sample')
child.expect('PPDF>')

# Info
child.sendline("info > info")
child.expect('PPDF>')
info_f = open("info", 'r')
info_str = info_f.read()
result_dict['info'] = info_str

# parse info for URIs
uris_obj = []
for line in info_str.split('\n'):
    if "Objects with URIs" in line:
        uris = line.split(':')
        if len(uris) is 2:
            uris_obj = json.loads(uris[1])

# JS
result_dict['js'] = []
for ind in js_objs:
    child.sendline("object "+str(ind)+" > js"+str(ind))
    child.expect('PPDF>')
    js_f = open("js"+str(ind), 'r')
    js_str = js_f.read()
    result_dict['js'].append(base64.b64encode(js_str))

# URIs
result_dict['uris'] = []
for ind in uris_obj:
    child.sendline("object "+str(ind)+" > uri"+str(ind))
    child.expect('PPDF>')
    uri_f = open("uri"+str(ind), 'r')
    uri_str = uri_f.read()
    result_dict['uris'].append(base64.b64encode(uri_str))

print(json.dumps(result_dict))
