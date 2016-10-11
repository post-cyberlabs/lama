__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import os
import json

result_dict = dict()

# execute ffdec
os.system('echo "I" | ffdec -export all "/lama/out/extract" /lama/sample > /lama/ffdec-stdout 2> /lama/ffdec-stderr')

os.system('chmod 777 -R /lama/out/extract 2>/dev/null')
os.system('chmod 777 /lama/out/out.tar.gz 2>/dev/null')

# create an archive
os.system('tar zcvf /lama/out/out.tar.gz /lama/out/extract > /lama/tar-stdout 2> /lama/tar-stderr')

# collect stdout/stderr from ffdec and tar
ffdec_file = open("/lama/ffdec-stdout", "r")
ffdec_file_err = open("/lama/ffdec-stderr", "r")
tar_file = open("/lama/tar-stdout", "r")
tar_file_err = open("/lama/tar-stderr", "r")

ffdec_content = ffdec_file.read()
ffdec_content_err = ffdec_file_err.read()
tar_content = tar_file.read()
tar_content_err = tar_file_err.read()

result_dict['ffdec'] = ffdec_content
result_dict['ffdec_err'] = ffdec_content_err
result_dict['tar'] = tar_content
result_dict['tar_err'] = tar_content_err

# return result
print(json.dumps(result_dict))
