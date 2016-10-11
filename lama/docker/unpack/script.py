__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


from pyunpack import Archive
import os
import json
import magic
import mimetypes
import shutil

result_dict = dict()


success = False
name = "/lama/sample"
mime = magic.from_file("/lama/sample", mime=True)
ext = mimetypes.guess_extension(mime)
if not ext:
    if "/x-" in mime:
        mime2 = mime.replace("/x-", "/").strip()
        ext = mimetypes.guess_extension(mime2)
        if ext:
            mime = mime2
if ext:
    name = name+ext
    shutil.copy("/lama/sample", name)


if not success:
    try:
        Archive(name).extractall("/lama/out")
        success = True
    except Exception as e:
        pass


if success:
    result_dict['res'] = "ok"
else:
    result_dict['error'] = "Not an archive"
os.system("chmod 777 -R /lama/out")
# return result
print(json.dumps(result_dict))
