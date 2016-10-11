"""
API/WEB functions

WEB :
    /
    /about
    /analyze/create
    /analyze/report/<id>/<type>

API :
    /api/analyze/create
    /api/analyze/report/<id>/<type>
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import os
import shutil
import logging
import configparser

from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for
from werkzeug import secure_filename

from lama.input.input import Input
from lama.reporter.reporter import Reporter
from lama.models.analysis import Analysis


config = configparser.ConfigParser()
config.read('lama/conf/project.conf')

flask_listen_host = config.get('API', 'flask_listen_host', fallback='127.0.0.1')
flask_listen_port = int(config.get('API', 'flask_listen_port', fallback='5000'))

app = Flask(__name__)


app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

app.config['UPLOAD_FOLDER'] = config.get('API', 'upload_folder', fallback='uploadsfallback')

app.url_map.strict_slashes = False

def allowed_file(filename):
    return True
    # return '.' in filename and \
    #        filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

# ########################################################################### #
#                                Web Part                                     #
# ########################################################################### #


@app.route("/", methods=['GET'])
def web_index():
    return render_template("index.html")


@app.route("/about", methods=['GET'])
def web_about():
    return render_template("about.html")


@app.route("/analyze/create", methods=['POST', 'GET'])
def web_analyze_create():
    if request.method == 'POST':
        uploaded_files = request.files.getlist("file[]")
        uploaded_url = request.form.getlist("url[]")
        print(uploaded_url)
        analysis_id = create(uploaded_files, uploaded_url)
        # TODO get report types
        types = ["json", "html"]
        return render_template("create.html", analysis_id=analysis_id,
                               types=types)
    elif request.method == 'GET':
        return render_template("create.html")


@app.route("/analyze/list", methods=['GET'])
@app.route("/analyze/list/<int:page>", methods=['GET'])
@app.route("/analyze/list/<int:page>/<int:limit>", methods=['GET'])
def web_analyze_list(page=1, limit=10):
    if page > 0:
        page -= 1
    else:
        page = 0
    if limit <= 0:
        limit = 10
    offset = page*limit
    analysis_list = get_list(offset=offset, limit=limit)
    next_page = len(analysis_list) == limit
    prev_page = page >= 1
    return render_template("list.html", analysis_list=analysis_list,
                           page=page+1, limit=limit,
                           next_page=next_page, prev_page=prev_page)


@app.route("/analyze/report/<int:analysis_id>", methods=['GET'])
@app.route("/analyze/report/<int:analysis_id>/<string:out_format>",
           methods=['GET'])
def web_analyze_report(analysis_id, out_format='html'):
    report = make_report(analysis_id, out_format)
    # TODO get report types
    types = ["json", "html"]
    return render_template("report.html", report=report,
                           analysis_id=analysis_id,
                           types=types)


@app.route("/analyze/<int:uid>/delete", methods=['GET'])
def web_analyze_delete(uid):
    delete(uid)
    return redirect(url_for('web_analyze_list'))


@app.route("/file", methods=['GET'])
def web_remote_file():
    remote_path = request.args.get('path')
    if not remote_path:
        return "No remote path given."
    local_path, name = get_remote_file(remote_path)
    if not local_path:
        return "Remote file '{}' not found.".format(remote_path)
    res = send_from_directory(local_path, name, as_attachment=True)
    shutil.rmtree(local_path)
    return res

# ########################################################################### #
#                                API Part                                     #
# ########################################################################### #


@app.route("/api/analyze/create", methods=['POST'])
def api_analyze_create():
    uploaded_files = request.files.getlist("file[]")
    uploaded_url = request.files.getlist("url[]")
    analysis_id = create(uploaded_files, uploaded_url)
    return str(analysis_id)


@app.route("/api/analyze/flush", methods=['GET'])
def api_analyze_flush():
    return str(flush())

@app.route("/api/analyze/<int:uid>/delete", methods=['GET'])
def api_analyze_delete(uid):
    return str(delete(uid))


@app.route("/api/analyze/report/<int:analysis_id>", methods=['GET'])
@app.route("/api/analyze/report/<int:analysis_id>/<string:format>",
           methods=['GET'])
def api_analyze_report(analysis_id, out_format='json'):
    report = make_report(analysis_id, out_format)
    return str(report)


@app.route("/api/file", methods=['GET'])
def api_remote_file():
    return "TODO"


# ########################################################################### #
#                                Err Part                                     #
# ########################################################################### #


def request_wants_json():
    best = request.accept_mimetypes \
        .best_match(["application/json", "text/html"])
    return best == "application/json" and \
        request.accept_mimetypes[best] >= \
        request.accept_mimetypes["text/html"]


@app.errorhandler(404)
def page_not_found(e):
    if request_wants_json():
        response = jsonify({'error': 'not found'})
        response.status_code = 404
        return response
    return render_template('404.html'), 404

# ########################################################################### #
#                                Fct Part                                     #
# ########################################################################### #


def create(uploaded_files=[], uploaded_url=[]):
    paths = []
    for file in uploaded_files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # TODO check path before save
            path = os.path.join(app.config['UPLOAD_FOLDER'])
            if not os.path.exists(path):
                os.makedirs(path)
            path_filename = os.path.join(path, filename)
            file.save(path_filename)
            paths.append(path_filename)
    inp = Input(paths, urls=uploaded_url)
    analysis_id = inp.analyze()
    logging.info("Analysis {} : {}".format(analysis_id, paths))
    return analysis_id


def delete(uid):
    return Input.delete_analysis(uid)


def flush():
    return Input.flush()


def get_list(offset=0, limit=10, children=False):
    return Input.get_all_analysis(offset=offset, limit=limit, children=children)


def make_report(analysis_id, out_format):
    report = Reporter.make_report(analysis_id, out_format)
    return str(report)


def get_remote_file(remote_path):
    local_path = Input.get_remote_file(remote_path)
    return local_path


# ########################################################################### #
#                                Run Part                                     #
# ########################################################################### #

def run_api(debug=False):
    logging.info("Run API")
    app.run(host=flask_listen_host, port=flask_listen_port, debug=debug, threaded=True)
