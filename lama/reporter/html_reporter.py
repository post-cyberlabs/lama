"""
Html Reporter Class

This class allow to create a report in HTML.
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


from html import escape

from lama.analyzer.module import Module
from lama.models.module_status import ModuleStatus

import json

class HtmlReporter(object):

    @staticmethod
    def make_report(analysis):
        """
        Method to report in HTML format.

        Args :
            **analysis** (Analysis) : Analysis to report
        """
        html = ""
        stats = analysis.compute_stat()

        analysis.malwares.sort(key=lambda m: m.uid)
        html += "<div>"
        html += "<span>Creation date : {}</span><br/>".format(analysis.start_date)
        html += "<span>Finish date : {}</span><br/>".format(analysis.end_date)
        html += "<span>Score : Avg {}, Max {}</span>".format(stats['score_avg'], stats['score_max'])
        html += "<div style=\"float:right\">"
        html += "  <a href=\"/analyze/{}/delete\" class=\"remove_field\" ><span class=\"badge badge-important\">Delete analysis</span></a>".format(analysis.uid)
        html += "</div>"
        html += "</div>"

        html += HtmlReporter._make_menu(analysis)
        html += "<div id=\"analysis_results\">"
        for i, m in enumerate(analysis.malwares):
            html += HtmlReporter._make_malware_report(m, (i == 0))
        html += ""
        html += ""
        html += "</div>"
        return html

    def _make_menu(analysis):
        html = "<aside id=\"analysis_tree\" style=\"word-wrap: break-word;\">"
        html += "<h3 class=\"analysis_title\">Malwares</h3>"
        html += "<ul  class=\"nav nav-list\">"
        for i, m in enumerate(analysis.malwares):
            if not m.parent_uid:
                actif = ""
                if i is 0:
                    actif = "active"
                html += HtmlReporter._make_menu_malware(m, 0, actif)
        html += "</ul>"
        html += "</aside>"
        return html

    def _make_menu_malware(m, level=0, actif=""):
        html = ""
        tab = ""
        if level:
            tab = level * 4 * "&nbsp;" + level * "-" + "&nbsp;"

        html += "<li id=\"menu_malware_{}\" class=\"menu_malware {}\"><a href=\"#\" onclick=\"show_malware({})\">{}{}</a></li>".format(str(m.uid), actif, str(m.uid), tab, escape(m.name))
        if len(m.extract_malware):
            html += "<ul class=\"nav nav-list\">"
            for m_e in m.extract_malware:
                html += HtmlReporter._make_menu_malware(m_e, level+1)
            html += "</ul>"
        return html
        html += "{}".format([me.name for me in m.extract_malware])

    def _make_malware_report(malware, display):
        display_style = ""
        if not display:
            display_style = "display: none;"
        html = "<div class=\"malware\" id=\"malware_{}\" style=\"{}\">".format(malware.uid, display_style)

        html += "<div class=\"malware_info\" id=\"malware\">"
        html += "<h3 class=\"analysis_title\">Malware Infos</h3>"
        stats = malware.compute_stat()
        html += "Score : <b>Avg : {0:.1f}, Max : {1:.1f}</b><br/>".format(stats['score_avg'], stats['score_max'])
        html += "<ul>"
        html += "<li>Name : {}</li>".format(malware.name)
        html += "<li>Size : {}</li>".format(malware.size)
        html += "<li>MD5 : {}</li>".format(malware.md5)
        html += "<li>SHA1 : {}</li>".format(malware.sha1)
        html += "<li>Mime type : {}</li>".format(malware.mime)
        malware_link = str(malware.analysis_uid)+"/"+str(malware.uid)+"/"+malware.name
        html += "<li>Download : <a href=\"/file?path={}\">link</a></li>".format(malware_link)
        html += "</ul>"
        html += "</div>"

        html += "<h3 class=\"analysis_title\">Modules</h3>"

        if malware.nb_module > 0:
            malware.module_status.sort(key=lambda ms: ms.module_cls_name)
            html += HtmlReporter._make_module_menu(malware)

            html += "<div class=\"malware_modules\">"
            for i, ms in enumerate(malware.module_status):
                html += HtmlReporter._make_module_status_report(ms, malware.uid, (i==0))
            html += "</div>"
        else:
            html += "<span>No module compatible.</span>"

        html += "</div>"
        return html

    def _make_module_menu(malware):
        html = ""
        html += "<div>"
        html += "<ul class=\"nav nav-pills modules-pills\">"
        for i, m in enumerate(malware.module_status):
            module_class = Module.get_module_by_name(m.module_cls_name)
            module_name = module_class.module_name()
            active = ""
            if i is 0:
                active = "active"
            html += "<li id=\"menu_module_malware_{}_{}\" class=\"menu_module_malware menu_module_malware_{} {}\"><a href=\"#\" onclick=\"show_module_malware({},{})\">{}</a></li>".format(str(malware.uid),str(m.id),str(malware.uid),active,str(malware.uid),str(m.id),escape(module_name))
        html += "</ul>"
        html += "</div>"
        return html

    def _make_module_status_report(ms, malware_uid, display):
        display_style = ""
        if not display:
            display_style = "display: none;"
        html = "<div class=\"module_malware_{}\" id=\"module_malware_{}_{}\"  style=\"{}\">".format(malware_uid, malware_uid, ms.id, display_style)
        html += "<h4 class=\"module_title\">{}</h4>".format(ms.module_cls_name)
        html += "Status : <b>{}</b><br/>".format(ModuleStatus.STATUS_LABEL[ms.status])
        stats = ms.compute_stat()
        html += "Score : <b>Avg : {0:.1f}, Max : {1:.1f}</b><br/>".format(stats['avg'], stats['max'])

        html += "<div class=\"module_content\">"
        if len(ms.indicators):
            html += HtmlReporter._make_indicator_report(ms.module_cls_name,
                                                        ms.indicators)
        else:
            html += "No indicator."
        html += "</div>"

        html += "</div>"
        return html

    def _make_indicator_report(module_cls_name, indicators):
        module_class = Module.get_module_by_name(module_cls_name)
        html_report_fct = getattr(module_class, "html_report", None)
        html = ""
        if callable(html_report_fct):
            html += html_report_fct(indicators)
        else:
            for indic in indicators:
                html += "<div><b>{} ({}): </b>{}<br/></div>".format(escape(indic.name),
                                                                    indic.score,
                                                                    escape(indic.content))
        return html
