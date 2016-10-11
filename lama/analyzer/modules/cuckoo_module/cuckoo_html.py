"""
Cuckoo HTML class

This class parse all indicators of Cuckoo and create an HTML report.
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
import json
from html import escape


class CuckooHtml(object):

    def make_html(content):
        """
        Main function for report generation

        Args:
            **content** (dict): dict to be parsed.
        """
        html = ""
        vms = dict()
        for item in content:
            if item.option not in vms:
                vms[item.option] = dict()
            if item.name == "score":
                vms[item.option]['score'] = item.content
            elif item.name == "machine_label":
                vms[item.option]['machine_label'] = item.content
            else:
                if item.name not in vms[item.option]:
                    vms[item.option][item.name] = []
                vms[item.option][item.name].append(item)

        vm_nb = 0
        html += "<ul class=\"cuckoo_vm\">"
        for _, vm in vms.items():
            html += "<li class=\"cuckoo_vm_li\">"
            # print VM name
            vm_nb += 1
            if "machine_label" in vm:
                machine_label = vm['machine_label']
            else:
                machine_label = str(vm_nb)
            # add machine label
            html += "<h3  class=\"analysis_title\">{}</h3>".format(machine_label)
            # add score
            if "score" in vm:
                html += CuckooHtml._score_make_html(vm['score'])
            else:
                # TODO error maybe ???
                html += "###########################"
            # add file category

            html += "<ul class=\"cuckoo_part\">"

            if 'all' in vm:
                html += "<h4>-> Full archive</h4>"
                html += "<li class=\"cuckoo_part_li\">"
                html += CuckooHtml._tar_make_html(vm['all'])
                html += "</li>"

            if 'pcap' in vm:
                html += "<h4>-> Pcap</h4>"
                html += "<li class=\"cuckoo_part_li\">"
                html += CuckooHtml._pcap_make_html(vm['pcap'])
                html += "</li>"


            # screenshot
            if 'screenshots' in vm:
                html += "<h4>-> Screenshots</h4>"
                html += "<li class=\"cuckoo_part_li\">"
                html += CuckooHtml._screenshot_make_html(vm['screenshots'])
                html += "</li>"

            # signatures
            if "signature" in vm:
                html += "<h4>-> Signatures</h4>"
                html += "<li class=\"cuckoo_part_li\">"
                # sort by severity
                vm['signature'].sort(key=lambda sign:
                                     json.loads(sign.content)['severity'])
                for item in reversed(vm['signature']):
                    html += CuckooHtml._signatures_make_html(item.content)
                html += "</li>"

            # network
            if "network" in vm:
                html += "<h4>-> Network</h4>"
                html += "<li class=\"cuckoo_part_li\">"
                for item in vm['network']:
                    html += CuckooHtml._network_make_html(item.content)
                html += "</li>"

            # process
            if "process" in vm:
                html += "<h4>-> Process</h4>"
                html += "<li class=\"cuckoo_part_li\">"
                for item in vm['process']:
                    html += CuckooHtml._process_make_html(item.content)
                html += "</li>"

            # yara
            if "buff_yara" in vm:
                html += "<h4>-> Yara</h4>"
                html += "<li class=\"cuckoo_part_li\">"
                for item in vm['buff_yara']:
                    html += CuckooHtml._buff_yara_make_html(item.content)
                html += "</li>"

            html += "</ul>"

            html += "</li>"

        html += "</ul>"
        return html

    def _score_make_html(content):
        """
        Create part with score
        """
        int_score = float(content)
        if int_score <= 1:
            flag = "info"
        elif int_score <= 4:
            flag = "warning"
        else:
            flag = "important"
        html = "<div>"
        html += (
                "Score <label class=\"label label-{}\">{}</label>"
                ).format(flag, str(int_score))
        html += "</div>"
        return html

    def _category_make_html(content):
        """
        Create part with categorie
        """
        html = "<div>"
        html += "<b>Category : </b>{}".format(escape(content))
        html += "</div>"
        return html

    def _buff_yara_make_html(content):
        """
        Create part with YARA results
        """
        decode_content = json.loads(content)
        html = "<div>"
        for cont in decode_content:
            html += (
                    "<label class=\"label label-info\">{}</label> : strings {}"
                    ).format(escape(cont['name']),
                             escape(", ".join(cont['strings'])))
            html += "<br/>{}".format(cont['meta']['description'])
        html += "</div>"
        return html

    def _signatures_make_html(content):
        """
        Create part with Signatures
        """
        html = "<div>"
        decode_content = json.loads(content)
        severity = int(decode_content['severity'])
        if severity <= 1:
            flag = "info"
        elif severity <= 4:
            flag = "warning"
        else:
            flag = "important"
        html += (
                "<label class=\"label label-{}\">{} ({})</label> <pre>{}</pre>"
                ).format(flag, escape(decode_content['name']),
                         escape(str(severity)),
                         escape(decode_content['description']))
        html += "</div>"
        return html

    def _network_make_html(content):
        """
        Create part with Network results
        """
        html = "<div>"
        decode_content = json.loads(content)
        for proto in decode_content:
            if not (proto == "pcap_sha256" or proto == "sorted_pcap_sha256")  and len(decode_content[proto])>=1:
                html += "<div>"
                html += "<label class=\"label label-info\">{}</label>".format(escape(proto))
                html += "<ul>"
                for item in decode_content[proto]:
                    if proto == "icmp":
                        html += "<li>{}</li>".format("<label class=\"label label-inverse\">TODO icmp</label>")
                    elif proto == "dns":
                        html += "<li>"
                        html += "<b>{}</b> : type <b>{}</b>".format(escape(item['request']),
                                                                    escape(item['type']))
                        html += "<ul>"
                        for answer in item['answers']:
                            html += "<li>-> {} : type {}</li>".format(escape(answer['data']),
                                                                      escape(answer['type']))
                        html += "</ul>"

                        html += "</li>"

                    elif proto == "tcp":
                        html += "<li style=\"white-space: pre;\">{}: {} -> {}: {}</li>".format(
                            escape(item['src']).ljust(16),
                            escape(str(item['sport'])).ljust(6),
                            escape(item['dst']).ljust(16),
                            escape(str(item['dport'])).ljust(6)
                        )
                    elif proto == "domains":
                        html += "<li><b>{}</b> : {}</li>".format(
                            escape(item['domain']),
                            escape(item['ip'])
                        )
                    elif proto == "irc":
                        html += "<li>{}</li>".format("<label class=\"label label-inverse\">TODO irc</label>")
                    elif proto == "udp":
                        html += "<li style=\"white-space: pre;\">{}: {} -> {}: {}</li>".format(
                            escape(item['src']).ljust(16),
                            escape(str(item['sport'])).ljust(6),
                            escape(item['dst']).ljust(16),
                            escape(str(item['dport'])).ljust(6)
                        )
                    elif proto == "https_ex":
                        html += "<li>{}</li>".format("<label class=\"label label-inverse\">TODO https_ex</label>")
                    elif proto == "http_ex":
                        html += "<li>{}</li>".format("<label class=\"label label-inverse\">TODO http_ex</label>")
                    elif proto == "tls":
                        html += "<li>{}</li>".format("<label class=\"label label-inverse\">TODO tls</label>")
                    elif proto == "smtp":
                        html += "<li>{}</li>".format("<label class=\"label label-inverse\">TODO smtp</label>")
                    elif proto == "mitm":
                        html += "<li>{}</li>".format("<label class=\"label label-inverse\">TODO mitm</label>")
                    elif proto == "hosts":
                        html += "<li>{}</li>".format(escape(item))
                    elif proto == "http":
                        html += (
                            "<li>"
                            "<b>{}</b><br/>"
                            "<pre>{}</pre>"
                            "</li>"
                                 ).format(escape(item['uri']),
                                          escape(item['data']))
                    elif proto == "dead_hosts":
                        html += "<li><b>{}</b> : {}</li>".format(
                            escape(item[0]),
                            escape(str(item[1])))
                    else:
                        html += "<li>ERROR PARSE CuckooHtml : {}</li>".format(proto)
                html += "</ul>"
                html += "</div>"
        html += "</div>"
        return html

    def _process_make_html(content):
        """
        Create part with Processtree results
        """
        html = ""
        decode_content = json.loads(content)
        for proctree in decode_content:
            html += CuckooHtml._process_make_html_rec(proctree)
        return html

    def _process_make_html_rec(proctree):
        html = ""
        html += "<div class=\"processtree\">"
        html += "{} : {}".format(proctree['process_name'], proctree['command_line'])
        for child in proctree['children']:
            html += CuckooHtml._process_make_html_rec(child)
        html += "</div>"
        return html

    def _tar_make_html(content):
        """
        Create part with link to the archive report
        """
        html = ""
        paths = content[0].content.split(",")
        for path in paths:
            html += "<label class=\"label\">Archive : </label> <a href=\"/file?path={}\">all.tar.gz</a><br />".format(path)
        return html

    def _screenshot_make_html(content):
        """
        Create part with screenshots
        """
        html = ""
        paths = content[0].content.split(",")
        for path in sorted(paths):
            name = os.path.basename(path)
            html += "<a href=\"/file?path={}\"><label class=\"label\">Screenshots : {}</label><br/><img src=\"/file?path={}\"/></a><br />".format(path, name, path)
        return html

    def _pcap_make_html(content):
        """
        Create part with link to PCAP
        """
        html = ""
        paths = content[0].content.split(",")
        for path in paths:
            html += "<label class=\"label\">Pcap : </label> <a href=\"/file?path={}\">Pcap</a><br />".format(path)
        return html
