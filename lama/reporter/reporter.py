""" Reporter Class

This class manages the reporting part.
Manual: for the api or html reporting for exemple.
Automated: for sending mail or MISP for exemple

Modules for automated part are autoloaded. They need tro be on the lama.remoter.automated package.
Modules for manual reporting need to be added on the make_repport function.

"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


from lama.reporter.automated import *
from lama.models.analysis import Analysis
from lama.reporter.json_reporter import JsonReporter
from lama.reporter.html_reporter import HtmlReporter
from lama.reporter.automated_reporter import AutomatedReporter


class Reporter(object):
    """
    Reporter class
    """

    @staticmethod
    def make_automated_report(analysis):
        """
        Call by the dispatcher when an analysis if finished.
        It call on each automated module the function run()
        """
        for rep in AutomatedReporter:
            r = rep()
            r.run(analysis)

    @staticmethod
    def make_report(analysis_uid, report_type="json"):
        """
        Static make_report method
        Generate the report for givent format (json, html)

        Args :
            **analysis_id** (int) : Id of analysis.
            **report_type** (string) : Type of output format (json)
        """
        report_type = report_type.lower()
        analysis = Analysis.find_by_uid(analysis_uid)
        if analysis:
            if report_type == "json":
                # make json report
                return "<pre>" + JsonReporter.make_report(analysis) + "</pre>"
            if report_type == "html":
                # make html report
                return HtmlReporter.make_report(analysis)
            # type no found
        return "Doesn't exists"
