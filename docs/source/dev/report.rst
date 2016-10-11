Report
======

Manual
------

On the ``lama/reporter`` directory you can add manual reporter (like html_reporter.py and json_reporter.py)

You need to call it on the make_report function on Reporter class (reporter.py).

In future, this part will be refactored like the automated reporting.

Automated
---------


To implement a automated reporting module you need to add your code on the ``lama/reporter/automated`` directory.
Your class need to override the AutomatedReporter class and implement the run(self, analysis) function.
On this function you have access to an Analysis object with link to Malware, ModuleStatus and Indicator related to this Analysis.
