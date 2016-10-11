"""
Module Status class

This class represent a module's status for a malware.
Status are :
- NOT_ANALYZED
- IN_PROGRESS
- FINISH
- REPORTED
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import datetime
import lama.models.dao.module_status_dao


class ModuleStatus(object):
    """ModuleStatus class

    Args :
        **module_cls_name** (string) : Name of module.

        **status** (int) : Status for the module.

        **uid** (int) : Uid of ModuleStatus.

        **malware_uid** (int) : Id of related malware.

        **start_analyze_date** (datetime) : Start analysis time.

        **end_analyze_date** (datetime) : End analysis time.

        **options** (String) : option for the module.

        **indicators** (list):  List of indicator for this module.

    Attributes :
        **module_cls_name** (string) : Name of class module.

        **status** (int) : Status for the module.

        **uid** (int) : Uid of ModuleStatus.

        **malware_uid** (int) : Id of related malware.

        **start_analyze_date** (datetime) : Start analysis time.

        **end_analyze_date** (datetime) : End analysis time.

        **options** (String) : option for the module.

        **indicators** (list):  List of indicator for this module.
    """

    MODULE_NOT_ANALYZED = "0"
    MODULE_IN_PROGRESS = "1"
    MODULE_FINISH = "2"
    MODULE_REPORTED = "3"
    STATUS_LABEL = [
        "Not analyzed",
        "In progress",
        "Finish",
        "Reported"
    ]

    def __init__(self, module_cls_name, status, uid=None, malware_uid=None,
                 start_analyze_date=None, end_analyze_date=None, options=None,
                 indicators=None):
        self._uid = uid
        self._module_cls_name = module_cls_name
        self._status = status
        self._start_analyze_date = start_analyze_date
        self._end_analyze_date = end_analyze_date
        self._malware_uid = malware_uid
        self._options = options
        self._indicators = indicators
        if self._indicators is None:
            self._indicators = []

    def factory(module_cls_name, status, options=None):
        """
        Return a ModuleStatus for given args.

        Args :
            **module_cls_name** (String) : Name of class module.

            **status** (int) : Status for the module.

            **options** (String) : option for the module.

        """
        if not ModuleStatus._check_status(status):
            pass
        return ModuleStatus(uid=None, module_cls_name=module_cls_name,
                            status=status, options=options)

    def compute_stat(self):
        """
        Compute stats of module like :

        - Average score
        - Max score
        - Min score
        - Number of null
        - Number of error
        """
        stat = dict()
        stat['max'] = 0
        stat['avg'] = 0
        stat['avg_null'] = 0
        stat['nb_ind'] = 0
        stat['nb_null'] = 0
        stat['nb_err'] = 0
        for indicator in self._indicators:
            if indicator.score > 0:
                stat['nb_ind'] += 1
                stat['avg'] += indicator.score
                if stat['max'] is None or stat['max'] < indicator.score:
                    stat['max'] = indicator.score
            elif indicator.score == 0:
                stat['nb_null'] += 1
            else:
                stat['nb_err'] += 1
        if stat['nb_ind'] > 0:
            stat['avg_null'] = stat['avg']/(stat['nb_ind']+stat['nb_null'])
            stat['avg'] = stat['avg']/stat['nb_ind']
        return stat

    def is_finish(self):
        """
        Check if finish. (cf status is MODULE_REPORTED)
        """
        return str(self._status) == ModuleStatus.MODULE_REPORTED

    @property
    def id(self):
        """
        Return the uid
        """
        return self._uid

    @property
    def module_cls_name(self):
        """
        Return the module name.
        """
        return self._module_cls_name

    @property
    def status(self):
        """
        Return the status.
        """
        return self._status

    @property
    def start_analyze_date(self):
        """
        Return the start analysis datetime
        """
        return self._start_analyze_date

    @property
    def end_analyze_date(self):
        """
        Return the end analysis datetime
        """
        return self._end_analyze_date

    @property
    def options(self):
        """
        Return options
        """
        return self._options

    @property
    def malware_uid(self):
        """
        Return the malware uid
        """
        return self._malware_uid

    @property
    def indicators(self):
        """
        Return the list of indicators of module.
        """
        return self._indicators

    def add_indicator(self, indicator):
        """
        Add an indicator into current module.

        Args :
            **indicator** (string): Indicator object to add.
        """
        indicator.module_status_uid = self.id
        self._indicators.append(indicator)

    def add_options(self, options):
        """
        set options to module
        """
        self._options = options

    @malware_uid.setter
    def malware_uid(self, malware_uid):
        """
        Set the malware uid
        """
        self._malware_uid = malware_uid

    @staticmethod
    def _check_status(status):
        """
        Check modification state.
        """
        if status is not ModuleStatus.MODULE_NOT_ANALYZED and\
            status is not ModuleStatus.MODULE_IN_PROGRESS and\
                status is not ModuleStatus.MODULE_FINISH and\
                status is not ModuleStatus.MODULE_REPORTED:
            print("Error set_module with value : {}.".format(status))
            return False
        else:
            return True

    def change_status(self, status):
        """
        Change status for given status.
        Change start/end datetime.
        """
        if not ModuleStatus._check_status(status):
            return False
        self._status = status
        if self._status == ModuleStatus.MODULE_IN_PROGRESS:
            self._start_analyze_date = datetime.datetime.now()
            self._end_analyze_date = None
        elif self._status == ModuleStatus.MODULE_FINISH:
            self._end_analyze_date = datetime.datetime.now()
        return True

    def __str__(self):
        return (
            "uId \t{}\n"
            "Module name \t{}\n"
            "Status \t{}\n"
            "Start \t{}\n"
            "End \t{}\n"
            "options \t{}\n"
            "indicators\n\t************\n\t{}\n"
            .format(self._uid, self.module_cls_name, self.status,
                    self.start_analyze_date,
                    self.start_analyze_date, self.options,
                    '\t'.join(("************\n"
                               .join(f.__str__() for f in self.indicators))
                              .splitlines(True)))
        )

    # DATABASE SECTION

    def persist(self, commit=False):
        """
        Persist the malware and all indicator in the database.

        Args :
            **commit** (bool): Indicate if we want to commit.
        """
        if self._uid:
            # update
            res = lama.models.dao.module_status_dao.ModuleStatusDAO.update(self)
        else:
            # insert
            res = lama.models.dao.module_status_dao.ModuleStatusDAO.create(self)

        if not res:
            return False

        for i in self.indicators:
            i._malware_uid = self._uid
            res = i.persist()
            if not res:
                return False
        return True

    @staticmethod
    def delete(uid):
        """
        Static method.
        Delete ModuleStatus by uid
        """
        ms = lama.models.dao.module_status_dao.ModuleStatusDAO.read(uid)
        for i in ms.indicators:
            lama.models.indicator.Indicator.delete(i.uid)
        lama.models.dao.module_status_dao.ModuleStatusDAO.delete(uid)
