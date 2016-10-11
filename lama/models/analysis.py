"""
Analysis class

This class represent an analysis.
It allow to add many malware and send it for analysis.

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
import lama.models.malware
import lama.models.dao.analysis_dao


class Analysis(object):
    """Analysis class

        Args :
            **uid** (Integer) : uid of Analysis

            **start_date** (date): Date of analysis creation.

            **end_date** (date) : Date of analysis finish.

            **malwares** (list): List of malware for this analysis.

        Attributes :
            **_uid** (str): UID of analysis.

            ***_start_date** (date): Date of analysis creation.

            ***_end_date** (date): Date of analysis finish.

            **_malwares** (list): List of malware for this analysis.
    """

    ALERT_THRESHOLD = 3
    """
    Threshold to run an alert.
    """

    def __init__(self, uid, start_date, end_date=None, malwares=None):
        self._uid = uid
        self._start_date = start_date
        self._end_date = end_date
        self._malwares = malwares
        if self._malwares is None:
            self._malwares = []

    @staticmethod
    def factory(start_date=None):
        """
        Return a Analysis for given args.

        Args:
            **start_date** (date) : Start date of analysis.
        """
        if start_date is None:
            start_date = datetime.datetime.now()

        analysis = Analysis(uid=None, start_date=start_date, malwares=[])
        return analysis

    def __str__(self):
        return (
            "UID \t{}\n"
            "Start date \t{}\n"
            "Finish date \t{}\n"
            "Malwares \n\t{}\n"
            .format(self.uid,
                    self.start_date,
                    self.end_date,
                    '\t'.join(("\n".join(m.__str__() for m in self.malwares))
                              .splitlines(True)))
            )

    def add_malware(self, malware):
        """
        Add a malware into current analysis.

        Args :
            **malware** (string): Malware object to add.
        """
        malware.analysis_uid = self.uid
        self._malwares.append(malware)

    def is_finish(self):
        """
        Check if all malwares are finished and return the result.
        """
        if len(self._malwares):
            for m in self._malwares:
                if not m.is_finish():
                    return False
            return True
        else:
            return False

    def finish(self):
        """
        Change the stat of analysis to finish.
        Set te end date to current datetime and persist it.
        """
        self._end_date = datetime.datetime.now()
        res = self.persist(cascade=False)
        if not res:
            # TODO handle error
            logging.debug("Error persist analysis")

    def compute_stat(self):
        """
        Compute stats of analysis like :

        - Average score
        - Max score
        - Min score
        """
        stats = {}
        stats['score_avg'] = 0
        stats['score_max'] = 0
        stats['nb_not_null'] = 0
        for m in self.malwares:
            stat = m.compute_stat()
            x = stat['score_avg']
            if x > 0:
                stats['score_avg'] += x
                stats['nb_not_null'] += 1
                if x > stats['score_max']:
                    stats['score_max'] = x

        if stats['nb_not_null'] > 0:
            stats['score_avg'] = stats['score_avg'] / stats['nb_not_null']
        return stats

    @property
    def start_date(self):
        """
        Return the start date of analysis.
        """
        return self._start_date

    @property
    def end_date(self):
        """
        Return the end date of analysis.
        """
        return self._end_date

    @property
    def uid(self):
        """
        Return the uid of analysis.
        """
        return self._uid

    @property
    def malwares(self):
        """
        Return the list of malwares of analysis.
        """
        return self._malwares

    # DATABASE SECTION

    def persist(self, cascade=True):
        """
        Persist the analysis and all malware in the database.

        Args :
            **commit** (bool): Indicate if we want to commit.
        """
        if self._uid:
            # update
            res = lama.models.dao.analysis_dao.AnalysisDAO.update(self)
        else:
            # insert
            res = lama.models.dao.analysis_dao.AnalysisDAO.create(self)

        if not res:
            return False

        if cascade:
            for m in self.malwares:
                m.analysis_uid = self.uid
                res = m.persist()
                if not res:
                    return False
        return True

    @staticmethod
    def delete(uid):
        """
        Static method.
        Delete analysis by uid
        """
        analysis = lama.models.dao.analysis_dao.AnalysisDAO.read(uid)
        if analysis:
            for m in analysis.malwares:
                if not m.parent_uid:
                    lama.models.malware.Malware.delete(m.uid)
        lama.models.dao.analysis_dao.AnalysisDAO.delete(uid)

    @staticmethod
    def flush():
        """
        Static method.
        Flush all analysis
        """
        analysis = Analysis.get_all_analysis()
        for uid in analysis:
            Analysis.delete(uid)

    @staticmethod
    def find_by_uid(uid):
        """
        Static method.
        Find analysis by uid.
        """
        analysis = lama.models.dao.analysis_dao.AnalysisDAO.read(uid)
        return analysis

    @staticmethod
    def get_all_analysis(offset=0, limit=None, children=False):
        """
        Static method.
        Find all analysis.
        """
        res = dict()
        uids = lama.models.dao.analysis_dao.AnalysisDAO.findAllUid(offset=offset, limit=limit)
        for uid in uids:
            res[uid] = dict()
            analysis = Analysis.find_by_uid(uid)
            stats = analysis.compute_stat()
            res[uid]['avg'] = stats['score_avg']
            res[uid]['max'] = stats['score_max']
            res[uid]['malwares'] = dict()
            for m in analysis.malwares:
                if not m.parent_uid or children:
                    res[uid]['malwares'][m.uid] = dict()
                    res[uid]['malwares'][m.uid]['name'] = m.name
                    res[uid]['malwares'][m.uid]['path'] = m.path
                    res[uid]['malwares'][m.uid]['mime'] = m.mime
                    res[uid]['malwares'][m.uid]['size'] = m.size
        return res
