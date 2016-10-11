"""
Analysis DAO class

This class bind Analysis object to database.
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


from sqlalchemy.sql import select
from sqlalchemy import desc

import lama.models.analysis
from lama.utils.database import Lamadb
from lama.models.dao.malware_dao import MalwareDAO


class AnalysisDAO(object):

    def create(analysis):
        ins = Lamadb.analysis.insert().values(
            _start_date=analysis.start_date,
            _end_date=analysis.end_date
        )
        result = Lamadb.execute(ins)
        if result:
            analysis._uid = result.inserted_primary_key[0]
            return True
        else:
            return False

    def read(uid):
        s = select([Lamadb.analysis]).where(Lamadb.analysis.c._uid == uid)
        result = Lamadb.execute(s)
        if result.rowcount != 1:
            print("Error read analysis DAO")
            return None
        row = result.fetchone()
        analysis = AnalysisDAO.make_from_row(row)
        analysis._malwares = MalwareDAO.find_by_analysis_uid(analysis.uid)
        return analysis

    def update(analysis):
        ins = Lamadb.analysis.update()\
                .where(Lamadb.analysis.c._uid == analysis._uid)\
                .values(
                    _start_date=analysis.start_date,
                    _end_date=analysis.end_date
                    )
        res = Lamadb.execute(ins)
        return res.rowcount == 1

    def delete(uid):
        d = Lamadb.analysis.delete(Lamadb.analysis.c._uid == uid)
        Lamadb.execute(d)

    def findAllUid(offset=0, limit=None):
        s = select([Lamadb.analysis.c._uid]).order_by(desc("_uid")).limit(limit).offset(offset)
        result = Lamadb.execute(s)
        return [row[0] for row in result]

    def make_from_row(row):
        analysis = lama.models.analysis.Analysis(
                            uid=row[Lamadb.analysis.c._uid],
                            start_date=row[Lamadb.analysis.c._start_date],
                            end_date=row[Lamadb.analysis.c._end_date],
                            malwares=[])
        return analysis
