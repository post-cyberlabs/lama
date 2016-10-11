"""
Module Status DAO class

This class bind ModuleStatus object to database.
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

import lama.models.module_status
from lama.models.dao.dao import LamaDAO
from lama.utils.database import Lamadb
from lama.models.dao.indicator_dao import IndicatorDAO


class ModuleStatusDAO(LamaDAO):

    def create(module_status):
        ins = Lamadb.module_status.insert().values(
            _module_cls_name=module_status.module_cls_name,
            _status=module_status.status,
            _start_analyze_date=module_status.start_analyze_date,
            _end_analyze_date=module_status.end_analyze_date,
            _options=module_status.options,
            _malware_uid=module_status.malware_uid
        )
        result = Lamadb.execute(ins)
        if result:
            module_status._uid = result.inserted_primary_key[0]
            return True
        else:
            return False

    def read(uid):
        s = select([Lamadb.module_status])\
                    .where(Lamadb.module_status.c._uid == uid)
        result = Lamadb.execute(s)
        if result.rowcount != 1:
            print("Error read module Status DAO")
            return None
        row = result.fetchone()
        ms = ModuleStatusDAO.make_from_row(row)
        return ms

    def find_by_malware_uid(malware_uid):
        s = select([Lamadb.module_status])\
                    .where(Lamadb.module_status.c._malware_uid == malware_uid)
        result = Lamadb.execute(s)
        ms_tab = []
        for row in result:
            ms_tab.append(ModuleStatusDAO.make_from_row(row))
        return ms_tab

    def update(module_status):
        ins = Lamadb.module_status.update()\
                    .where(Lamadb.module_status.c._uid == module_status._uid)\
                    .values(
                        _module_cls_name=module_status._module_cls_name,
                        _status=module_status._status,
                        _start_analyze_date=module_status._start_analyze_date,
                        _end_analyze_date=module_status._end_analyze_date,
                        _options=module_status._options,
                        _malware_uid=module_status._malware_uid
                        )
        res = Lamadb.execute(ins)
        return res.rowcount == 1

    def delete(uid):
        d = Lamadb.module_status.delete(Lamadb.module_status.c._uid == uid)
        Lamadb.execute(d)

    def make_from_row(row):
        column = Lamadb.module_status.c
        ms = lama.models.module_status.ModuleStatus(
                                 uid=row[column._uid],
                                 module_cls_name=row[
                                      column._module_cls_name],
                                 status=row[
                                      column._status],
                                 start_analyze_date=row[
                                      column._start_analyze_date],
                                 end_analyze_date=row[
                                      column._end_analyze_date],
                                 options=row[Lamadb.module_status.c._options],
                                 malware_uid=row[Lamadb.module_status.c._malware_uid]
                                 )
        ms._indicators = IndicatorDAO.find_by_module_uid(ms.id)
        return ms
