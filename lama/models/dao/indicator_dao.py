"""
Indicator DAO class

This class bind Indicator object to database.
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

import lama.models.indicator
from lama.models.dao.dao import LamaDAO
from lama.utils.database import Lamadb


class IndicatorDAO(LamaDAO):

    def create(indicator):
        ins = Lamadb.indicator.insert().values(
            _module_cls_name=indicator._module_cls_name,
            _name=indicator._name,
            _content_type=indicator._content_type,
            _content=indicator._content,
            _option=indicator._option,
            _score=indicator._score,
            _module_uid=indicator._module_uid
        )
        result = Lamadb.execute(ins)
        if result:
            indicator._uid = result.inserted_primary_key[0]
            return True
        else:
            return False

    def read(uid):
        s = select([Lamadb.indicator]).where(Lamadb.indicator.c._uid == uid)
        result = Lamadb.execute(s)
        if result.rowcount != 1:
            print("Error read indicator DAO")
            return None
        row = result.fetchone()
        ms = IndicatorDAO.make_from_row(row)
        return ms

    def find_by_module_uid(module_uid):
        s = select([Lamadb.indicator])\
                    .where(Lamadb.indicator.c._module_uid == module_uid)
        result = Lamadb.execute(s)
        ms_tab = []
        for row in result:
            ms_tab.append(IndicatorDAO.make_from_row(row))
        return ms_tab

    def update(indicator):
        ins = Lamadb.indicator.update()\
                    .where(Lamadb.indicator.c._uid == indicator._uid)\
                    .values(
                        _module_cls_name=indicator._module_cls_name,
                        _name=indicator._name,
                        _content_type=indicator._content_type,
                        _content=indicator._content,
                        _option=indicator._option,
                        _score=indicator._score,
                        _module_uid=indicator._module_uid
                        )
        res = Lamadb.execute(ins)
        return res.rowcount == 1

    def delete(uid):
        d = Lamadb.indicator.delete(Lamadb.indicator.c._uid == uid)
        Lamadb.execute(d)

    def make_from_row(row):
        ind = lama.models.indicator.Indicator(
                       uid=row[Lamadb.indicator.c._uid],
                       module_cls_name=row[
                           Lamadb.indicator.c._module_cls_name],
                       name=row[
                           Lamadb.indicator.c._name],
                       content_type=row[
                           Lamadb.indicator.c._content_type],
                       content=row[
                           Lamadb.indicator.c._content],
                       option=row[
                           Lamadb.indicator.c._option],
                       score=row[
                           Lamadb.indicator.c._score],
                       module_uid=row[
                           Lamadb.indicator.c._module_uid]
                       )
        return ind
