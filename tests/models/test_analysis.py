import unittest
import datetime
from lama.models.analysis import Analysis


class TestAnalysis(unittest.TestCase):

    def test_attrs(self):
        date = datetime.datetime.now()
        a = Analysis.factory(date)
        self.assertEqual(a.start_date, date)
