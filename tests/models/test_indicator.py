import unittest
from lama.models.indicator import Indicator
from lama.utils.type import Type


class TestIndicator(unittest.TestCase):

    def test_attrs(self):
        ind = Indicator.factory(module_cls_name="test_module",
                                name="test_name", content_type=Type.STRING,
                                content="content", score=4, option="option")
        self.assertEqual(ind.module_cls_name, "test_module")
        self.assertEqual(ind.name, "test_name")
        self.assertEqual(ind.content_type, Type.STRING)
        self.assertEqual(ind.content, "content")
        self.assertEqual(ind.score, 4)
        self.assertEqual(ind.option, "option")
