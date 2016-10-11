import unittest
from lama.models.module_status import ModuleStatus


class TestModuleStatus(unittest.TestCase):

    def test_attrs(self):
        ms = ModuleStatus.factory("test_module",
                                  ModuleStatus.MODULE_NOT_ANALYZED, "options")
        self.assertEqual(ms.module_cls_name, "test_module")
        self.assertEqual(ms.status, ModuleStatus.MODULE_NOT_ANALYZED)
        self.assertEqual(ms.options, "options")

    def test_change_status(self):
        ms = ModuleStatus.factory("test_module",
                                  ModuleStatus.MODULE_NOT_ANALYZED, "options")
        self.assertEqual(ms.status, ModuleStatus.MODULE_NOT_ANALYZED)
        self.assertEqual(ms.is_finish(), False)

        res = ms.change_status(ModuleStatus.MODULE_NOT_ANALYZED)
        self.assertEqual(ms.status, ModuleStatus.MODULE_NOT_ANALYZED)
        self.assertEqual(res, True)
        self.assertEqual(ms.is_finish(), False)

        res = ms.change_status(ModuleStatus.MODULE_IN_PROGRESS)
        self.assertEqual(ms.status, ModuleStatus.MODULE_IN_PROGRESS)
        self.assertEqual(res, True)
        self.assertEqual(ms.is_finish(), False)

        res = ms.change_status(ModuleStatus.MODULE_FINISH)
        self.assertEqual(ms.status, ModuleStatus.MODULE_FINISH)
        self.assertEqual(res, True)
        self.assertEqual(ms.is_finish(), False)

        res = ms.change_status(ModuleStatus.MODULE_REPORTED)
        self.assertEqual(ms.status, ModuleStatus.MODULE_REPORTED)
        self.assertEqual(res, True)
        self.assertEqual(ms.is_finish(), True)
