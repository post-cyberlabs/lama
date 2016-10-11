import unittest
from lama.utils.type import Type
from lama.models.malware import Malware
from lama.models.analysis import Analysis
from lama.models.indicator import Indicator
from lama.models.module_status import ModuleStatus


class TestModels(unittest.TestCase):

    TEST_FILE = "tests/models/files/malware_file_test.txt"

    def test_case_1(self):
        a = Analysis.factory()

        self.assertEqual(len(a.malwares), 0)
        self.assertEqual(a.is_finish(), False)

        m = Malware.empty_malware()
        m.factory(local_path=TestModels.TEST_FILE, remote_path="remote_path",
                  name="malware_filte_test.txt")
        a.add_malware(m)

        self.assertEqual(len(a.malwares), 1)
        self.assertEqual(m.nb_module, 0)
        self.assertEqual(len(m.module_status), 0)
        self.assertEqual(a.is_finish(), False)

        m.set_module_status("test_module", ModuleStatus.MODULE_IN_PROGRESS)
        m.add_nb_module()

        self.assertEqual(m.nb_module, 1)
        self.assertEqual(len(m.module_status), 1)
        self.assertEqual(a.is_finish(), False)

        m.set_module_status("test_module", ModuleStatus.MODULE_FINISH)
        ms = m.get_module_status("test_module")

        self.assertEqual(len(ms.indicators), 0)

        ind = Indicator.factory(module_cls_name="test_module",
                                name="test_name", content_type=Type.STRING,
                                content="content", score=4, option="option")
        ms.add_indicator(ind)

        self.assertEqual(len(ms.indicators), 1)
        self.assertEqual(a.is_finish(), False)

        m.set_module_status("test_module", ModuleStatus.MODULE_REPORTED)

        self.assertEqual(a.is_finish(), True)

    def test_case_2(self):
        a = Analysis.factory()

        for i in range(1, 4):
            m = Malware.empty_malware()
            m.factory(local_path=TestModels.TEST_FILE,
                      remote_path="remote_path",
                      name="malware_filte_test.txt_"+str(i))
            a.add_malware(m)

            self.assertEqual(len(a.malwares), i)
            self.assertEqual(m.nb_module, 0)
            self.assertEqual(len(m.module_status), 0)
            self.assertEqual(a.is_finish(), False)

        for m in a.malwares:
            for i in range(1, 4):
                ms_name = "test_module_"+str(i)
                m.set_module_status(ms_name, ModuleStatus.MODULE_IN_PROGRESS)
                m.add_nb_module()

                self.assertEqual(m.nb_module, i)
                self.assertEqual(len(m.module_status), i)
                self.assertEqual(a.is_finish(), False)

                m.set_module_status(ms_name, ModuleStatus.MODULE_FINISH)
                ms = m.get_module_status(ms_name)

                self.assertEqual(len(ms.indicators), 0)

                for j in range(1, 4):
                    ind = Indicator.factory(module_cls_name=ms_name,
                                            name="test_name_"+str(i),
                                            content_type=Type.STRING,
                                            content="content",
                                            score=4, option="option"+str(i))
                    ms.add_indicator(ind)

                    self.assertEqual(len(ms.indicators), j)
                    self.assertEqual(a.is_finish(), False)

                m.set_module_status(ms_name, ModuleStatus.MODULE_REPORTED)

        self.assertEqual(a.is_finish(), True)

    def test_case_3(self):
        a = Analysis.factory()

        m = Malware.empty_malware()
        m.factory(local_path=TestModels.TEST_FILE, remote_path="remote_path",
                  name="malware_filte_test.txt")
        a.add_malware(m)

        m.set_module_status("test_module", ModuleStatus.MODULE_IN_PROGRESS)
        m.add_nb_module()

        m.set_module_status("test_module", ModuleStatus.MODULE_FINISH)
        ms = m.get_module_status("test_module")

        ind = Indicator.factory(module_cls_name="test_module",
                                name="test_name",
                                content_type=Type.STRING, content="content",
                                score=4, option="option")
        ms.add_indicator(ind)

        extract_malware = m.add_extract_malware("test_module",
                                                content="test_extract_module")

        m.set_module_status("test_module", ModuleStatus.MODULE_REPORTED)
        self.assertEqual(a.is_finish(), False)

        extract_malware.add_nb_module()
        extract_malware.set_module_status("test_module",
                                          ModuleStatus.MODULE_IN_PROGRESS)
        extract_malware.set_module_status("test_module",
                                          ModuleStatus.MODULE_FINISH)

        self.assertEqual(a.is_finish(), False)
        extract_malware.set_module_status("test_module",
                                          ModuleStatus.MODULE_REPORTED)
        self.assertEqual(a.is_finish(), True)
