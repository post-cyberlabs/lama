""" SyncModule class

This abstract submodule add a running queue to execution process.
It's usefull if the final program don't have a intern queue
(like Cuckoo or IRMA)
"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


from lama.analyzer.module import Module


class SyncModule(Module):
    """SyncModule class

    Args :
        **name** (string) : Name of submodule.

        **malware** (Malware) : Malware who is analyzed

        **local_path** (PATH) : Path of malware on the machine
    """
    def __init__(self, name, malware, local_path):
        super().__init__(name, malware, local_path, checker=False)

    def check_elem(self):
        """
        (Override super)
        Nothing in this case because analysis are synchronous.
        The result is given directly.
        """
        pass
