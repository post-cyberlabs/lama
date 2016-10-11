"""
Indicator class

This class represent a indicator for malwares.
After analysis, theses indicators are added to malware.

"""

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import lama.models.dao.indicator_dao


class Indicator(object):
    """Indicator class

        Args :
            **module_cls_name** (String) : Class name of the analysis module.

            **name** (string) : Name of indicator.

            **content_type** (Integer) : Type of the content.

            **content** (string) : Content of indicator.

            **score** (Integer) : Score of the indicator

            **uid** (Integer) : uid of indicator

            **module_uid** () : uid of analysis module

            **option** () : options

        Attributes :
            **_module_cls_name** (String) : Class name of the analysis module.

            **_name** (string) : Name of indicator.

            **_content_type** (Integer) : Type of the content.

            **_content** (string) : Content of indicator.

            **_score** (Integer) : Score of the indicator

            **_uid** (Integer) : uid of indicator

            **_module_uid** () : uid of analysis module

            **_option** () : options
    """

    def __init__(self, module_cls_name, name, content_type, content, score,
                 uid=None, module_uid=None, option=None):
        self._uid = uid
        self._module_cls_name = module_cls_name
        self._name = name
        self._content_type = content_type
        self._content = content
        self._option = option
        self._score = score
        self._module_uid = None

    def factory(module_cls_name, name, content_type, content,
                option=None, score=0):
        """
        Return a Indicator for given args.
        """
        return Indicator(module_cls_name=module_cls_name,
                         name=name,
                         content_type=content_type,
                         content=content,
                         option=option,
                         score=score)

    def __str__(self):
        return (
            "Module name   \t{}\n"
            "Name   \t{}\n"
            "Content type   \t{}\n"
            "Content\t{}\n"
            "option\t{}\n"
            "Module_uid\t{}\n"
            .format(
                self.module_cls_name, self.name, self.content_type, self.content,
                self.option, self._module_uid
            )
        )

    @property
    def uid(self):
        """
        Return the uid of indicator.
        """
        return self._uid

    @property
    def module_cls_name(self):
        """
        Return the module_cls_name of indicator.
        """
        return self._module_cls_name

    @property
    def name(self):
        """
        Return the name of indicator.
        """
        return self._name

    @property
    def content_type(self):
        """
        Return the content type of indicator.
        """
        return self._content_type

    @property
    def content(self):
        """
        Return the content of indicator.
        """
        return self._content

    @property
    def option(self):
        """
        Return the option of indicator.
        """
        return self._option

    @property
    def score(self):
        """
        Return the score of indicator.
        """
        return self._score

    @property
    def module_status_uid(self):
        """
        Return the content of indicator.
        """
        return self.module_uid

    @module_status_uid.setter
    def module_status_uid(self, module_uid):
        self._module_uid = module_uid

    # DATABASE SECTION

    def persist(self, commit=False):
        """
        Persist the indicator in the database.

        Args :
            **commit** (bool): Indicate if we want to commit.
        """
        if self._uid:
            # update
            res = lama.models.dao.indicator_dao.IndicatorDAO.update(self)
        else:
            # insert
            res = lama.models.dao.indicator_dao.IndicatorDAO.create(self)
        return res

    @staticmethod
    def delete(uid):
        """
        Static method.
        Delete indicator by uid
        """
        lama.models.dao.indicator_dao.IndicatorDAO.delete(uid)
