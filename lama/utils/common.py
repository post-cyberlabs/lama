__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


def compatible_mime_set(m1, set_m2):
    """
    Check if a mime type is compatible with a set of mime type.
    """
    for m2 in set_m2:
        # check for each type of set
        if compatible_mime(m1, m2):
            return True
    return False


def compatible_mime(m1, m2):
    """
    Check if two mime type are compatible

    m1 : type of file

    m2 : type of module

    Rules :

    if m2 is "*" and m1 is not "URL" -> True


    if m1 == m2 -> True

    if m1 is a part of m2 -> True

    for exemple if m1 is text/html and m2 is text -> True
    """
    if m2 == "*" and m1 != "URL":
        return True
    if m1 == m2:
        return True
    if "/" not in m2:
        m1_type = (m1.split("/"))[0]
        if "/" not in m2 and m1_type == m2:
            return True
    return False
