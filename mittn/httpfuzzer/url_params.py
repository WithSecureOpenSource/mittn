"""Functions to (de)serialise URL path parameters.

These aren't query parameters but instead a less-used part of the URL path
(like keyword1=value1,value2;keyword2=value3).

"""
import urllib
from collections import OrderedDict

__copyright__ = "Copyright (c) 2013- F-Secure"


def url_to_dict(params):
    """Return a dict of URL path parameters
    """
    paramdict = OrderedDict()
    for keyword_value_pair in params.split(';'):
        (keyword, values) = keyword_value_pair.split('=')
        paramdict[str(keyword)] = []
        for value in values.split(','):
            paramdict[keyword].append(str(value))
    return paramdict


def dict_to_urlparams(paramdict):
    """Return URL path parameters from a dict
    """
    paramstring = ""
    for keyword in paramdict.keys():
        paramstring += ';' + urllib.quote_plus(keyword) + "="
        first_value = 1
        for value in paramdict[keyword]:
            if not first_value:
                paramstring += ','
            if value is None:  # As a result of injection
                value = ""
            paramstring += urllib.quote_plus(str(value))
            first_value = 0
    return paramstring
