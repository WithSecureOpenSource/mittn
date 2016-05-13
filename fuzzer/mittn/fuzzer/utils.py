import urllib
from collections import OrderedDict

import six


def urlparams_to_dict(params, delimiter=';'):
    """Like urllib.parse_qs() but array values are delimited by colons."""
    paramdict = OrderedDict()
    for keyword_value_pair in params.split(delimiter):
        keyword, values = keyword_value_pair.split('=')
        paramdict[keyword] = []
        for value in values.split(','):
            paramdict[keyword].append(value)
    return paramdict


def dict_to_urlparams(paramdict, delimiter=';'):
    """Like urllib.urlencode() but array values are delimited by colons.

    {'eka': [1, 2, 3], 'toka': ['auto', None, 66]}
    --> eka=1,2,3;toka=auto,,66

    """
    params = []
    for key, value in six.iteritems(paramdict):
        values = []
        for v in value:
            if v is None:  # As a result of injection
                values.append('')
            else:
                values.append(urllib.quote_plus(str(v)))
        params.append(urllib.quote_plus(key) + '=' + ','.join(values))
    return delimiter.join(params)
