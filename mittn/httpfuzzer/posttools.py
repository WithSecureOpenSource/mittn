"""Helper functions for outputting GET/POST content"""

"""
Copyright (c) 2014 F-Secure
See LICENSE for details
"""

import urllib
import json


def serialise_to_url(dictionary, encode=True):
    """Take a dictionary and URL-encode it for HTTP submission

    :param dictionary: A dictionary to be serialised
    :param encode: Should it be URL-encoded?
    """
    serialised = []
    for key in dictionary.keys():
        if isinstance(dictionary[key], list):  # Multiple values for a key
            for value in dictionary[key]:
                if encode is True:
                    enc_key = urllib.quote(str(key))
                    enc_value = urllib.quote(str(value))
                    serialised.append("%s=%s" % (enc_key, enc_value))
                else:  # Output raw data (against spec, for fuzzing)
                    serialised.append("%s=%s" % (str(key), str(value)))
        else:
            if encode is True:
                enc_key = urllib.quote(str(key))
                enc_value = urllib.quote(str(dictionary[key]))
                serialised.append("%s=%s" % (enc_key, enc_value))
            else:  # Output raw data (against spec, for fuzzing)
                serialised.append("%s=%s" % (str(key), str(dictionary[key])))
    return str("&".join(serialised))


def serialise_to_json(dictionary, encode=True):
    """Take a dictionary and JSON-encode it for HTTP submission

    :param dictionary: A dictionary to be serialised
    :param encode: Should the putput be ensured to be ASCII
    """

    # Just return the JSON representation, and output as raw if requested
    # The latin1 encoding is a hack that just allows a 8-bit-clean byte-wise
    # output path. Using UTF-8 here would make Unicode libraries barf when using
    # fuzzed data. The character set is communicated to the client in the
    # HTTP headers anyway, so this shouldn't have an effect on efficacy.
    return json.dumps(dictionary, ensure_ascii=encode, encoding="iso-8859-1")
