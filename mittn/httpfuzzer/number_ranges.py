"""A function to unpack integer ranges of the form x-y,z"""

"""
Copyright (c) 2014 F-Secure
See LICENSE for details
"""

import re


def unpack_integer_range(integerrange):
    """Input an integer range spec like "200,205-207" and return a list of
    integers like [200, 205, 206, 207]

    :param integerrange: The range specification as a string
    :return: Sorted integers in a list
    """

    integers = []  # To hold the eventual result
    valid_chars = re.compile("^[0-9\-, ]+$")
    if re.match(valid_chars, integerrange) is None:
        assert False, "Number range %s in the feature file is invalid. Must " \
                      "contain just numbers, commas, and hyphens" % integerrange
    integerrange.replace(" ", "")
    rangeparts = integerrange.split(',')  # One or more integer ranges
                                          # separated by commas
    for rangepart in rangeparts:
        rangemaxmin = rangepart.split('-')  # Range is defined with a hyphen
        if len(rangemaxmin) == 1:  # This was a single value
            try:
                integers.extend([int(rangemaxmin[0])])
            except ValueError:
                assert False, "Number range %s in the feature file is " \
                    "invalid. Must be integers separated with commas and " \
                    "hyphens" % integerrange
        elif len(rangemaxmin) == 2:  # It was a range of values
            try:
                rangemin = int(rangemaxmin[0])
                rangemax = int(rangemaxmin[1]) + 1
            except ValueError:
                assert False, "Number range %s in the feature file is " \
                    "invalid. Must be integers separated with commas and " \
                    "hyphens" % integerrange
            if rangemin >= rangemax:
                assert False, "Number range %s in the feature file is " \
                              "invalid. Range minimum is more than " \
                              "maximum" % integerrange
            integers.extend(range(rangemin, rangemax))
        else:  # Range specifier was not of the form x-y
            assert False, "Number range %s in the feature file is invalid. " \
                          "Incorrect range specifier" % \
                          integerrange
    return sorted(integers)