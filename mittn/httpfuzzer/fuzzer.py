"""Wrapper for Radamsa for fuzzing objects. It will collect valid
strings from objects, run a fuzzer over them, and return them in a dict
that can be passed on to the injector."""

import tempfile
import os
import subprocess
import shutil

"""
Copyright (c) 2012-2014 F-Secure
See LICENSE for details
"""


def collect_values(branch, valid_values, anomaly_key=None):
    """Recursively collect all values from a data structure into a dict where
    valid values are organised under keys, or a "None" key if
    they weren't found under any key

    :param branch: A branch of the data structure
    :param valid_values: The collected valid values
    :param anomaly_key: Under which key the current branch is
    """
    # Each key found in valid samples will have a list of values
    if valid_values.get(anomaly_key) is None:
        valid_values[anomaly_key] = []
    # If we see a dict, we will get all the values under that key
    if isinstance(branch, dict):
        for key, value in branch.items():
            collect_values(value, valid_values, key)
    # If we see a list, we will add all values under current key
    # (perhaps a parent dict)
    if isinstance(branch, list):
        for i in range(0, len(branch)):
            collect_values(branch[i], valid_values, anomaly_key)
    # If we see an actual value, we will add the value under both the
    # current key and the "None" key
    if isinstance(branch, (int, str, unicode, float)) or branch in (
            True, False, None):
        valid_values[anomaly_key].append(branch)
        valid_values[None].append(branch)
    return valid_values


def fuzz_values(valuedict, no_of_fuzzcases, radamsacmd):
    """Run every key's valid value list through a fuzzer

    :param valuedict: Dict of collected valid values
    :param no_of_fuzzcases: How many injection cases to produce
    :param radamsacmd: Command to run Radamsa
    """
    fuzzdict = {}  # Will hold the result
    for key in valuedict.keys():
        # If no values for a key, use the samples under the None key
        if valuedict[key] == []:
            fuzzdict[key] = get_fuzz(valuedict[None], no_of_fuzzcases,
                                     radamsacmd)
        else:  # Use the samples collected for the specific key
            fuzzdict[key] = get_fuzz(valuedict[key], no_of_fuzzcases,
                                     radamsacmd)
    return fuzzdict


def get_fuzz(valuelist, no_of_fuzzcases, radamsacmd):
    """Run Radamsa on a set of valid values

    :param valuelist: Valid cases to feed to Radamsa
    :param no_of_fuzzcases: Number of fuzz cases to generate
    :param radamsacmd: Command to run Radamsa
    :return:
    """

    # Radamsa is a file-based fuzzer so we need to write the valid strings
    # out to files
    valid_case_directory = tempfile.mkdtemp()
    fuzz_case_directory = tempfile.mkdtemp()
    for valid_string in valuelist:
        tempfilehandle = tempfile.mkstemp(suffix='.case',
                                          dir=valid_case_directory)
        with os.fdopen(tempfilehandle[0], "w") as filehandle:
            # Radamsa only operates on strings, so make numbers and booleans
            # into strings. (No, this won't fuzz effectively, use static
            # injection to cover those cases.)
            if isinstance(valid_string, (bool, int, long, float)):
                valid_string = str(valid_string)
            filehandle.write(bytearray(valid_string, "UTF-8"))

    # Run Radamsa
    try:
        subprocess.check_call(
            [radamsacmd, "-o", fuzz_case_directory + "/%n.fuzz", "-n",
             str(no_of_fuzzcases), "-r", valid_case_directory])
    except subprocess.CalledProcessError as error:
        assert False, "Could not execute Radamsa: %s" % error

    # Read the fuzz cases from the output directory and return as list
    fuzzlist = []
    for filename in os.listdir(fuzz_case_directory):
        filehandle = open(fuzz_case_directory + "/" + filename, "r")
        fuzzlist.append(filehandle.read())
    shutil.rmtree(valid_case_directory)
    shutil.rmtree(fuzz_case_directory)
    return fuzzlist
