"""Walk through unserialised Python dict/list objects and inject
badness at each key/value. Badness is provided in a dict that has one
or more keys, and each key has a list of bad values that are to be
injected into that key.

E.g.:
key1 -> list of bad things to be injected for key1
key2 -> list of bad things to be injected for key1
None -> list of bad things to be injected generally

The key "None" is used for general in injection.

This is done because this allows us to fuzz the values for keys with specific
valid samples for each key separately.

"""
import copy

__copyright__ = "Copyright (c) 2013- F-Secure"


def anomaly_dict_generator_static(static_anomalies_list):
    """Return a dict with a key None and one single anomaly from static
    anomalies list. This means that all injections using this use one
    single static anomalies list, irrespective of where they are
    injected.

    :param static_anomalies_list: List of static bad data (e.g.,
    static_anomalies.py)
    """
    anomalies = iter(static_anomalies_list)
    for a in anomalies:
        yield {None: a}


def anomaly_dict_generator_fuzz(fuzzed_anomalies_dict):
    """Return a dict with fuzzed data for keys and a "None" key

    :param fuzzed_anomalies_dict: List of fuzzer-generated bad data (see
    fuzzer.py)
    """
    fuzzcase = {}
    for key in fuzzed_anomalies_dict.keys():
        fuzzcase[key] = iter(fuzzed_anomalies_dict[key])
    while True:
        data = {}
        for key in fuzzed_anomalies_dict.keys():
            data[key] = fuzzcase[key].next()
        yield data


def dictwalk(branch, anomaly_dict, anomaly_key=None):
    """Walk through a data structure recursively, return a list of data
    structures where each key and value has been replaced with an
    injected (fuzz) case one by one. The anomaly that is injected is
    taken from a dict of anomalies. The dict has a "generic" anomaly with
    a key of None, and may have specific anomalies under other keys.

    :param branch: The branch of a data structure to walk into.
    :param anomaly_dict: One of the anomaly dictionaries that has been prepared
    :param anomaly_key: If the branch where we walk into is under a specific
    key, this is under what key it is
    """
    # Process dict-type branches
    if isinstance(branch, dict):
        fuzzed_branch = []
        # Add cases where one of the keys has been removed
        for key in branch.keys():
            # Add a case where key has been replaced with an anomaly
            fuzzdict = branch.copy()
            try:  # Keys need to be strings
                fuzzdict[str(anomaly_dict[None])] = fuzzdict[key]
            except UnicodeEncodeError:  # Key was too broken to be a string
                fuzzdict['\xff\xff'] = fuzzdict[key]  # Revenge using key 0xFFFF
            del fuzzdict[key]
            fuzzed_branch.append(fuzzdict)

        for key, value in branch.items():
            # Last, add a case where the key's value (branch or leaf)
            # has been replaced with its fuzzed version
            sub_branches = dictwalk(value, anomaly_dict, key)
            for sub_branch in sub_branches:
                fuzzdict = branch.copy()
                fuzzdict[key] = sub_branch
                fuzzed_branch.append(fuzzdict)
        return fuzzed_branch
    # Process list-type branches
    if isinstance(branch, list):
        fuzzed_branch = []
        # Replace each list item (branch or leaf) with its fuzzed version
        for i in range(0, len(branch)):
            # Add a version where a list item has been fuzzed
            sub_branches = dictwalk(branch[i], anomaly_dict, anomaly_key)
            for sub_branch in sub_branches:
                fuzzdict = copy.copy(branch)
                fuzzdict[i] = sub_branch
                fuzzed_branch.append(fuzzdict)
        return fuzzed_branch
    # A leaf node; return just a list of anomalies for a value
    if isinstance(branch, (int, str, unicode, float)) or branch in (
    True, False, None):
        # Get the anomaly to be injected from the anomaly_dict.
        anomaly = anomaly_dict.get(anomaly_key)
        if anomaly is None:
            # There is no specific anomaly for this key's values, so we use a
            #  generic one
            anomaly = anomaly_dict.get(None)
        return [anomaly]
    # Finally, the data structure contains something that a unserialised JSON
    # cannot contain; instead of just removing it, we return it as-is without
    # injection
    return [branch]
