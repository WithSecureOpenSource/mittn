"""httpfuzzer step library for Behave."""
from behave import *
from mittn.httpfuzzer.static_anomalies import *
from mittn.httpfuzzer.fuzzer import *
from mittn.httpfuzzer.injector import *
from mittn.httpfuzzer.number_ranges import *
from mittn.httpfuzzer.url_params import *
import mittn.httpfuzzer.dbtools as fuzzdb
import json
import urlparse2
import subprocess
import re

__copyright__ = "Copyright (c) 2013- F-Secure"


@given(u'a baseline database for injection findings')
def step_impl(context):
    """Test that we can connect to a database. As a side effect, open_database(9 also creates the necessary table(s) that are required."""
    if hasattr(context, 'dburl') is False:
        assert False, "Database URI not specified"
    dbconn = fuzzdb.open_database(context)
    if dbconn is None:
        assert False, "Cannot open database %s" % context.dburl
    dbconn.close()

@given(u'an authentication flow id "{auth_id}"')
def step_impl(context, auth_id):
    """Store the authentication flow identifier. Tests in the feature file
    can use different authentication flows, and this can be used to
    select one of them in authenticate.py.
    """

    context.authentication_id = auth_id
    assert True


@given(u'valid case instrumentation with success defined as "{valid_cases}"')
def step_impl(context, valid_cases):
    """Make a note of the fact that we would like to do valid case
    instrumentation."""

    context.valid_cases = unpack_integer_range(valid_cases)
    context.valid_case_instrumentation = True
    assert True


@given(u'a web proxy')
def step_impl(context):
    """Check that we have a proxy defined in the environment file.
    """

    if not hasattr(context, "proxy_address"):
        assert False, "The feature file requires a proxy, but one has not " \
                      "been defined in environment.py."
    assert True


@given(u'a timeout of "{timeout}" seconds')
def step_impl(context, timeout):
    """Store the timeout value.
    """
    context.timeout = float(timeout)
    if context.timeout < 0:
        assert False, "Invalid timeout value %s" % context.timeout
    assert True


@given(u'A working Radamsa installation')
def step_impl(context):
    """Check for a working Radamsa installation."""

    if context.radamsa_location is None:
        assert False, "The feature file requires Radamsa, but the path is " \
                      "undefined."
    try:
        subprocess.check_output([context.radamsa_location, "--help"],
                                stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, OSError) as error:
        assert False, "Could not execute Radamsa from %s: %s" % (context.radamsa_location, error)
    assert True


@given(u'target URL "{uri}"')
def step_impl(context, uri):
    """Store the target URI that we are injecting or fuzzing."""

    # The target URI needs to be a string so it doesn't trigger Unicode
    # conversions for stuff we concatenate into it later; the Python
    # Unicode library will barf on fuzzed data
    context.targeturi = str(uri)
    assert True


@given(u'a valid form submission "{submission}" using "{method}" method')
def step_impl(context, submission, method):
    """For static injection, store a valid form where elements are replaced with
    injections and test it once. This is also used for the valid case
    instrumentation.
    """

    if hasattr(context, 'timeout') is False:
        context.timeout = 5  # Sensible default
    if hasattr(context, 'targeturi') is False:
        assert False, "Target URI not specified"

    # Unserialise into a data structure and store in a list
    # (one valid case is just a special case of providing
    # several valid cases)
    context.submission = [urlparse2.parse_qs(submission)]
    context.submission_method = method
    context.type = 'urlencode'  # Used downstream for selecting encoding
    context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
    test_valid_submission(context)
    assert True


@given(u'valid url parameters "{submission}"')
def step_impl(context, submission):
    """For static injection, get the url parameters (semicolon
    separated URL parameters)
    """

    if hasattr(context, 'timeout') is False:
        context.timeout = 5  # Sensible default
    if hasattr(context, 'targeturi') is False:
        assert False, "Target URI not specified"

    # Unserialise into a data structure and store in a list
    # (one valid case is just a special case of providing
    # several valid cases)
    context.submission = [url_to_dict(submission)]
    context.submission_method = 'GET'
    context.type = 'url-parameters'  # Used downstream for selecting encoding
    context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
#    test_valid_submission(context)
    assert True


@when(u'injecting static bad data for every key and value')
def step_impl(context):
    """Perform injection of static anomalies
    """
    context.new_findings = 0
    # Create the list of static injections using a helper generator
    injection_list = anomaly_dict_generator_static(anomaly_list)
    context.responses = inject(context, injection_list)
    assert True


@when(u'storing any new cases of return codes "{returncode_list}"')
def step_impl(context, returncode_list):
    """Go through responses and store any with suspect return codes
    into the database
    """

    disallowed_returncodes = unpack_integer_range(returncode_list)
    new_findings = 0
    for response in context.responses:
        if response['resp_statuscode'] in disallowed_returncodes:
            if fuzzdb.known_false_positive(context, response) is False:
                fuzzdb.add_false_positive(context, response)
                new_findings += 1
    if new_findings > 0:
        context.new_findings += new_findings
    assert True


@when(u'storing any new cases of responses timing out')
def step_impl(context):
    """Go through responses and save any that timed out into the database
    """

    new_findings = 0
    for response in context.responses:
        if response.get('server_timeout') is True:
            if fuzzdb.known_false_positive(context, response) is False:
                fuzzdb.add_false_positive(context, response)
                new_findings += 1
    if new_findings > 0:
        context.new_findings += new_findings
    assert True


@when(u'storing any new invalid server responses')
def step_impl(context):
    """Go through responses and store any with HTTP protocol errors
    (as caught by Requests) into the database
    """

    new_findings = 0
    for response in context.responses:
        if response.get('server_protocol_error') is not None:
            if fuzzdb.known_false_positive(context, response) is False:
                fuzzdb.add_false_positive(context, response)
                new_findings += 1
    if new_findings > 0:
        context.new_findings += new_findings
    assert True


@when(u'storing any new cases of response bodies that contain strings')
def step_impl(context):
    """Go through responses and store any that contain a string from
    user-supplied list of strings into the database
    """

    # Create a regex from the error response list
    error_list = []
    for row in context.table:
        error_list.append(row['string'])
    error_list_regex = "(" + ")|(".join(error_list) + ")"

    # For each response, check that it isn't in the error response list
    new_findings = 0
    for response in context.responses:
        if re.search(error_list_regex, response.get('resp_body'),
                     re.IGNORECASE) is not None:
            response['server_error_text_detected'] = True
            if fuzzdb.known_false_positive(context, response) is False:
                fuzzdb.add_false_positive(context, response)
                new_findings += 1
    if new_findings > 0:
        context.new_findings += new_findings
    assert True


@given(u'a valid JSON submission "{valid_json}" using "{method}" method')
def step_impl(context, valid_json, method):
    """Store an example of a valid submission
    """

    if hasattr(context, 'timeout') is False:
        context.timeout = 5  # Sensible default
    if hasattr(context, 'targeturi') is False:
        assert False, "Target URI not specified"

    # Unserialise into a data structure and store in a list
    # (one valid case is just a special case of providing
    # several valid cases)
    context.submission = [json.loads(valid_json)]
    context.submission_method = method
    context.type = 'json'  # Used downstream to select encoding, etc.
    context.content_type = 'application/json'
    test_valid_submission(context)
    assert True


@given(u'valid JSON submissions using "{method}" method')
def step_impl(context, method):
    """Store a list of valid JSON submissions (used for valid cases
    for fuzz generation
    """

    if hasattr(context, 'timeout') is False:
        context.timeout = 5  # Sensible default
    if hasattr(context, 'targeturi') is False:
        assert False, "Target URI not specified"
    context.submission = []
    context.submission_method = method
    context.type = 'json'  # Used downstream for selecting encoding
    context.content_type = 'application/json'
    # Add all valid cases into a list as unserialised data structures
    for row in context.table:
        context.submission.append(json.loads(row['submission']))
    test_valid_submission(context)
    assert True


@given(u'valid form submissions using "{method}" method')
def step_impl(context, method):
    """Store a list of valid form submissions (used for valid cases for
    fuzz generation)
    """

    if hasattr(context, 'timeout') is False:
        context.timeout = 5  # Sensible default
    if hasattr(context, 'targeturi') is False:
        assert False, "Target URI not specified"
    context.submission = []
    context.submission_method = method
    context.type = 'urlencode'  # Used downstream for selecting encoding
    context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
    # Add all valid cases into a list as unserialised data structures
    for row in context.table:
        context.submission.append(urlparse2.parse_qs(row['submission']))
    test_valid_submission(context)
    assert True


@given(u'valid url parameters')
def step_impl(context, method):
    """Store a list of valid url parameters (used for valid cases for
    fuzz generation)
    """

    if hasattr(context, 'timeout') is False:
        context.timeout = 5  # Sensible default
    if hasattr(context, 'targeturi') is False:
        assert False, "Target URI not specified"
    context.submission = []
    context.submission_method = 'GET'
    context.type = 'url-parameters'  # Used downstream for selecting encoding
    context.content_type = 'application/x-www-form-urlencoded; charset=utf-8'
    # Add all valid cases into a list as unserialised data structures
    for row in context.table:
        context.submission.append(url_to_dict(row['submission']))
    test_valid_submission(context)
    assert True


@when(u'fuzzing with "{no_of_cases}" fuzz cases for each key and value')
def step_impl(context, no_of_cases):
    """Perform fuzzing and fuzz case injection
    """

    context.new_findings = 0
    # Collect the valid keys/values from the valid examples
    valuelist = {}
    for submission in context.submission:
        valuelist = collect_values(submission, valuelist)
    # Create the list of fuzz injections using a helper generator
    fuzzed_anomalies_dict = fuzz_values(valuelist, no_of_cases,
                                        context.radamsa_location)
    injection_list = anomaly_dict_generator_fuzz(fuzzed_anomalies_dict)
    context.responses = inject(context, injection_list)
    assert True


@given(u'tests conducted with HTTP methods "{methods}"')
def step_impl(context, methods):
    """Store a list of HTTP methods to use
    """

    context.injection_methods = methods.split(",")
    assert True


@then(u'no new issues were stored')
def step_impl(context):
    """Check whether we stored any new findings
    """
    if context.new_findings > 0:
        assert False, "%s new findings were found." % context.new_findings
    old_findings = fuzzdb.number_of_new_in_database(context)
    if old_findings > 0:
        assert False, "No new findings found, but %s unprocessed findings from past runs found in database." % old_findings
    assert True

