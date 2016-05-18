# pylint: disable=E0602,E0102
"""Burp and Burp Suite are trademarks of Portswigger, Ltd."""
from behave import *
import shlex
import subprocess
import select
import requests
import json
import time
import re
import logging
import os
from mittn.headlessscanner.proxy_comms import *
import mittn.headlessscanner.dbtools as scandb
# Import positive test scenario implementations
from features.scenarios import *

__copyright__ = "Copyright (c) 2013- F-Secure"


@given(u'a baseline database for scanner findings')
def step_impl(context):
    """Test that we can connect to a database. As a side effect, open_database(9 also creates the necessary table(s) that are required."""
    if hasattr(context, 'dburl') is False:
        assert False, "Database URI not specified"
    dbconn = scandb.open_database(context)
    if dbconn is None:
        assert False, "Cannot open database %s" % context.dburl
    dbconn.close()

@given(u'a working Burp Suite installation')
def step_impl(context):
    """Test that we have a correctly installed Burp Suite and the scanner driver available"""
    logging.getLogger("requests").setLevel(logging.WARNING)
    burpprocess = start_burp(context)

    # Send a message to headless-scanner-driver extension and wait for response.
    # Communicates to the scanner driver using a magical port number.
    # See https://github.com/F-Secure/headless-scanner-driver for additional documentation

    proxydict = {'http': 'http://' + context.burp_proxy_address,
                 'https': 'https://' + context.burp_proxy_address}
    try:
        requests.get("http://localhost:1111", proxies=proxydict)
    except requests.exceptions.RequestException as e:
        kill_subprocess(burpprocess)
        assert False, "Could not fetch scan item status over %s (%s). Is the proxy listener on?" % (
            context.burp_proxy_address, e)
    proxy_message = read_next_json(burpprocess)
    if proxy_message is None:
        kill_subprocess(burpprocess)
        assert False, "Timed out communicating to headless-scanner-driver extension over %s. Is something else running there?" % context.burp_proxy_address

    # Shut down Burp Suite. Again, see the scanner driver plugin docs for further info.

    poll = select.poll()
    poll.register(burpprocess.stdout, select.POLLNVAL | select.POLLHUP)  # pylint: disable-msg=E1101
    try:
        requests.get("http://localhost:1112", proxies=proxydict)
    except requests.exceptions.RequestException as e:
        kill_subprocess(burpprocess)
        assert False, "Could not fetch scan results over %s (%s)" % (context.burp_proxy_address, e)
    descriptors = poll.poll(10000)
    if descriptors == []:
        kill_subprocess(burpprocess)
        assert False, "Burp Suite clean exit took more than 10 seconds, killed"
    assert True


@given(u'scenario id "{scenario_id}"')
def step_impl(context, scenario_id):
    """Store the identifier of the test scenario to be run"""
    context.scenario_id = scenario_id
    assert True


@given(u'all URIs successfully scanned')
def step_impl(context):
    """Store a flag whether abandoned scans should be flagged as scan failures"""
    context.fail_on_abandoned_scans = True
    assert True


@when(u'scenario test is run through Burp Suite with "{timeout}" minute timeout')
def step_impl(context, timeout):
    """Call scenarios.py to run a test scenario referenced by the scenario identifier"""

    # Run the scenario (implemented in scenarios.py)
    burpprocess = start_burp(context)
    timeout = int(timeout)
    scan_start_time = time.time()  # Note the scan start time
    run_scenario(context.scenario_id, context.burp_proxy_address, burpprocess)

    # Wait for end of scan or timeout
    re_abandoned = re.compile("^abandoned")  # Regex to match abandoned scan statuses
    re_finished = re.compile("^(abandoned|finished)")  # Regex to match finished scans
    proxydict = {'http': 'http://' + context.burp_proxy_address,
                 'https': 'https://' + context.burp_proxy_address}
    while True:  # Loop until timeout or all scan tasks finished
        # Get scan item status list
        try:
            requests.get("http://localhost:1111", proxies=proxydict, timeout=1)
        except requests.exceptions.ConnectionError as error:
            kill_subprocess(burpprocess)
            assert False, "Could not communicate with headless-scanner-driver over %s (%s)" % (
                context.burp_proxy_address, error.reason)
        # Burp extensions' stdout buffers will fill with a lot of results, and
        # it hangs, so we time out here and just proceed with reading the output.
        except requests.Timeout:
            pass
        proxy_message = read_next_json(burpprocess)
        # Go through scan item statuses statuses
        if proxy_message is None:  # Extension did not respond
            kill_subprocess(burpprocess)
            assert False, "Timed out retrieving scan status information from Burp Suite over %s" % context.burp_proxy_address
        finished = True
        if proxy_message == []:  # No scan items were started by extension
            kill_subprocess(burpprocess)
            assert False, "No scan items were started by Burp. Check web test case and suite scope."
        for status in proxy_message:
            if not re_finished.match(status):
                finished = False
            if hasattr(context, 'fail_on_abandoned_scans'):  # In some test setups, abandoned scans are failures, and this has been set
                if re_abandoned.match(status):
                    kill_subprocess(burpprocess)
                    assert False, "Burp Suite reports an abandoned scan, but you wanted all scans to succeed. DNS problem or non-Target Scope hosts targeted in a test scenario?"
        if finished is True:  # All scan statuses were in state "finished"
            break
        if (time.time() - scan_start_time) > (timeout * 60):
            kill_subprocess(burpprocess)
            assert False, "Scans did not finish in %s minutes, timed out. Scan statuses were: %s" % (
                timeout, proxy_message)
        time.sleep(10)  # Poll again in 10 seconds

    # Retrieve scan results and request clean exit

    try:
        requests.get("http://localhost:1112", proxies=proxydict, timeout=1)
    except requests.exceptions.ConnectionError as error:
        kill_subprocess(burpprocess)
        assert False, "Could not communicate with headless-scanner-driver over %s (%s)" % (
            context.burp_proxy_address, error.reason)
    # Burp extensions' stdout buffers will fill with a lot of results, and
    # it hangs, so we time out here and just proceed with reading the output.
    except requests.Timeout:
        pass
    proxy_message = read_next_json(burpprocess)
    if proxy_message is None:
        kill_subprocess(burpprocess)
        assert False, "Timed out retrieving scan results from Burp Suite over %s" % context.burp_proxy_address
    context.results = proxy_message  # Store results for baseline delta checking

    # Wait for Burp to exit

    poll = select.poll()
    poll.register(burpprocess.stdout, select.POLLNVAL | select.POLLHUP)  # pylint: disable-msg=E1101
    descriptors = poll.poll(10000)
    if descriptors == []:
        kill_subprocess(burpprocess)
        assert False, "Burp Suite clean exit took more than 10 seconds, killed"

    assert True


@then(u'baseline is unchanged')
def step_impl(context):
    """Check whether the findings reported by Burp have already been found earlier"""
    scanissues = context.results

    # Go through each issue, and add issues that aren't in the database
    # into the database. If we've found new issues, assert False.

    new_items = 0
    for issue in scanissues:
        issue['scenario_id'] = context.scenario_id
        if scandb.known_false_positive(context, issue) is False:
            new_items += 1
            scandb.add_false_positive(context, issue)

    unprocessed_items = scandb.number_of_new_in_database(context)

    if unprocessed_items > 0:
        assert False, "Unprocessed findings in database. %s new issue(s), total %s issue(s)." % (new_items, unprocessed_items)
    assert True
