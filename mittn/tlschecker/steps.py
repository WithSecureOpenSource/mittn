# pylint: disable=E0602,E0102
from behave import *
from subprocess import check_output
from tempfile import NamedTemporaryFile
import re
import os
import xml.etree.ElementTree as ET
# The following for calculating validity times from potentially
# locale specific timestamp strings
import dateutil.parser
import dateutil.relativedelta
import pytz
from datetime import datetime

__copyright__ = "Copyright (c) 2013- F-Secure"


@step('sslyze is correctly installed')
def step_impl(context):
    context.output = check_output([context.sslyze_location, '--version'])
    assert "0.12.0" in context.output, "SSLyze version 0.12 is required"


@step('target host and port in "{host}" and "{port}"')
def step_impl(context, host, port):
    # Store target host, port for future use
    try:
        context.feature.host = os.environ[host]
    except KeyError:
        assert False, "Hostname not defined in %s" % host
    try:
        context.feature.port = os.environ[port]
    except KeyError:
        assert False, "Port number not defined in %s" % port
    assert True


@given(u'target host "{host}" and port "{port}"')
def step_impl(context, host, port):
    assert host != "", "Hostname not defined"
    assert port != "", "Port number not defined"
    context.feature.host = host
    context.feature.port = port
    assert True


@step(u'a TLS connection can be established')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    # The connection target should have been resolved
    # The .//foo notation is an Xpath
    assert len(root.findall('.//invalidTargets')) == 1, \
        "Target system did not resolve or could not connect"
    for error in root.findall('.//errors'):
        # There should be no connection errors
        assert len(error) == 0, \
            "Errors found creating a connection to %s:%s" % (context.feature.host, context.feature.port)
    num_acceptedsuites = 0
    for acceptedsuites in root.findall('.//acceptedCipherSuites'):
        num_acceptedsuites += len(acceptedsuites)
    # If there are more than zero accepted suites (for any enabled protocol)
    # the connection was successful
    assert num_acceptedsuites > 0, \
        "No acceptable cipher suites found at %s:%s" % (context.feature.host, context.feature.port)


@step(u'the certificate is in major root CA trust stores')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    certificate = root.findall(".//pathValidation")
    for pathvalidation in certificate:
        assert pathvalidation.get("validationResult") == 'ok', "Certificate not in trust store %s" % pathvalidation.get(
            "usingTrustStore")


@step(u'the certificate has a matching host name')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    certificate = root.find(".//hostnameValidation")
    assert certificate.get("certificateMatchesServerHostname") == 'True', \
        "Certificate subject does not match host name"


@step(u'the D-H group size is at least "{groupsize}" bits')
def step_impl(context, groupsize):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    keyexchange = root.find(".//keyExchange")
    if keyexchange is None:
       # Kudos bro!
        return
    keytype = keyexchange.get('Type')
    realgroupsize = keyexchange.get('GroupSize')
    if keytype == 'DH':
        assert int(groupsize) <= int(realgroupsize), \
            "D-H group size less than %s" % groupsize


@step(u'the public key size is at least "{keysize}" bits')
def step_impl(context, keysize):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    publickeysize = root.find(".//publicKeySize").text
    assert int(keysize) <= int(publickeysize[0]), \
        "Public key size less than %s" % keysize


@step(u'a "{proto}" connection is made')
def step_impl(context, proto):
    host = context.feature.host
    port = context.feature.port
    xmloutfile = NamedTemporaryFile(delete=False)
    xmloutfile.close()  # Free the lock on the XML output file
    context.output = check_output([context.sslyze_location, "--%s" % proto.lower(),
                                   "--compression", "--reneg",
                                   "--chrome_sha1", "--heartbleed",
                                   "--xml_out=" + xmloutfile.name,
                                   "--certinfo=full",
                                   "--hsts",
                                   "--http_get",
                                   "--sni=%s" % host,
                                   "%s:%s" % (host, port)])
    context.xmloutput = ET.parse(xmloutfile.name)
    os.unlink(xmloutfile.name)


@step(u'a TLS connection cannot be established')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    num_suites = 0
    for suites in root.findall('.//acceptedCipherSuites'):
        num_suites += len(suites)
    for suites in root.findall('.//preferredCipherSuite'):
        num_suites += len(suites)
    # If there are zero accepted and preferred suites, connection was
    # not successful
    assert num_suites == 0, \
        "An acceptable cipher suite was found (= a connection was made)."


@step(u'compression is not enabled')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    compr = root.findall('.//compressionMethod')
    compression = False
    for comp_method in compr:
        if comp_method.get('isSupported') != 'False':
            compression = True
    assert compression is False, "Compression is enabled"


@step(u'secure renegotiation is supported')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    reneg = root.find('.//reneg/sessionRenegotiation')
    assert reneg is not None, \
        "Renegotiation is not supported"
    assert reneg.get('canBeClientInitiated') == 'False', \
        "Client side renegotiation is enabled (shouldn't be)"
    assert reneg.get('isSecure') == 'True', \
        "Secure renegotiation is not supported (should be)"


@step(u'the connection results are stored')
def step_impl(context):
    try:
        context.feature.xmloutput = context.xmloutput
    except AttributeError:
        assert False, "No connection results found. Perhaps a connection problem to %s:%s" % (
            context.feature.host, context.feature.port)


@step(u'a stored connection result')
def step_impl(context):
    try:
        context.xmloutput = context.feature.xmloutput
    except AttributeError:
        assert False, "A stored connection result was not found. Perhaps a connection problem to %s:%s" % (
            context.feature.host, context.feature.port)


@step(u'the following cipher suites are disabled')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    # Extract blacklisted suites from behave's table & create a regex
    suite_blacklist = []
    for row in context.table:
        suite_blacklist.append(row['cipher suite'])
    suite_blacklist_regex = "(" + ")|(".join(suite_blacklist) + ")"
    # The regex should not match to any accepted suite for any protocol
    passed = True
    found_list = ""
    for accepted_suites in root.findall('.//acceptedCipherSuites'):
        for suite in accepted_suites:
            if re.search(suite_blacklist_regex, suite.get("name")) is not None:
                passed = False
                found_list = found_list + "%s " % suite.get("name")
    assert passed, "Blacklisted cipher suite(s) found: %s" % found_list


@step(u'at least one the following cipher suites is enabled')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    acceptable_suites = []
    for row in context.table:
        acceptable_suites.append(row['cipher suite'])
    acceptable_suites_regex = "(" + ")|(".join(acceptable_suites) + ")"
    # The regex must match at least once for some protocol
    found = False
    for accepted_suites in root.findall('.//acceptedCipherSuites'):
        for suite in accepted_suites:
            if re.search(acceptable_suites_regex, suite.get("name")) is not None:
                found = True
    assert found, "None of listed cipher suites were enabled"


@step(u'one of the following cipher suites is preferred')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    acceptable_suites = []
    for row in context.table:
        acceptable_suites.append(row['cipher suite'])
    acceptable_suites_regex = "(" + ")|(".join(acceptable_suites) + ")"
    # The regex must match the preferred suite for every protocol
    found = True
    accepted_suites = root.findall('.//preferredCipherSuite/cipherSuite')
    for accepted_suite in accepted_suites:
        if re.search(acceptable_suites_regex, accepted_suite.get("name")) is None:
            found = False
    assert found, "None of the listed cipher suites were preferred"


@step(u'Time is more than validity start time')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    notbefore_string = root.find('.//validity/notBefore').text
    notbefore = dateutil.parser.parse(notbefore_string)
    assert notbefore <= datetime.utcnow().replace(tzinfo=pytz.utc), \
        "Server certificate is not yet valid (begins %s)" % notbefore_string


@step(u'Time plus "{days}" days is less than validity end time')
def step_impl(context, days):
    days = int(days)
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    notafter_string = root.find('.//validity/notAfter').text
    notafter = dateutil.parser.parse(notafter_string)
    notafter = notafter - dateutil.relativedelta.relativedelta(days=+days)
    assert notafter >= datetime.utcnow().replace(tzinfo=pytz.utc), \
        "Server certificate will not be valid in %s days (expires %s)" % \
        (days, notafter_string)


@step(u'Strict TLS headers are seen')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    hsts = root.find('.//httpStrictTransportSecurity')
    assert hsts.get('isSupported') == 'True', \
        "HTTP Strict Transport Security header not observed"

@step(u'server has no Heartbleed vulnerability')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    heartbleed = root.find('.//openSslHeartbleed')
    assert heartbleed.get('isVulnerable') == 'False', \
        "Server is vulnerable for Heartbleed"

@step(u'certificate does not use SHA-1')
def step_impl(context):
    try:
        root = context.xmloutput.getroot()
    except AttributeError:
        assert False, "No stored TLS connection result set was found."
    sha1 = root.find('.//chromeSha1Deprecation')
    assert sha1.get('isServerAffected') == "False", \
        "Server is affected by SHA-1 deprecation (sunset)"
