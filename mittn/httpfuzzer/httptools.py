"""Send a request to server using a variety of ways and return the results"""

"""
Copyright (c) 2014 F-Secure
See LICENSE for details
"""

import requests
import logging
import json


def send_http(context, submission, timeout=5, proxy=None,
              content_type='application/x-www-form-urlencoded; charset="utf-8"',
              scenario_id=0, auth=None, method='POST'):
    """Send out HTTP request and store the request and response for
    analysis

    :param context: The Behave context
    :param submission: Data to be sent (body or GET parameters)
    :param timeout: Timeout value (optional)
    :param proxy: Proxy specification (optional)
    :param body_only: False to send GET data in request body, not in URI
    :param scenario_id: User specified scenario identifier from feature file
    :param auth: Requests authentication object, from authenticate.py
    :param method: HTTP method to be used
    :return: A dict of request and response data
    """
    logging.getLogger("requests").setLevel(logging.WARNING)

    if not hasattr(context, "targeturi"):
        assert False, "Target URI not specified"
    uri = context.targeturi

    proxydict = None  # Default is no proxies
    if proxy is not None:
        proxydict = {'http': 'http://' + proxy, 'https': 'https://' + proxy}
    response_list = []  # We return list of responses we got

    response = {}

    req = create_http_request(method,
                              uri,
                              content_type,
                              submission,
                              auth)

    # Store the actual request & submission bytes for reference
    response['req_headers'] = json.dumps(dict(req.headers))
    response['req_body'] = submission
    response['url'] = uri
    response['req_method'] = method
    response['server_protocol_error'] = None  # Default
    response['server_timeout'] = False  # Default
    response['scenario_id'] = scenario_id
    response['resp_statuscode'] = ""  # Default
    response['resp_headers'] = ""  # Default
    response['resp_body'] = ""  # Default
    response['resp_history'] = ""  # Default

    # Next, perform the request
    session = requests.Session()
    try:
        resp = session.send(req, timeout=timeout, verify=False,
                            proxies=proxydict, allow_redirects=True)

    # Catalogue any errors and save responses for inspection
    except requests.exceptions.Timeout:
        response['server_timeout'] = True
    except requests.exceptions.RequestException as error:
        response['server_protocol_error'] = error
    else:  # Valid response, store response data
        response['resp_statuscode'] = resp.status_code  # Response code
        response['resp_headers'] = json.dumps(dict(resp.headers))  # Header dict
        response['resp_body'] = resp.content  # Bytes in body
        response['resp_history'] = resp.history  # Redirection history
    response_list.append(response)
    return response_list


def create_http_request(method, uri, content_type, submission, auth=None):
    # Set up some headers
    """Create and return a Requests HTTP request object. In a separate
    function to allow reuse.

    :param method: HTTP method to be used
    :param uri: URL to send the data to
    :param content_type: Content type of data to be sent
    :param submission: Data to be sent
    :param auth: Requests Auth object from authenticate.py
    :return: Requests HTTP request object
    """
    headers = {'Content-Type': content_type,
               'Cache-Control': 'no-cache',
               'User-Agent': 'Mozilla/5.0 (compatible; Mittn HTTP '
                             'Fuzzer-Injector)',
               'X-Abuse': 'This is an automatically generated robustness test '
                          'request',
               'Connection': 'close'}

    if method == 'GET':  # Inject into URI parameter
        req = requests.Request(method=method, headers=headers,
                               url=str(uri) + submission,
                               auth=auth).prepare()
    else:  # Inject into request body
        req = requests.Request(method=method, headers=headers, url=uri,
                               data=submission, auth=auth).prepare()
    return req
