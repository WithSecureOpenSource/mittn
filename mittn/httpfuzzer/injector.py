"""Helper functions for injecting data and testing valid cases"""

"""
Copyright (c) 2014 F-Secure
See LICENSE for details
"""

from mittn.httpfuzzer.httptools import *
from mittn.httpfuzzer.dictwalker import *
from mittn.httpfuzzer.posttools import *
from features.authenticate import authenticate
import requests
import logging
from mittn.httpfuzzer.url_params import *


def inject(context, injection_list):
    """Helper function to inject the payload and to collect the results

    :param context: The Behave context
    :param injection_list: An anomaly dictionary, see dictwalker.py
    """

    # Get the user-supplied list of HTTP methods that we will inject with
    if hasattr(context, "injection_methods"):
        methods = context.injection_methods
    else:
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']

    responses = []
    for injection in injection_list:
        # Walk through the submission and inject at every key, value
        for injected_submission in dictwalk(context.submission[0], injection):
            # Use each method
            for method in methods:
                # Output according to what the original source was
                # Send URL-encoded submissions
                if context.type == 'urlencode':
                    form_string = serialise_to_url(injected_submission, encode=True)
                    if method == 'GET':
                        form_string = '?' + form_string

                # If the payload is in URL parameters (_not_ query)
                if context.type == 'url-parameters':
                    form_string = dict_to_urlparams(injected_submission)

                # If the payload is JSON, send the raw thing
                if context.type == 'json':
                    form_string = serialise_to_json(injected_submission,
                                                    encode=True)

                if hasattr(context, 'proxy_address') is False:
                    context.proxy_address = None

                responses += send_http(context, form_string,
                                     timeout=context.timeout,
                                     proxy=context.proxy_address,
                                     method=method,
                                     content_type=context.content_type,
                                     scenario_id=context.scenario_id,
                                     auth=authenticate(context,
                                                       context.authentication_id))

                # Here, I'd really like to send out unencoded (invalid)
                # JSON too, but the json library barfs too easily, so
                # we concentrate on application layer input fuzzing.

                if hasattr(context, "valid_case_instrumentation"):
                    test_valid_submission(context, injected_submission)
    return responses


def test_valid_submission(context, injected_submission=None):
    """Test submitting the valid case (or the first of a list of valid cases)
    as a HTTP POST. The server has to respond with something sane. This ensures
    the endpoint actually exists so testing has any effect. This function is
    called once in the beginning of a test run, and if valid case
    instrumentation is set, after every injection to check if everything's
    still working. Unlike injection problems, a failure of a valid case will
    terminate the whole test run (if valid cases don't work, the validity of
    the test run would be questionable).

    :param context: The Behave context
    :param injected_submission: Request body to be sent
    """

    # to avoid errors re/ uninitialized object  
    proxydict = {}
    
    if injected_submission is None:
        injected_submission = "(None)"  # For user readability only

    logging.getLogger("requests").setLevel(logging.WARNING)
    if hasattr(context, 'proxy_address'):
        if context.proxy_address:
            proxydict = {'http': 'http://' + context.proxy_address,
                         'https': 'https://' + context.proxy_address}
    else:
        context.proxy = None
        proxydict = None

    if context.type == 'json':
        data = json.dumps(context.submission[0])
    if context.type == 'urlencode':
        data = serialise_to_url(context.submission[0], encode=True)
        if context.submission_method == 'GET':
            data = '?' + data
    if context.type == 'url-parameters':
        data = dict_to_urlparams(context.submission[0])

    # In the following loop, we try to send the valid case to the target.
    # If the response code indicates an auth failure, we acquire new auth
    # material (e.g., relogin), implemented in authenticate() in
    # authenticate.py.
    # If authentication fails twice in a row, we bail out.
    # If the valid case fails for other reasons (unsuccessful status code,
    # timeout, HTTP error), we bail out.
    # We report the previous injection (if any) in the error message.

    retry = 0
    while True:
        if retry == 1:  # On second try, recreate auth material
            auth = authenticate(context, context.authentication_id,
                                acquire_new_authenticator=True)
        else:
            auth = authenticate(context, context.authentication_id)
        retry += 1  # How many retries
        try:
            req = create_http_request(context.submission_method,
                                      context.targeturi,
                                      context.content_type,
                                      data,
                                      auth,
                                      valid_case=True)
            session = requests.Session()
            resp = session.send(req,
                                timeout=context.timeout,
                                verify=False, proxies=proxydict)
        except requests.exceptions.Timeout:
            assert False, "Valid case %s request to URI %s timed out after an " \
                          "injection %s" % (
                              context.submission_method, context.targeturi,
                              injected_submission)
        except requests.exceptions.ConnectionError as error:
            assert False, "Valid case %s request to URI %s after an injected " \
                          "submission %s failed: %s" % (
                              context.submission_method, context.targeturi,
                              injected_submission, error)
        if resp.status_code in [401, 403, 405, 407, 419, 440]:
            if retry > 1:  # Unauthorised two times in a row?
                assert False, "Valid case %s request to URI %s failed " \
                              "authorisation twice in a row after injected " \
                              "submission %s: Response status code %s" % (
                                  context.submission_method, context.targeturi,
                                  injected_submission, resp.status_code)
            else:
                continue  # Unauthorised. Retry
        if hasattr(context, "valid_cases"):
            if resp.status_code not in context.valid_cases:
                assert False, "Valid case %s request to URI %s after injected " \
                              "submission %s did not work: Response status " \
                              "code %s" % (context.submission_method,
                                           context.targeturi,
                                           injected_submission, resp.status_code)

        # If we are here, the request was successful
        break  # Stop trying, continue with the test run
