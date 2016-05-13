import codecs
import copy
import datetime
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile

import six
from requests.exceptions import Timeout, RequestException
from requests.models import Response
from requests.sessions import Session
from sqlalchemy import create_engine, Column, types
from sqlalchemy.ext.declarative.api import declarative_base
from sqlalchemy.orm.session import sessionmaker

from mittn.fuzzer.static_anomalies import STATIC_ANOMALIES

FQDN = socket.getfqdn()
HOSTNAME = socket.gethostbyname(socket.gethostname())

Base = declarative_base()


class BaseModel(Base):
    __abstract__ = True

    def __init__(self, **kwargs):
        # Fill in defaults (SQLAlchemy by default only has these after commit())
        for attr in self.__mapper__.column_attrs:
            if attr.key in kwargs:
                continue

            col = attr.columns[0]

            if col.default and not callable(col.default.arg):
                kwargs[attr.key] = col.default.arg

        super(BaseModel, self).__init__(**kwargs)


class Issue(BaseModel):
    __tablename__ = 'httpfuzzer_issues',

    # We use LargeBinary to store those fields that could contain somehow
    # bad Unicode, just in case some component downstream tries to parse
    # a string provided as Unicode.

    issue_no = Column(types.Integer, primary_key=True, nullable=False)
    new_issue = Column(types.Boolean, default=False, nullable=False)
    timestamp = Column(types.DateTime(timezone=True), nullable=False)
    test_runner_host = Column(types.Text, nullable=False)
    scenario_id = Column(types.Text, nullable=False)
    url = Column(types.Text, nullable=False)

    server_protocol_error = Column(types.Text, default='')
    server_timeout = Column(types.Boolean, default=False, nullable=False)
    server_error_text_detected = Column(types.Boolean, default=False, nullable=False)
    server_error_text_matched = Column(types.Text, default='')

    req_method = Column(types.Text, default='')
    req_headers = Column(types.LargeBinary, default='')
    req_body = Column(types.LargeBinary, default='')

    resp_statuscode = Column(types.Text, default='')
    resp_headers = Column(types.LargeBinary, default='')
    resp_body = Column(types.LargeBinary, default='')
    resp_history = Column(types.LargeBinary, default='')

    @staticmethod
    def from_resp_or_exc(scenario, resp_or_exc):

        issue = Issue(
            new_issue=True,
            timestamp=datetime.datetime.utcnow(),  # misleading...
            test_runner_host=HOSTNAME,
            scenario_id=scenario,
        )

        if isinstance(resp_or_exc, RequestException):
            e = resp_or_exc
            if e.request:
                issue.req_headers = json.dumps(dict(e.request.headers))
                issue.req_body = str(e.request.body)
                issue.url = e.request.url
                issue.req_method = e.request.method
            if e.response:
                issue.resp_statuscode = e.response.status_code
                issue.resp_headers = json.dumps(dict(e.response.headers))
                issue.resp_body = str(e.response.text)
                issue.resp_history = str(e.response.history)

            if isinstance(e, Timeout):
                issue.server_timeout = True
            else:
                issue.server_protocol_error = '{}: {}'.format(e.__class__.__name__, e)  # TODO: Add stacktrace!

        elif isinstance(resp_or_exc, Response):
            resp = resp_or_exc
            issue.req_headers = json.dumps(dict(resp.request.headers))
            issue.req_body = str(resp.request.body)
            issue.url = resp.request.url
            issue.req_method = resp.request.method
            issue.resp_statuscode = resp.status_code
            issue.resp_headers = json.dumps(dict(resp.headers))
            issue.resp_body = str(resp.text)
            issue.resp_history = str(resp.history)

            if hasattr(resp, 'server_error_text_matched'):  # Hacky!
                issue.server_error_text_detected = True
                issue.server_error_text_matched = resp.server_error_text_matched
        else:
            raise NotImplemented

        return issue


class Archiver(object):

    def __init__(self, db_url=None):
        self.db_url = db_url
        self.session = None

    def init(self):
        """Opens the database specified in the feature file and creates tables if not already created.

        :return: A database handle, or None if no database in use

        """
        if not self.db_url:
            return None  # No false positives database is in use

        # Connect to the database
        db_engine = create_engine(self.db_url)
        Session = sessionmaker(bind=db_engine)
        self.session = Session()

        # Create DB tables (has no effect, if they already exist)
        Base.metadata.create_all(db_engine)

    def known_false_positive(self, issue):
        """Check whether issue already exists in the database (usually a "false positive" if it does exist).

        :param issue:
        :return: True if a known issue, False if not.

        """
        if self.session is None:
            # No false positive db is in use, all findings are treated as new
            return False

        # XXX: Because each fuzz case is likely to be separate, we cannot store
        # all those. Two different fuzz cases that elicit a similar response are
        # indistinguishable in this regard and only the one triggering payload
        # gets stored here. This does not always model reality. If fuzzing a
        # field triggers an issue, you should thoroughly fuzz-test that field
        # separately.

        # TODO: Put everything into single column, so that is instantly query as well? JSON field would allow structure
        # This really forces the DB structure and semantics, we don't want that!

        # Check whether we already know about this
        hits = (
            self.session.query(Issue)
            .filter(Issue.scenario_id == issue.scenario_id)
            .filter(Issue.req_method == issue.req_method)
            .filter(Issue.resp_statuscode == issue.resp_statuscode)
            .filter(Issue.server_protocol_error == issue.server_protocol_error)
            .filter(Issue.server_error_text_detected == issue.server_error_text_detected)
            .filter(Issue.server_error_text_matched == issue.server_error_text_matched)
            .filter(Issue.server_timeout == issue.server_timeout)
            .all()
        )

        return len(hits) > 0

    def add_issue(self, issue):
        """Add a finding into the database as a new finding

        :param issue: The response data structure (see httptools.py)

        """

        # If no db in use, simply fail now
        if self.session is None:
            # XXX: Long assert messages seem to fail, so we truncate uri and submission to 200 bytes.
            truncated_submission = issue.resp_body[:200] + "... (truncated)" if len(issue.resp_body) > 210 else issue.resp_body
            truncated_url = issue.resp_body[:200] + "... (truncated)" if len(issue.url) > 210 else issue.url
            assert False, (
                "Response from server failed a check, and no errors "
                "database is in use."
                "Scenario id = {issue.scenario_id}, "
                "error = {issue.server_protocol_error}, "
                "timeout = {issue.server_timeout}, "
                "status = {issue.resp_statuscode}, "
                "URL = {url}, "
                "req_method = {issue.req_method}, "
                "submission = {submission}".format(
                    issue=issue, url=truncated_url, submission=truncated_submission
                ))

        # Add the finding into the database
        self.session.add(issue)
        self.session.commit()

    def add_if_not_found(self, issue):
        if not self.known_false_positive(issue):
            self.add_issue(issue)

    def new_issue_count(self):
        if self.session is None:
            return 0

        hits = self.session.query(Issue).filter_by(new_issue=True).all()

        return len(hits)


class PythonRadamsa(object):

    def __init__(self, path):
        self.radamsa_path = path

        # Ensure that binary exists
        try:
            subprocess.check_output([path, "--help"], stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, OSError) as e:
            raise ValueError("Could not execute Radamsa from %s: %s" % (path, e))

    def fuzz_values(self, valuedict, no_of_fuzzcases):
        """Run every key's valid value list through a fuzzer.

        :param valuedict: Dict of collected valid values
        :param no_of_fuzzcases: How many injection cases to produce

        """
        fuzzes = {}  # Will hold the result
        for key in valuedict.keys():
            if len(valuedict[key]) == 0:
                # If no values for a key, use the samples under the None key
                fuzzes[key] = self._get_fuzz(valuedict[None], no_of_fuzzcases)
            else:
                # Use the samples collected for the specific key
                fuzzes[key] = self._get_fuzz(valuedict[key], no_of_fuzzcases)

        return fuzzes

    def _get_fuzz(self, valuelist, no_of_fuzzcases):
        """Run Radamsa on a set of valid values.

        :param valuelist: Valid cases to feed to Radamsa.
        :param no_of_fuzzcases: Number of fuzz cases to generate.
        :return:

        """
        # Radamsa is a file-based fuzzer so we need to write the valid strings out to file
        # XXX: Isn't there also piping mechanism? Though writing files might be easier, still...
        valid_case_directory = tempfile.mkdtemp()
        fuzz_case_directory = tempfile.mkdtemp()

        try:
            # XXX: Create file per string, wtf
            for valid_string in valuelist:
                handle, tmpfile_path = tempfile.mkstemp(suffix='.case', dir=valid_case_directory)

                # Radamsa only operates on strings, so make numbers and booleans
                # into strings. (No, this won't fuzz effectively, use static
                # injection to cover those cases.)
                # TODO: Um... what? That is HUGE!
                if isinstance(valid_string, (bool, six.integer_types, float)):
                    valid_string = str(valid_string)

                with codecs.open(tmpfile_path, 'w', 'utf-8') as fh:
                    fh.write(valid_string)

            # Run Radamsa (one execution for all files)
            try:
                subprocess.check_call([
                    self.radamsa_path,
                    "-o", fuzz_case_directory + "/%n.fuzz",
                    "-n", str(no_of_fuzzcases),
                    "-r", valid_case_directory
                ])
            except subprocess.CalledProcessError as error:
                assert False, "Could not execute Radamsa: %s" % error

            # Read the fuzz cases from the output directory and return as list
            fuzzlist = []
            for filename in os.listdir(fuzz_case_directory):
                # XXX: Radamsa produces even broken bytearrays, so we need to read contents as bytestr!
                # FIXME: Python 3?
                with open(os.path.join(fuzz_case_directory, filename), 'r') as fh:
                    fuzzlist.append(fh.read())

        finally:
            shutil.rmtree(valid_case_directory)
            shutil.rmtree(fuzz_case_directory)

        return fuzzlist


class AnomalyGenerator(object):

    def __init__(self, radamsa):
        self.radamsa = radamsa

    def collect_values(self, source, target, target_key=None):
        """Recursively collect all values from a data structure into a dict where values are organised under keys,
        or a "None" key if they weren't found under any key.

        For example: {'foo': {'bar': 1, 'baz': 2}, 'toka': 1}

        --> {'foo': [1, 2],
             'toka': [1],
              None: [1, 2, 1]
            }

        XXX: Shouldn't we use set() instead?

        :param source: Source data structure
        :param target: The collected values
        :param target_key: Under which key to store the collected values

        """
        # Each key found in source will have a list of values
        if target_key not in target:
            target[target_key] = []

        # If we see a dict, we will get all the values under that key
        if isinstance(source, dict):
            for key, value in six.iteritems(source):
                self.collect_values(value, target, target_key=key)

        # If we see a list, we will add all values under current key
        elif isinstance(source, list):
            for el in source:
                self.collect_values(el, target, target_key=target_key)

        # If we see an actual value, we will add the value under both the
        # current key and the "None" key
        elif isinstance(source, (six.integer_types, six.string_types, six.text_type, float, bool)) or source is None:
            target[target_key].append(source)
            target[None].append(source)

        else:
            raise NotImplemented

    def create_anomalies(self, branch, anomaly_dict, anomaly_key=None):
        """Walk through a data structure recursively and replace each key and value with an injected (fuzz) case
        one by one.

        The anomaly that is injected is taken from a dict of anomalies. The dict has a "generic" anomaly with
        a key of None, and may have specific anomalies under other keys.

        List length: <number of keys> + <number of values>?

        :param branch: The branch of a data structure to walk into.
        :param anomaly_dict: The anomaly dictionary that has been prepared, must be 1-level deep.
        :param anomaly_key: If the branch where we walk into is under a specific key, this is under what key it is.
        :return: list

        """
        if isinstance(branch, dict):
            fuzzed_branch = []

            # Add cases where *single key* has been replaced with its fuzzed version (value is unchanged)
            for key in branch.keys():
                fuzzdict = branch.copy()

                # Replace key (unchanged value)
                try:
                    new_key = str(anomaly_dict[None])  # Keys need to be strings (why?)
                except UnicodeEncodeError:
                    # Key was too broken to be a string, revenge using key 0xFFFF
                    new_key = '\xff\xff'
                fuzzdict[new_key] = fuzzdict.pop(key)

                fuzzed_branch.append(fuzzdict)

            # Add cases where *single value* has been replaced with its fuzzed version (key is unchanged)
            for key, value in six.iteritems(branch):
                sub_branches = self.create_anomalies(value, anomaly_dict, anomaly_key=key)
                for sub_branch in sub_branches:
                    fuzzdict = branch.copy()
                    fuzzdict[key] = sub_branch
                    fuzzed_branch.append(fuzzdict)

            return fuzzed_branch

        elif isinstance(branch, list):
            fuzzed_branch = []

            # Add cases where *single list item* has been replaced with its fuzzed version
            for i, el in enumerate(branch):
                sub_branches = self.create_anomalies(el, anomaly_dict, anomaly_key=anomaly_key)
                for sub_branch in sub_branches:
                    fuzzdict = copy.copy(branch)
                    fuzzdict[i] = sub_branch
                    fuzzed_branch.append(fuzzdict)

            return fuzzed_branch

        # A leaf node; return just a list of anomalies for a value
        elif isinstance(branch, (six.integer_types, six.string_types, six.text_type, float, bool)) or branch is None:
            anomaly = anomaly_dict.get(anomaly_key, anomaly_dict.get(None))
            return [anomaly]

        # If the data structure contains something that a unserialised JSON
        # cannot contain; instead of just removing it, we return it as-is without
        # injection
        # FIXME: JSON probably cannot contain the *non-fuzzed* version of it (fuzzed version is str), so let's disable this!
        # return [branch]
        raise NotImplemented

    def generate_anomalies(self, wireframe, submissions, amount):

        # Collect values per key from all submissions
        values = {}
        for submission in submissions:
            self.collect_values(submission, values)

        # Create the list of fuzz injections using a helper generator
        fuzzed_anomalies = self.radamsa.fuzz_values(values, amount)

        for index in range(0, amount):
            # Walk through the submission and inject at every key, value

            injection = {}
            for key, value in six.iteritems(fuzzed_anomalies):
                injection[key] = value[index]

            for fuzzed_submission in self.create_anomalies(wireframe, injection):
                yield fuzzed_submission

    def generate_static(self, anomaly_list=STATIC_ANOMALIES):
        for anomaly in anomaly_list:
            yield anomaly


class Client(Session):

    def __init__(self):
        super(Client, self).__init__()
        self.headers.update({
            'Cache-Control': 'no-cache',
            'User-Agent': 'Mozilla/5.0 (compatible; Mittn HTTP Fuzzer-Injector)',
            'X-Abuse': 'This is an automatically generated robustness test request from %s [%s]' % (FQDN, HOSTNAME),
            'Connection': 'close',
            'X-Valid-Case-Instrumentation': 'This is a valid request that should succeed',
        })

    def request_safe(self, *args, **kwargs):
        try:
            resp = self.request(*args, **kwargs)
        except RequestException as e:
            return e
        return resp


class Checker(object):

    BODY_ERROR_LIST = [
        'string',
        'server error',
        # 'exception', # too generic!
        'invalid response',
        'bad gateway',
        'internal ASP error',
        'service unavailable',
        'exceeded',
        'premature',
        'fatal error',
        'proxy error',
        'database error',
        'backend error',
        'mysql',
        'root:',
        'parse error',
        'exhausted',
        'warning',
        'denied',
        # 'failure',  # too generic!
    ]

    def check(self, resp_or_exc, body_errors=None, allowed_status_codes=None, disallowed_status_codes=None):
        if isinstance(resp_or_exc, RequestException):
            return True
        elif isinstance(resp_or_exc, Response):
            if (
                allowed_status_codes and resp_or_exc.status_code not in allowed_status_codes or
                disallowed_status_codes and resp_or_exc.status_code in disallowed_status_codes
            ):
                return True
            elif body_errors:
                matches = [index for index, el in enumerate(body_errors) if re.search(el, resp_or_exc.text, re.IGNORECASE)]
                if matches:
                    resp_or_exc.server_error_text_matched = ', '.join([body_errors[m] for m in matches])  # Hacky
                    return True
        else:
            raise NotImplemented

        return False

    # As context manager?
    # with checker() as r:
    #     r.resp = requests.get(...)


class MittnFuzzer(object):

    def __init__(self, db_url=None, radamsa_path='/usr/bin/radamsa',
                 archiver=None, radamsa=None, generator=None, checker=None, client=None):
        self.archiver = archiver or Archiver(db_url)
        radamsa = radamsa or PythonRadamsa(radamsa_path)
        self.generator = generator or AnomalyGenerator(radamsa)
        self.checker = checker or Checker()
        self.client = client or Client()

        self.archiver.init()
