import unittest
import tempfile
import uuid
import os
import datetime
import socket
import sqlalchemy
from sqlalchemy import create_engine, Table, Column, MetaData, exc, types
from sqlalchemy.orm.session import Session

from mittn.httpfuzzer.fuzzing import Archiver

from mittn.httpfuzzer.fuzzing import Issue


class dbtools_test_case(unittest.TestCase):

    def setUp(self):
        # Whip up a sqlite database URI for testing
        self.db_file = os.path.join(tempfile.gettempdir(), 'mittn_unittest.' + str(uuid.uuid4()))
        self.db_url = 'sqlite:///' + self.db_file

    def test_dburl_not_defined(self):
        a = Archiver()
        a.init()
        assert a.session is None, "No db_url provided, should return None as connection"

    def test_create_db_connection(self):
        # Try whether an actual database connection can be opened
        a = Archiver(self.db_url)
        a.init()
        assert isinstance(a.session, Session), "An SQLAlchemy connection object was not returned"

    def test_number_of_new_false_positives(self):
        # Add a couple of false positives to database as new issues,
        # and check that the they're counted properly
        a = Archiver(self.db_url)
        a.init()

        # OK: Add one, expect count to be 1
        issue = Issue(
            new_issue=True,
            scenario_id='test-scenario',
        )
        a.add_issue(issue)
        assert a.new_issue_count() == 1

        # OK: Add a second one, expect count to be 2
        issue = Issue(
            new_issue=True,
            scenario_id='test-scenario',
        )
        a.add_issue(issue)
        assert a.new_issue_count() == 2

    def test_false_positive_detection(self):
        # Test whether false positives in database are identified properly
        response = {'scenario_id': '1',
                    'req_headers': 'headers',
                    'req_body': 'body',
                    'url': 'url',
                    'req_method': 'method',
                    'timestamp': datetime.datetime.utcnow(),
                    'server_protocol_error': False,
                    'server_timeout': False,
                    'server_error_text_detected': False,
                    'server_error_text_matched': 'matched_text',
                    'resp_statuscode': 'statuscode',
                    'resp_headers': 'resp_headers',
                    'resp_body': 'resp_body',
                    'resp_history': 'resp_history'}

        # First add one false positive and try checking against it
        dbtools.add_issue(self.context, response)

        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         True, "Duplicate false positive not detected")

        # Change one of the differentiating fields, and test, and
        # add the tested one to the database.
        response['scenario_id'] = '2'  # Non-duplicate
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: scenario_id different")
        dbtools.add_issue(self.context, response)

        # Repeat for all the differentiating fields
        response['server_protocol_error'] = 'Error text'
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: server_protocol_error different")
        dbtools.add_issue(self.context, response)

        response['resp_statuscode'] = '500'
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: resp_statuscode different")
        dbtools.add_issue(self.context, response)

        response['server_timeout'] = True
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: server_timeout different")
        dbtools.add_issue(self.context, response)

        response['server_error_text_detected'] = True
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: server_error_text_detected different")
        dbtools.add_issue(self.context, response)

        # Finally, test the last one again twice, now it ought to be
        # reported back as a duplicate
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         True, "A duplicate case not detected")

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except:
            pass
