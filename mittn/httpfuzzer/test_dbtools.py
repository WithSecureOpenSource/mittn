import unittest
import tempfile
import uuid
import os
import datetime
import socket
import mittn.httpfuzzer.dbtools as dbtools
import sqlalchemy
from sqlalchemy import create_engine, Table, Column, MetaData, exc, types


class dbtools_test_case(unittest.TestCase):
    def setUp(self):
        # Create an empty mock inline "context" object
        # See https://docs.python.org/2/library/functions.html#type
        self.context = type('context', (object,), dict())

        # Whip up a sqlite database URI for testing
        self.db_file = os.path.join(tempfile.gettempdir(),
                                    'mittn_unittest.' + str(uuid.uuid4()))
        self.context.dburl = 'sqlite:///' + self.db_file

    def test_dburl_not_defined(self):
        # Try to open connection without a defined database URI
        empty_context = type('context', (object,), dict())
        dbconn = dbtools.open_database(empty_context)
        self.assertEqual(dbconn,
                         None,
                         "No dburl provided should return None as connection")

    def test_create_db_connection(self):
        # Try whether an actual database connection can be opened
        dbconn = dbtools.open_database(self.context)
        self.assertEqual(type(dbconn),
                         sqlalchemy.engine.base.Connection,
                         "An SQLAlchemy connection object was not returned")

    def test_add_false_positive(self):
        # Add a false positive to database and check that all fields
        # get populated and can be compared back originals
        response = {'scenario_id': '1',
                    'req_headers': 'headers',
                    'req_body': 'body',
                    'url': 'url',
                    'timestamp': datetime.datetime.utcnow(),
                    'req_method': 'method',
                    'server_protocol_error': None,
                    'server_timeout': False,
                    'server_error_text_detected': False,
                    'server_error_text_matched': 'matched_text',
                    'resp_statuscode': 'statuscode',
                    'resp_headers': 'resp_headers',
                    'resp_body': 'resp_body',
                    'resp_history': 'resp_history'}

        dbtools.add_false_positive(self.context, response)

        # Connect directly to the database and check the data is there
        db_engine = sqlalchemy.create_engine(self.context.dburl)
        dbconn = db_engine.connect()
        db_metadata = sqlalchemy.MetaData()
        httpfuzzer_issues = Table('httpfuzzer_issues', db_metadata,
                                  Column('new_issue', types.Boolean),
                                  Column('issue_no', types.Integer, primary_key=True, nullable=False),
                                  Column('timestamp', types.DateTime(timezone=True)),
                                  Column('test_runner_host', types.Text),
                                  Column('scenario_id', types.Text),
                                  Column('url', types.Text),
                                  Column('server_protocol_error', types.Text),
                                  Column('server_timeout', types.Boolean),
                                  Column('server_error_text_detected', types.Boolean),
                                  Column('server_error_text_matched', types.Text),
                                  Column('req_method', types.Text),
                                  Column('req_headers', types.LargeBinary),
                                  Column('req_body', types.LargeBinary),
                                  Column('resp_statuscode', types.Text),
                                  Column('resp_headers', types.LargeBinary),
                                  Column('resp_body', types.LargeBinary),
                                  Column('resp_history', types.LargeBinary))
        db_select = sqlalchemy.sql.select([httpfuzzer_issues])
        db_result = dbconn.execute(db_select)
        result = db_result.fetchone()
        for key, value in response.iteritems():
            self.assertEqual(result[key], value,
                             '%s not found in database after add' % key)
        self.assertEqual(result['test_runner_host'], socket.gethostbyname(socket.getfqdn()),
                         'Test runner host name not correct in database')
        self.assertLessEqual(result['timestamp'], datetime.datetime.utcnow(),
                             'Timestamp not correctly stored in database')
        dbconn.close()

    def test_number_of_new_false_positives(self):
        # Add a couple of false positives to database as new issues,
        # and check that the they're counted properly
        response = {'scenario_id': '1',
                    'req_headers': 'headers',
                    'req_body': 'body',
                    'url': 'url',
                    'req_method': 'method',
                    'timestamp': datetime.datetime.utcnow(),
                    'server_protocol_error': None,
                    'server_timeout': False,
                    'server_error_text_detected': False,
                    'server_error_text_matched': 'matched_text',
                    'resp_statuscode': 'statuscode',
                    'resp_headers': 'resp_headers',
                    'resp_body': 'resp_body',
                    'resp_history': 'resp_history'}

        # Add one, expect count to be 1
        dbtools.add_false_positive(self.context, response)
        self.assertEqual(dbtools.number_of_new_in_database(self.context),
                         1, "After adding one, no one finding in database")

        # Add a second one, expect count to be 2
        dbtools.add_false_positive(self.context, response)
        self.assertEqual(dbtools.number_of_new_in_database(self.context),
                         2, "After adding two, no two findings in db")

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
        dbtools.add_false_positive(self.context, response)

        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         True, "Duplicate false positive not detected")

        # Change one of the differentiating fields, and test, and
        # add the tested one to the database.
        response['scenario_id'] = '2'  # Non-duplicate
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: scenario_id different")
        dbtools.add_false_positive(self.context, response)

        # Repeat for all the differentiating fields
        response['server_protocol_error'] = 'Error text'
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: server_protocol_error different")
        dbtools.add_false_positive(self.context, response)

        response['resp_statuscode'] = '500'
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: resp_statuscode different")
        dbtools.add_false_positive(self.context, response)

        response['server_timeout'] = True
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: server_timeout different")
        dbtools.add_false_positive(self.context, response)

        response['server_error_text_detected'] = True
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      response),
                         False, "Not a duplicate: server_error_text_detected different")
        dbtools.add_false_positive(self.context, response)

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
