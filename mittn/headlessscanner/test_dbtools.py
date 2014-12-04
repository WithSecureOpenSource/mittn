import unittest
import tempfile
import uuid
import os
import mittn.headlessscanner.dbtools as dbtools
import datetime
import socket
import json
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
        issue = {'scenario_id': '1',
                 'url': 'testurl',
                 'severity': 'testseverity',
                 'issuetype': 'testissuetype',
                 'issuename': 'testissuename',
                 'issuedetail': 'testissuedetail',
                 'confidence': 'testconfidence',
                 'host': 'testhost',
                 'port': 'testport',
                 'protocol': 'testprotocol',
                 'messages': '{foo=bar}'}

        dbtools.add_false_positive(self.context, issue)

        # Connect directly to the database and check the data is there
        db_engine = sqlalchemy.create_engine(self.context.dburl)
        dbconn = db_engine.connect()
        db_metadata = sqlalchemy.MetaData()
        headlessscanner_issues = Table('headlessscanner_issues',
                                       db_metadata,
                                       Column('new_issue', types.Boolean),
                                       Column('issue_no', types.Integer, primary_key=True, nullable=False),  # Implicit autoincrement
                                       Column('timestamp', types.DateTime(timezone=True)),
                                       Column('test_runner_host', types.Text),
                                       Column('scenario_id', types.Text),
                                       Column('url', types.Text),
                                       Column('severity', types.Text),
                                       Column('issuetype', types.Text),
                                       Column('issuename', types.Text),
                                       Column('issuedetail', types.Text),
                                       Column('confidence', types.Text),
                                       Column('host', types.Text),
                                       Column('port', types.Text),
                                       Column('protocol', types.Text),
                                       Column('messages', types.LargeBinary))
        db_select = sqlalchemy.sql.select([headlessscanner_issues])
        db_result = dbconn.execute(db_select)
        result = db_result.fetchone()
        for key, value in issue.iteritems():
            if key == 'messages':
                self.assertEqual(result[key], json.dumps(value))
            else:
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
        issue = {'scenario_id': '1',
                 'timestamp': datetime.datetime.utcnow(),
                 'test_runner_host': 'localhost',
                 'url': 'url',
                 'severity': 'severity',
                 'issuetype': 'issuetype',
                 'issuename': 'issuename',
                 'issuedetail': 'issuedetail',
                 'confidence': 'confidence',
                 'host': 'host',
                 'port': 'port',
                 'protocol': 'protocol',
                 'messages': 'messagejson'}

        # Add one, expect count to be 1
        dbtools.add_false_positive(self.context, issue)
        self.assertEqual(dbtools.number_of_new_in_database(self.context),
                         1, "After adding one, expect one finding in database")

        # Add a second one, expect count to be 2
        dbtools.add_false_positive(self.context, issue)
        self.assertEqual(dbtools.number_of_new_in_database(self.context),
                         2, "After adding two, expect two findings in db")

    def test_false_positive_detection(self):
        # Test whether false positives in database are identified properly
        issue = {'scenario_id': '1',
                 'timestamp': datetime.datetime.utcnow(),
                 'test_runner_host': 'localhost',
                 'url': 'url',
                 'severity': 'severity',
                 'issuetype': 'issuetype',
                 'issuename': 'issuename',
                 'issuedetail': 'issuedetail',
                 'confidence': 'confidence',
                 'host': 'host',
                 'port': 'port',
                 'protocol': 'protocol',
                 'messages': 'messagejson'}

        # First add one false positive and try checking against it
        dbtools.add_false_positive(self.context, issue)

        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      issue),
                         True, "Duplicate false positive not detected")

        # Change one of the differentiating fields, and test, and
        # add the tested one to the database.
        issue['scenario_id'] = '2'  # Non-duplicate
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      issue),
                         False, "Not a duplicate: scenario_id different")
        dbtools.add_false_positive(self.context, issue)

        # Repeat for all the differentiating fields
        issue['url'] = 'another url'
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      issue),
                         False, "Not a duplicate: url different")
        dbtools.add_false_positive(self.context, issue)

        issue['issuetype'] = 'foo'
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      issue),
                         False, "Not a duplicate: issuetype different")
        dbtools.add_false_positive(self.context, issue)

        # Finally, test the last one again twice, now it ought to be
        # reported back as a duplicate
        self.assertEqual(dbtools.known_false_positive(self.context,
                                                      issue),
                         True, "A duplicate case not detected")


    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except:
            pass
