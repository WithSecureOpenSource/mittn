"""Helper functions for managing the false positives database"""
import os
import datetime
import socket
import json
from sqlalchemy import create_engine, Table, Column, MetaData, exc, types
from sqlalchemy import sql, and_

__copyright__ = "Copyright (c) 2013- F-Secure"


def open_database(context):
    """Opens the database specified in the feature file and creates
    tables if not already created

    :param context: The Behave context
    :return: A database handle, or None if no database in use
    """
    if hasattr(context, 'dburl') is False:
        return None  # No false positives database is in use
    dbconn = None

    # Try to connect to the database
    try:
        db_engine = create_engine(context.dburl)
        dbconn = db_engine.connect()
    except (IOError, exc.OperationalError):
        assert False, "Cannot connect to database '%s'" % context.dburl

    # Set up the database table to store new findings and false positives.
    # We use LargeBinary to store the message, because it can potentially
    # be big.
    db_metadata = MetaData()
    db_metadata.bind = db_engine
    context.headlessscanner_issues = Table('headlessscanner_issues',
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

    # Create the table if it doesn't exist
    # and otherwise no effect
    db_metadata.create_all(db_engine)

    return dbconn


def known_false_positive(context, issue):
    """Check whether a finding already exists in the database (usually
    a "false positive" if it does exist)

    :param context: The Behave context
    :param issue: A finding from the scanner (see steps.py)
    :return: True or False, depending on whether this is a known issue
    """

    dbconn = open_database(context)
    if dbconn is None:
        # No false positive db is in use, all findings are treated as new
        return False

    # Check whether we already know about this. A finding is a duplicate if:
    # - It has the same scenario id, AND
    # - It was found in the same URL, AND
    # - It has the same issue type.

    db_select = sql.select([context.headlessscanner_issues]).where(
        and_(
            context.headlessscanner_issues.c.scenario_id == issue['scenario_id'],  # Text
            context.headlessscanner_issues.c.url == issue['url'],  # Text
            context.headlessscanner_issues.c.issuetype == issue['issuetype']))  # Text

    db_result = dbconn.execute(db_select)

    # If none found with these criteria, we did not know about this

    if len(db_result.fetchall()) == 0:
        return False  # No, we did not know about this

    db_result.close()
    dbconn.close()
    return True


def add_false_positive(context, issue):
    """Add a finding into the database as a new finding

    :param context: The Behave context
    :param response: An issue data structure (see steps.py)
    """
    dbconn = open_database(context)
    if dbconn is None:
        # There is no false positive db in use, and we cannot store the data,
        # so we will assert a failure.
        assert False, "Issues were found in scan, but no false positive database is in use."

    # Add the finding into the database

    db_insert = context.headlessscanner_issues.insert().values(
        new_issue=True,  # Boolean
        # The result from Burp Extender does not include a timestamp,
        # so we add the current time
        timestamp=datetime.datetime.utcnow(),  # DateTime
        test_runner_host=socket.gethostbyname(socket.getfqdn()),  # Text
        scenario_id=issue['scenario_id'],  # Text
        url=issue['url'],  # Text
        severity=issue['severity'],  # Text
        issuetype=issue['issuetype'],  # Text
        issuename=issue['issuename'],  # Text
        issuedetail=issue['issuedetail'],  # Text
        confidence=issue['confidence'],  # Text
        host=issue['host'],  # Text
        port=issue['port'],  # Text
        protocol=issue['protocol'],  # Text
        messages=json.dumps(issue['messages']))  # Blob

    dbconn.execute(db_insert)
    dbconn.close()


def number_of_new_in_database(context):
    dbconn = open_database(context)
    if dbconn is None:  # No database in use
        return 0

    true_value = True  # SQLAlchemy cannot have "is True" in where clause

    db_select = sql.select([context.headlessscanner_issues]).where(
        context.headlessscanner_issues.c.new_issue == true_value)
    db_result = dbconn.execute(db_select)
    findings = len(db_result.fetchall())
    db_result.close()
    dbconn.close()
    return findings
