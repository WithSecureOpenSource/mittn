"""Helper functions for managing the false positives database."""
import os
import socket  # For getting hostname where we're running on
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
    # We use LargeBinary to store those fields that could contain somehow
    # bad Unicode, just in case some component downstream tries to parse
    # a string provided as Unicode.
    db_metadata = MetaData()
    db_metadata.bind = db_engine
    context.httpfuzzer_issues = Table('httpfuzzer_issues', db_metadata,
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

    # Create the table if it doesn't exist
    # and otherwise no effect
    db_metadata.create_all(db_engine)

    return dbconn


def known_false_positive(context, response):
    """Check whether a finding already exists in the database (usually
    a "false positive" if it does exist)

    :param context: The Behave context
    :param response: The server response data structure (see httptools.py)
    :return: True or False, depending on whether this is a known issue
    """

    # These keys may not be present because they aren't part of
    # the response dict Requests produces, but instead added by us.
    # If this function is called without them, default to False.
    if 'server_error_text_detected' not in response:
        response['server_error_text_detected'] = False
    if 'server_error_text_matched' not in response:
        response['server_error_text_matched'] = ''

    dbconn = open_database(context)
    if dbconn is None:
        # No false positive db is in use, all findings are treated as new
        return False

    # Check whether we already know about this. A finding is a duplicate if:
    # - It has the same protocol level error message (or None) from Requests AND
    # - It has the same scenario id, AND
    # - It has the same return status code from the server, AND
    # - It has the same timeout boolean value, AND
    # - It has the same server error text detection boolean value.

    # Because each fuzz case is likely to be separate, we cannot store
    # all those. Two different fuzz cases that elicit a similar response are
    # indistinguishable in this regard and only the one triggering payload
    # gets stored here. This does not always model reality. If fuzzing a
    # field triggers an issue, you should thoroughly fuzz-test that field
    # separately.

    db_select = sql.select([context.httpfuzzer_issues]).where(
        and_(
            context.httpfuzzer_issues.c.scenario_id == response['scenario_id'],  # Text
            context.httpfuzzer_issues.c.server_protocol_error == response['server_protocol_error'],  # Text
            context.httpfuzzer_issues.c.resp_statuscode == str(response['resp_statuscode']),  # Text
            context.httpfuzzer_issues.c.server_timeout == response['server_timeout'],  # Boolean
            context.httpfuzzer_issues.c.server_error_text_detected == response['server_error_text_detected']))  # Boolean

    db_result = dbconn.execute(db_select)

    # If none found with these criteria, we did not know about this

    if len(db_result.fetchall()) == 0:
        return False  # No, we did not know about this

    db_result.close()
    dbconn.close()
    return True


def add_false_positive(context, response):
    """Add a finding into the database as a new finding

    :param context: The Behave context
    :param response: The response data structure (see httptools.py)
    """

    # These keys may not be present because they aren't part of
    # the response dict Requests produces, but instead added by us.
    # If this function is called without them, default to False.
    if 'server_error_text_detected' not in response:
        response['server_error_text_detected'] = False
    if 'server_error_text_matched' not in response:
        response['server_error_text_matched'] = ''

    dbconn = open_database(context)
    if dbconn is None:
        # There is no false positive db in use, and we cannot store the data,
        # so we will assert a failure. Long assert messages seem to fail,
        # so we truncate uri and submission to 200 bytes.
        truncated_submission = (
            response['req_body'][:200] + "... (truncated)") if len(
            response['req_body']) > 210 else response['req_body']
        truncated_uri = (response['url'][:200] + "... (truncated)") if len(
            response['url']) > 210 else response['url']
        assert False, "Response from server failed a check, and no errors " \
                      "database is in use. Scenario id = %s, error = %s, " \
                      "timeout = %s, status = %s, URI = %s, req_method = %s, " \
                      "submission = %s" % (
                          response['scenario_id'],
                          response['server_protocol_error'],
                          response['server_timeout'],
                          response['resp_statuscode'],
                          truncated_uri,
                          response['req_method'],
                          truncated_submission)

    # Add the finding into the database

    db_insert = context.httpfuzzer_issues.insert().values(
        new_issue=True,  # Boolean
        timestamp=response['timestamp'],  # DateTime
        test_runner_host=socket.gethostbyname(socket.getfqdn()),  # Text
        scenario_id=str(response['scenario_id']),  # Text
        req_headers=str(response['req_headers']),  # Blob
        req_body=str(response['req_body']),  # Blob
        url=str(response['url']),  # Text
        req_method=str(response['req_method']),  # Text
        server_protocol_error=response['server_protocol_error'],  # Text
        server_timeout=response['server_timeout'],  # Boolean
        server_error_text_detected=response['server_error_text_detected'],  # Boolean
        server_error_text_matched=response['server_error_text_matched'],  # Text
        resp_statuscode=str(response['resp_statuscode']),  # Text
        resp_headers=str(response['resp_headers']),  # Blob
        resp_body=str(response['resp_body']),  # Blob
        resp_history=str(response['resp_history']))  # Blob

    dbconn.execute(db_insert)
    dbconn.close()


def number_of_new_in_database(context):
    dbconn = open_database(context)
    if dbconn is None:  # No database in use
        return 0

    true_value = True  # SQLAlchemy cannot have "is True" in where clause

    db_select = sql.select([context.httpfuzzer_issues]).where(
        context.httpfuzzer_issues.c.new_issue == true_value)
    db_result = dbconn.execute(db_select)
    findings = len(db_result.fetchall())
    db_result.close()
    dbconn.close()
    return findings
