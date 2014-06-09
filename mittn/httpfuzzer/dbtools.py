"""Helper functions for managing the false positives database"""

"""
Copyright (c) 2014 F-Secure
See LICENSE for details
"""

import psycopg2
import sqlite3
import os


def open_database(context):
    """Opens the database specified in the feature file

    :param context: The Behave context
    :return: A database handle, or None if no database in use
    """
    if hasattr(context, 'db') is False:
        return None  # No false positives database is in use
    dbconn = None
    if context.db == "sqlite":
        database = context.sqlite_database
        try:
            dbconn = sqlite3.connect(database)
        except (IOError, sqlite3.DatabaseError):
            assert False, "sqlite database '%s' not found, or not a database" \
                          % database
    if context.db == "postgres":
        try:
            dbconn = psycopg2.connect(database=context.psql_dbname,
                                      user=context.psql_dbuser,
                                      password=os.environ[context.psql_dbpwdenv],
                                      host=context.psql_dbhost,
                                      port=int(context.psql_dbport))
        except psycopg2.Error as error:
            assert False, "Cannot connect to the PostgreSQL database %s on " \
                          "%s:%s as user %s: %s" % (
                              context.psql_dbname,
                              context.psql_dbhost,
                              context.psql_dbport,
                              context.psql_dbuser,
                              error.pgerror)
    if dbconn is None:
        assert False, "Unknown database type %s" % context.db
    return dbconn


def known_false_positive(context, response, server_error_text_match=False):
    """Check whether a finding already exists in the database (usually
    a "false positive" if it does exist)

    :param context: The Behave context
    :param response: The server response data structure (see httptools.py)
    :param server_error_text_match: Whether the server response matched some
    of the error texts specified in the feature file (True or False)
    :return: True or False, depending on whether this is a known issue
    """
    dbconn = open_database(context)
    if dbconn is None:
        # No false positive db is in use, all findings are treated as new
        return False

    # Check whether we already know about this. A finding is a duplicate if:
    # - It has the same protocol level error message (or None) from Requests AND
    # - It has the same scenario id, AND
    # - It has the same return status code from the server, AND
    # - It has the same timeout boolean value, AND
    # - It has the same server error text match boolean value.

    # Because each fuzz case is likely to be separate, we cannot store
    # all those. Two different fuzz cases that elicit a similar response are
    # indistinguishable in this regard and only the one triggering payload
    # gets stored here. This does not always model reality. If fuzzing a
    # field triggers an issue, you should thoroughly fuzz-test that field
    # separately.

    dbcursor = dbconn.cursor()
    if context.db == "sqlite":
        dbcursor.execute("SELECT * FROM httpfuzzer_issues WHERE scenario_id=? "
                         "AND server_protocol_error=? "
                         "AND resp_statuscode=? "
                         "AND server_timeout=? "
                         "AND server_error_text_match=?", (
                             str(response['scenario_id']),
                             str(response['resp_statuscode']),
                             str(response['server_protocol_error']),
                             str(response['server_timeout']),
                             str(server_error_text_match)))
    if context.db == "postgres":
        dbcursor.execute(
            "select * from httpfuzzer_issues where scenario_id=%s and status="
            "%s and error=%s and timeout=%s and server_error_text_match=%s", (
                str(response['scenario_id']), str(response['resp_statuscode']),
                str(response['server_protocol_error']),
                str(response['server_timeout']), str(server_error_text_match)))
    if len(dbcursor.fetchall()) == 0:
        return False  # No, we did not know about this
    dbconn.close()
    return True


def add_false_positive(context, response, server_error_text_match=False):
    """Add a finding into the database as a new finding

    :param context: The Behave context
    :param response: The response data structure (see httptools.py)
    :param server_error_text_match: Whether the response matched any strings
    in the feature file (True or False)
    """
    dbconn = open_database(context)
    if dbconn is None:
        # There is no false positive db in use, and we cannot store the data,
        # so we will assert a failure. Long assert messages seem to fail,
        # so we truncate uri and submission to 200 bytes.
        truncated_submission = (
            response['req_body'][:200] + "... (truncated)") if len(
            response['req_body']) > 210 else response['req_body']
        truncated_uri = (response['url'][:200] + "... (truncated)") if len(
            response['url']) > 210 else response['uri']
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

    dbcursor = dbconn.cursor()
    if context.db == "sqlite":
        dbcursor.execute(
            "INSERT INTO httpfuzzer_issues (new_issue, "
            "scenario_id, req_headers, req_body, "
            "url, req_method, server_protocol_error, "
            "server_timeout, server_error_text_match, "
            "resp_statuscode, "
            "resp_headers, resp_body, resp_history) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, str(response['scenario_id']),
             str(response['req_headers']),
             str(response['req_body']),
             str(response['url']),
             str(response['req_method']),
             str(response['server_protocol_error']),
             str(response['server_timeout']),
             str(server_error_text_match),
             str(response['resp_statuscode']),
             str(response['resp_headers']), str(response['resp_body']),
             str(response['resp_history'])))
    if context.db == "postgres":
        dbcursor.execute(
            "insert into httpfuzzer_issues (new_issue, "
            "scenario_id, req_headers, req_body, "
            "url, req_method, server_protocol_error, "
            "server_timeout, server_error_text_match, "
            "resp_statuscode, "
            "resp_headers, resp_body, resp_history) "
            "values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (1, str(response['scenario_id']),
             str(response['req_headers']),
             str(response['req_body']),
             str(response['url']),
             str(response['req_method']),
             str(response['server_protocol_error']),
             str(response['server_timeout']),
             str(server_error_text_match),
             str(response['resp_statuscode']),
             str(response['resp_headers']), str(response['resp_body']),
             str(response['resp_history'])))

    dbconn.commit()
    dbconn.close()


def number_of_new_in_database(context):
    dbconn = open_database(context)
    dbcursor = dbconn.cursor()
    if dbconn is None:  # No database in use
        return 0
    dbcursor.execute("SELECT * FROM httpfuzzer_issues WHERE new_issue=1")
    findings = len(dbcursor.fetchall())
    dbconn.close()
    return findings
