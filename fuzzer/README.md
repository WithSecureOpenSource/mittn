============
mittn-fuzzer
============

HTTP Injector / Fuzzer Installation
===================================

If you have a question, please open a ticket at
https://github.com/F-Secure/mittn/issues?labels=question and tag it
with the 'question' label.

If you stumble upon a bug, please file a ticket on the GitHub
project or send a pull request with the patch.

HTTP Injector / Fuzzer Concept
==============================

The HTTP Injector / Fuzzer takes an HTTP API (form submissions or JSON
submissions) and injects malformed input to each of the values and
parameters in the submission. The malformed input can come from a
library of static, hand-crafted inputs, or from a fuzzer (currently,
generated using Radamsa from the University of Oulu, Finland). When
using the fuzzer, the malformed inputs are created based on valid
examples you provide.

Servers that fail to process malformed inputs may exhibit a range of
responses:

- A 5xx series error, indicating a server-side error
- A timeout
- A response that contains a string that usually indicates an error
  situation (e.g., "internal server error")
- An HTTP level protocol error

The test tool can look for these kinds of malformed responses. If one
is encountered, the test case that caused the response is logged in a
database. A developer can look at the database entries in order to
reproduce and fix the issue.

These responses do not necessarily mean that the system would be
vulnerable. However, they most likely indicate a bug in input
processing, and the code around the injection path that triggered the
problem is probably worth a closer look.

The system does _not_ look for malformed data that would be reflected
back in the responses. This is a strategy often used for Cross-Site
Scripting detection. Please look at dedicated web vulnerability
scanners such as Burp Suite Professional or OWASP Zaproxy if you
require this (and the associated Mittn test runner for headless
scanning). The system also does not do a very deep SQL injection
detection. For this, we suggest using tools such as SQLmap.

The test system runs test cases described in the Gherkin language and
run using Behave. This makes it easy to create new tests for new HTTP
APIs even without programming experience. The test script can be
instructed to emit JUnit XML test results for integration in test
automation.

The test system also supports "valid case instrumentation", where each
malformed submission is interleaved with a valid case. The valid case
needs to succeed. Valid case instrumentation is used for:

- Re-authenticating and authorising the test script to the target
  system, if the malformed test case caused the authorisation to
  expire.
- Detecting cases where a valid request following an invalid request
  is not properly processed. This may indicate a Denial of Service
  issue.

Quickstart
==========

1. Install the requirements.
2. Create authenticate.py and environment.py under mittn/features
   (templates are provided that you can edit).
3. Edit the .feature files.
4. Run the took from the mittn directory:

     behave features/your-tests.feature

For details, read on.

Software requirements
=====================

1. Python package requirements in addition to the standard libraries
   are listed in requirements.txt. You can install the requirements
   using pip:

     pip install -r requirements.txt

   As a suggestion, you might want to use a virtualenv.

2. Radamsa, a fuzzer compiled on your system. Radamsa is available
   from https://github.com/aoh/radamsa. Mittn has been
   tested with version 0.4a. Radamsa is an excellent file-based fuzzer
   created by the University of Oulu Secure Programming Group.

Environment requirements
========================

- The test driver is Behave. Behave runs BDD test cases described in
  Gherkin, a BDD language. Changes to your tests would be likely to be
  made to the Gherkin files that have a .feature suffix. Behave can
  emit JUnit XML test result documents. This is likely to be your
  preferred route of getting the test results into Jenkins.

- New findings are added into an SQL database, which holds the
  information about known false positives, so that they are not
  reported during subsequent runs. You need to have CREATE TABLE,
  SELECT and INSERT permissions on the database.

- You need a deployment of your test system that is safe to test
  against. You might not want to use your production system due to
  Denial of Service potential. You might not want to run the tool
  through an Intrusion Detection System or a Web Application Firewall,
  unless you want to test the efficacy and behaviour of those
  solutions.

- You may not want to run the fuzz tests from a host that is running
  antivirus software. Fuzz test cases created by the fuzzer are
  written to files and have a tendency of being mistaken as
  malware. These are false positives. There is no real malware in the
  tool, unless you provide it with such inputs.

What are baseline databases?
============================

The tests in Mittn have a tendency of finding false positives. Also,
due to the distributed nature of cloud-based Continuous Integration
systems, the tests might be running on transient nodes that are
deployed just for the duration of a test run and then shut down. The
baseline database holds the information on new findings and known
false positives in a central place.

Currently, the httpfuzzer and headlessscanner tools use baseline
databases. The headlessscanner tool requires a database; the httpfuzzer
can be run without one, but the usefulness is greatly reduced.

The tool uses SQL Alchemy Core as a database abstraction layer. The
supported database options are listed at
http://docs.sqlalchemy.org/en/rel_0_9/dialects/index.html.

If you need a centralised database that receives issues from a number
of nodes, you need a database with network connectivity.  If you only
need a local database, you can use a file-based (such as sqlite)
database. The latter is much easier to set up as it requires no
database server or users to be defined.

Whichever database you use, you will provide the configuration options
in features/environment.py as a database URI. For details on the URI
syntax, see
http://docs.sqlalchemy.org/en/rel_0_9/core/engines.html#database-urls.

Managing findings
=================

After a failing test run, the database (if one is used) will contain
new findings. They will be marked as new. Once the issue has been
studied, the developers should:

1) If the issue was a real finding, remove the issue from the
   database. If the issue re-occurs, it will fail the test again.

2) If the issue was a false positive, mark it as not new by zeroing
   the new_issue flag. if the issue re-occurs, it will not be reported
   again but treated as a false positive.

Selecting the appropriate database
==================================

The test system uses an SQL database to store false positives, so that
it doesn't report them as errors. Whenever new positives are
encountered, those are added to the database. The developers can then
check the finding. If the finding is a false positive, they will need
to mark it as such in the database (by setting a flag new_issue as
false (or zero) on that finding). If it was a real positive, that
finding needs to be removed from the database, and of course, the
system under test needs a fix.

The system supports either databases in local files with sqlite, or a
connection over the network to an off-host database. Select
the database solution you want to use:

  1. If you run the tests on a developer machine, or on a host that is
     not redeployed from scratch every time (i.e., the host has
     persistent storage), or if the host has a persistent
     network-mounted file system, it is probably easier to store the
     results into a file-based local database.

  2. If you run tests concurrently on several nodes against the same
     system under test, or if your test system is on a VM instance
     that is destroyed after the tests (i.e., the host has no
     persistent storage), or if you want to share the results easily
     with a larger team, it is probably easier to use a
     network-connected database.

Setup instructions
==================

User-editable files
-------------------

Test cases are written in Gherkin and stored in .feature files. The
cases are run with Behave, for example, from the mittn base directory:

  behave features/mytests.feature --junit --junit-directory
  /path/to/junit/reports
  
If you are not using JUnit XML reports, leave the --junit and
--junit-directory options out.

Feature file setup is described later in this document, under "Writing
test cases".

All user-editable files are in the mittn/features/ directory. For
basic usage, you should not need to edit anything in the mittn/mittn/
directory.

Authentication and authorisation
--------------------------------

If you do NOT need to authorise yourself to your test target, just
copy mittn/features/authenticate.py.template into
mittn/features/authenticate.py.

If your system DOES require authorisation, you need to provide your
own modifications to the template and store that in
mittn/features/authenticate.py. There is a template available that you
can copy and edit; the template contains instructions as to what to
do. In essence, you need to return a Requests library Auth object that
implements the authentication and authorisation against your test
target. The Requests library already provides some standard Auth
object types. If your system requires a non-standard login (e.g.,
username and password typed into a web form), you need to provide the
code to perform this. Please see the Requests library documentation at
http://docs.python-requests.org/en/latest/user/authentication/ and the
template for modification instructions.

You can have several different auth methods for different cases; these
are identified through an authentication flow identifier, specified in
the test description.

Environment settings
--------------------

- Edit the mittn/features/environment.py to reflect your setup. You
  need to edit at least the common and httpfuzzer specific
  settings. There is a template available that you can copy and edit.

- Edit mittn/features/environment.py so that context.dburl points to
  your database. The pointer is an SQL Alchemy URI, and the syntax
  varies for each database. Examples are provided in the file for
  sqlite and PostgreSQL. Further documentation on the database URIs is
  available on
  http://docs.sqlalchemy.org/en/rel_0_9/core/engines.html#database-urls.

- Ensure that you have CREATE TABLE, INSERT and SELECT rights to the
  database. (SQL Alchemy might require something else under the hood
  too, depending on what database you are using.)

- During the first run of the tool, the false positives database table
  will be automatically created. If one exists already, it will not be
  deleted.

Writing test cases
==================

Test cases are defined through feature files. These are files with a
.feature suffix, written in Gherkin, a BDD language.

You can find example tests in Mittn/features/*template.feature
files. It is recommended that you view these examples, and unless some
of the lines are not self-explanatory, you can find the documentation
below.

There are two example templates: One for injection of static anomalies
(shell command injections, etc.), and one for injection of fuzz test
cases. These templates are extensively commented, so you could just
grab one of them and start editing it. This section gives more
information on some selected topics.

Environmental settings
----------------------

  Given a baseline database for injection findings

Checks whether you have a database available.

  Given a web proxy

Sets a web proxy. This is useful if you are, in fact, behind a proxy,
or if you want to see what the tool does, using an intercepting
proxy. When setting up the system, it could be a good idea to view the
requests. The proxy settings are in feature/environment.py.

  Given a working Radamsa installation

Performs a sanity check for the fuzzer. This needs to be present if
you inject fuzz cases. The path to radamsa is provided in
features/environment.py.

Test case settings
------------------

  Given scenario id "ID"

You should give each test case a different ID (an arbitrary string)
as that helps you to separate results.

  Given an authentication flow id "1"

This selects which authentication / authorisation you want to use with
this specific scenario. This is an arbitrary string. If you just use
one type of authorisation with all the test cases, or do not need
authentication / authorisation, you can just leave it as is.

  Given tests conducted with HTTP methods "GET,POST,PUT,DELETE"

What HTTP methods should be used to inject. Even if your system only
expects, say, POST, it might be a good idea to try injecting with GET,
too.

  Given a timeout of "5" seconds

How long to wait for a server response.

Setting up valid case instrumentation
-------------------------------------

  Given valid case instrumentation with success defined as "100-499"

Valid case instrumentation tries a valid test case after each
injection. This is done for two reasons:

  1) If you need authentication / authorisation, the valid case tests
     whether your auth credentials are still valid, and if not, it
     logs you in again.
  2) If the valid case suddenly stops working, the remaining injection
     cases wouldn't probably actually test your system either.

A valid case is the same API call which you are using injection
against.

If you do not use valid case instrumentation, the valid case is tried
just once as the first test case.

Valid cases have an HTTP header that indicates they are valid
cases. This may be helpful if you are looking at the injected requests
using a proxy tool.

Defining test targets for static injection
------------------------------------------

  Given target URL "http://mittn.org/dev/null"
  Given a valid JSON submission "{something}" using "POST" method
  Given a valid form submission "something" using "POST" method

These lines define the target for static injection testing. The target
URL is the API URL. Depending on whether you are testing a JSON API or
a form submission, you should then provide an example of a _valid_
case.

For best results, the valid case should trigger maximal processing
behind the API. You can do this by using any and all options and
parameters that your API supports, and by having several valid test
cases (in separate Gherkin scenarios) that cause maximal functional
coverage.

You can only do _either_ static injection of fuzzing in a single test
scenarion, not both.

Defining test targets for fuzz testing
--------------------------------------

  Given target URL "http://mittn.org/dev/null"
  Given valid JSON submissions using "POST" method
    | submission                            |
    | {"foo": 1, "bar": "OMalleys"}         |
    | {"foo": 2, "bar": "Liberty or Death"} |
    | {"foo": 42, "bar": "Kauppuri 5"}      |
  Given valid form submissions using "POST" method
    | submission                     |
    | foo=1&bar=OMalleys             |
    | foo=2&bar=Liberty%20or%20Death |
    | foo=42&bar=Kauppuri%205        |

These lines define the target for fuzz case injection testing. The
target URL is the API URL. Depending on whether you are testing a JSON
API or a form submission, you should then provide several examples of
valid cases. These examples are used to create fuzz case data.

The first line ("submission") is a column title and must be included.

The first valid case you provide is used as the reference valid case
and should aim at triggering maximal processing behind the API. The
other valid cases should be technically valid, but do not need to be
positive test cases; the other cases could also be negative test
cases or have less parameters.

You can only do _either_ static injection of fuzzing in a single test
scenarion, not both.

Form submissions should be URL-encoded.

Running the tests and checking for responses
--------------------------------------------

  When fuzzing with "10" fuzz cases for each key and value
  When injecting static bad data for every key and value

These perform the actual test run. You can only have one of these per
scenario.

When fuzzing, you can start small but you should probably aim to run
hundreds or thousands of test cases when you actually take the system
into production.

By default, requests that are sent to the remote host contain an
X-Abuse: header that lists your hostname and IP address. These are
intended to give a remote system administrator some way of contacting
you if you mistakenly point your tool towards a wrong endpoint.

  When storing any new cases of return codes "500,502-599"
  When storing any new cases of responses timing out
  When storing any new invalid server responses
  When storing any new cases of response bodies that contain strings
    | string                |
    | server error          |
    | exception             |
    | invalid response      |

These lines check for anomalous server responses. The response bodies
are searched for the specified strings. If you know your framework's
default critical error strings, you should probably add them here, and
remove any that are likely to cause false positives. The first line
("string") is a column title and must be included.

  Then no new issues were stored

This final line raises a failed assertion if there were any new
findings.

Findings in the database
------------------------

The findings in the database contain the following columns:

  new_issue: A flag that indicates a new finding. If this is 0, and
  the issue is found again, it will not be reported - it will be
  assumed to be a known false positive.

  issue_no: A unique serial number.

  timestamp: The timestamp (in UTC) when the request was sent to the
  server. You can use this information to correlate findings in server
  logs.

  test_runner_host: the IP address from where the tests were run. You
  can use this to correlate the finding against server logs. If you
  only see local addresses here, have a look at your /etc/hosts file.

  scenario_id: The arbitrary scenario identifier you provided in the
  feature file.

  url: The target URL that was being injected.

  server_protocol_error: If the issue was caused by a malformed HTTP
  response, this is what the Requests library had to say about the
  response.

  server_timeout: True if the request timed out.

  server_error_text_match: True if the server's response body matched
  one of the error strings listed in the feature file.

  req_method: The HTTP request method (e.g., POST) used for the injection.

  req_headers: A JSON structure of the HTTP request headers used for
  the injection.

  req_body: The HTTP request body that was injected. (This is where
  you can find the bad data.)

  resp_statuscode: The HTTP response status code from the server.

  resp_headers: A JSON structure of the HTTP response headers from the
  server.

  resp_body: The body of the HTTP response from the server.

  resp_history: If the response came after a series of redirects, this
  contains the requests and responses of the redirects.

Future features
---------------

The plan is to make the fuzzer also fuzz URL parts, including path and
parameters. Currently, the URL parts fuzzing is not there, but you can
inject into, and fuzz, URL parameters.

URL parameters (not to be confused with form parameters!) are semicolon-
separated:

  ;parameter1=value1,value2;parameter2=value3

This is specified in RFC 3986, section 3.3. This is a fairly niche
thing, and has not been tested as much as the other modes.

Currently, only the GET method (i.e., without body) is supported for
URL path parameter injection.  If you want to inject to these, the
feature file lines are:

  Given valid url parameters ";foo=bar"
  Given valid url parameters
  	| submission   |
	| ;foo=bar     |
	| ;quux=bletch |

for static injection and fuzzing, respectively.

If URL path fuzzing will be supported in the future, this syntax
_will_ change into accepting the actual complete URL, and an
additional feature file rule will be introduced that specifies the
valid body for other HTTP methods than GET.
