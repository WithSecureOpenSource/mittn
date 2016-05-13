=============
mittn-scanner
=============

Headless Scanning Installation
==============================

If you stumble upon a bug, please file a ticket on the GitHub
project or send a pull request with the patch.

Note that this functionality requires a Burp Suite extension that is
provided at https://github.com/F-Secure/headless-scanner-driver, and a
licensed Burp Suite Professional, available from
http://portswigger.net/.

Burp and Burp Suite are trademarks of Portswigger, Ltd.

Headless Scanning Concept
=========================

The idea is to run an intercepting scanning proxy as an active scanner
between a test script (e.g., simple HTTP requests, or a browser driven
by Selenium) and the web site. The findings from the proxy are written
into a database. If there is a previously unseen finding, the test
suite will fail, requiring the developer to check the cause. If the
issue was a false positive, it can be left in the database so the same
issue will not re-trigger.

As a picture:

                  Dev.
  +----------+      o
  | Database |---- -+-
  +----------+     / \
       |
  +----------+   start    +----------+      +--------+
  | Test     |----------->|Intercept |----->|Web site|
  | runner   |<-----------|Proxy     |      +--------+
  +----------+  results   |- - - - - |
       |                  |Headless  |
  +----------+       8080 |Scanning  |
  | Browser  |----------->|Extension |
  +----------+            +----------+

The test runner, Behave, starts the proxy in headless mode, and then
calls developer-provided project-specific positive test cases that
generate HTTP traffic. The scripts run by Behave communicate with an
extension that is loaded within the intercepting proxy that handles
scanning-related chores.

The test script and the extension within the proxy communicate using
in-band signaling (this is a suboptimal design, but at the time of
writing, the best I could come up with). There are special requests
made to specific ports that trigger activities in the extension. The
results are dumped to the standard output of the proxy as JSON, picked
up by the test script, and stored into the database.

After setting up the system, the developer / test engineer only needs
to provide the positive test cases that cause HTTP traffic, and
analyse the findings in the database.

The target is that the developers only need to provide new functional
test cases; addition of new functional tests automagically extends the
scanning into that new territory.

Software requirements
=====================

1. Python package dependencies; see requirements.txt. You should be
   able to install the requirements using

    pip install -r requirements.txt

   As a suggestion, you might want to use a virtualenv.

2. Burp Suite Professional. You need the commercially licensed
   version, which can be obtained from http://portswigger.net/. Please
   note that according to Burp Suite licence at the time of writing,
   you are not permitted to offer a "Burp Suite as a Service" type
   system. The tool has been tested with Burp Suite Professional
   1.6.07.

3. The Headless Scanner Driver extension for Burp Suite, available
   from https://github.com/F-Secure/headless-scanner-driver.

4. Jython standalone JAR file, minimum version 2.7beta1, available
   from http://www.jython.org/downloads.html. This is used to run the
   Headless Scanner Driver extension within Burp Suite.

5. Valid, positive test cases that actually generate HTTP requests
   towards your system. This can be browser automation (e.g.,
   Selenium) or just simple requests performed from a script. Because
   these are application specific, these test cases need to be
   provided by you. As an example, if your project has a REST API, you
   should write a function that creates those requests; if your app is
   a web application with a browser UI, you probably need to create a
   positive test case in Selenium to drive through the user scenario.

6. A database that is supported by SQLAlchemy Core 0.9. See
   http://docs.sqlalchemy.org/en/rel_0_9/dialects/index.html.

   Note: Older versions of Mittn used PostgreSQL and sqlite. The
   database schema has changed, and the old databases are no longer
   compatible with the current release. The oldest release of Mittn
   that is schema-compatible has been tagged as "0.1" on GitHub.

Environment requirements
========================

- A properly installed intercepting proxy.

- The test driver is Behave. Behave runs BDD test cases described in
  Gherkin, a BDD language. Changes to your tests would be likely to be
  made to the Gherkin files that have a .feature suffix. Behave can
  emit JUnit XML test result documents. This is likely to be your
  preferred route of getting the test results into Jenkins.

- New findings are added into an SQL database, which holds the
  information about known false positives, so that they are not
  reported during subsequent runs. You need to have CREATE TABLE,
  SELECT and INSERT permissions on the database.

- Your test target (the server) should preferably be under a specific
  domain that never changes, so you can create a safety-net proxy
  configuration that ensures that the proxy does not send scanning
  requests to third party web sites. The stricter you can make this
  filter, the better.

- I would recommend that, as the scanning target, you use a test
  deployment that has no real customer data and is not in
  production.

Installing the Headless Scanner Driver
======================================

- We assume you have a working and properly installed copy of Burp
  Suite Professional.

- Install the Jython JAR file and the HeadlessScannerDriver.py Python
  script into a suitable directory.

- Start Burp Suite Professional with:

    java -jar -Xmx1g -XX:MaxPermSize=1G <BurpSuiteJarFile> &

- Check the Alerts tab. If it reports any errors, those need to be
  resolved before you continue the setup.

- Install the HeadlessScannerDriver.py extension. From Extension tab,
  Options subtab, select "Location of Jython standalone JAR file" so
  that it points to the Jython JAR file; "Folder for loading modules"
  so that it points to the directory where you downloaded the
  HeadlessScannerDriver.py extension.

- From Extension tab, Extensions subtab, click on Add. "Extension
  type" is Python, and "Extension file" is HeadlessScannerDriver.py.

- Select "Output to system console" as the Standard Output. Click
  Next.

- Check that the Errors tab has no Python errors in it, and click
  Close. Check that the standard output in the shell from where you
  started the proxy says

    {"running": 1}

  This signals that the HeadlessScannerDriver.py extension has
  started. You need to get this working before it makes sense to
  continue.

- Under Target tab, Scope subtab, click on Add.

- Under Host or IP range, enter the domain or IP range your test
  server resides in. This is the safety net. Click Ok. Under Options
  tab, locate the Out-of-Scope Requests section, and ensure that "Drop
  all out-of-scope requests" and "Use suite scope" are selected. This
  enforces the safety net.

  If your test scenarios cause requests to be made to hosts that are
  outside your Target Scope, that specific scan is listed by Burp Suite
  as "abandoned". You can select whether that will trigger a scan failure
  or just treated as a finished scan. If you know exactly that your test
  scenario only sends requests to your target, you should enforce a failure
  with any abandoned scan. This ensures that if there is a misconfiguration
  that prevents scanning from happening, your test case will fail instead of
  silently not working. The example .feature file has an example of how
  to configure this behaviour.

- Under Proxy tab, Options subtab, check that there is one Proxy
  Listener, running at 127.0.0.1:8080, and there is a checkbox in
  "Running" column. If your functional test cases are not proxy-aware,
  you also need to check the "Invisible" column.

- From Burp menu, select Exit. This will save this configuration as
  the default, and it will be used every time the proxy is started in
  headless mode.

- It would now be a good idea to test the proxy and the extension
  manually with a GUI-based browser (run on the same host) to ensure
  it works. If you want to do this, start the proxy again, and set all
  the proxy settings of the browser to use localhost:8080.

  In the Proxy tab, Intercept subtab, click on the Intercept button so
  it reads "Intercept is off", and switch to the History subtab. Make
  a (plain) http request to one of the domains you whitelisted in
  Target / Scope from the browser, and you should see the request and
  response appearing in the list.

  Under the Scanner tab, you should see new scans begin for each HTTP
  request made by the browser. These are initiated by the
  extension. If this does not work, it is useful to debug before you
  continue, as there is little chance things would be fixed
  automagically for you if they don't work now. Check again the Alerts
  tab to determine if anything went wrong.

- Edit mittn/features/environment.py to reflect the location where you
  installed the proxy.

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

Configuring a false positives database
======================================

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

Setting up the test case
========================

The important files that apply to the HeadlessScannerDriver.py test
are:

  1. The headless scanning tests are specified in
     mittn/features/headless-scanning.feature. You need to edit this
     file to describe the test targets you want to test.

  2. The headless scanning test steps are in
     mittn/mittn/headlessscanning. There should not be a need to alter
     anything in this directory.

  3. The function that is called to run your project-specific
     positive, valid test scenarios is in
     mittn/features/scenarios.py. A template has been provided which
     you can edit. You need to edit this file to run the positive
     valid test cases; this is described in more detail below.

  4. General test configuration items in
     mittn/features/environment.py; again, a template has been
     provided.

In the features/scenarios.py, you will need to implement the valid
test case(s) (e.g., Selenium test run(s)) in a function that gets two
parameters: The identifier of the test case (which you can use to
select a specific test, if you have several) and the HTTP proxy
address.

Your function needs to set the HTTP proxies appropriately, and then
run the valid test case. 

If your valid test fails, you should assert failure so that the test
case is marked as a failure:

  assert False, "Valid test scenario did not work as expected, scenario id %s" % scenario_id

or something similar; this will cause the test run to fail and the
error message to get logged. For the coverage and success of scanning,
it is important that your positive valid tests function
correctly. Otherwise it is not guaranteed that you are actually
testing anything. At a minimum, for example, when testing a REST API,
you should check that your valid request returned a 2xx response or
something.

If your tests can raise an exception, catch those and kill the Burp
Suite process before exiting. If you leave Burp Suite running,
subsequent tests runs will fail as Burp Suite invocations will be
unable to bind to the proxy port.

Running the tests
=================

Run the tests with

  behave features/yourfeaturefile.feature --junit --junit-directory PATH

with the mittn directory in your PYTHONPATH (or run the tool from
mittn/), and PATH pointing where you want the JUnit XML output. If
your test automation system does not use JUnit XML, you can, of
course, leave those options out.

You should first try to run the tool from the command line so that you
can determine that the proxy is started cleanly. If there is an issue,
see the section "Troubleshooting" at the end of this file.

Checking the results
====================

If there were any new findings (i.e., active scanner issues that were
not previously seen for this specific test scenario), the test will
flag a failure.

The findings are added into the false positives database.  All new
issues have "1" in the new_issue column. Any new issues are
re-reported after each run, until they are marked as false positives
or fixed.

If the issue was a false positive, you need to mark this column as
"0". The issue will not be reported after this. If the same issue
manifests itself in a different URI or a different test case, it will
be re-reported as a separate issue.

If the issue was a true positive, after fixing the issue, you need to
delete the line from the database.

The results database has the following fields:

- new_issue: true (or 1) if the issue is pending triage (whether or
  not it is a false positive)

- issue_no: an unique id number

- timestamp: a timestamp, in UTC, of when the issue was added to the
  database. You can use this to correlate the finding against server
  logs. Unfortunately, the exact time of the offending HTTP request is
  not made available by Burp, so it cannot be provided here; however,
  you should be able to look at logs that pre-date this timestamp.

- test_runner_host: the IP address from where the tests were run. You
  can use this to correlate the finding against server logs. If you
  only see local addresses here, have a look at your /etc/hosts file.

- scenario_id: test case identifier corresponding to the test case id
  in the .feature file

- url: the URI in which the issue was found

- severity: severity level reported by the proxy

- issuetype: issue type code reported by the proxy (can be useful for
  sorting a large number of findings)

- issuename: issue explanation provided by the proxy

- issuedetail: details of this finding provided by the proxy

- confidence: confidence estimate reported by the proxy

- host: the host where the issue was detected

- port: the port (on the host) where the issue was detected

- protocol: http or https

- messagejson: a list of JSON objects that contain the complete HTTP
  requests and responses that the proxy sent or received when
  detecting this issue. There may be several request/response pairs;
  if this is the case, the interesting part is usually found by
  comparing the requests and responses side-by side.

If you are required to file a bug report on the finding to someone
else (e.g., the development team within your organisation), it is
suggested you include, at a minimum, the URI, issue type, issue
detail, and the HTTP request/response pairs as debug information.

Troubleshooting
===============

If starting the proxy fails, check:

  - whether there is an instance already running. Exit those
    instances. Only one proxy instance can bind to the same port
    at any given time. If your test cases terminate without killing
    the proxy process, this may leave the proxy running.

  - whether the proxy has been properly installed. Follow the guidance
    earlier in this document and try to create HTTP requests manually
    with a browser while running the HeadlessScannerDriver.py
    extension.

If Burp Suite does not seem to listen to the socket, start Burp Suite
with GUI and check whether the proxy listener is running and listening
(the appropriate checkboxes should be checked).

Check that the output of the extension is directed to system
console. When you start the proxy in headless mode from a command
line, you should see it output a small JSON blob when the extension
starts.
