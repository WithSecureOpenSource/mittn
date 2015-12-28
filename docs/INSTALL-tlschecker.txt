=========================
 tlschecker installation
=========================

If you need further guidance
============================

If you stumble upon a bug, please file a ticket on the GitHub
project or send a pull request with the patch.

TLS checker concept
===================

The TLS checker runs the great sslyze.py tool against a server,
requesting XML output. The test steps then interrogate the XML
tree to find out whether the server configuration is correct.

These tests should be run against production deployment.

Software requirements
=====================

1. Python package dependencies; see setup.py.

2. sslyze, which you can obtain from
   https://github.com/nabla-c0d3/sslyze. The version against which
   the tool works is 0.12. If the XML output changes, tests may break
   unexpectedly. You may want to obtain a pre-built version from
   https://github.com/nabla-c0d3/sslyze/releases. Ensure the script
   is executable.

Environment requirements
========================

- The test driver is Behave. Behave runs BDD test cases described in
  Gherkin, a BDD language. Changes to your tests would be likely to be
  made to the Gherkin files that have a .feature suffix. Behave can
  emit JUnit XML test result documents. This is likely to be your
  preferred route of getting the test results into Jenkins.

- Set up Mittn/features/environment.py using the supplied
  environment.py.template. This should contain a link to the sslyze
  executable.

- You have two ways of defining the target of the scan; you can either
  populate environment variables with the hostname and port number,
  and set those in the feature file (by default: TLSCHECK_HOST and
  TLSCHECK_PORT), or you can hardcode these in the feature file.

Setting up the test case
========================

The important files that apply to tlschecker tests are:

  1. The test steps, tlschecker.feature as an example. The tests
     should be rather self-explanatory. See below for more details.

  2. The actual test steps are in Mittn/mittn/tlschecker. There
     should not be a need to alter anything in this directory.

  3. General test configuration items in
     Mittn/features/environment.py.

The tests use an optimisation where the potentially slow scanning
activity is done only once, the result is stored, and subsequent tests
just check the resulting XML.

After doing a connection, you should probably have a "Then" statement
"the connection results are stored".

Subsequent steps that start with "Given a stored connection result"
operate with the result set that was last stored.

Running the tests
=================

Run the tests with

  behave features/yourfeaturefile.feature --junit --junit-directory PATH

with the Mittn directory in your PYTHONPATH (or run the tool from
Mittn/), and PATH pointing where you want the JUnit XML output. If
your test automation system does not use JUnit XML, you can, of
course, leave those options out.

