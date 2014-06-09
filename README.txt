Mittn
=====

"For that warm and fluffy feeling"

Background
----------

Mittn is an evolving suite of security testing tools to be run in
Continuous Integration context. It uses Python and Behave.

The idea is that security people or developers can define a hardening
target using a human-readable language, in this case, Gherkin.

The rationale is:

- Once the initial set of tests is running in test automation, new
  security test cases can be added based on existing ones without
  having to understand exactly how the tools are set up and run.

- Existing functional tests can be reused to drive security tests.

- Test tools are run automatically in Continuous Integration, catching
  regression and low-hanging fruit, and helping to concentrate
  exploratory security testing into areas where it has a better
  bang-for-buck ratio.

Mittn was originally inspired by Gauntlt (http://gauntlt.org/). You
might also want to have a look at BDD-Security
(http://www.continuumsecurity.net/bdd-intro.html) that is a pretty
awesome system for automating security testing, and offers similar
functionality with OWASP Zaproxy.

Installation
------------

Exact installation varies by the test tool you want to use. See the
docs/ directory for detailed instructions.

Features
--------

Currently, the tool implements:

- Automated web scanning by driving Burp Suite Professional's Active
  Scanner, available from http://portswigger.net/. Burp and Burp Suite
  are trademarks of Portswigger, Ltd.

- TLS configuration scanning using sslyze, available from
  https://github.com/iSECPartners/sslyze.

- HTTP API fuzzing (JSON and form submissions) with Radamsa, available
  from https://code.google.com/p/ouspg/wiki/Radamsa.

If you'd like something else to be supported, please open an issue
ticket against the GitHub project.

As you can see, all the heavy lifting is done by existing tools.
Mittn just glues it together.

Contact information
-------------------

If you have questions about the usage, please open a ticket in the
GitHub project with a "Question" tag.

If you have found a bug, please file a ticket in the GitHub project.

If necessary, you can also email opensource@f-secure.com, but opening
a ticket on GitHub is preferable.
