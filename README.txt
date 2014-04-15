Mittn
=====

"For that warm and fluffy feeling"

Background
----------

Mittn is (or will be) a suite of security testing tools to be run in
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
awesome system for automating security testing with OWASP Zaproxy.

Installation
------------

Exact installation varies by the test tool you want to use. See the
docs/ directory for detailed instructions.

Note on the status
------------------

Currently, the tool implements:

- Automated web scanning by driving Burp Suite Professional's Active
  Scanner (you need a commercial licence)

- TLS configuration scanning using sslyze

In near future, we will also release:

- HTTP API fuzzing (JSON, form submissions, URI paths) with Radamsa

As you can see, all the heavy lifting is done by existing tools.
Mittn just glues it together.

Burp and Burp Suite are trademarks of Portswigger, Ltd.

Contact information
-------------------

If you have found a bug, please file a ticket in the GitHub project,
or just send a pull request with a patch.

I would really like to hear about successful or non-successful tries
to use the tools; my email addresses are
antti.vaha-sipila@f-secure.com (work) and avs@iki.fi (private).