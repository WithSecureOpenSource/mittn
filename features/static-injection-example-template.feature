# Read docs/INSTALL-httpfuzzer.txt for further documentation

Feature: Do static injection testing for an API
  As a developer,
  I want to inject bad data into an API
  So that I detect lack of robustness in how inputs are processed

  Background: Check that we have a working installation
    # Select sqlite or postgres. Configuration in features/environment.py
    # Given a PostgreSQL baseline database
    Given an sqlite baseline database

    # If you are behind a proxy, set this and configure in environment.py
    # (hint: use an intercepting proxy to see what the tool does when
    # setting it up). Configuration in features/environment.py
    # And a web proxy

  Scenario:
    # Give different tests different identifiers, so when an error is reported
    # into the database, you know which test scenario it applies to.
    Given scenario id "1"

    # If you need authentication, implement it in authenticate.py.
    # You can have several authentication options, referred to by an id here.
    And an authentication flow id "1"

    # It is recommended that after each injection, you check that your target
    # still works by trying a valid case. The following turns on valid case
    # instrumentation. One valid case is always run at first irrespective of
    # this setting.
    And valid case instrumentation with success defined as "100-499"

    # The target URL where valid cases and injections are sent
    And target URL "http://mittn.org/dev/null"

    # An example of a valid JSON submission, used both for injection and for
    # valid case instrumentation
    And a valid JSON submission "{"foo": 1, "bar": "OMalleys"}" using "POST" method

    # An example of a valid form submission (only select one or the other)
    # And a valid form submission "foo=1&bar=OMalleys" using "POST" method

    # Which HTTP methods to use for injection; comma-separated list
    # If you're injecting JSON, GET doesn't make much sense, but with
    # form submissions, you probably want to include GET.
    And tests conducted with HTTP methods "POST,PUT,DELETE"

    # Timeout after which the requests are canceled so the test won't hang
    And a timeout of "5" seconds

    # The actual test; this injects static data. If you want to fuzz,
    # see the other example
    When injecting static bad data for every key and value

    # Which return codes from the server are flagged as failures
    And storing any new cases of return codes "500,502-599"

    # Whether timeouts are flagged as failures or not
    And storing any new cases of responses timing out

    # Whether HTTP level problems are flagged as failures
    And storing any new invalid server responses

    # Strings that, if present in the server response, indicate a failure.
    # Add your web frameworks' error strings here, and remove any that
    # would cause false positives. The first row is a title row.
    And storing any new cases of response bodies that contain strings
    | string                |
    | server error          |
    | exception             |
    | invalid response      |
    | bad gateway           |
    | internal ASP error    |
    | service unavailable   |
    | exceeded              |
    | premature             |
    | fatal error           |
    | proxy error           |
    | database error        |
    | backend error         |
    | SQL                   |
    | mysql                 |
    | postgres              |
    | root:                 |
    | parse error           |
    | exhausted             |
    | warning               |
    | denied                |
    | failure               |

    # Finally, if any of the above have failed, fail the test run
    Then no new issues were stored
