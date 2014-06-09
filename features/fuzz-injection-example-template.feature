# Read docs/INSTALL-httpfuzzer.txt for further documentation

Feature: Do fuzz injection testing for an API
  As a developer,
  I want to inject fuzzed values into an API
  So that I detect lack of robustness in how inputs are processed

  Background: Check that we have a working installation
    # Select sqlite or postgres. Configuration in features/environment.py
    # Given a PostgreSQL baseline database
    Given an sqlite baseline database

    # If you are behind a proxy, set this and configure in environment.py
    # (hint: use an intercepting proxy to see what the tool does when
    # setting it up). Configuration in features/environment.py
    # And a web proxy

    # This line is required for fuzz runs; it does a sanity check for
    # your Radamsa installation. Configuration in features/environment.py
    And a working Radamsa installation

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

    # You need to give (preferably several) examples of the _same_ kind
    # of JSON object that you are sending. This means that the parameters
    # should be the same, but the values should be different, and preferably
    # cover the valid input space for the values. The first in this list
    # is used for valid case instrumentation and for initial valid case
    # probing, so it should respond with a success. Others samples listed
    # can trigger controlled errors, too. The first line is a column title.
    #And valid JSON submissions using "POST" method
    #| submission                            |
    #| {"foo": 1, "bar": "OMalleys"}         |
    #| {"foo": 2, "bar": "Liberty or Death"} |
    #| {"foo": 42, "bar": "Kauppuri 5"}      |

    # And this is for valid form submissions, see above (JSON) for guidance.
    # You can only have either the JSON or form submission active.
    And valid form submissions using "POST" method
      | submission                     |
      | foo=1&bar=OMalleys             |
      | foo=2&bar=Liberty%20or%20Death |
      | foo=42&bar=Kauppuri%205        |

    # Which HTTP methods to use for injection; comma-separated list
    # If you're injecting JSON, GET doesn't make much sense, but with
    # form submissions, you probably want to include GET.
    And tests conducted with HTTP methods "GET,POST,PUT,DELETE"

    # Timeout after which the requests are canceled so the test won't hang
    And a timeout of "5" seconds

    # The actual test; this does fuzzing. Start with a small number
    # first and once you know it works, aim to do thousands of injections.
    # Note that this number is multiplied by every key and value in your
    # valid submissions and for each HTTP method; So, for example, two
    # key=value pairs with four methods and 10 fuzz cases is 4 * 4 * 10
    # HTTP requests that are generated, plus a valid case instrumentation
    # requests would already lead to already requests generated.
    When fuzzing with "10" fuzz cases for each key and value

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
