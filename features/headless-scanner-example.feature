Feature: Do a headless active scan
  As a developer,
  I want to run an active scan against my system
  So that I detect any regression from baseline security

  # Edit features/environment.py to include correct paths to Burp
  # Suite and your database. The following Background will test the
  # configuration.

  Background: Test that the database and Burp Suite are configured correctly
    Given a baseline database for scanner findings
    And a working Burp Suite installation

  # You need to implement the actual test scenarios that cause HTTP
  # requests to be sent to your target (using, e.g., Selenium,
  # RoboBrowser, Requests) in scenarios.py. They are executed by the
  # scenario id, below.

  # If you can strictly control where your test scenarios make HTTP requests, e.g.,
  # you are using Requests or similar to specific URIs, setting "all URIs successfully scanned"
  # will fail if any one of the URIs will be skipped (e.g., for being out of scope, or DNS failing,
  # or something else). This decreases the likelihood that you run useless scans.
  # However, if you're using Selenium or similar to scan, and your browser automation makes
  # requests outside your target scope, remove that line; abandoned scans are normal in that
  # sort of an environment - but you have to verify that your target actually is being scanned.

  @slow
  Scenario: 
    Given scenario id "1"
    And all URIs successfully scanned
    When scenario test is run through Burp Suite with "10" minute timeout
    Then baseline is unchanged

  # More scenarios can be added, differentiated with an id
  #  @slow
  #  Scenario: 
  #    Given scenario id "2"
  #    When scenario test is run through Burp Suite with "10" minute timeout
  #    Then baseline is unchanged
