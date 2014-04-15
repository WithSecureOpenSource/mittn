Feature: Do a Burp Suite active scan
  As a developer,
  I want to run Burp Suite active scan against my system
  So that I detect any regression from baseline security

  # Edit features/environment.py to include correct paths to Burp
  # Suite and your database. The following Background will test the
  # configuration.

  Background: Test that the database and Burp Suite are configured correctly
    Given an sqlite baseline database
    # Alternatively:
    # Given a PostgreSQL baseline database
    And a working Burp Suite installation

  # You need to implement the actual test scenarios that cause HTTP
  # requests to be sent to your target (using, e.g., Selenium,
  # RoboBrowser, Requests) in scenarios.py. They are executed by the
  # scenario id, below.

  @slow
  Scenario: 
    Given scenario id "1"
    When scenario test is run through Burp Suite with "10" minute timeout
    Then baseline is unchanged

  # More scenarios can be added, differentiated with an id
  #  @slow
  #  Scenario: 
  #    Given scenario id "2"
  #    When scenario test is run through Burp Suite with "10" minute timeout
  #    Then baseline is unchanged
