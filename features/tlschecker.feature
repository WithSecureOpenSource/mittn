Feature: Test TLS server-side configuration
  As a developer,
  I want to verify the deployed TLS server cipher suite configuration
  So that compliance with TLS guideline is assessed

  Background: Setting the target host
    # You can populate environment variables with the target
    Given target host and port in "TLSCHECK_HOST" and "TLSCHECK_PORT"
    # or alternatively, specify the target here
    # Given target host "target.domain" and port "443"

  Scenario: A TLSv1 connection can be established (baseline interop TLS version)
    # This scenario stores the connection result, which is interrogated by
    # the subsequent steps
    Given sslyze is correctly installed
    When a "TLSv1" connection is made
    Then a TLS connection can be established
    And the connection results are stored

  Scenario: Certificate should be within validity period
    Given a stored connection result
    Then Time is more than validity start time
    And Time plus "30" days is less than validity end time

  Scenario: Compression should be disabled
    Given a stored connection result
    Then compression is not enabled 

  Scenario: Server should support secure renegotiation
    Given a stored connection result
    Then secure renegotiation is supported

  Scenario: Weak cipher suites should be disabled
    # Suites are regular expressions
    Given a stored connection result
    Then the following cipher suites are disabled
         | cipher suite |
         | EXP-         |
         | ADH          |
         | AECDH        |
         | NULL         |
         | DES-CBC-     |
         | RC2          |
         | RC5          |
         | MD5          |

  Scenario: Questionable cipher suites should be disabled
    # Suites are regular expressions
    Given a stored connection result
    Then the following cipher suites are disabled
         | cipher suite |
         | CAMELLIA     |
         | SEED         |
         | IDEA         |
         | SRP-         |
         | PSK-         |
         | DSS          |
         | ECDSA        |
         | DES-CBC3     |
         | RC4          |

  Scenario: An Ephemeral D-H cipher suite should be enabled
    # Suites are regular expressions
    Given a stored connection result
    Then at least one the following cipher suites is enabled
         | cipher suite       |
         | DHE-               |
         | ECDHE-             |

  Scenario: The preferred cipher suite should be adequate
    # Suites are regular expressions
    # This checks against the baseline TLSv1 result
    Given a stored connection result
    Then one of the following cipher suites is preferred
         | cipher suite      |
         | DHE.*AES256-GCM   |
         | DHE.*AES256       |
         | ECDHE.*AES256-GCM |
         | ECDHE.*AES256     |

  Scenario: The server certificate should be trusted
    Given a stored connection result
    Then the certificate has a matching host name
    And the certificate is in major root CA trust stores

  Scenario: The server key should be large enough
    Given a stored connection result
    Then the public key size is at least "2048" bits

  Scenario: The server should set Strict TLS headers
    Given a stored connection result
    Then Strict TLS headers are seen

  Scenario: The server is not vulnerable for Heartbleed
    Given a stored connection result
    Then server has no Heartbleed vulnerability

  Scenario: The certificate does not use SHA-1 any more
    Given a stored connection result
    Then certificate does not use SHA-1

  Scenario: SSLv2 should be disabled
    When a "SSLv2" connection is made
    Then a TLS connection cannot be established

  Scenario: SSLv3 should be disabled
    When a "SSLv3" connection is made
    Then a TLS connection cannot be established

  Scenario: TLS 1.2 should be enabled
    When a "TLSv1_2" connection is made
    Then a TLS connection can be established
    And the connection results are stored

  Scenario: The preferred cipher suite in TLS 1.2 should be a secure one
    # Given TLS 1.2! Make sure that one is stored currently
    # Suites are regular expressions
    Given a stored connection result
    Then one of the following cipher suites is preferred
         | cipher suite      |
         | DHE.*AES256-GCM   |
         | ECDHE.*AES256-GCM |

