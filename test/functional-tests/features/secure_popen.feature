Feature: Secure popen execution

  Scenario: Read output from command
    When I popen "echo hello" in read mode
    Then output should be available

  Scenario: Command with pipe using popen
    When I popen "echo hello | wc -c" in read mode
    Then output should be available

  Scenario: Empty command tolerated at runtime
    When I popen an empty command
    Then popen should return a valid stream

  Scenario: Invalid redirection rejected
    When I popen "echo > %s"
    Then popen should fail
