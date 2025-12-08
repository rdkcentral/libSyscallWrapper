Feature: Limits enforcement

  Scenario: Too many arguments is rejected
    When I execute a command with excessive arguments
    Then command should fail

  Scenario: Too many command chains is rejected
    When I execute excessive piped commands
    Then command should fail

  Scenario: Redirect to variable is rejected
    When I execute "echo hi > %s"
    Then command should fail
