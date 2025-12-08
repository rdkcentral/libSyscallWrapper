Feature: Parser tolerance behavior

  Scenario: Unterminated subshell does not crash
    When I execute "(echo hello"
    Then the command should exit successfully

  Scenario: Unexpected closing parenthesis tolerated
    When I execute "echo hello )"
    Then the command should exit successfully

  Scenario: Missing redirect target tolerated
    When I execute "echo hello >"
    Then the command should exit successfully

  Scenario: Duplicate redirection tolerated
    When I execute "echo hi > /tmp/a > /tmp/b"
    Then the command should exit successfully
