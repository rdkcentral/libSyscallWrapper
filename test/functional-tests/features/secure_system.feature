Feature: Secure system execution

  Scenario: Execute a simple command
    Given the system wrapper is available
    When I execute "echo hello"
    Then the command should exit successfully

  Scenario: Execute piped commands
    When I execute "echo hello | wc -c"
    Then the command should exit successfully

  Scenario: Execute multiple commands with semicolon
    When I execute "echo one ; echo two"
    Then the command should exit successfully

  Scenario: Handle AND short-circuit
    When I execute "false && echo fail"
    Then the command should exit successfully

  Scenario: Handle OR short-circuit
    When I execute "true || echo fail"
    Then the command should exit successfully

  Scenario: Redirect standard output to file
    When I execute "echo hello > /tmp/syswrap_out.txt"
    Then the file "/tmp/syswrap_out.txt" should exist
