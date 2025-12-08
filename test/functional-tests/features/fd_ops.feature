Feature: File descriptor operations

  Scenario: Output redirection applies open and close
    When I execute "echo hello > /tmp/fdops.txt"
    Then file "/tmp/fdops.txt" should exist

  Scenario: dup2 failure is handled safely
    When a dup2 operation fails internally
    Then the command should not crash
