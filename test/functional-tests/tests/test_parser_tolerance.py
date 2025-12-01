from conftest import run_cmd

def test_unterminated_subshell_tolerated():
    run_cmd("(echo hello")

def test_unexpected_close_paren_tolerated():
    run_cmd("echo hello )")

def test_redirect_missing_target_tolerated():
    run_cmd("echo hello >")

def test_duplicate_redirect_tolerated():
    run_cmd("echo hi > /tmp/a > /tmp/b")

