from conftest import run_cmd_list, LIB_BINARY

def test_unterminated_subshell_tolerated():
    run_cmd_list([LIB_BINARY, "system", "(echo hello"])

def test_unexpected_close_paren_tolerated():
    run_cmd_list([LIB_BINARY, "system", "echo hello )"])

def test_redirect_missing_target_tolerated():
    run_cmd_list([LIB_BINARY, "system", "echo hello >"])

def test_duplicate_redirect_tolerated():
    run_cmd_list([LIB_BINARY, "system", "echo hi > /tmp/a > /tmp/b"])
