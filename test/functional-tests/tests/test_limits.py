from conftest import run_cmd

def test_too_many_arguments():
    run_cmd("echo " + "a " * 600)
    assert True

def test_too_many_pipes():
    run_cmd("|".join(["echo hi"] * 40))
    assert True

def test_redirect_to_variable_literal_allowed():
    assert run_cmd("echo hi > %s") == 0
