from conftest import popen_cmd

def test_popen_simple_read():
    p = popen_cmd("echo hello")
    out, err = p.communicate()
    assert "hello" in out

def test_popen_pipe():
    p = popen_cmd("echo hello | wc -c")
    out, err = p.communicate()
    assert out.strip().isdigit()

def test_empty_command_runtime():
    p = popen_cmd("")
    out, err = p.communicate()
    assert p.returncode == 0 or p.returncode is None

def test_redirect_variable_literal_allowed():
    p = popen_cmd("echo hi > %s")
    out, err = p.communicate()
    assert p.returncode == 0
