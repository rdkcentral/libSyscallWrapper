from conftest import run_cmd
import os

def test_simple_command():
    assert run_cmd("echo hello") == 0

def test_pipe_command():
    assert run_cmd("echo hello | wc -c") == 0

def test_semicolon():
    assert run_cmd("echo one ; echo two") == 0

def test_and_short_circuit():
    assert run_cmd("false && echo fail") != 0

def test_or_short_circuit():
    assert run_cmd("true || echo fail") == 0

def test_output_redirect(tmp_path):
    outfile = tmp_path / "out.txt"
    assert run_cmd(f"echo hello > {outfile}") == 0
    assert outfile.exists()
