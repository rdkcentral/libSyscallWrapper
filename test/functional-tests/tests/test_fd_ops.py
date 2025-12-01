from conftest import run_cmd
import os

def test_open_and_close_redirect(tmp_path):
    outfile = tmp_path / "fdops.txt"
    ret = run_cmd(f"echo fdops > {outfile}")
    assert ret == 0
    assert outfile.exists()

def test_dup2_failure_safe():
    # dup2 failure internally must not crash
    ret = run_cmd("echo hello 1>&-")
    assert ret == 0 or ret != -11  
