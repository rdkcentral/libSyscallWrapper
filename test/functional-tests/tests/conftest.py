import os
import subprocess
import pytest

LIB_BINARY = os.environ.get("SYSWRAP_BIN", os.path.join(os.getcwd(), "syswrapper_l2_helper"))

def run_cmd(cmd):
    return subprocess.call(cmd, shell=True)

def popen_cmd(cmd):
    return subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
