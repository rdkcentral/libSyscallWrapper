import os
import subprocess
import pytest

LIB_BINARY = os.environ.get("SYSWRAP_BIN")
if not LIB_BINARY:
    raise RuntimeError("SYSWRAP_BIN is not set!")

def run_cmd_list(args):
    return subprocess.call(args)

def popen_cmd_list(args):
    return subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
