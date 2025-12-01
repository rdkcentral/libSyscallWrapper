#!/bin/sh

echo "===== libSyscallWrapper L2 runner ====="

export top_srcdir=$(pwd | sed 's#/test##')
RESULT_DIR="/tmp/libsyswrapper_l2_report"
mkdir -p "$RESULT_DIR"

echo "top_srcdir = $top_srcdir"
echo "RESULT_DIR = $RESULT_DIR"

###############################################################################
# Step 1: Build library
###############################################################################
echo "===== Building libsecure_wrapper ====="
cd "$top_srcdir"

autoreconf --install
./configure
make clean
make

###############################################################################
# Step 2: Build L2 helper binary
###############################################################################
echo "===== Building L2 helper binary ====="
cd test/functional-tests/tests
make clean
make

###############################################################################
# Step 3: Run pytest
###############################################################################
echo "===== Running L2 pytest tests ====="
cd ..
pytest --json-report --json-report-file "$RESULT_DIR/libsyswrapper_l2_report.json" tests/

echo "===== L2 execution completed ====="
echo "Results at: $RESULT_DIR/libsyswrapper_l2_report.json"
