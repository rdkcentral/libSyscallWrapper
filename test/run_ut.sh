#!/bin/sh
#
#
cd ../

autoreconf --install

export top_srcdir=`pwd`

./configure --enable-gtestapp

make clean
make -C source/test

./source/test/syswrapper_gtest.bin

lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*gtest*' '*libsyswrapper*' --output-file coverage.info
lcov --list coverage.info
