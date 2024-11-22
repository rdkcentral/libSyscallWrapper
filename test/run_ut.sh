#!/bin/sh
#
#
cd ../

autoreconf --install

export top_srcdir=`pwd`

./configure --enable-gtestapp

make -C source/test

./source/test/syswrapper_gtest.bin

