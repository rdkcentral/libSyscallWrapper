#!/bin/sh

# Copyright 2023 Comcast Cable Communications Management, LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#

cd ../

autoreconf --install

export top_srcdir=`pwd`

echo "Enabling coverage options"
export CXXFLAGS="-g -O0 -fprofile-arcs -ftest-coverage"
export CFLAGS="-g -O0 -fprofile-arcs -ftest-coverage"
export LDFLAGS="-lgcov --coverage"

./configure --enable-gtestapp

make clean
make -C source/test

./source/test/syswrapper_gtest.bin

lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*gtest*' '*libsyswrapper*' --output-file coverage.info
lcov --list coverage.info
genhtml coverage.info --output-directory out
