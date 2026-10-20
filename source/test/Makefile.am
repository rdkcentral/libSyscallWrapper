##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
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
##########################################################################
AM_CXXFLAGS = -std=c++14 -DGTEST_ENABLE

AM_CFLAGS = -DGTEST_ENABLE

AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = syswrapper_gtest.bin

syswrapper_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)/googletest/include/gtest -I$(PKG_CONFIG_SYSROOT_DIR)/googletest/include/ -I$(PKG_CONFIG_SYSROOT_DIR)/googletest/googletest/include -I$(PKG_CONFIG_SYSROOT_DIR)/googletest/googlemock/include/ -I${top_srcdir}/source -I${top_srcdir}/source/include

syswrapper_gtest_bin_SOURCES = gtest_main.cpp  libsyswrapper_test.cpp ../secure_wrapper.c

syswrapper_gtest_bin_LDFLAGS = -L/$(PKG_CONFIG_SYSROOT_DIR)/googletest/lib  -lgmock -lgtest -lpthread -lgcov -lgtest_main

# Compile-time enforcement test for raw system()/popen()
.PHONY: check_syscall_restriction

check_syscall_restriction:
	@echo "Checking that system() and popen() are rejected..."
	@if $(CC) $(AM_CFLAGS) $(CFLAGS) \
	    -include ${top_srcdir}/source/syscall_restriction.h \
	    -I${top_srcdir}/source \
	    -c ${srcdir}/test_syscall_restriction.c \
	    -o test_syscall_restriction.o >/dev/null 2>&1; then \
	    echo "ERROR: system()/popen() were not rejected"; \
	    rm -f test_syscall_restriction.o; \
	    exit 1; \
	else \
	    echo "PASS: system()/popen() were rejected"; \
	fi

# Compile-time validation that secure wrapper APIs remain allowed
.PHONY: check_secure_wrapper_allowed

check_secure_wrapper_allowed:
	@echo "Checking that secure wrapper APIs are allowed..."
	@$(CC) $(AM_CFLAGS) $(CFLAGS) \
	    -include ${top_srcdir}/source/syscall_restriction.h \
	    -I${top_srcdir}/source \
	    -c ${srcdir}/test_secure_wrapper_allowed.c \
	    -o test_secure_wrapper_allowed.o
	@rm -f test_secure_wrapper_allowed.o
	@echo "PASS: secure wrapper APIs are allowed"
