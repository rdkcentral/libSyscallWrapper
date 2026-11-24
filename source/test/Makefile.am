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

syswrapper_gtest_bin_CPPFLAGS += -D_GNU_SOURCE=1 -D_LARGEFILE64_SOURCE=1 -include $(top_srcdir)/source/syscall_restriction.h

syswrapper_gtest_bin_SOURCES = gtest_main.cpp  libsyswrapper_test.cpp ../secure_wrapper.c

syswrapper_gtest_bin_LDFLAGS = -L/$(PKG_CONFIG_SYSROOT_DIR)/googletest/lib  -lgmock -lgtest -lpthread -lgcov -lgtest_main

EXTRA_DIST = test_system_forbidden.c \
    test_popen_forbidden.c \
    test_secure_wrapper_allowed.c

check-local:
	@set -eu; \
    tmpdir=.syscall-restriction-check; \
    mkdir -p "$$tmpdir"; \
    trap 'rm -rf "$$tmpdir"' 0 1 2 3 15; \
    check_forbidden() { \
        source_file="$$1"; expected="$$2"; \
        if $(CC) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) \
            $(CFLAGS) $(AM_CFLAGS) -I$(top_srcdir)/source \
            -include $(top_srcdir)/source/syscall_restriction.h \
            -c "$$source_file" -o "$$tmpdir/check.o" \
            >"$$tmpdir/output.log" 2>&1; then \
            echo "ERROR: $$source_file compiled but should have failed"; \
            return 1; \
        fi; \
        if ! grep -F "$$expected" "$$tmpdir/output.log" >/dev/null; then \
            echo "ERROR: $$source_file failed for the wrong reason"; \
            cat "$$tmpdir/output.log"; \
            return 1; \
        fi; \
        echo "PASS: $$source_file rejected as expected"; \
    }; \
    check_forbidden "$(srcdir)/test_system_forbidden.c" \
        "Direct system() calls are forbidden"; \
    check_forbidden "$(srcdir)/test_popen_forbidden.c" \
        "Direct popen() calls are forbidden"; \
    if ! $(CC) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) \
        $(CFLAGS) $(AM_CFLAGS) -I$(top_srcdir)/source \
        -include $(top_srcdir)/source/syscall_restriction.h \
        -c "$(srcdir)/test_secure_wrapper_allowed.c" \
        -o "$$tmpdir/check.o" >"$$tmpdir/output.log" 2>&1; then \
        echo "ERROR: wrapper API fixture should compile"; \
        cat "$$tmpdir/output.log"; \
        exit 1; \
    fi; \
    echo "PASS: wrapper API fixture compiled"
