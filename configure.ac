##########################################################################
# If not stated otherwise in this file or this component's LICENSE 
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
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
AC_PREREQ([2.65])
AC_INIT([libsyswrapper], [1.0], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([source])
AM_CONFIG_HEADER(m4/config.h)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([m4])
AM_INIT_AUTOMAKE([foreign no-dist-gzip dist-bzip2 1.9])
LT_INIT

#gtest check for libsyswrapper
GTEST_ENABLE_FLAG = ""

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

# dnl Checks for programs.
AC_PROG_CXX

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CPP
AC_PROG_CXXCPP

# dnl use pretty build output with automake >= 1.11
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
  [AM_DEFAULT_VERBOSITY=1
   AC_SUBST(AM_DEFAULT_VERBOSITY)])

TRACE_CFLAGS=" "
TRACE_LIBS=" "

RDKLOGGER_CFLAGS=" "
RDKLOGGER_LIBS=" "

AC_HEADER_STDC

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# dnl Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strerror])

# dnl Checks for typedefs, structures, and compiler characteristics.
# dnl AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT8_T

AC_ARG_ENABLE([ccsptrace],
              AS_HELP_STRING([--enable-ccsptrace],[enable ccsp based tracing (default is no)]),
              [
                case "${enableval}" in
                 yes) TRACE_CFLAGS="-DCCSP_TRACE -I=${includedir}/ccsp"
                      TRACE_LIBS="-lccsp_common";;
                 no) echo[videouploader library & binary support is disabled];;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dtcpdec]) ;;
                esac
              ],
              [echo "ccsp based tracing is disabled"])

#check for test program

AC_ARG_ENABLE([testapp],
              AS_HELP_STRING([--enable-testapp],[enable testing application of secure wrapper (default is no)]),
              [
                case "${enableval}" in
                 yes) ENABLE_TEST_APP=true;;
                 no) ENABLE_TEST_APP="",	echo[testing app is disabled];;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-testapp]) ;;
                esac
              ],
              [echo "test application is disabled by default"])

AM_CONDITIONAL([ENABLE_TEST_APP], [test x$ENABLE_TEST_APP = xtrue])

AC_ARG_ENABLE([gtestapp],
              AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
              [
                case "${enableval}" in
                 yes) GTEST_SUPPORT_ENABLED=true
                      GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                      m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
                  no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
                   *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]) ;;
                esac
              ],
              [echo "Gtestapp is disabled"])

AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])

AC_ARG_WITH([rdklogger],
            AS_HELP_STRING([--without-rdklogger], [Compile without librdklogger]))

AS_IF([test "x$with_rdklogger" != "xno"],
      [
       RDKLOGGER_CFLAGS="-DWITH_RDKLOGGER"
       RDKLOGGER_LIBS="-lrdkloggers"
      ])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_SUBST(TRACE_CFLAGS)
AC_SUBST(TRACE_LIBS)
AC_SUBST(RDKLOGGER_CFLAGS)
AC_SUBST(RDKLOGGER_LIBS)
AC_CONFIG_FILES([
    source/Makefile
      Makefile
    testapp/Makefile
    ])
AC_SUBST(GTEST_ENABLE_FLAG)
AC_OUTPUT


