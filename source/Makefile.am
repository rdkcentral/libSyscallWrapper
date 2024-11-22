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

if  WITH_GTEST_SUPPORT
SUBDIRS = test
endif

AM_CFLAGS=$(RDKLOGGER_CFLAGS) $(TRACE_CFLAGS) -std=c99

lib_LTLIBRARIES = libsecure_wrapper.la
libsecure_wrapper_la_SOURCES = secure_wrapper.c
libsecure_wrapper_la_LDFLAGS =$(TRACE_LIBS) $(RDKLOGGER_LIBS)

libsecure_wrapper_la_includedir = ${includedir}
libsecure_wrapper_la_include_HEADERS = secure_wrapper.h 

AM_LDFLAGS = $(GLIB_LDFLAGS) $(GLIB_LIBS) \
	$(G_THREAD_LIBS) -lrdkloggers $(LOG4C_LIBS) -lpthread -lcjson
