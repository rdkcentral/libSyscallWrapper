#!/bin/bash
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2016 RDK Management
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

#SETTING TOOLCHAIN AND RAMDISK PATH
export PLATFORM_SDK=${RDK_DIR}/sdk/toolchain/arm-linux-gnueabihf
export RDK_TOOLCHAIN_PATH=$RDK_PROJECT_ROOT_PATH/sdk/toolchain/arm-linux-gnueabihf
export ROOTFS=${RDK_DIR}/sdk/fsroot/ramdisk
export RDK_FSROOT_PATH=$RDK_PROJECT_ROOT_PATH/sdk/fsroot/ramdisk
#SETTING CROSS COMPILER
export CROSS_COMPILE=${PLATFORM_SDK}/bin/arm-linux-gnueabihf-
export CC=${CROSS_COMPILE}gcc
export CXX=${CROSS_COMPILE}g++
export DEFAULT_HOST=arm-linux
export PKG_CONFIG_PATH="$RDK_PROJECT_ROOT_PATH/opensource/lib/pkgconfig/:$RDK_FSROOT_PATH/img/fs/shadow_root/usr/local/lib/pkgconfig/:$RDK_TOOLCHAIN_PATH/lib/pkgconfig/:$PKG_CONFIG_PATH"
