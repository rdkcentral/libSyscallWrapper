#!/bin/sh
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
#
PWD=`pwd`
export RDK_DIR=`echo $PWD/..`
source build/build_env.sh


copyLibs=0
instalLibs=0
setupSDK=0
buildMode="build"
instaldir=build

for option in $@
do
  echo option = $option
  if [ "$option" = "clean" ]; then
    buildMode="clean"
  elif [ "$option" = "install" -o  "$option" = "instal" ] ; then
    instalLibs=1
  elif [ "$option" = "copy"  ] ; then
    copyLibs=1
  elif [ "$option" = "setup" ] ; then
    setupSDK=1
 fi


done

if [ $setupSDK -eq 1 ];
then
  echo $PLATFORM_SDK
  if [ -d "$PLATFORM_SDK" ]
  then
	  echo "toolchain is already installed..."
  else
	  echo Installing toolchain, it may take few seconds depends on your system
	  tar zxf $RDK_DIR/sdk/toolchain/staging_dir.tgz -C $RDK_DIR/sdk/toolchain
	  echo "toolchain installed $PLATFORM_SDK"
  fi

  echo $ROOTFS
  if [ -d "$ROOTFS" ]
  then
	  echo "ROOT FS is already extracted..."
  else
	  echo extracting ROOT FS, it may take few seconds depends on your system
	  sudo tar zxf $RDK_DIR/sdk/fsroot/fsroot.tgz -C $RDK_DIR/sdk/fsroot
	  sudo tar zxf $RDK_DIR/sdk/fsroot/curl.tgz -C $RDK_DIR/sdk/fsroot
	  sudo tar zxf $RDK_DIR/sdk/fsroot/mafLib.tgz -C $RDK_DIR/sdk/fsroot
	  echo "ROOT FS is extracted $ROOTFS"
  fi

fi

if [ "$buildMode" = "clean" ];
then
  echo "Cleaning the build and $instaldir"
  make clean
fi

if [ $copyLibs -ne 1 ] ;
then
  echo =========================================================================================================================================================
  echo --------------------------BUILDING LIBSYSWRAPPER ---------------------------------
  echo =========================================================================================================================================================
  make
  if [ $? -ne 0 ] ;
  then
      echo LIBSYSWRAPPER build failed 
      exit -1
  fi
  echo ========================================================================================================================================================
  echo --------------------------BUILDING LIBSYSWRAPPER DONE ---------------------------------
  echo ========================================================================================================================================================
fi

if [ $instalLibs -eq 1 ];
then
  echo installing binaries....
  mkdir -p $instaldir/env
  mkdir -p $ROOTFS/mnt/nfs/env
  mkdir -p $ROOTFS/mnt/nfs/lib

  cp -a $instaldir/env/* $ROOTFS/mnt/nfs/env
  mkdir -p $ROOTFS/usr/lib
  cp -a $instaldir/lib/* $ROOTFS/usr/lib
fi
