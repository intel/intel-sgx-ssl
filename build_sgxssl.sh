#!/bin/bash

#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

# run "./build_sgxssl.sh no-clean" to leave the binaries in the package folder

# set -x # enable this for debugging this script

# this variable must be set to the path where sgx sdk is installed
SGX_SDK_PATH=/opt/intel/sgxsdk

# this variable must be set to the openssl file name (version) located in the openssl_source folder
OPENSSL_VERSION="openssl-1.1.0f"

# this variable must be set to the SGX SSL version
SVN_REVISION=`svn info | grep Revision | cut -d ' ' -f 2` || exit 1

if [ "$SVN_REVISION" == "" ] 
then
	SVN_REVISION=99999
fi 

SGXSDK_VERSION=`strings $SGX_SDK_PATH/lib64/libsgx_trts.a | grep VERSION | cut -c 18- | grep -o -E "^[1-9]\.[0-9]"`
SGXSSL_VERSION="$SGXSDK_VERSION.100.$SVN_REVISION"

#=========================================#
# Do not edit this script below this line #
#=========================================#

if [ -f $SGX_SDK_PATH/environment ]; then
	source $SGX_SDK_PATH/environment || exit 1
else
	echo "In order to run this script, Intel SGX SDK 1.7 must be installed on this machine, and SGX_SDK_PATH (in this script) must be set to the installation location"
	exit 1
fi

CONFNAME_HEADER=/usr/include/x86_64-linux-gnu/bits/confname.h

##Get OS_ID (Ubuntu/CentOS), and SDK integer number version (1.8 -> 18)
OS_NAME=`lsb_release -i | cut -d ":" -f 2 | xargs`
SGXSDK_INT_VERSION=`echo "${SGXSDK_VERSION//.}" `

OS_ID=1
if [ $OS_NAME == 'CentOS' ] 
then
	OS_ID=2
fi 

##Create required directories
mkdir -p package/lib64/release/
mkdir -p package/lib64/debug/
mkdir -p package/include/openssl/


SGXSSL_ROOT="`pwd`"
OPENSSL_INSTALL_DIR="$SGXSSL_ROOT/openssl_source/OpenSSL_install_dir_tmp"

cd $SGXSSL_ROOT/sgx/libsgx_tsgxssl || exit 1
sed -e "s|#define STRFILEVER \"1.0.0.0\"|#define STRFILEVER \"$SGXSSL_VERSION\"|" tsgxssl_version.cpp.in > tsgxssl_version.cpp

cd $SGXSSL_ROOT/sgx/libsgx_usgxssl || exit 1
sed -e "s|#define STRFILEVER \"1.0.0.0\"|#define STRFILEVER \"$SGXSSL_VERSION\"|" usgxssl_version.cpp.in > usgxssl_version.cpp

# build release modules
cd $SGXSSL_ROOT/openssl_source || exit 1
tar xvf $OPENSSL_VERSION.tar.gz || exit 1

cp rand_unix.c $OPENSSL_VERSION/crypto/rand/rand_unix.c || exit 1
cp md_rand.c $OPENSSL_VERSION/crypto/rand/md_rand.c || exit 1
cd $SGXSSL_ROOT/openssl_source/$OPENSSL_VERSION || exit 1
perl Configure linux-x86_64 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng  -D_FORTIFY_SOURCE=2 -DSGXSDK_INT_VERSION=$SGXSDK_INT_VERSION -DGETPID_IS_MEANINGLESS -include$SGXSSL_ROOT/openssl_source/bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR || exit 1
make build_generated libcrypto.a || exit 1
cp libcrypto.a $SGXSSL_ROOT/package/lib64/release/libsgx_tsgxssl_crypto.a || exit 1
cp include/openssl/* $SGXSSL_ROOT/package/include/openssl/ || exit 1
cd $SGXSSL_ROOT/openssl_source || exit 1
rm -rf $OPENSSL_VERSION || exit 1
cd $SGXSSL_ROOT/sgx || exit 1
make OS_ID=$OS_ID || exit 1 # will also copy the resulting files to package
./test_app/TestApp || exit 1 # verify everything is working ok
make clean || exit 1

# build debug modules
cd $SGXSSL_ROOT/openssl_source || exit 1
tar xvf $OPENSSL_VERSION.tar.gz || exit 1
#sed -i "s|my \$user_cflags=\"\"\;|my \$user_cflags=\"-include $SGXSSL_ROOT/openssl_source/bypass_to_sgxssl.h\"\;|" $OPENSSL_VERSION/Configure
cp rand_unix.c $OPENSSL_VERSION/crypto/rand/rand_unix.c || exit 1
cp md_rand.c $OPENSSL_VERSION/crypto/rand/md_rand.c || exit 1
cd $SGXSSL_ROOT/openssl_source/$OPENSSL_VERSION || exit 1
perl Configure linux-x86_64 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng  -D_FORTIFY_SOURCE=2 -DSGXSDK_INT_VERSION=$SGXSDK_INT_VERSION -DGETPID_IS_MEANINGLESS -DCONFNAME_HEADER=$CONFNAME_HEADER -include$SGXSSL_ROOT/openssl_source/bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR -g || exit 1
make build_generated libcrypto.a || exit 1
cp libcrypto.a $SGXSSL_ROOT/package/lib64/debug/libsgx_tsgxssl_crypto.a || exit 1

cd $SGXSSL_ROOT/openssl_source || exit 1
rm -rf $OPENSSL_VERSION || exit 1
cd $SGXSSL_ROOT/sgx || exit 1

make OS_ID=$OS_ID SGX_MODE=SIM SGX_DEBUG=1 || exit 1 # will also copy the resulting files to package
./test_app/TestApp || exit 1 # verify everything is working ok
make clean || exit 1

make OS_ID=$OS_ID SGX_DEBUG=1 || exit 1 # will also copy the resulting files to package
./test_app/TestApp || exit 1 # verify everything is working ok
make clean || exit 1



cd $SGXSSL_ROOT/package || exit 1

tar -zcvf ../sgxssl.$SGXSSL_VERSION.tar.gz * || exit 1

cd $SGXSSL_ROOT || exit 1

# generate list of tools used for creating this release
BUILD_TOOLS_FILENAME=sgxssl.$SGXSSL_VERSION.build-tools.txt
echo "SGX SDK version:" > $BUILD_TOOLS_FILENAME
echo $SGXSDK_VERSION >> $BUILD_TOOLS_FILENAME
echo "OpenSSL package version:" >> $BUILD_TOOLS_FILENAME
echo "$OPENSSL_VERSION" >> $BUILD_TOOLS_FILENAME
echo "SVN revision:" >> $BUILD_TOOLS_FILENAME
echo "$SVN_REVISION" >> $BUILD_TOOLS_FILENAME
echo "uname -a:" >> $BUILD_TOOLS_FILENAME
uname -a >> $BUILD_TOOLS_FILENAME
echo "cat /etc/*-release:" >> $BUILD_TOOLS_FILENAME
cat /etc/*-release >> $BUILD_TOOLS_FILENAME
echo "gcc --version:" >> $BUILD_TOOLS_FILENAME
gcc --version >> $BUILD_TOOLS_FILENAME
echo "g++ --version:" >> $BUILD_TOOLS_FILENAME
g++ --version >> $BUILD_TOOLS_FILENAME
echo "sed --version:" >> $BUILD_TOOLS_FILENAME
sed --version >> $BUILD_TOOLS_FILENAME
echo "perl --version:" >> $BUILD_TOOLS_FILENAME
perl --version >> $BUILD_TOOLS_FILENAME

if [[ $# -gt 0 && $1 == "no-clean" ]]; then
	cd $SGXSSL_ROOT || exit 1
	exit 0
fi

cd $SGXSSL_ROOT/sgx/libsgx_tsgxssl || exit 1
rm -f tsgxssl_version.cpp

cd $SGXSSL_ROOT/sgx/libsgx_usgxssl || exit 1
rm -f usgxssl_version.cpp

cd $SGXSSL_ROOT/package || exit 1
rm -f include/openssl/*
rm -f lib64/release/*
rm -f lib64/debug/*

cd $SGXSSL_ROOT || exit 1

exit 0

