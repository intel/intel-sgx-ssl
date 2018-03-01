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

function clean_and_ret {
	ret_status=$1
	if [ $ret_status == 1 ] 
	then
		echo "******************************************************************************"
		echo "**                                                                          **"
		echo "**                Build package failed, cleaning environment                **"
		echo "**                                                                          **"
		echo "******************************************************************************"
	fi
	cd $SGXSSL_ROOT/sgx/
	make clean

	cd $SGXSSL_ROOT/sgx/libsgx_tsgxssl
	rm -f tsgxssl_version.cpp

	cd $SGXSSL_ROOT/sgx/libsgx_usgxssl
	rm -f usgxssl_version.cpp

	cd $SGXSSL_ROOT/package
	rm -rf include/openssl/*
	rm -rf lib64/release/*
	rm -rf lib64/debug/*

	cd $SGXSSL_ROOT

	exit $ret_status

}

# run "./build_sgxssl.sh no-clean" to leave the binaries in the package folder
# run "./build_sgxssl.sh linux-sgx" to build in linux-sgx repository enviroment

# set -x # enable this for debugging this script

# this variable must be set to the path where Intel® Software Guard Extensions SDK is installed
SGXSSL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $SGXSSL_ROOT
if [[ $# -gt 0 ]] && [[ $1 == "linux-sgx" || $2 == "linux-sgx" ]] ; then
	LINUX_BUILD_FLAG=LINUX_SGX_BUILD=1
	SGXSDK_VERSION=`/bin/grep -m 1 "STRFILEVER" $SGXSSL_ROOT/../../../common/inc/internal/se_version.h | /bin/grep -o -E "[1-9]\.[0-9]" | /usr/bin/head -n 1`
	SGX_SDK_LIBS_PATH=$SGXSSL_ROOT/../../../build/linux
else
	LINUX_BUILD_FLAG=LINUX_SGX_BUILD=0
	SGX_SDK=/opt/intel/sgxsdk
	SGXSDK_VERSION=`pkg-config --modversion $SGX_SDK/pkgconfig/libsgx_urts.pc | /usr/bin/cut -d "." -f 1-2`
	if [ -f $SGX_SDK/environment ]; then
		source $SGX_SDK/environment || clean_and_ret 1
	else
		echo "In order to run this script, Intel® Software Guard Extensions SDK 1.7 must be installed on this machine, and SGX_SDK (in this script) must be set to the installation location"
		clean_and_ret 1
	fi
fi

#=========================================#
# Do not edit this script below this line #
#=========================================#

SGXSSL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $SGXSSL_ROOT
OPENSSL_INSTALL_DIR="$SGXSSL_ROOT/../openssl_source/OpenSSL_install_dir_tmp"
OPENSSL_VERSION=`/bin/ls $SGXSSL_ROOT/../openssl_source/*.tar.gz | /usr/bin/head -1 | /bin/grep -o '[^/]*$' | /bin/sed -s -- 's/\.tar\.gz//'`
if [ "$OPENSSL_VERSION" == "" ] 
then
	echo "In order to run this script, OpenSSL tar.gz package must be located in openssl_source/ directory."
	clean_and_ret 1
fi
echo $OPENSSL_VERSION
# this variable must be set to the Intel® Software Guard Extensions SSL version
SVN_REVISION=`svn info | grep Revision | cut -d ' ' -f 2` || clean_and_ret 1

if [ "$SVN_REVISION" == "" ] 
then
	SVN_REVISION=99999
fi 

SGXSSL_VERSION="$SGXSDK_VERSION.100.$SVN_REVISION"



CONFNAME_HEADER=/usr/include/x86_64-linux-gnu/bits/confname.h

##Get OS_ID (Ubuntu/CentOS), and SDK integer number version (1.8 -> 18)
SGXSDK_INT_VERSION=`/bin/echo "${SGXSDK_VERSION//.}" `

OS_ID=1
if [ -f "/usr/include/x86_64-linux-gnu/bits/confname.h" ]
then
	OS_ID=1
elif [ -f "/usr/include/bits/confname.h" ]
then
	OS_ID=2
else
	echo "WARNING: Can't get OS_ID"
fi


##Create required directories
mkdir -p $SGXSSL_ROOT/package/lib64/release/
mkdir -p $SGXSSL_ROOT/package/lib64/debug/
mkdir -p $SGXSSL_ROOT/package/include/openssl/

cd $SGXSSL_ROOT/sgx/libsgx_tsgxssl || clean_and_ret 1
sed -e "s|#define STRFILEVER \"1.0.0.0\"|#define STRFILEVER \"$SGXSSL_VERSION\"|" tsgxssl_version.cpp.in > tsgxssl_version.cpp

cd $SGXSSL_ROOT/sgx/libsgx_usgxssl || clean_and_ret 1
sed -e "s|#define STRFILEVER \"1.0.0.0\"|#define STRFILEVER \"$SGXSSL_VERSION\"|" usgxssl_version.cpp.in > usgxssl_version.cpp

# build release modules
cd $SGXSSL_ROOT/../openssl_source || clean_and_ret 1
tar xvf $OPENSSL_VERSION.tar.gz || clean_and_ret 1

# Intel® Software Guard Extensions SSL uses rd_rand, so there is no need to get a random based on time
sed -i "s|time_t tim;||g" $OPENSSL_VERSION/crypto/bn/bn_rand.c
sed -i "s|time(&tim);||g" $OPENSSL_VERSION/crypto/bn/bn_rand.c
sed -i "s|RAND_add(&tim, sizeof(tim), 0.0);||g" $OPENSSL_VERSION/crypto/bn/bn_rand.c

# Remove AESBS to support only AESNI and VPAES
sed -i '/BSAES_ASM/d' $OPENSSL_VERSION/Configure

cp rand_unix.c $OPENSSL_VERSION/crypto/rand/rand_unix.c || clean_and_ret 1
cp rand_lib.c $OPENSSL_VERSION/crypto/rand/rand_lib.c || clean_and_ret 1
cp md_rand.c $OPENSSL_VERSION/crypto/rand/md_rand.c || clean_and_ret 1
cd $SGXSSL_ROOT/../openssl_source/$OPENSSL_VERSION || clean_and_ret 1
perl Configure linux-x86_64 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng  -D_FORTIFY_SOURCE=2 -DSGXSDK_INT_VERSION=$SGXSDK_INT_VERSION -DGETPID_IS_MEANINGLESS -include$SGXSSL_ROOT/../openssl_source/bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR || clean_and_ret 1
make build_generated libcrypto.a || clean_and_ret 1
cp libcrypto.a $SGXSSL_ROOT/package/lib64/release/libsgx_tsgxssl_crypto.a || clean_and_ret 1
objcopy --remove-section .init $SGXSSL_ROOT/package/lib64/release/libsgx_tsgxssl_crypto.a || clean_and_ret 1
cp include/openssl/* $SGXSSL_ROOT/package/include/openssl/ || clean_and_ret 1
cd $SGXSSL_ROOT/../openssl_source || clean_and_ret 1
rm -rf $OPENSSL_VERSION || clean_and_ret 1
cd $SGXSSL_ROOT/sgx || clean_and_ret 1

make OS_ID=$OS_ID SGXSDK_INT_VERSION=$SGXSDK_INT_VERSION $LINUX_BUILD_FLAG || clean_and_ret 1 # will also copy the resulting files to package
if [[ $1 != "linux-sgx" && $2 != "linux-sgx" ]] ; then
	./test_app/TestApp || clean_and_ret 1 # verify everything is working ok
fi
make clean || clean_and_ret 1


# build debug modules
cd $SGXSSL_ROOT/../openssl_source || clean_and_ret 1
tar xvf $OPENSSL_VERSION.tar.gz || clean_and_ret 1

# Intel® Software Guard Extensions SSL uses rd_rand, so there is no need to get a random based on time
sed -i "s|time_t tim;||g" $OPENSSL_VERSION/crypto/bn/bn_rand.c
sed -i "s|time(&tim);||g" $OPENSSL_VERSION/crypto/bn/bn_rand.c
sed -i "s|RAND_add(&tim, sizeof(tim), 0.0);||g" $OPENSSL_VERSION/crypto/bn/bn_rand.c

# Remove AESBS to support only AESNI and VPAES
sed -i '/BSAES_ASM/d' $OPENSSL_VERSION/Configure

#sed -i "s|my \$user_cflags=\"\"\;|my \$user_cflags=\"-include $SGXSSL_ROOT/../openssl_source/bypass_to_sgxssl.h\"\;|" $OPENSSL_VERSION/Configure
cp rand_unix.c $OPENSSL_VERSION/crypto/rand/rand_unix.c || clean_and_ret 1
cp rand_lib.c $OPENSSL_VERSION/crypto/rand/rand_lib.c || clean_and_ret 1
cp md_rand.c $OPENSSL_VERSION/crypto/rand/md_rand.c || clean_and_ret 1
cd $SGXSSL_ROOT/../openssl_source/$OPENSSL_VERSION || clean_and_ret 1
perl Configure linux-x86_64 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng  -D_FORTIFY_SOURCE=2 -DSGXSDK_INT_VERSION=$SGXSDK_INT_VERSION -DGETPID_IS_MEANINGLESS -DCONFNAME_HEADER=$CONFNAME_HEADER -include$SGXSSL_ROOT/../openssl_source/bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR -g || clean_and_ret 1
make build_generated libcrypto.a || clean_and_ret 1
cp libcrypto.a $SGXSSL_ROOT/package/lib64/debug/libsgx_tsgxssl_crypto.a || clean_and_ret 1
objcopy --rename-section .init=Q6A8dc14f40efc4288a03b32cba4e $SGXSSL_ROOT/package/lib64/debug/libsgx_tsgxssl_crypto.a || clean_and_ret 1

cd $SGXSSL_ROOT/../openssl_source || clean_and_ret 1
rm -rf $OPENSSL_VERSION || clean_and_ret 1
cd $SGXSSL_ROOT/sgx || clean_and_ret 1

make OS_ID=$OS_ID SGXSDK_INT_VERSION=$SGXSDK_INT_VERSION SGX_MODE=SIM DEBUG=1 $LINUX_BUILD_FLAG || clean_and_ret 1 # will also copy the resulting files to package
if [[ $1 != "linux-sgx" && $2 != "linux-sgx" ]] ; then
	./test_app/TestApp || clean_and_ret 1 # verify everything is working ok
fi
make clean || clean_and_ret 1

make OS_ID=$OS_ID SGXSDK_INT_VERSION=$SGXSDK_INT_VERSION DEBUG=1 $LINUX_BUILD_FLAG || clean_and_ret 1 # will also copy the resulting files to package
if [[ $1 != "linux-sgx" && $2 != "linux-sgx" ]] ; then
	./test_app/TestApp || clean_and_ret 1 # verify everything is working ok
fi
make clean || clean_and_ret 1




cd $SGXSSL_ROOT/package || clean_and_ret 1

tar -zcvf ../sgxssl.$SGXSSL_VERSION.tar.gz * || clean_and_ret 1

cd $SGXSSL_ROOT || clean_and_ret 1

# generate list of tools used for creating this release
BUILD_TOOLS_FILENAME=sgxssl.$SGXSSL_VERSION.build-tools.txt
echo "Intel® Software Guard Extensions SDK version:" > $BUILD_TOOLS_FILENAME
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

if [[ $# -gt 0 ]] && [[ $1 == "no-clean" || $2 == "no-clean" ]] ; then
	cd $SGXSSL_ROOT || exit 1
	exit 0
fi

clean_and_ret 0


