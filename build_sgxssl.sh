#!/bin/bash

# run "./build_sgxssl.sh no-clean" to leave the binaries in the package folder

# set -x # enable this for debugging this script

# this variable must be set to the path where sgx sdk is installed
SGX_SDK_PATH=/opt/intel/sgxsdk

# this variable must be set to the openssl file name (version) located in the openssl_source folder
OPENSSL_VERSION="openssl-1.1.0e"

# this variable must be set to the SGX SSL version
SVN_REVISION=`svn info | grep Revision | cut -d ' ' -f 2` || exit 1
SGXSSL_VERSION="1.8.100.$SVN_REVISION"

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

##Get OS_ID (Ubuntu/CentOS)
OS_NAME=`lsb_release -i | cut -d ":" -f 2 | xargs`
OS_ID=1
if [ $OS_NAME == 'CentOS' ] 
then
	OS_ID=2
fi 

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
perl Configure linux-x86_64 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng  -D_FORTIFY_SOURCE=2 -DGETPID_IS_MEANINGLESS -include$SGXSSL_ROOT/openssl_source/bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR || exit 1
make build_generated libcrypto.a -j || exit 1
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
perl Configure linux-x86_64 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng  -D_FORTIFY_SOURCE=2 -DGETPID_IS_MEANINGLESS -DCONFNAME_HEADER=$CONFNAME_HEADER -include$SGXSSL_ROOT/openssl_source/bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR -g || exit 1
make build_generated libcrypto.a -j || exit 1
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
strings $SGX_SDK_PATH/lib64/libsgx_trts.a | grep VERSION | cut -c 18- >> $BUILD_TOOLS_FILENAME
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

