#!/bin/bash

#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

# set -x # enable this for debugging this script

# this variable must be set to the path where Intel® Software Guard Extensions SDK is installed
SGXSSL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $SGXSSL_ROOT

OPENSSL_INSTALL_DIR="$SGXSSL_ROOT/../openssl_source/OpenSSL_install_dir_tmp"
OPENSSL_VERSION=`/bin/ls $SGXSSL_ROOT/../openssl_source/*1.1.1*.tar.gz | /usr/bin/head -1 | /bin/grep -o '[^/]*$' | /bin/sed -s -- 's/\.tar\.gz//'`
if [ "$OPENSSL_VERSION" == "" ] 
then
	echo "In order to run this script, OpenSSL tar.gz package must be located in openssl_source/ directory."
	exit 1
fi
echo $OPENSSL_VERSION

#Create required directories
mkdir -p $SGXSSL_ROOT/package/include/openssl/
mkdir -p $SGXSSL_ROOT/package/include/crypto/
mkdir -p $SGXSSL_ROOT/package/lib64/


# build openssl modules, clean previous openssl dir if it exist
cd $SGXSSL_ROOT/../openssl_source || exit 1
rm -rf $OPENSSL_VERSION
tar xvf $OPENSSL_VERSION.tar.gz || exit 1

# Remove AESBS to support only AESNI and VPAES
sed -i '/BSAES_ASM/d' $OPENSSL_VERSION/Configure

##Space optimization flags.
SPACE_OPT=
if [[ $# -gt 0 ]] && [[ $1 == "space-opt" || $2 == "space-opt" || $3 == "space-opt" || $4 == "space-opt" ]] ; then
SPACE_OPT="-fno-tree-vectorize no-autoalginit -fno-asynchronous-unwind-tables no-cms no-dsa -DOPENSSL_assert=  no-filenames no-rdrand -DOPENSSL_SMALL_FOOTPRINT no-err -fdata-sections -ffunction-sections -Os -Wl,--gc-sections"
sed -i "/# define OPENSSL_assert/d" $OPENSSL_VERSION/include/openssl/crypto.h
sed -i '/OPENSSL_die("assertion failed/d' $OPENSSL_VERSION/include/openssl/crypto.h
fi

OUTPUT_LIB=libsgx_tsgxssl_crypto.a
if [[ $# -gt 0 ]] && [[ $1 == "debug" || $2 == "debug" || $3 == "debug" || $4 == "debug" ]] ; then
	OUTPUT_LIB=libsgx_tsgxssl_cryptod.a
    ADDITIONAL_CONF="-g "
fi

# Mitigation flags
MITIGATION_OPT=""
MITIGATION_FLAGS=""
CC_VERSION=`gcc -dumpversion`
for arg in "$@"
do
    case $arg in
    LOAD)
        MITIGATION_OPT="$arg"
        shift
        ;;
    CF)
        MITIGATION_OPT="$arg"
        shift
        ;;
    -mindirect-branch=thunk-extern)
        MITIGATION_FLAGS+=" $arg"
        shift
        ;;
    -mfunction-return=thunk-extern)
        MITIGATION_FLAGS+=" $arg"
        if [[ $CC_VERSION -ge 8 ]] ; then
            MITIGATION_FLAGS+=" -fcf-protection=none"
        fi
        shift
        ;;
    -Wa,-mlfence-before-indirect-branch=all)
        MITIGATION_FLAGS+=" $arg"
        shift
        ;;
    -Wa,-mlfence-before-indirect-branch=memory)
        MITIGATION_FLAGS+=" $arg"
        shift
        ;;
    -Wa,-mlfence-before-ret=shl)
        MITIGATION_FLAGS+=" $arg"
        shift
        ;;
    -Wa,-mlfence-after-load=yes)
        MITIGATION_FLAGS+=" $arg"
        shift
        ;;
    *)
        # Unknown option
        shift
        ;;
    esac
done
echo $MITIGATION_OPT
echo $MITIGATION_FLAGS
echo $SPACE_OPT 

sed -i -- 's/OPENSSL_issetugid/OPENSSLd_issetugid/g' $OPENSSL_VERSION/crypto/uid.c || exit 1
cp rand_lib.c $OPENSSL_VERSION/crypto/rand/rand_lib.c || exit 1
cp sgx_config.conf $OPENSSL_VERSION/ || exit 1
cp x86_64-xlate.pl $OPENSSL_VERSION/crypto/perlasm/ || exit 1

cd $SGXSSL_ROOT/../openssl_source/$OPENSSL_VERSION || exit 1
perl Configure --config=sgx_config.conf sgx-linux-x86_64 --with-rand-seed=none $ADDITIONAL_CONF $SPACE_OPT $MITIGATION_FLAGS no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng -D_FORTIFY_SOURCE=2 -DGETPID_IS_MEANINGLESS -include$SGXSSL_ROOT/../openssl_source/bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR || exit 1

make build_all_generated || exit 1

if [[ "$MITIGATION_OPT" == "LOAD" ]]
then
    cp $SGXSSL_ROOT/../openssl_source/Linux/aesni-x86_64.s      ./crypto/aes/aesni-x86_64.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/keccak1600-x86_64.s ./crypto/sha/keccak1600-x86_64.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/rsaz-avx2.s         ./crypto/bn/rsaz-avx2.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/rsaz-x86_64.s       ./crypto/bn/rsaz-x86_64.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/x86_64-mont.s       ./crypto/bn/x86_64-mont.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/x86_64-mont5.s      ./crypto/bn/x86_64-mont5.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/vpaes-x86_64.s      ./crypto/aes/vpaes-x86_64.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/x86_64cpuid.s       ./crypto/x86_64cpuid.s
fi
if [[ "$MITIGATION_OPT" == "CF" ]]
then
    cp $SGXSSL_ROOT/../openssl_source/Linux/aesni-x86_64.s      ./crypto/aes/aesni-x86_64.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/vpaes-x86_64.s      ./crypto/aes/vpaes-x86_64.s
    cp $SGXSSL_ROOT/../openssl_source/Linux/x86_64cpuid.s       ./crypto/x86_64cpuid.s
fi

make libcrypto.a || exit 1
cp libcrypto.a $SGXSSL_ROOT/package/lib64/$OUTPUT_LIB || exit 1
objcopy --rename-section .init=Q6A8dc14f40efc4288a03b32cba4e $SGXSSL_ROOT/package/lib64/$OUTPUT_LIB || exit 1
cp include/openssl/* $SGXSSL_ROOT/package/include/openssl/ || exit 1
cp include/crypto/* $SGXSSL_ROOT/package/include/crypto/ || exit 1
exit 0
