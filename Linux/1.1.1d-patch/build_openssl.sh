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

# set -vx # enable this for debugging this script
# set -x # enable this for debugging this script

# trap read debug

OPENSSL_INSTALL_DIR="$(pwd)"
OPENSSL_INSTALL_DIR+="/OpenSSL_install_dir_tmp"
echo $OPENSSL_INSTALL_DIR

# Mitigation flags
MITIGATIONS_FLAGS=""
for arg in "$@"
do
    case $arg in
    -mindirect-branch=thunk-extern)
        MITIGATIONS_FLAGS+=" $arg"
        shift
        ;;
    -mfunction-return=thunk-extern)
        MITIGATIONS_FLAGS+=" $arg"
        shift
        ;;
    -Wa,-mlfence-before-indirect-branch=register)
        MITIGATIONS_FLAGS+=" $arg"
        shift
        ;;
    -Wa,-mlfence-before-ret=not)
        MITIGATIONS_FLAGS+=" $arg"
        shift
        ;;
    -Wa,-mlfence-after-load=yes)
        MITIGATIONS_FLAGS+=" $arg"
        shift
        ;;
    indirects)
        MITIGATIONS_FLAGS+=" -mfunction-return=thunk-extern -mindirect-branch-register -Wa,-mlfence-before-indirect-branch=register -Wa,-mlfence-before-ret=not"
        shift
        ;;
    full)
        MITIGATIONS_FLAGS+=" -mfunction-return=thunk-extern -mindirect-branch-register -Wa,-mlfence-after-load=yes -Wa,-mlfence-before-ret=not"
        shift
        ;;
    *)
        # Unknown option
        shift
        ;;
    esac
done
echo $MITIGATIONS_FLAGS

perl Configure --config=sgx_config.conf sgx-linux-x86_64 --with-rand-seed=none $ADDITIONAL_CONF $SPACE_OPT -DMITIGATION_FLAGS_START $MITIGATIONS_FLAGS -DMITIGATION_FLAGS_STOP no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ssl3 no-md2 no-md4 no-ui no-stdio no-afalgeng -D_FORTIFY_SOURCE=2 -DGETPID_IS_MEANINGLESS -include./bypass_to_sgxssl.h --prefix=$OPENSSL_INSTALL_DIR || exit 1

make build_generated libcrypto.a || exit 1
exit 0

