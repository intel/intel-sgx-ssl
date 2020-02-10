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
include buildenv.mk
LINUX_SGX_BUILD ?= 0

.PHONY: all clean test

BUILD_OPENSSL := ../build_openssl.sh

ifeq ($(SPACE_OPT), 1)
	OPENSSL_CONFIG += space-opt
endif

ifeq ($(DEBUG), 1)
	OPENSSL_CONFIG += debug
endif

all: $(PACKAGE_LIB)/$(OPENSSL_LIB)
	$(MAKE) -C $(TRUSTED_LIB_DIR) all
	$(MAKE) -C $(UNTRUSTED_LIB_DIR) all

ifeq ($(LINUX_SGX_BUILD), 0)
	$(MAKE) -C $(TEST_DIR) all
endif

$(PACKAGE_LIB)/$(OPENSSL_LIB):
	chmod 755 $(BUILD_OPENSSL)
	test -f $(PACKAGE_LIB)/$(OPENSSL_LIB) || $(BUILD_OPENSSL) $(OPENSSL_CONFIG)

clean:	
	$(MAKE) -C $(TRUSTED_LIB_DIR) clean
	$(MAKE) -C $(UNTRUSTED_LIB_DIR) clean
	$(MAKE) -C $(TEST_DIR) clean
	rm -f $(PACKAGE_LIB)/$(TRUSTED_LIB) $(PACKAGE_LIB)/$(UNTRUSTED_LIB)

test: $(PACKAGE_LIB)/$(OPENSSL_LIB) all
	$(MAKE) -C $(TEST_DIR) test 

