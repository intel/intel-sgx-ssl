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

TRUSTED_LIB_MK=$(shell find . -name '*sgx_t_static.mk')
UNTRUSTED_LIB_MK=$(shell find . -name '*sgx_u_static.mk')

UNTRUSTED_APP_MK=$(shell find . -name '*sgx_u.mk')
TRUSTED_ENCLAVE_MK=$(shell find . -name '*sgx_t.mk')

.PHONY: all clean run

all:
	$(foreach U_MK, $(UNTRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) $@;)
	$(foreach T_MK, $(TRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(T_MK))  -f $(shell basename $(T_MK)) LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) $@;)
	
ifdef DEBUG
	cp libsgx_tsgxssl/libsgx_tsgxssl.a ../package/lib64/debug
	cp libsgx_usgxssl/libsgx_usgxssl.a ../package/lib64/debug
else
	cp libsgx_tsgxssl/libsgx_tsgxssl.a ../package/lib64/release
	cp libsgx_usgxssl/libsgx_usgxssl.a ../package/lib64/release
endif

ifeq ($(LINUX_SGX_BUILD), 0)
	$(foreach U_MK, $(UNTRUSTED_APP_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) $@;)
	$(foreach T_MK, $(TRUSTED_ENCLAVE_MK), $(MAKE) -C $(shell dirname $(T_MK))  -f $(shell basename $(T_MK)) LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) $@;)
endif

clean:	
	$(foreach U_MK, $(UNTRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) $@;)
	$(foreach T_MK, $(TRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(T_MK))  -f $(shell basename $(T_MK)) $@;)
	$(foreach U_MK, $(UNTRUSTED_APP_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) $@;)
	$(foreach T_MK, $(TRUSTED_ENCLAVE_MK), $(MAKE) -C $(shell dirname $(T_MK))    -f $(shell basename $(T_MK)) $@;)

run:
	$(foreach U_MK, $(UNTRUSTED_APP_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) LINUX_SGX_BUILD=$(LINUX_SGX_BUILD) $@;)

