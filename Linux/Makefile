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
include sgx/buildenv.mk
LINUX_SGX_BUILD ?= 0
EMPTY_SRC = check_lvi_toolset
.PHONY: sgxssl sgxssl_no_mitigation clean install uninstall


all: sgxssl

sgxssl:
	@rm -rf $(EMPTY_SRC).* && touch $(EMPTY_SRC).cpp
	@gcc -Wa,-mlfence-after-load=yes -c $(EMPTY_SRC).cpp 2> /dev/null \
		|| (echo "Please follow the instruction at https://github.com/intel/linux-sgx/blob/master/README.md#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package to install \"mitigation tools\" first."  &&  exit 1)
	@rm -rf $(EMPTY_SRC).*
	$(MAKE) -C sgx/ clean
	$(MAKE) -C sgx/ MITIGATION-CVE-2020-0551=LOAD
	$(MAKE) -C sgx/ clean
	$(MAKE) -C sgx/ MITIGATION-CVE-2020-0551=CF
	$(MAKE) -C sgx/ clean
	$(MAKE) -C sgx/ 

sgxssl_no_mitigation:
	$(MAKE) -C sgx/ all

clean:
	$(MAKE) -C sgx/ clean
	rm -rf $(PACKAGE_LIB)/$(OPENSSL_LIB) $(PACKAGE_INC)/openssl/
	rm -rf $(PACKAGE_LIB)/cve_2020_0551_load
	rm -rf $(PACKAGE_LIB)/cve_2020_0551_cf

test:
	$(MAKE) -C sgx/ test

install: $(PACKAGE_LIB)/$(TRUSTED_LIB) $(PACKAGE_LIB)/$(UNTRUSTED_LIB) $(PACKAGE_LIB)/$(OPENSSL_LIB)
ifeq ($(DEBUG), 1)
	@echo "WARNING: Installing Debug libraries."
endif
	mkdir -p $(DESTDIR)/lib64/
	mkdir -p $(DESTDIR)/include/
	cp -prf $(PACKAGE_LIB)/*  $(DESTDIR)/lib64/
	cp -prf $(PACKAGE_INC)/* $(DESTDIR)/include/

uninstall:
	rm -rf $(DESTDIR)/
