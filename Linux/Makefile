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
include sgx/buildenv.mk
LINUX_SGX_BUILD ?= 0

.PHONY: clean install uninstall



all:
	$(MAKE) -C sgx/ all

clean:
	$(MAKE) -C sgx/ clean
	rm -rf $(PACKAGE_LIB)/$(OPENSSL_LIB) $(PACKAGE_INC)/openssl/
test:
	$(MAKE) -C sgx/ test

install: $(PACKAGE_LIB)/$(TRUSTED_LIB) $(PACKAGE_LIB)/$(UNTRUSTED_LIB) $(PACKAGE_LIB)/$(OPENSSL_LIB)
ifeq ($(DEBUG), 1)
	@echo "WARNING: Installing Debug libraries."
endif
	mkdir -p $(DESTDIR)/lib64/
	mkdir -p $(DESTDIR)/include/
	cp $(PACKAGE_LIB)/$(OPENSSL_LIB) $(DESTDIR)/lib64/
	cp $(PACKAGE_LIB)/$(TRUSTED_LIB) $(DESTDIR)/lib64/
	cp $(PACKAGE_LIB)/$(UNTRUSTED_LIB) $(DESTDIR)/lib64/
	cp -prf $(PACKAGE_INC)/* $(DESTDIR)/include/

uninstall:
	rm -rf $(DESTDIR)/
