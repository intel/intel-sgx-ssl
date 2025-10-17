#
# Copyright (C) 2024 Intel Corporation. All rights reserved.
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
include ../Linux/sgx/buildenv.mk

.PHONY: all install uninstall clean clean_dirs clean_all

CURRENT_DIR:=$(CURDIR)
FIPSMODULE:=fips.so
FIPSMODULECONF:=fipsmodule.cnf
LIBDIR := lib64

OPENSSL_VERSION := $(shell ls *3.1.*.tar.gz 2>/dev/null | sort -V | tail -1 | sed -s -- 's/\.tar\.gz$$//')
ifeq ($(OPENSSL_VERSION),)
    $(info No matching OpenSSL 3.1 tarball found for FIPS provider support.)
else
    $(info Found OpenSSL version $(OPENSSL_VERSION) for FIPS provider support.)
    OSSL_FIPS_SOURCE_DIR := $(CURDIR)/$(OPENSSL_VERSION)-source-fips
    OSSL_FIPS_BUILD_DIR := $(CURDIR)/$(OPENSSL_VERSION)-build-fips
    OSSL_FIPS_INSTALL_DIR := $(CURDIR)/$(OPENSSL_VERSION)-install-fips
    OSSL_FIPS_SOURCE_DIR_SET = $(shell test -d $(OSSL_FIPS_SOURCE_DIR) && echo 1 || echo 0)
    OSSL_FIPS_BUILD_DIR_SET = $(shell test -d $(OSSL_FIPS_BUILD_DIR) && echo 1 || echo 0)
    OSSL_FIPS_INSTALL_DIR_SET = $(shell test -d $(OSSL_FIPS_INSTALL_DIR) && echo 1 || echo 0)
endif


BUILD_TARGET = fips

all: $(BUILD_TARGET)

# Build the FIPS provider
fips:
	@echo OPENSSL_VERSION is $(OPENSSL_VERSION)
	@echo OSSL_FIPS_SOURCE_DIR is $(OSSL_FIPS_SOURCE_DIR)
	@echo OSSL_FIPS_INSTALL_DIR is $(OSSL_FIPS_INSTALL_DIR)
	@echo OSSL_FIPS_BUILD_DIR is $(OSSL_FIPS_BUILD_DIR)
ifneq ($(OPENSSL_VERSION),)
	rm -rf $(OSSL_FIPS_SOURCE_DIR)/
	rm -rf $(OSSL_FIPS_INSTALL_DIR)/
	rm -rf $(OSSL_FIPS_BUILD_DIR)/
	mkdir -p $(OSSL_FIPS_SOURCE_DIR)
	mkdir -p $(OSSL_FIPS_INSTALL_DIR)
	mkdir -p $(OSSL_FIPS_BUILD_DIR)
	tar xvf $(OPENSSL_VERSION).tar.gz -C $(OSSL_FIPS_SOURCE_DIR) --strip-components=1  > /dev/null
	cd $(OSSL_FIPS_BUILD_DIR) && $(OSSL_FIPS_SOURCE_DIR)/Configure enable-fips --with-rand-seed=rdcpu --prefix=$(OSSL_FIPS_INSTALL_DIR) && \
		$(MAKE) -j$(shell getconf _NPROCESSORS_ONLN) && $(MAKE) install_fips
endif

# Install the FIPS provider and its configuration file in the SGX SDK location
install:
ifeq ($(OSSL_FIPS_INSTALL_DIR_SET), 1)
	@echo "*** Installing FIPS module"
	@echo "install $(FIPSMODULE) -> $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE)"
	cp -f $(OSSL_FIPS_INSTALL_DIR)/$(LIBDIR)/ossl-modules/$(FIPSMODULE) $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE).new
	chmod 755 $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE).new
	mv -f $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE).new $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE)

	@echo "*** Installing FIPS module configuration"
	@echo "install $(FIPSMODULECONF) -> $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULECONF)"
	echo "module-filename = $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE)" >> $(OSSL_FIPS_INSTALL_DIR)/ssl/$(FIPSMODULECONF)
	cp -f $(OSSL_FIPS_INSTALL_DIR)/ssl/$(FIPSMODULECONF) $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULECONF)
	chmod 644 $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULECONF)
endif

# Remove the FIPS provider and configuration file from the SGX SDK location
uninstall:
ifeq ($(OSSL_FIPS_INSTALL_DIR_SET), 1)
	@echo "*** Uninstalling FIPS module"
	@echo "uninstall $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE)"
	rm -f $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULE)

	@echo "*** Uninstalling FIPS module configuration"
	@echo "uninstall $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULECONF)"
	rm -f $(SGX_SDK)/$(LIBDIR)/$(FIPSMODULECONF)
endif

clean:
ifeq ($(OSSL_FIPS_BUILD_DIR_SET), 1)
	@echo "*** Cleaning FIPS module"
	cd $(OSSL_FIPS_BUILD_DIR) && $(MAKE) uninstall && $(MAKE) clean
endif

clean_dirs:
ifeq ($(OSSL_FIPS_SOURCE_DIR_SET), 1)
	@rm -rf $(OSSL_FIPS_SOURCE_DIR)/
	@rm -rf $(OSSL_FIPS_INSTALL_DIR)/
	@rm -rf $(OSSL_FIPS_BUILD_DIR)/
endif

clean_all: clean clean_dirs
