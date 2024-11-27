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


######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64
ENCLAVE_DIR=trusted

ifeq ($(shell getconf LONG_BIT), 32)
    SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
    SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
    SGX_COMMON_CFLAGS := -m64 -Wall
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
    SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
    SGX_SDK_INC := $(SGX_SDK)/include
    LIBCXX_INC := $(SGX_SDK)/include/libcxx
    ifeq ($(VERBOSE),1)
        SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
    else
        SGX_ENCLAVE_SIGNER := @$(SGX_SDK)/bin/x64/sgx_sign
    endif
endif

ifeq ($(DEBUG), 1)
    ifeq ($(SGX_PRERELEASE), 1)
        $(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
    endif
endif

# Added to build with SgxSSL library
OPENSSL_LIBRARY_PATH := $(PACKAGE_LIB)/
TSETJMP_LIB := -lsgx_tsetjmp

ifeq "20" "$(word 1, $(sort 20 $(SGXSDK_INT_VERSION)))"
    TSETJMP_LIB:=
endif

ifeq ($(DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g
    SGXSSL_Library_Name := sgx_tsgxssld
    OpenSSL_Crypto_Library_Name := sgx_tsgxssl_cryptod
else
    SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
    SGXSSL_Library_Name := sgx_tsgxssl
    OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
endif

ifneq ($(SGX_MODE), HW)
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
else
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
endif
# tRTS library that provides the symbol get_fips_sym_addr()
SGXSSL_FIPS_TLIB = sgx_ossl_fips

ifeq ($(SGX_MODE), HW)
    ifndef DEBUG
        ifneq ($(SGX_PRERELEASE), 1)
            Build_Mode = HW_RELEASE
        endif
    endif
endif

Enclave_Cpp_Files := $(wildcard $(ENCLAVE_DIR)/*.cpp) $(wildcard $(ENCLAVE_DIR)/tests/*.cpp)
Enclave_C_Files := $(wildcard $(ENCLAVE_DIR)/*.c) $(wildcard $(ENCLAVE_DIR)/tests/*.c)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Include_Paths := -I. -I$(ENCLAVE_DIR) -I$(SGX_SDK_INC) -I$(SGX_SDK_INC)/tlibc -I$(LIBCXX_INC) -I$(PACKAGE_INC)

Common_C_Cpp_Flags := -DOS_ID=$(OS_ID) $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security \
                      $(Enclave_Include_Paths) -include "tsgxsslio.h"
Common_C_Cpp_Flags += -DSGXSSL_FIPS -DOPENSSL_NO_SM2 -DFIPS_MODULE

Enclave_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
Enclave_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
    $(Security_Link_Flags) \
    $(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -l$(SGXSSL_FIPS_TLIB) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_pthread -lsgx_tcxx -lsgx_tcrypto $(TSETJMP_LIB) -l$(Service_Library_Name) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
    -Wl,--defsym,__ImageBase=0 \
    -Wl,--version-script=$(ENCLAVE_DIR)/enclave.lds

Enclave_Test_Key := $(ENCLAVE_DIR)/enclave_private.pem

.PHONY: all clean

all: enclave.signed.so

######## Enclave Objects ########
SGXSSL_ADDTIONAL_EDL_PATH=$(PACKAGE_INC)/filefunc

$(ENCLAVE_DIR)/enclave_t.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/enclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted enclave.edl --search-path $(PACKAGE_INC) --search-path $(SGX_SDK_INC) --search-path $(SGXSSL_ADDTIONAL_EDL_PATH)
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/enclave_t.o: $(ENCLAVE_DIR)/enclave_t.c
	$(VCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.cpp $(ENCLAVE_DIR)/enclave_t.c
	$(VCXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c $(ENCLAVE_DIR)/enclave_t.c
	$(VCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(ENCLAVE_DIR)/tests/%.o: $(ENCLAVE_DIR)/tests/%.c $(ENCLAVE_DIR)/enclave_t.c
	$(VCC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

enclave.so: $(ENCLAVE_DIR)/enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_C_Objects)
	$(VCXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

enclave.signed.so: enclave.so
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "There is no enclave test key <enclave_private.pem>."
	@echo "The project will generate a key <enclave_private.pem> for testing."
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	@echo "SIGN =>  $@"
	$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave enclave.so -out $@ -config $(ENCLAVE_DIR)/enclave.config.xml
	@cp $(SGX_LIBRARY_PATH)/openssl.cnf .

clean:
	@rm -f enclave.* $(ENCLAVE_DIR)/enclave_t.* $(Enclave_Cpp_Objects) $(Enclave_C_Objects) $(Enclave_Test_Key)
	@rm -f fips.so openssl.cnf
