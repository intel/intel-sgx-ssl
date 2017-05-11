######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64
ENCLAVE_DIR=enclave

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
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

# Added to build with SgxSSL libraries
OPENSSL_PACKAGE := ../../package
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
#OpenSSL_SSL_Library_Name := sgx_tsgxssl_ssl

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/debug/
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/release/
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

								
TestEnclave_Cpp_Files := $(wildcard $(ENCLAVE_DIR)/*.cpp) $(wildcard $(ENCLAVE_DIR)/tests/*.cpp)
TestEnclave_C_Files := $(wildcard $(ENCLAVE_DIR)/*.c) $(wildcard $(ENCLAVE_DIR)/tests/*.c)

TestEnclave_Cpp_Objects := $(TestEnclave_Cpp_Files:.cpp=.o)
TestEnclave_C_Objects := $(TestEnclave_C_Files:.c=.o)

TestEnclave_Include_Paths := -I. -I$(ENCLAVE_DIR) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(OPENSSL_PACKAGE)/include

Common_C_Cpp_Flags := -DOS_ID=$(OS_ID) $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security $(TestEnclave_Include_Paths) -include "tsgxsslio.h"
TestEnclave_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
TestEnclave_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

TestEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tsetjmp -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/TestEnclave.lds


.PHONY: all run

all: TestEnclave.signed.so
# usually release mode don't sign the enclave, but here we want to run the test also in release mode
# this is not realy a release mode as the XML file don't disable debug - we can't load real release enclaves (white list)

run: all


######## TestEnclave Objects ########

$(ENCLAVE_DIR)/TestEnclave_t.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/TestEnclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted TestEnclave.edl --search-path ../$(OPENSSL_PACKAGE)/include --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/TestEnclave_t.o: $(ENCLAVE_DIR)/TestEnclave_t.c
	@$(CC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.cpp
	@$(CXX) $(TestEnclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c
	@$(CC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(ENCLAVE_DIR)/tests/%.o: $(ENCLAVE_DIR)/tests/%.c
	@$(CC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

TestEnclave.so: $(ENCLAVE_DIR)/TestEnclave_t.o $(TestEnclave_Cpp_Objects) $(TestEnclave_C_Objects)
	@$(CXX) $^ -o $@ $(TestEnclave_Link_Flags)
	@echo "LINK =>  $@"

TestEnclave.signed.so: TestEnclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_DIR)/TestEnclave_private.pem -enclave TestEnclave.so -out $@ -config $(ENCLAVE_DIR)/TestEnclave.config.xml
	@echo "SIGN =>  $@"

clean:
	@rm -f TestEnclave.* $(ENCLAVE_DIR)/TestEnclave_t.* $(TestEnclave_Cpp_Objects) $(TestEnclave_C_Objects)

