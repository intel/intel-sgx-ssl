######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
endif


ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

SgxSSL_Package_Include := ../../package/include
SGX_EDL_FILE := $(SgxSSL_Package_Include)/sgx_tsgxssl.edl

Sgx_tssl_Cpp_Files := $(wildcard *.cpp)
Sgx_tssl_C_Files := $(wildcard *.c)
Sgx_tssl_S_Files := $(wildcard *.S)

Sgx_tssl_Cpp_Objects := $(Sgx_tssl_Cpp_Files:.cpp=.o)
Sgx_tssl_C_Objects := $(Sgx_tssl_C_Files:.c=.o)
Sgx_tssl_S_Objects := $(Sgx_tssl_S_Files:.S=.o)

Sgx_tssl_Include_Paths := -I. -I$(SgxSSL_Package_Include) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Common_C_Cpp_Flags := -DOS_ID=$(OS_ID) $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fpic -fstack-protector -fno-builtin-printf -Wformat -Wformat-security $(Sgx_tssl_Include_Paths)
Sgx_tssl_C_Flags := $(Common_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
Sgx_tssl_Cpp_Flags := $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++

.PHONY: all run

all: libsgx_tsgxssl.a

######## sgx_tsgxssl Objects ########
sgx_tsgxssl_t.c: $(SGX_EDGER8R) $(SGX_EDL_FILE)
	$(SGX_EDGER8R) --header-only --trusted $(SGX_EDL_FILE) --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

sgx_tsgxssl_t.o: sgx_tsgxssl_t.c
	@$(CC) $(Sgx_tssl_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

%.o: %.cpp
	@$(CXX) $(Sgx_tssl_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

%.o: %.c
	@$(CC) $(Sgx_tssl_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

%.o: %.S
	@$(CC) $(Common_C_Cpp_Flags) -c $< -o $@
	@echo "CC  <=  $<"

libsgx_tsgxssl.a: sgx_tsgxssl_t.c $(Sgx_tssl_Cpp_Objects) $(Sgx_tssl_C_Objects) $(Sgx_tssl_S_Objects)
	ar rcs libsgx_tsgxssl.a $(Sgx_tssl_Cpp_Objects) $(Sgx_tssl_C_Objects) $(Sgx_tssl_S_Objects) 
	@echo "LINK =>  $@"

clean:
	@rm -f libsgx_tsgxssl.* sgx_tsgxssl_t.* $(Sgx_tssl_Cpp_Objects) $(Sgx_tssl_C_Objects) $(Sgx_tssl_S_Objects)
	
