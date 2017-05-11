
TRUSTED_LIB_MK=$(shell find . -name '*sgx_t_static.mk')
UNTRUSTED_LIB_MK=$(shell find . -name '*sgx_u_static.mk')

UNTRUSTED_APP_MK=$(shell find . -name '*sgx_u.mk')
TRUSTED_ENCLAVE_MK=$(shell find . -name '*sgx_t.mk')

.PHONY: all clean run

all:
	$(foreach U_MK, $(UNTRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) $@;)
	$(foreach T_MK, $(TRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(T_MK))  -f $(shell basename $(T_MK)) $@;)
	
ifeq ($(SGX_DEBUG), 1)
	cp libsgx_tsgxssl/libsgx_tsgxssl.a ../package/lib64/debug
	cp libsgx_usgxssl/libsgx_usgxssl.a ../package/lib64/debug
else
	cp libsgx_tsgxssl/libsgx_tsgxssl.a ../package/lib64/release
	cp libsgx_usgxssl/libsgx_usgxssl.a ../package/lib64/release
endif

	$(foreach U_MK, $(UNTRUSTED_APP_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) $@;)
	$(foreach T_MK, $(TRUSTED_ENCLAVE_MK), $(MAKE) -C $(shell dirname $(T_MK))    -f $(shell basename $(T_MK)) $@;)

clean:	
	$(foreach U_MK, $(UNTRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) $@;)
	$(foreach T_MK, $(TRUSTED_LIB_MK), $(MAKE) -C $(shell dirname $(T_MK))  -f $(shell basename $(T_MK)) $@;)
	$(foreach U_MK, $(UNTRUSTED_APP_MK), $(MAKE) -C $(shell dirname $(U_MK))  -f $(shell basename $(U_MK)) $@;)
	$(foreach T_MK, $(TRUSTED_ENCLAVE_MK), $(MAKE) -C $(shell dirname $(T_MK))    -f $(shell basename $(T_MK)) $@;)

run:
	$(foreach U_MK, $(UNTRUSTED_APP_MK), $(MAKE) -C $(shell dirname $(U_MK))   -f $(shell basename $(U_MK)) $@;)

