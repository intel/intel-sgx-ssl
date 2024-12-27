/*
 * Copyright (C) 2011-2024 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>

#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"
#include "sgx_trts.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/provider.h>

#define ADD_ENTROPY_SIZE	32

OSSL_LIB_CTX *libctx = NULL;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

typedef void CRYPTO_RWLOCK;

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        char *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;

int rsa_key_gen()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    //EVP_PKEY_CTX_new_id() doesn't work properly with FIPS provider
    if (!ctx)
    {
        printf("EVP_PKEY_CTX_new_from_name: %ld\n", ERR_get_error());
        return -1;
    }
    int ret = EVP_PKEY_keygen_init(ctx);
    if (!ret)
    {
        printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
    {
        printf("EVP_PKEY_CTX_set_rsa_keygen_bits: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY* evp_pkey = NULL;
    if (EVP_PKEY_generate(ctx, &evp_pkey) <= 0)
    {
        printf("EVP_PKEY_generate: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    // public key - string
    int len = i2d_PublicKey(evp_pkey, NULL);
    unsigned char *buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    unsigned char *tbuf = buf;
    i2d_PublicKey(evp_pkey, &tbuf);

    // print public key
    printf ("{\"public\":\"");
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned char) buf[i]);
    }
    printf("\"}\n");

    free(buf);

    // private key - string
    len = i2d_PrivateKey(evp_pkey, NULL);
    buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    tbuf = buf;
    i2d_PrivateKey(evp_pkey, &tbuf);

    // print private key
    printf ("{\"private\":\"");
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned char) buf[i]);
    }
    printf("\"}\n");

    free(buf);

    EVP_PKEY_free(evp_pkey);
    return 0;
}

int ec_key_gen()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
    //EVP_PKEY_CTX_new_id() doesn't work properly with FIPS provider
    if (!ctx)
    {
        printf("EVP_PKEY_CTX_new_from_name: %ld\n", ERR_get_error());
        return -1;
    }
    int ret = EVP_PKEY_keygen_init(ctx);
    if (!ret)
    {
        printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0)
    {
        printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY* ec_pkey = NULL;
    if (EVP_PKEY_generate(ctx, &ec_pkey) <= 0)
    {
        printf("EVP_PKEY_generate: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    // public key - string
    int len = i2d_PublicKey(ec_pkey, NULL);
    unsigned char *buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    unsigned char *tbuf = buf;
    i2d_PublicKey(ec_pkey, &tbuf);

    // print public key
    printf ("{\"public\":\"");
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned char) buf[i]);
    }
    printf("\"}\n");

    free(buf);

    // private key - string
    len = i2d_PrivateKey(ec_pkey, NULL);
    buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    tbuf = buf;
    i2d_PrivateKey(ec_pkey, &tbuf);

    // print private key
    printf ("{\"private\":\"");
    for (i = 0; i < len; i++) {
        printf("%02x", (unsigned char) buf[i]);
    }
    printf("\"}\n");

    free(buf);

    EVP_PKEY_free(ec_pkey);
    return 0;
}

int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
{
	char buf[BUFSIZ] = {'\0'};

	int res = vsnprintf(buf, BUFSIZ, fmt, arg);
	if (res >=0) {
		sgx_status_t sgx_ret = uprint((const char *) buf);
		TEST_CHECK(sgx_ret);
	}
	return res;
}

/*
extern "C" int CRYPTO_set_mem_functions(
        void *(*m)(size_t, const char *, int),
        void *(*r)(void *, size_t, const char *, int),
        void (*f)(void *, const char *, int));
void* priv_malloc(size_t size, const char *file, int line)
{
	void* addr = malloc(size);
	
	printf("[malloc:%s:%d] size: %d, addr: %p\n", file, line, size, addr);
	
	return addr;
}
void* priv_realloc(void* old_addr, size_t new_size, const char *file, int line)
{
	void* new_addr = realloc(old_addr, new_size);
	
	printf("[realloc:%s:%d] old_addr: %p, new_size: %d, new_addr: %p\n", file, line, old_addr, new_size, new_addr);
	
	return new_addr;
}
void priv_free(void* addr, const char *file, int line)
{
	printf("[free:%s:%d] addr: %p\n", file, line, addr);
	
	free(addr);
}
*/


void t_sgxssl_call_apis()
{
    int ret = 0;
    
    printf("Start tests\n");
    
    SGXSSLSetPrintToStdoutStderrCB(vprintf_cb);
    OSSL_PROVIDER *prov;
#ifndef SGXSSL_FIPS
    prov = OSSL_PROVIDER_load(NULL, "default");
#else
    void *entry = sgx_get_ossl_fips_sym("OSSL_provider_init");

    if (!entry )
    {
        printf("provider init func address not found\n");
        goto end;
    }

    // OSSL_PROVIDER_add_builtin
    ret = OSSL_PROVIDER_add_builtin(NULL, "fips", (OSSL_provider_init_fn *)entry);
    if (ret != 1)
    {
        printf("FIPS provider add fail\n");
        goto end;
    } else {
        printf("OSSL_PROVIDER_add_builtin added FIPS entry\n");
    }
    if (OSSL_PROVIDER_available(NULL, "fips") == 1)
    {
        printf("Loading FIPS provider...\n");
    } else {
        printf("FIPS provider not available, quitting...\n");
        return;
    }
    
    prov = OSSL_PROVIDER_load(NULL, "fips");
    if (prov == NULL) {
        printf("Failed to load FIPS provider\n");
        exit(EXIT_FAILURE);
    } else {
        printf("Loaded FIPS provider\n");
    }
#endif
    if (OSSL_PROVIDER_self_test(prov) == 1)
    {
        printf("OSSL_PROVIDER_self_test: %s\n", OSSL_PROVIDER_get0_name(prov));
        const char *build = NULL;
        OSSL_PARAM request[] = {
            { "buildinfo", OSSL_PARAM_UTF8_PTR, &build, 0, 0 },
            { NULL, 0, NULL, 0, 0 }
        };

        OSSL_PROVIDER_get_params(prov, request);
        printf("Provider buildinfo: %s\n", build);
     } else {
	printf("OSSL_PROVIDER_self_test: failed\n");
        OSSL_PROVIDER_unload(prov);
        return;
     }	

    //CRYPTO_set_mem_functions(priv_malloc, priv_realloc, priv_free);

    // Initialize SGXSSL crypto
    OPENSSL_init_crypto(0, NULL);

    libctx = OSSL_LIB_CTX_new();//added for keygen test with FIPS provider
    if (libctx == NULL) {
        goto end;
    }

    ret = rsa_key_gen();
    if (ret != 0)
    {
        printf("test rsa_key_gen returned error %d\n", ret);
        goto end;
    }
    printf("test rsa_key_gen completed\n");

    ret = ec_key_gen();
    if (ret != 0)
    {
        printf("test ec_key_gen returned error %d\n", ret);
        goto end;
    }
	printf("test ec_key_gen completed\n");

    ret = rsa_test();
    if (ret != 0)
    {
        printf("test rsa_test returned error %d\n", ret);
       	goto end;
    }
        printf("test rsa_test completed\n");

    ret = ec_test();
    if (ret != 0)
    {
    	printf("test ec_test returned error %d\n", ret);
        goto end;
    }
	printf("test ec_test completed\n");

	ret = ecdh_test();
	if (ret != 0)
    {
    	printf("test ecdh_test returned error %d\n", ret);
        goto end;
    }
	printf("test ecdh_test completed\n"); 

	ret = ecdsa_test();
	if (ret != 0)
    {
        printf("test ecdsa_test returned error %d\n", ret);
        goto end;
    }
	printf("test ecdsa_test completed\n");

	ret = bn_test();
	if (ret != 0)
    {
    	printf("test bn_test returned error %d\n", ret);
        goto end;
    }
        printf("test bn_test completed\n");

        ret = dhtest();
        if (ret != 0)
    {
       	printf("test dhtest returned error %d\n", ret);
        goto end;
    }
        printf("test dhtest completed\n");

	ret = aesccm_test();
	if (ret != 0)
    {
         printf("test aesccm_test returned error %d\n", ret);
         goto end;
    }
	printf("test aesccm_test completed\n");

	ret = aesgcm_test();
	if (ret != 0)
	{
		printf("test aesgcm_test returned error %d\n", ret);
		goto end;
	}
	printf("test aesgcm_test completed\n");

       ret = sha256_test();
	if (ret != 0)
    {
    	printf("test sha256_test returned error %d\n", ret);
        goto end;
    }
	printf("test sha256_test completed\n");
	
	ret = sha1_test();
	if (ret != 0)
    {
        printf("test sha1_test returned error %d\n", ret);
        goto end;
    }
	printf("test sha1_test completed\n");

	ret = hmac_tests();
        if (ret != 0)
    {
        printf("test hmac_test returned error %d\n", ret);
        goto end;
    }
        printf("test hmac_test completed\n");

	ret = threads_test();
	if (ret != 0)
    {
    	printf("test threads_test returned error %d\n", ret);
        goto end;
    }
	printf("test threads_test completed\n");
#ifndef SGXSSL_FIPS
    //GM SM2 - sign and verify
    ret = ecall_sm2_sign_verify();
    if (ret != 0)
    {
        printf("test evp_sm2_sign_verify returned error %d\n", ret);
        goto end;
    }
    printf("test evp_sm2_sign_verify completed\n");

    //GM SM2 - encrypt and decrypt
    ret = ecall_sm2_encrypt_decrypt();
    if (ret != 0)
    {
        printf("test evp_sm2_encrypt_decrypt returned error %d\n", ret);
        goto end;
    }
    printf("test evp_sm2_encrypt_decrypt completed\n");

    //GM SM3 - compute digest of message
    ret = ecall_sm3();
    if (ret != 0)
    {
        printf("test evp_sm3 returned error %d\n", ret);
        goto end;
    }
    printf("test evp_sm3 completed\n");

    //GM SM4 - cbc encrypt and decrypt
    ret = ecall_sm4_cbc();
    if (ret != 0)
    {
        printf("test evp_sm4_cbc returned error %d\n", ret);
        goto end;
    }
    printf("test evp_sm4_cbc completed\n");

    //GM SM4 - ctr encrypt and decrypt
    ret = ecall_sm4_ctr();
    if (ret != 0)
    {
        printf("test evp_sm4_ctr returned error %d\n", ret);
        goto end;
    }
    printf("test evp_sm4_ctr completed\n");
#endif
    printf("ALL tests in t_sgxssl_call_apis passed!\n");
end:
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
}
