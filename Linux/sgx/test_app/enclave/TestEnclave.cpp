/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define ADD_ENTROPY_SIZE	32

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

void rsa_key_gen()
{
	BIGNUM *bn = BN_new();
	if (bn == NULL) {
		printf("BN_new failure: %ld\n", ERR_get_error());
	    return;
	}
	int ret = BN_set_word(bn, RSA_F4);
    if (!ret) {
       	printf("BN_set_word failure\n");
	    return;
	}
	
	RSA *keypair = RSA_new();
	if (keypair == NULL) {
		printf("RSA_new failure: %ld\n", ERR_get_error());
	    return;
	}
	ret = RSA_generate_key_ex(keypair, 4096, bn, NULL);
	if (!ret) {
        printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
	    return;
	}

	EVP_PKEY *evp_pkey = EVP_PKEY_new();
	if (evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_RSA(evp_pkey, keypair);

	// public key - string
	int len = i2d_PublicKey(evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
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
	tbuf = buf;
	i2d_PrivateKey(evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	BN_free(bn);

	EVP_PKEY_free(evp_pkey);

	if (evp_pkey->pkey.ptr != NULL) {
	  RSA_free(keypair);
	}
}

void ec_key_gen()
{
	unsigned char entropy_buf[ADD_ENTROPY_SIZE] = {0};

	RAND_add(entropy_buf, sizeof(entropy_buf), ADD_ENTROPY_SIZE);
	RAND_seed(entropy_buf, sizeof(entropy_buf));

	EC_KEY * ec = NULL;
    int eccgroup;
    eccgroup = OBJ_txt2nid("secp384r1");
    ec = EC_KEY_new_by_curve_name(eccgroup);
    if (ec == NULL) {
    	printf("EC_KEY_new_by_curve_name failure: %ld\n", ERR_get_error());
	    return;
    }
    
	EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);

	int ret = EC_KEY_generate_key(ec);
	if (!ret) {
        printf("EC_KEY_generate_key failure\n");
	    return;
	}

	EVP_PKEY *ec_pkey = EVP_PKEY_new();
	if (ec_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_EC_KEY(ec_pkey, ec);

	// public key - string
	int len = i2d_PublicKey(ec_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
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
	if (ec_pkey->pkey.ptr != NULL) {
	  EC_KEY_free(ec);
	}
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

    //CRYPTO_set_mem_functions(priv_malloc, priv_realloc, priv_free);

    // Initialize SGXSSL crypto
    OPENSSL_init_crypto(0, NULL);
    
    rsa_key_gen();
    printf("test rsa_key_gen completed\n");
           
    ec_key_gen();
	printf("test ec_key_gen completed\n");
	
    ret = rsa_test();
    if (ret != 0)
    {
    	printf("test rsa_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test rsa_test completed\n");

	ret = ec_test();
	if (ret != 0)
    {
    	printf("test ec_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test ec_test completed\n");
	
	ret = ecdh_test();
	if (ret != 0)
    {
    	printf("test ecdh_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test ecdh_test completed\n");
	
	ret = ecdsa_test();
	if (ret != 0)
    {
    	printf("test ecdsar_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test ecdsa_test completed\n");

	ret = bn_test();
	if (ret != 0)
    {
    	printf("test bn_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test bn_test completed\n");

	ret = dh_test();
	if (ret != 0)
    {
    	printf("test dh_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test dh_test completed\n");

	ret = sha256_test();
	if (ret != 0)
    {
    	printf("test sha256_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test sha256_test completed\n");
	
	ret = sha1_test();
	if (ret != 0)
    {
    	printf("test sha1_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test sha1_test completed\n");
	
	ret = threads_test();
	if (ret != 0)
    {
    	printf("test threads_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test threads_test completed\n");
	
    //GM SM2 - sign and verify
    ret = ecall_sm2();
    if (ret != 0)
    {
        printf("test evp_sm2 returned error %d\n", ret);
        exit(ret);
    }
    printf("test evp_sm2 completed\n");

    //GM SM3 - compute digest of message
    ret = ecall_sm3();
    if (ret != 0)
    {
        printf("test evp_sm3 returned error %d\n", ret);
        exit(ret);
    }
    printf("test evp_sm3 completed\n");

    //GM SM4 - cbc encrypt and decrypt
    ret = ecall_sm4_cbc();
    if (ret != 0)
    {
        printf("test evp_sm4_cbc returned error %d\n", ret);
        exit(ret);
    }
    printf("test evp_sm4_cbc completed\n");

    //GM SM4 - ctr encrypt and decrypt
    ret = ecall_sm4_ctr();
    if (ret != 0)
    {
        printf("test evp_sm4_ctr returned error %d\n", ret);
        exit(ret);
    }
    printf("test evp_sm4_ctr completed\n");
}
