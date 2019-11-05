/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
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

#include <mbusafecrt.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define ADD_ENTROPY_SIZE	32

#include <femc_enclave.h> /*Fortanix Enclave Manager library*/
#include <femc_common.h>

#include "sgx_trts.h"
#define ENCLAVE_BUFFER_SIZE 24*1024 // 24KB buffer for enclave boundry

/* print helper
 * */
void print_binary(const char * tag, const unsigned char* buf, size_t len)
{
    printf ("{\" %s\":\"", tag);
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\"}\n");
}

static int64_t femc_cb_sha256 (size_t data_size, uint8_t *data,
        struct femc_sha256_digest *digest)
{
    EVP_Digest(data, data_size, digest->md, NULL, EVP_sha256(), NULL);
    //print_binary("cb_sha256", (const unsigned char*)digest->md, sizeof(digest->md));
    return 0;
}

static int64_t femc_cb_sig (void *opaque_signing_context, uint8_t *data,
        size_t data_len, size_t max_sig_len, struct  femc_sig *signature,
        size_t *sig_len, femc_signing_algorithm_t *algorithm)
{
    int ret = 0;
    struct femc_sha256_digest digest;
    EVP_PKEY *pk_ctx = (EVP_PKEY*)opaque_signing_context; // needs to be a pk_handle

    printf("FEMC Callback femc_cb_sig\n");
    ret = femc_cb_sha256(data_len, data, &digest);
    if (ret) {
        printf("Error db_femc_cb_sha256 %d\n", ret);
        goto out;
    }
    unsigned int siglen;
    ret = RSA_sign(NID_sha256, digest.md, sizeof(digest.md),
            (unsigned char *)&signature->sig, &siglen,  EVP_PKEY_get1_RSA(pk_ctx));
    if (!ret) {
        printf("Error FEMC sign %d\n", ret);
        goto out;
    }
    printf("FEMC Callback femc_cb_sig success siglen %d \n", siglen);
    *algorithm = SIGN_SHA256_RSA;
    *sig_len = siglen;
    ret = 0;
out:
    return ret;


}

static int64_t femc_cb_verify_sha256_rsa (uint8_t *public_key,
        size_t public_key_len, uint8_t *data, size_t data_len,
        uint8_t *signature, size_t sig_len)
{
    int ret;
    struct femc_sha256_digest digest;

    ret = femc_cb_sha256(data_len, data, &digest);
    if (ret) {
        printf("Error db_femc_cb_sha256 %d\n", ret);
        return ret;
    }

    RSA *pub_rsa = d2i_RSAPublicKey (NULL, (const unsigned char**)&public_key, public_key_len);

    ret = RSA_verify(NID_sha256, digest.md, sizeof(digest.md),
            signature, sig_len, pub_rsa);
    if (ret) {
        printf("Error DkPkVerify %d\n", ret);
        goto out;
    }
    ret = 0;
out:
    return ret;

}

/* FEMC call-back for symmetric encryption
 * */
static int64_t femc_cb_aes_cmac_128 (femc_aes_cmac_128_key_t *key, uint8_t *data,
        size_t data_len, struct femc_aes_cmac_128_mac *mac)
{
    size_t mac_len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key->key_bytes, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, data, data_len);
    CMAC_Final(ctx, mac->mac, &mac_len);
    CMAC_CTX_free(ctx);
    return 0;
}

/*FEMC call-back for PK signing*/
static int init_femc_signer (struct femc_enclave_ctx_init_args *args,
        EVP_PKEY *pk_ctx)
{

    int ret = 0;
    int size = i2d_PUBKEY(pk_ctx, NULL);
    unsigned char *pub_key_buf = (unsigned char *) malloc(size+1);
    unsigned char *tbuf = pub_key_buf;
    if (!pub_key_buf) {
        ret = -ENOMEM;
        printf("Can't alloc/ pem_key_buf memroy %d \n", ret);
        goto out;
    }

    i2d_PUBKEY(pk_ctx, &tbuf);
    //print_binary(" public key ", (const unsigned char*)pub_key_buf, size);
    args->app_public_key = pub_key_buf;
    args->app_public_key_len = size;
    args->crypto_functions.signer.sign = femc_cb_sig;
    args->crypto_functions.signer.opaque_signer_context = pk_ctx;
out:
    if (ret) {
        // TODO This should get freed after zircon calls libexit also.
        if (pub_key_buf) {
            free(pub_key_buf);
        }
    }
    return ret;
}

/* FEMC crypto function initialization */
static int init_femc_crypto (struct femc_enclave_ctx_init_args *femc_ctx_args,
        EVP_PKEY *pk_ctx)
{
    int ret;
    femc_ctx_args->crypto_functions.hash_sha256 = femc_cb_sha256;
    femc_ctx_args->crypto_functions.verify_sha256_rsa = femc_cb_verify_sha256_rsa;
    femc_ctx_args->crypto_functions.aes_cmac_128 = femc_cb_aes_cmac_128;
    ret = init_femc_signer(femc_ctx_args, pk_ctx);
    return ret;
}


/* FEMC context initialization */
static int init_femc_ctx_args (struct femc_enclave_ctx_init_args *femc_ctx_args,
        EVP_PKEY *pk_ctx, femc_req_type req_type)
{
    femc_ctx_args->req_type = req_type;
    return init_femc_crypto(femc_ctx_args, pk_ctx);
}

static bool _sgx_is_within_enclave (const void * addr, size_t size)
{
    if(sgx_is_within_enclave (addr, size))
         return true;
    return false;
}

static bool _sgx_is_outside_enclave(const void *addr, size_t size)
{
    if(sgx_is_outside_enclave (addr, size))
         return true;
    return false;
}

/* FEMC helper function */
static void
init_femc_global_args(struct femc_enclave_global_init_args *global_args)
{
    global_args->encl_helper_functions.enclave_calloc = calloc;
    global_args->encl_helper_functions.enclave_free = free;
    global_args->encl_helper_functions.buffer_is_within_enclave = _sgx_is_within_enclave;
    global_args->encl_helper_functions.buffer_is_outside_enclave = _sgx_is_outside_enclave;
}


/* Ocall to get target info from node agent enclave */
int ocall_get_targetinfo(struct femc_encl_context *ctx,
                         struct femc_bytes *target_info)
{
    int ret = 0;
    uocall_get_targetinfo(&ret, femc_bytes_data_mut(target_info), ENCLAVE_BUFFER_SIZE);
    if (ret < 0) {
        printf("Error getting target_info inside encalve %d", ret);
        goto out;
    }
    assert(!femc_bytes_set_len(target_info, ret));
    //printf("ocall_get_targetinfo success %d and %d \n", ret, (*target_info)->data_len);

    if (femc_bytes_resize(target_info, ret) < 0) {
        printf("Error resize target_info inside encalve %d", ret);
        ret = -ENOMEM;
        goto out;
    }
    //print_binary("etarget info",(const char*)femc_bytes_data(target_info), ret);
    printf("success copy_target_info_rsp %d\n", ret);
    ret = 0;
out:
    return ret;
}

/* Ocall for local attestation to Fortanix node agent
 */
static int ocall_local_attest(struct femc_encl_context *ctx,
                               struct femc_bytes *req, size_t buf_size_req,
                               struct femc_bytes *rsp, size_t buf_size_rsp)
{
    int ret = 0;
    assert(!femc_bytes_set_len(rsp, buf_size_rsp));
    uocall_local_attest(&ret, femc_bytes_data_mut(req), buf_size_req, femc_bytes_data_mut(rsp), buf_size_rsp);
    if (ret < 0) {
        printf("ucall_local_attest error %d\n", ret);
        goto out;
    }

    assert(!femc_bytes_set_len(rsp, ret));
    if (femc_bytes_resize(rsp, ret) < 0) {
        printf("ucall_local_attest resize error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    printf("ucall_local_attest resize success %d\n", ret);
out:
    return ret;
}



/* Fortanix Enclave Manager local attestation
 */
static int femc_local_attestation (struct femc_encl_context *femc_ctx,
        struct femc_bytes *la_rsp, const char* subject)
{
    int ret = 0;
    struct femc_bytes *target_info = NULL;
    struct femc_bytes *la_req = NULL;
    struct femc_data_bytes const * const extra_subject = NULL;
    struct femc_data_bytes const *extra_attr = NULL;

    // Allocat encalve buffer for target info
    target_info = femc_bytes_new(ENCLAVE_BUFFER_SIZE);
    if (!target_info) {
        printf("Error allocation enclave buffer for target_info \n");
        ret = -ENOMEM;
        goto out;
    }

    /* Ocall to get targetinfo from node agent enclave */
    ret = ocall_get_targetinfo(femc_ctx, target_info);
    if (ret < 0) {
        printf("ocall_get_targetinfo error %d\n", ret);
        goto out;
    }

    la_req = femc_bytes_new(0);
    if (!la_req) {
        ret = -ENOMEM;
        goto out;
    }
    // Generate local attestation request using femc helper function
    ret = femc_generate_la_req(la_req, femc_ctx, target_info,
            subject, strlen(subject), extra_subject, extra_attr);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("femc_generate_la_req error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    // Ocall to attest with node agent
    ret = ocall_local_attest(femc_ctx, la_req, femc_bytes_len(la_req),
            la_rsp, ENCLAVE_BUFFER_SIZE);
    if (ret < 0) {
        printf("ocall_local_attest error %d\n", ret);
        goto out;
    }

    printf("Success ocall_local_attest size %d \n", ret);
    ret = 0;
out:
    femc_bytes_free(target_info);
    femc_bytes_free(la_req);
    return ret;
}


/* Ocall for remote attestation to Fortanix Enclave Manager */
static int ocall_remote_attest(struct femc_encl_context *ctx,
                                struct femc_bytes *req, size_t buf_size_req,
                                struct femc_bytes *rsp, size_t buf_size_rsp)
{
    int ret = 0;
    // Intel SDK copies (out, size = size)
    printf("execute ocall_remote_attest \n");
    uocall_remote_attest(&ret, femc_bytes_data_mut(req), buf_size_req, femc_bytes_data_mut(rsp), buf_size_rsp);
    if (ret < 0) {
        printf("ucall_local_attest error %d\n", ret);
        goto out;
    }

    assert(!femc_bytes_set_len(rsp, ret));
    if (femc_bytes_resize(rsp, ret) < 0) {
        printf("ucall_local_attest resize error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }
    printf("ucall_local_attest resize success %d\n", ret);
out:
    return ret;

}


/* Fortanix Enclave Manager remote attestation
 */

static int femc_remote_attestation (struct femc_encl_context *femc_ctx,
    struct femc_bytes *la_rsp, struct femc_bytes *ra_rsp, const char* subject)
{

    int ret = 0;
    struct femc_bytes *ra_req = NULL;
    struct femc_data_bytes const * const extra_subject = NULL;
    struct femc_data_bytes const *extra_attr = NULL;

    ra_req = femc_bytes_new(0);
    if (!ra_req) {
        printf("femc_generate_ra_req error %d\n", ret);
        ret = -ENOMEM;
        goto out;
    }

    ret = femc_generate_ra_req(femc_ctx, ra_req,
            la_rsp, subject, strlen(subject), extra_subject, extra_attr);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("femc_generate_ra_req error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    ret = ocall_remote_attest(femc_ctx, ra_req, femc_bytes_len(ra_req),
            ra_rsp, ENCLAVE_BUFFER_SIZE);
    if (ret < 0) {
        printf("ocall_remote_attest error %d\n", ret);
        goto out;
    }

    // Verify remote attestation
    ret = verify_ra_rsp(femc_ctx, ra_rsp);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("verify_ra_rsp error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }
    printf("Success ocall_remote_attest size %d \n", ret);
    ret = 0;
out:
    femc_bytes_free(ra_req);
    return ret;
}

int femc_cert_provision(struct femc_encl_context *femc_ctx, const char* subject, void **femc_cert)
{
    int ret = 0;

    struct femc_bytes *la_rsp = NULL;
    struct femc_bytes *ra_rsp = NULL;
    size_t cert_len = 0;
    void * cert_data = NULL;

    // Allocate enclave buffer for urts responses
    la_rsp = femc_bytes_new(ENCLAVE_BUFFER_SIZE);
    ra_rsp = femc_bytes_new(ENCLAVE_BUFFER_SIZE);
    if (!la_rsp || !ra_rsp) {
        printf("Femc local attestation failed: out of memory\n");
        ret = -ENOMEM;
        goto out;
    }

    /* Local attestation with node agent */
    ret = femc_local_attestation (femc_ctx, la_rsp, subject);
    if (ret) {
        printf("Femc local attestation failed \n");
        goto out;
    }

    /* Remote attestation with Enclave Manager */
    ret = femc_remote_attestation (femc_ctx, la_rsp, ra_rsp, subject);
    if (ret) {
        printf("Femc remote attestation failed \n");
        goto out;
    }

    cert_len = femc_bytes_len(ra_rsp);
    // Check PEM is null ternimated
    assert(((const char *)femc_bytes_data(ra_rsp))[cert_len - 1] == '\0');

    cert_data = malloc(cert_len);
    memcpy(cert_data, femc_bytes_data(ra_rsp), cert_len);
    *femc_cert = cert_data;

out:
    femc_bytes_free(la_rsp);
    femc_bytes_free(ra_rsp);
    return ret;
}


/* Initialize FEMC context */
int femc_init (struct femc_encl_context **femc_ctx,EVP_PKEY* pk_ctx, femc_req_type req_type)
{
    int ret = 0;
    struct femc_enclave_ctx_init_args femc_ctx_init_args;
    struct femc_enclave_global_init_args femc_global_args;
    struct femc_sha256_digest digest;
    *femc_ctx = NULL;


    ret = init_femc_ctx_args(&femc_ctx_init_args, pk_ctx, req_type);
    if (ret < 0) {
        printf("init_femc_ctx_args error %d\n", ret);
        goto out;
    }

    femc_cb_sha256 (femc_ctx_init_args.app_public_key_len, femc_ctx_init_args.app_public_key, &digest);
    init_femc_global_args(&femc_global_args);

    ret = femc_enclave_global_init(&femc_global_args);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("femc_enclave_global_init error %d\n", ret);
        ret = -1;
        goto out;

    }

    ret = femc_enclave_ctx_init(femc_ctx, &femc_ctx_init_args);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("femc_enclave_ctx_init error %d\n", ret);
        ret = -1;
        goto out;
    }
    printf("Initialize FEMC context success\n");
    ret = 0;
out:
    if (ret < 0)
        *femc_ctx = NULL;
    return ret;
}


void rsa_key_gen(EVP_PKEY **evp_pkey);

/* Init FEMC Enclave Manager certificate provision
 */
static int ftx_manager_cert_flow ()
{
    int ret = 0;
    struct femc_encl_context *femc_ctx = NULL;
    EVP_PKEY *pk_ctx = NULL;
    void *femc_cert = NULL;
    const char *subject = "Intel SDK SGX Application";

    // Generate RSA key pair inside openssl envelope
    rsa_key_gen(&pk_ctx);
    if (NULL == pk_ctx) {
        printf("Can't create private key error %d\n", ret);
        goto out;
    }

    // Initialize FEMC context
    ret = femc_init(&femc_ctx, pk_ctx, FEMC_REQ_ATTEST_KEY);
    if (ret) {
        printf("Femc init failed error %d\n", ret);
        goto out;
    }

    // Fortanix certificate provisioning - uses FEMC API receive
    // Enclave Manager certificate for the RSA key generate inside encalve
    ret = femc_cert_provision(femc_ctx, subject, &femc_cert);
    if (ret) {
        printf("Fortanix certificate provisioning failed error %d\n", ret);
        goto out;
    }

    printf("Received Enclave Manager certificate for application cert \n%s\n",
            (char*)femc_cert);
    ret = 0;
out:

    if (femc_ctx) {
        femc_enclave_exit(&femc_ctx);
    }

    if (pk_ctx) {
        EVP_PKEY_free(pk_ctx);
    }
    if (femc_cert) {
        free(femc_cert);
    }
    return ret;
}

int ocall_heartbeat(struct femc_encl_context *ctx,
        struct femc_bytes *ra_req)
{
    int ret = 0;
    /* ocall to send heartbeat to fortanix node agent */
    uocall_heartbeat(&ret, femc_bytes_data_mut(ra_req), femc_bytes_len(ra_req));
    if (ret < 0) {
        printf("Error getting target_info inside encalve %d", ret);
        goto out;
    }
    printf("success heartbeat %d\n", ret);
    ret = 0;
out:
    return ret;
}

/* FEMC heart beat helper */
static int femc_heartbeat_send (struct femc_encl_context *femc_ctx,
        struct femc_bytes *la_rsp, const char* subject)
{

    int ret = 0;
    struct femc_bytes *ra_req = NULL;
    struct femc_data_bytes const * const extra_subject = NULL;
    struct femc_data_bytes const *extra_attr = NULL;

    ra_req = femc_bytes_new(0);
    if (!ra_req) {
        printf("femc_heartbeat_send: out of memory\n");
        ret = -ENOMEM;
        goto out;
    }

    ret = femc_generate_ra_req(femc_ctx, ra_req,
            la_rsp, subject, strlen(subject), extra_subject, extra_attr);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf( "femc_heartbeat_send error generating request %d\n", ret);
        ret = -EINVAL;
        goto out;
    }
    // Ocall to send ra_req to node agent.
    ret = ocall_heartbeat(femc_ctx, ra_req);
    if (ret < 0) {
        printf("ocall_heartbeat error %d\n", ret);
        goto out;
    }

out:
    femc_bytes_free(ra_req);
    return ret;
}

int femc_heartbeat_send(struct femc_encl_context *ctx, const char* subject)
{

    int ret = 0;
    struct femc_bytes *la_rsp = NULL;

    la_rsp = femc_bytes_new(ENCLAVE_BUFFER_SIZE);
    if (!la_rsp) {
        ret = -ENOMEM;
        printf("Femc local attestation failed: out of memory\n");
        goto out;
    }
    ret = femc_local_attestation (ctx, la_rsp, subject);
    if (ret) {
        printf("Femc local attestation failed \n");
        goto out;
    }
    ret = femc_heartbeat_send(ctx, la_rsp, subject);
    if (ret) {
        printf("Femc Heartbeat failed \n");
        goto out;
    }

out:
    femc_bytes_free(la_rsp);
    return ret;
}

/* FEMC periodic heartbeat with Enclave Manager
 * */
static int ftx_manager_heartbeat_init()
{
    int ret = 0;
    struct femc_encl_context *femc_ctx = NULL;
    EVP_PKEY     *pk_ctx     = NULL;
    const char *subject = "Intel SDK SGX Application";

    rsa_key_gen(&pk_ctx);
    if (NULL == pk_ctx) {
        printf("Can't create private key error %d\n", ret);
        goto out;
    }

    // Initialize FEMC context
    ret = femc_init(&femc_ctx, pk_ctx, FEMC_REQ_HEARTBEAT);
    if (ret) {
        printf("Femc init failed error %d\n", ret);
        goto out;
    }
    printf("Femc init Heart beat success \n");

    ret = femc_heartbeat_send(femc_ctx, subject);
out:
    if (femc_ctx) {
        femc_enclave_exit(&femc_ctx);
    }

    EVP_PKEY_free(pk_ctx);
    return ret;
}



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

/* rsa_key_gen:
 * Generate rsa keypair inside enclave
 * */
void rsa_key_gen(EVP_PKEY **evp_pkey)
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

	*evp_pkey = EVP_PKEY_new();
	if (*evp_pkey == NULL) {
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
		return;
	}
	EVP_PKEY_assign_RSA(*evp_pkey, keypair);

    /* Print public key - string
	int len = i2d_PUBKEY(*evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PUBKEY(*evp_pkey, &tbuf);
	print public key
	print_binary(" public", (const char*)buf, len);
	free(buf);
    */

    /* print private key - string
	len = i2d_PrivateKey(*evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(*evp_pkey, &tbuf);
	print_binary(" public", (const char*)buf, len);
	free(buf);
    */

    BN_free(bn);
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


void t_sgxssl_call_apis()
{
    printf("Start tests\n");

    SGXSSLSetPrintToStdoutStderrCB(vprintf_cb);

    // Initialize SGXSSL crypto
    OPENSSL_init_crypto(0, NULL);

    ftx_manager_cert_flow();

    /* Periodic heartbeat with Fortanix Enclave Manager
       while (1) {
       printf("Send heartbeat to enclave manager \n");
       ftx_manager_heartbeat_init();
    }*/
    return;

}

