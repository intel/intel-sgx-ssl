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

#define ADD_ENTROPY_SIZE	32

#include <femc_enclave.h>
#include <femc_common.h>

#include "sgx_trts.h"

typedef struct femc_encl_context PAL_FEMC_CONTEXT;
typedef EVP_PKEY PAL_PK_CONTEXT;
static int64_t femc_cb_sha256 (size_t data_size, uint8_t *data,
        struct femc_sha256_digest *digest)
{
    /*sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_ret = sgx_sha256_msg(data, data_size, digest->md);
    if (sgx_ret != SGX_SUCCESS) {
        return = -1;
    }*/
    EVP_Digest(data, data_size, digest->md, NULL, EVP_sha256(), NULL);

    return 0;
}


static int db_rng (void *rng_param, unsigned char *output_buffer,
        size_t output_len)
{
    femc_encl_status_t ret;
    // Parameter passed should be used.
    if (rng_param) {
        return -1;
    }

    ret = femc_random(output_buffer, output_len);
    if (ret) {
        return -1;
    }
    return 0;
}


static int64_t femc_cb_sig (void *opaque_signing_context, uint8_t *data,
        size_t data_len, size_t max_sig_len, struct  femc_sig *signature,
        size_t *sig_len, femc_signing_algorithm_t *algorithm)
{
    int ret = 0;
    struct femc_sha256_digest digest;
    EVP_PKEY *pk_ctx = (EVP_PKEY*)opaque_signing_context; // needs to be a pk_handle
    ret = femc_cb_sha256(data_len, data, &digest);
    if (ret) {
        //z_log(Z_LOG_ERROR, "Error db_femc_cb_sha256 %d\n", ret);
        goto out;
    }

    //ret = DkPkSign(ctx, md_alg, digest.md, sizeof(digest.md),
    //       (unsigned char *)&signature->sig, sig_len, db_rng, NULL);
    ret = RSA_sign(NID_sha256, digest.md, sizeof(digest.md),
                  (unsigned char *)&signature->sig, (unsigned int*)sig_len,  EVP_PKEY_get1_RSA(pk_ctx));
    if (!ret) {
        //z_log(Z_LOG_ERROR, "Error DkPksign %d\n", ret);
        goto out;
    }
    *algorithm = SIGN_SHA256_RSA;
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

static int64_t femc_cb_aes_cmac_128 (femc_aes_cmac_128_key_t *key, uint8_t *data,
        size_t data_len, struct femc_aes_cmac_128_mac *mac)
{
    /*
    return (int64_t) DkCipherCmac(cipher_info,
            (unsigned char *)key->key_bytes,
            (sizeof(key->key_bytes) *8),
            (unsigned char *)data,
            data_len,
            (unsigned char *)mac);

    //sgx_status_t ret = sgx_rijndael128_cmac_msg(key->key_bytes, data, data_len, mac->mac);
    */
    size_t mac_len;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key->key_bytes, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, data, data_len);
    CMAC_Final(ctx, mac->mac, &mac_len);
    CMAC_CTX_free(ctx);
    return 0;
}


static int init_femc_signer (struct femc_enclave_ctx_init_args *args,
        EVP_PKEY *pk_ctx)
{

    int ret = 0;
	int size = i2d_PublicKey(pk_ctx, NULL);
	unsigned char *pub_key_buf = (unsigned char *) malloc(size+1);
    if (!pub_key_buf) {
        ret = -ENOMEM;
        printf("Can't alloc/ pem_key_buf memroy %d \n", ret);
        goto out;
    }

	//unsigned char *tbuf = pub_key_buf;

    //ret = DkPublicKeyEncode(PAL_ENCODE_DER, pk_ctx,
    //                        pub_key_buf, &size);
	i2d_PublicKey(pk_ctx, &pub_key_buf);
	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < size; i++) {
	    printf("%02x", (unsigned char) pub_key_buf[i]);
	}
	printf("\"}\n");

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


static int init_femc_crypto (struct femc_enclave_ctx_init_args *femc_ctx_args,
        PAL_PK_CONTEXT *pk_ctx)
{
    int ret;
    femc_ctx_args->crypto_functions.hash_sha256 = femc_cb_sha256;
    femc_ctx_args->crypto_functions.verify_sha256_rsa = femc_cb_verify_sha256_rsa;
    femc_ctx_args->crypto_functions.aes_cmac_128 = femc_cb_aes_cmac_128;
    ret = init_femc_signer(femc_ctx_args, pk_ctx);
    return ret;
}




static int init_femc_ctx_args (struct femc_enclave_ctx_init_args *femc_ctx_args,
        PAL_PK_CONTEXT *pk_ctx, femc_req_type req_type)
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

static void
init_femc_global_args(struct femc_enclave_global_init_args *global_args)
{
    global_args->encl_helper_functions.enclave_calloc = calloc;
    global_args->encl_helper_functions.enclave_free = free;
    global_args->encl_helper_functions.buffer_is_within_enclave = _sgx_is_within_enclave;
    global_args->encl_helper_functions.buffer_is_outside_enclave = _sgx_is_outside_enclave;
}


typedef struct femc_encl_context PAL_FEMC_CONTEXT;


static int _copy_target_info_from_user(
    struct femc_encl_context *ctx,
    struct femc_data_bytes **target_info,
    const struct femc_data_bytes *target_info_src)
{
    femc_encl_status_t ret;
    int retval = 0;
    ret = copy_tgt_info_rsp(ctx, target_info_src, target_info);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("copy_tgt_info_rsp error %d\n", ret);
        retval = -EINVAL;
    }
    return retval;
}


/* Get target info */
int ocall_get_targetinfo(struct femc_encl_context *ctx,
                         struct femc_data_bytes ** target_info)
{
    int ret = 0;

    struct femc_data_bytes *target_info_oe = NULL;
    uocall_get_targetinfo(&ret, &target_info_oe);
    if (ret < 0) {
        printf("got tgt_info inside encalve %d", ret);
        goto out;
    } else {
        //for (int i=0; i < 9; i++)
          //  *(test+i) = *((char*)tgt_info + i);
        printf("ocall_get_targetinfo success %d \n", ret);
    }
    ret = _copy_target_info_from_user(ctx, target_info, target_info_oe);
    if (ret != 0) {
        printf("copy_tgt_info_rsp error %d\n", ret);
        goto out;
    }
    ret = 0;
out:
    return ret;
}


int get_tgtinfo() {

    struct femc_data_bytes *tgt_info = NULL;
    int ret = 0;
    char test[10] = {'\0'};
    // we get a user pointer back
    uocall_get_targetinfo(&ret, &tgt_info);
    if (ret < 0) {
        printf("got tgt_info inside encalve %d", ret);
    } else {
        //for (int i=0; i < 9; i++)
          //  *(test+i) = *((char*)tgt_info + i);
        printf("ocall_get_targetinfo success %d with %s \n", ret, test);
    }
}


static int _copy_la_rsp_from_user(struct femc_encl_context *ctx,
                                  struct femc_la_rsp **rsp,
                                  const struct femc_la_rsp *rsp_src)
{
    int retval = 0;
    femc_encl_status_t ret;
    // Copy la_rsp inside enclave
    ret = copy_la_rsp(ctx, rsp_src, rsp);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("copy_la_rsp error %d\n", ret);
        retval = -EINVAL;
    }
    return retval;
}


/* Sent attestation to local node
 */
static int ocall_local_attest(struct femc_encl_context *ctx,
                               struct femc_la_req **req,
                               struct femc_la_rsp **rsp, size_t *la_req_size)
{
    int retval = 0;
    struct femc_la_rsp *rsp_oe;
    // Intel SDK copies (out, size = size)
    uocall_local_attest(&retval, *req, *la_req_size, (void**)rsp_oe);
    if (retval) {
        printf("ucall_local_attest error %d\n", retval);
        retval = -EINVAL;
        goto out;
    }
    retval = _copy_la_rsp_from_user(ctx, rsp, rsp_oe);
    if (!retval) {
        printf("copy_la_req error %d\n", retval);
    }
out:
    return retval;
}



// Local attestation, Needs cert fields
static int _FEMCLocalAttestation (PAL_FEMC_CONTEXT *femc_ctx,
        struct femc_la_rsp **la_rsp, const char* subject)
{
    int ret = 0;
    struct femc_data_bytes *tgt_info = NULL;
    struct femc_la_req *la_req = NULL;
    size_t la_req_size;
    // Generate Local Attestation Request:
    struct femc_data_bytes const * const extra_subject = NULL;
    struct femc_data_bytes const *extra_attr = NULL;

    uocall_get_targetinfo(&ret, &tgt_info);
    if (ret < 0) {
        printf("ocall_get_targetinfo error %d\n", ret);
        goto out;
    }

    // Generate Local Attestation Request:
    ret = femc_generate_la_req(&la_req, &la_req_size, femc_ctx, &tgt_info,
            subject, strlen(subject), extra_subject, extra_attr);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("femc_generate_la_req error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    // Ocall to attest with node agent
    ret = ocall_local_attest(femc_ctx, &la_req, la_rsp, &la_req_size);
    if (ret < 0) {
        printf("ocall_local_attest error %d\n", ret);
        goto out;
    }
out:
    // TODO free will not be needed in second version
    /*if (la_req) {
        free_la_req(femc_ctx, &la_req);
    }
    if (tgt_info) {
        free_tgt_info_rsp(femc_ctx, &tgt_info);
    }*/
    return ret;
}


static int _copy_ra_rsp_from_user(struct femc_encl_context *ctx,
                                  struct femc_ra_rsp **rsp,
                                  const struct femc_ra_rsp *rsp_src)
{
    int retval = 0;
    femc_encl_status_t ret;
    // Copy ra_rsp inside enclave
    ret = copy_ra_rsp(ctx, rsp_src, rsp);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("copy_ra_rsp error %d\n", ret);
        retval = -EINVAL;
    }
    return retval;
}

static int ocall_remote_attest(struct femc_encl_context *ctx,
                                struct femc_ra_req **req,
                                struct femc_ra_rsp **rsp,
                                size_t *ra_req_size)
{
    int retval = 0;
    struct femc_ra_rsp *rsp_oe = NULL;
    uocall_remote_attest(&retval, *req, *ra_req_size, (void**)&rsp_oe);
    if (retval) {
        printf("ucall_local_attest error %d\n", retval);
        retval = -EINVAL;
        goto out;
    }
    retval = _copy_ra_rsp_from_user(ctx, rsp, rsp_oe);
    if (!retval) {
        printf("copy_ra_resp error %d\n", retval);
    }
out:
    return retval;
}




// Remote attestation
static int _FEMCRemoteAttestation (PAL_FEMC_CONTEXT *femc_ctx,
    struct femc_la_rsp **la_rsp, struct femc_ra_rsp **ra_rsp, const char* subject)
{

    int ret = 0;

    struct femc_data_bytes const * const extra_subject = NULL;
    struct femc_data_bytes const *extra_attr = NULL;

    struct femc_ra_req *ra_req = NULL;
    size_t ra_req_size;
    struct femc_ra_rsp *ra_rsp_tmp = NULL;

    // frees la_rsp
    ret = femc_generate_ra_req(femc_ctx, &ra_req, &ra_req_size,
            la_rsp, subject, strlen(subject), extra_subject, extra_attr);
    if (ret != FEMC_STATUS_SUCCESS) {
        printf("femc_generate_ra_req error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }
    // Ocall to send ra_req_oe to node agent to get ra_rsp_oe
    ret = ocall_remote_attest(femc_ctx, &ra_req, &ra_rsp_tmp, &ra_req_size);
    if (ret < 0) {
        printf("ocall_remote_attest error %d\n", ret);
        goto out;
    }
    // Verify ra_resp
    ret = verify_ra_rsp(femc_ctx, ra_rsp_tmp);

    if (ret != FEMC_STATUS_SUCCESS) {
        printf("verify_ra_rsp error %d\n", ret);
        ret = -EINVAL;
        goto out;
    }
out:
    *ra_rsp = ra_rsp_tmp;
    /*
    if (ra_req) {
        free_ra_req(femc_ctx, &ra_req);
    }
    if (ret) {
        if (*ra_rsp) {
            free(*ra_rsp);
            *ra_rsp = NULL;
        }
    }*/

    return ret;
}


int _FEMCCertProvision(PAL_FEMC_CONTEXT *femc_ctx, const char* subject, void **femc_cert)
{
    int ret = 0;

    struct femc_la_rsp *la_rsp = NULL;
    struct femc_ra_rsp *ra_rsp = NULL;

    ret = _FEMCLocalAttestation (femc_ctx, &la_rsp, subject);
    if (ret) {
        printf("Femc local attestation failed \n");
        return ret;
    }

    ret = _FEMCRemoteAttestation (femc_ctx, &la_rsp, &ra_rsp, subject);
    if (ret || ra_rsp == NULL || ra_rsp->app_cert.data_len < 1) {
        printf("Femc remote attestation failed \n");
        return ret;
    }

    // Check PEM is null ternimated -> don't write the last character.
    assert(ra_rsp->app_cert.pem[ra_rsp->app_cert.data_len -1]=='\0');

    // Allocate a buffer for the certificate data and pass it
     // to shim since shim does not have access to free_ra_rsp.
     // The shim is responsible of freeing this buffer after writing it
     // to file.
    void *cert_data = malloc(ra_rsp->app_cert.data_len);
    memcpy_s(cert_data, ra_rsp->app_cert.data_len, ra_rsp->app_cert.pem, ra_rsp->app_cert.data_len);
    *femc_cert = cert_data;

    printf("Femc Attestation response cert recvd: bytes  %d for cert \n  %s\n",
        ra_rsp->app_cert.data_len, (char*)*femc_cert);

//out:
    /*
    if (la_rsp) {
        free_la_rsp(femc_ctx, &la_rsp);
    }

    if (ra_rsp) {
        free_ra_rsp(femc_ctx, &ra_rsp);
    }*/

    return ret;
}


/* Init femc_context */
int _FEMCInit (PAL_FEMC_CONTEXT **femc_ctx,EVP_PKEY* pk_ctx, femc_req_type req_type)
{
    int ret = 0;
    struct femc_enclave_ctx_init_args femc_ctx_init_args;
    struct femc_enclave_global_init_args femc_global_args;
    *femc_ctx = NULL;


    ret = init_femc_ctx_args(&femc_ctx_init_args, pk_ctx, req_type);
    if (ret < 0) {
        printf("init_femc_ctx_args error %d\n", ret);
        goto out;
    }
    printf("init_femc_ctx_args success\n");

    init_femc_global_args(&femc_global_args);

    printf("init_femc_global_args success\n");


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
    printf("init_femc_ctx_init success\n");
    ret = 0;
out:
    if (ret < 0)
        *femc_ctx = NULL;
    return ret;
}

/* Init Fortanix certificate provisioning
 * If certificate is present bail out with a message
 * returns 0 on sucess
 * */

void rsa_key_gen(EVP_PKEY **evp_pkey);

static int ftx_manager_cert_flow (const char* config_key)
{
    int ret = 0;
    PAL_FEMC_CONTEXT   *femc_ctx  = NULL;
    PAL_PK_CONTEXT     *pk_ctx     = NULL;
    //void               *femc_cert = NULL;
    //DkPkInit(&pk_ctx);
    //TODO verify cert validity and with the key ZIRC-2662
    // Create the cert file if it doesn't already exist
    // Generate private key and write it to file
    rsa_key_gen(&pk_ctx);
    //if (ret != 0) {
        //z_log(Z_LOG_FATAL, "Can't create private key error %d\n", ret);
    //    goto out;
    //}
    //

    // Initialize FEMC context
    ret = _FEMCInit(&femc_ctx, pk_ctx, FEMC_REQ_ATTEST_KEY);
    if (ret) {
        printf("Femc init failed error %d\n", ret);
        //goto out;
    }
    printf("Femc init success \n");
}
/*
    // Fortanix certificate provisioning - uses FEMC API to connect
      to malbork and returns a buffer containing certificate data.
    ret = FEMCCertProvision(femc_ctx, value, &femc_cert);
    if (!ret) {
        ret = -PAL_ERRNO;
        z_log(Z_LOG_FATAL, "Fortanix certificate provisioning failed %s error %d\n" ,config_key, ret);
        goto out;
    }

    // Write the cert data to file, exclude the null character at the end
    ret = write_all_data(shim_hdl, femc_cert, strlen(femc_cert) -1, 0);
    if (ret < strlen(femc_cert) -1) {
        z_log(Z_LOG_FATAL, "Can't write Cert to file %d \n", ret);
        goto out;
    }

    ret = 0;

out:
    DkPkFree(&pk_ctx);
    if (femc_ctx) {
        if (!DkFEMCExit(&femc_ctx)) {
            z_log(Z_LOG_FATAL, "Femc exit failed\n");
        }
    }
    if (femc_cert) {
        free(femc_cert);
    }

    return ret;
}
*/



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

	// public key - string
	int len = i2d_PublicKey(*evp_pkey, NULL);
	unsigned char *buf = (unsigned char *) malloc (len + 1);
	unsigned char *tbuf = buf;
	i2d_PublicKey(*evp_pkey, &tbuf);

	// print public key
	printf ("{\"public\":\"");
	int i;
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	// private key - string
	len = i2d_PrivateKey(*evp_pkey, NULL);
	buf = (unsigned char *) malloc (len + 1);
	tbuf = buf;
	i2d_PrivateKey(*evp_pkey, &tbuf);

	// print private key
	printf ("{\"private\":\"");
	for (i = 0; i < len; i++) {
	    printf("%02x", (unsigned char) buf[i]);
	}
	printf("\"}\n");

	free(buf);

	BN_free(bn);

	//EVP_PKEY_free(evp_pkey);

	//if (evp_pkey->pkey.ptr != NULL) {
	// RSA_free(keypair);
   //}
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

    //PAL_FEMC_CONTEXT *femc_ctx;
    //int req_type = 0;
    //_FEMCInit (&femc_ctx, req_type);
    ftx_manager_cert_flow(NULL);

    EVP_PKEY *evp_pkey;

    rsa_key_gen(&evp_pkey);
    printf("test rsa_key_gen completed\n");

    ret = rsa_test();
    if (ret != 0)
    {
    	printf("test rsa_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test rsa_test completed\n");

	ret = sha256_test();
	if (ret != 0)
    {
    	printf("test sha256_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test sha256_test completed\n");

	ret = threads_test();
	if (ret != 0)
    {
    	printf("test threads_test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test threads_test completed\n");

    ftx_test(&ret, 0);
	if (ret != 0)
    {
    	printf("test ftx_Test returned error %d\n", ret);
    	exit(ret);
    }
	printf("test ftx_test completed\n");

    get_tgtinfo();

}

