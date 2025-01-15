/*
 * Copyright (C) 2024 Intel Corporation. All rights reserved.
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

#include "enclave.h"
#include "enclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"
#include "sgx_trts.h"
#include "ansi_color_utils.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

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
 * Print to console all OSSL errors.
 * Removes errors from the error queue and generates a humman-readable string
 * for each error code.
 */
void print_OSSL_errors(void)
{
    unsigned long err;
    char err_string[256];

    while (0 != (err = ERR_get_error()))
    {
        ERR_error_string_n(err, err_string, sizeof(err_string));
        printf("%s\n", err_string); /* OCALL */
    }
}

OSSL_PROVIDER *g_prov = NULL;

/* Enclave ECALLs */
int enclave_fips_test()
{
    enclave_fips_provider_load();
    enclave_fips_provider_test();
    enclave_fips_provider_unload();

    return 0;
}

int enclave_fips_provider_load(void)
{
    int ret = -1;
    void *entry = NULL;
    
    printf(ANSI_COLOR_YELLOW "%s started\n" ANSI_COLOR_RESET, __FUNCTION__);

    SGXSSLSetPrintToStdoutStderrCB(vprintf_cb);

#ifdef SGXSSL_FIPS
    /* Call tRTS API to get address of the FIPS provider init function */
    entry = sgx_get_ossl_fips_sym("OSSL_provider_init");
    if (NULL == entry)
    {
        PRINT_ERROR("FIPS provider init function (OSSL_provider_init) address not found\n");
        goto end;
    }

    /* Add the built in FIPS provider to the OSSL_PROVIDER store in the
       default library context, with "fips" as the provider name */
    ret = OSSL_PROVIDER_add_builtin(NULL, "fips", (OSSL_provider_init_fn *)entry);
    if (0 == ret)
    {
        PRINT_ERROR("FIPS provider couldn't be added to the OSSL_PROVIDER store\n");
        print_OSSL_errors();
        goto end;
    }
    else
    {
        PRINT_PASS("FIPS provider added to the OSSL_PROVIDER store\n");
    }

    /* Verify the "fips" provider is available before attempting to load it */
    if (0 == OSSL_PROVIDER_available(NULL, "fips"))
    {
        PRINT_ERROR("FIPS provider is not available\n");
        print_OSSL_errors();
    }
    else 
    {
        PRINT_PASS("FIPS provider is available\n");
    }
    
    /* Load the FIPS provider */
    g_prov = OSSL_PROVIDER_load(NULL, "fips");
    if (NULL == g_prov)
    {
        PRINT_ERROR("FIPS provider failed to load\n");
        print_OSSL_errors();
        exit(EXIT_FAILURE);
    }
    else
    {
        PRINT_PASS("FIPS provider loaded\n");
    }
#else
    /* Load the default provider */
    g_prov = OSSL_PROVIDER_load(NULL, "default");
    if (NULL == g_prov)
    {
        printf("Default provider failed to load\n");
        print_OSSL_errors();
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Default provider loaded\n");
    }
#endif
    if (1 == OSSL_PROVIDER_self_test(g_prov))
    {
        PRINT_PASS("OSSL_PROVIDER_self_test passed\n");
        printf("Provider name: %s\n", OSSL_PROVIDER_get0_name(g_prov));
        const char *build = NULL;
        OSSL_PARAM request[] = {
            { "buildinfo", OSSL_PARAM_UTF8_PTR, &build, 0, 0 },
            { NULL, 0, NULL, 0, 0 }
        };

        OSSL_PROVIDER_get_params(g_prov, request);
        printf("Provider buildinfo: %s\n", build);
     }
    else
    {
        printf("OSSL_PROVIDER_self_test failed\n");
        print_OSSL_errors();
        goto end;
    }	

    // Initialize SGXSSL crypto
    OPENSSL_init_crypto(0, NULL);

end:
    printf(ANSI_COLOR_YELLOW "%s completed\n" ANSI_COLOR_RESET, __FUNCTION__);

    return 0;
}

/*
 * Perform some crypto tests
 */
int enclave_fips_provider_test(void)
{
    int ret = -1;

    ret = aesgcm_test();
    if (0 != ret)
    {
        printf("AES-GCM test returned error %d\n", ret);
        goto end;
    }
    PRINT_PASS("AES-GCM test completed\n");

    ret = sha256_test();
    if (0 != ret)
    {
        printf("SHA-256 test returned error %d\n", ret);
        goto end;
    }
    PRINT_PASS("SHA-256 test completed\n");

    ret = hmac_tests();
    if (0 != ret)
    {
        printf("HMAC test returned error %d\n", ret);
        goto end;
    }
    PRINT_PASS("HMAC test completed\n");

end:
    printf(ANSI_COLOR_YELLOW "%s completed\n" ANSI_COLOR_RESET, __FUNCTION__);

    return 0;
}

int enclave_fips_provider_unload(void)
{
    OSSL_PROVIDER_unload(g_prov);

    printf(ANSI_COLOR_YELLOW "%s completed\n" ANSI_COLOR_RESET, __FUNCTION__);

    return 0;
}
