/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "bypass_for_sgxssl.h"
#include "fuzzer.h"

int FuzzerInitialize(int *argc, char ***argv)
{
    return 1;
}

int FuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    (void)len;
    int n = atoi((const char *)buf);
    if ( n < 0 ) return -1;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        fprintf(stderr, "Error creating context for EC key generation.\n");
        return -1;
    }

    // Set the curve (prime256v1)
    if (EVP_PKEY_paramgen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, n) <= 0) {
        fprintf(stderr, "Error setting curve parameters.\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Generate the key pair
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating EC key pair.\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    printf("ECDSA key pair generated successfully!\n");
    return 0;
}

void FuzzerCleanup(void)
{
    return;
}
