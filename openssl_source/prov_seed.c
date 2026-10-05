/*
 * Copyright 2020-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "rand_local.h"
#include "crypto/evp.h"
#include "crypto/rand.h"
#include "crypto/rand_pool.h"
#include "internal/core.h"
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <limits.h>

int get_sgx_rand_bytes(unsigned char *buf, int num);

static int sgx_get_random_bytes(unsigned char *buf, size_t len)
{
    if (len > (size_t)INT_MAX)
        return 0;
    return get_sgx_rand_bytes(buf, (int)len) > 0;
}

static size_t sgx_entropy_bytes_needed(int entropy, size_t min_len, size_t max_len)
{
    size_t needed = min_len;
    size_t entropy_bytes = 0;

    if (entropy > 0)
        entropy_bytes = ((size_t)entropy + 7) / 8;

    if (entropy_bytes > needed)
        needed = entropy_bytes;
    if (needed > max_len)
        needed = max_len;

    return needed;
}

size_t ossl_rand_get_entropy(ossl_unused OSSL_LIB_CTX *ctx,
    unsigned char **pout, int entropy,
    size_t min_len, size_t max_len)
{
    size_t ret = sgx_entropy_bytes_needed(entropy, min_len, max_len);
    unsigned char *buf;

    if (ret == 0)
        return 0;

    buf = OPENSSL_secure_malloc(ret);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_RAND, ERR_R_RAND_LIB);
        return 0;
    }

    if (!sgx_get_random_bytes(buf, ret)) {
        OPENSSL_secure_clear_free(buf, ret);
        ERR_raise(ERR_LIB_RAND, ERR_R_RAND_LIB);
        return 0;
    }

    *pout = buf;
    return ret;
}

size_t ossl_rand_get_user_entropy(OSSL_LIB_CTX *ctx,
    unsigned char **pout, int entropy,
    size_t min_len, size_t max_len)
{
    EVP_RAND_CTX *rng = ossl_rand_get0_seed_noncreating(ctx);

    if (rng != NULL && evp_rand_can_seed(rng))
        return evp_rand_get_seed(rng, pout, entropy, min_len, max_len,
            0, NULL, 0);
    else
        return ossl_rand_get_entropy(ctx, pout, entropy, min_len, max_len);
}

void ossl_rand_cleanup_entropy(ossl_unused OSSL_LIB_CTX *ctx,
    unsigned char *buf, size_t len)
{
    OPENSSL_secure_clear_free(buf, len);
}

void ossl_rand_cleanup_user_entropy(OSSL_LIB_CTX *ctx,
    unsigned char *buf, size_t len)
{
    EVP_RAND_CTX *rng = ossl_rand_get0_seed_noncreating(ctx);

    if (rng != NULL && evp_rand_can_seed(rng))
        evp_rand_clear_seed(rng, buf, len);
    else
        OPENSSL_secure_clear_free(buf, len);
}

size_t ossl_rand_get_nonce(ossl_unused OSSL_LIB_CTX *ctx,
    unsigned char **pout,
    size_t min_len, ossl_unused size_t max_len,
    const void *salt, size_t salt_len)
{
    size_t ret = min_len;
    unsigned char *buf;
    const unsigned char *salt_bytes = salt;
    size_t i;

    if (ret == 0)
        return 0;

    buf = OPENSSL_malloc(ret);
    if (buf == NULL)
        return 0;

    if (!sgx_get_random_bytes(buf, ret)) {
        OPENSSL_clear_free(buf, ret);
        return 0;
    }

    if (salt_bytes != NULL && salt_len > 0) {
        for (i = 0; i < ret; i++)
            buf[i] ^= salt_bytes[i % salt_len];
    }

    *pout = buf;
    return ret;
}

size_t ossl_rand_get_user_nonce(OSSL_LIB_CTX *ctx,
    unsigned char **pout,
    size_t min_len, size_t max_len,
    const void *salt, size_t salt_len)
{
    unsigned char *buf;
    EVP_RAND_CTX *rng = ossl_rand_get0_seed_noncreating(ctx);

    if (rng == NULL)
        return ossl_rand_get_nonce(ctx, pout, min_len, max_len, salt, salt_len);

    if ((buf = OPENSSL_malloc(min_len)) == NULL)
        return 0;

    if (!EVP_RAND_generate(rng, buf, min_len, 0, 0, salt, salt_len)) {
        OPENSSL_free(buf);
        return 0;
    }
    *pout = buf;
    return min_len;
}

void ossl_rand_cleanup_nonce(ossl_unused OSSL_LIB_CTX *ctx,
    unsigned char *buf, size_t len)
{
    OPENSSL_clear_free(buf, len);
}

void ossl_rand_cleanup_user_nonce(ossl_unused OSSL_LIB_CTX *ctx,
    unsigned char *buf, size_t len)
{
    OPENSSL_clear_free(buf, len);
}
