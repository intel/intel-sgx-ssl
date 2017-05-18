/* crypto/rand/rand_unix.c */
/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
#include <openssl/rand.h>
#include "rand_lcl.h"

int sgxssl_read_rand(unsigned char *rand_buf, int length_in_bytes);

// Using chunk of 4 bytes  is based on the internal implementation of sgx_read_rand,
// Giving larger buffer size will result in concatenation of chunks each one of 4 bytes length 
// and may cause entropy reduction.
#define RAND_BUF_SIZE 4

#ifndef _SIZE_T_DEFINED_
typedef __size_t    size_t;
#define _SIZE_T_DEFINED_
#endif

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

errno_t memset_s(void *s, size_t smax, int c, size_t n);

int RAND_poll(void)
{
	unsigned char rand_buf[RAND_BUF_SIZE];
	int ret;
	int entropy = 0;
	
	//printf("RAND_poll was called\n");

	// ENTROPY_NEEDED is defined in rand_lcl.c as 32 Bytes = 256 bits
	// Cannot use RAND_status() instead of the entropy check as RAND_status() calls RAND_poll().
	while ( entropy < ENTROPY_NEEDED) {
		ret = sgxssl_read_rand(rand_buf, RAND_BUF_SIZE);
        if (ret != 0) {
			//printf("read_rand error 0x%llx\n", ret);
			return 0;
		}
		RAND_seed(rand_buf, RAND_BUF_SIZE);
		entropy += RAND_BUF_SIZE;
    }
	
	// Clear the rand_buf on the stack
	memset_s(rand_buf, RAND_BUF_SIZE, 0, RAND_BUF_SIZE);
	
    return 1;
}
