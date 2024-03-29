/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/opensslconf.h>
#include <fcntl.h>
#include "fuzzer.h"

#if defined(__cplusplus)
extern "C" {
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return FuzzerInitialize(argc, argv);
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    return FuzzerTestOneInput(buf, len);
}

#define BUF_SIZE 65536

int main(int argc, char** argv)
{
    FuzzerInitialize(&argc, &argv);
    int fd = open(argv[1], O_RDONLY);
    if ( fd == -1 ) {
	perror("open");
	exit(EXIT_FAILURE);
    }

    while (__AFL_LOOP(10000)) {
        uint8_t *buf = malloc(BUF_SIZE);
        size_t size = read(fd, buf, BUF_SIZE);

        FuzzerTestOneInput(buf, size);
        free(buf);
    }

    FuzzerCleanup();
    return 0;
}

#if defined(__cplusplus)
}
#endif
