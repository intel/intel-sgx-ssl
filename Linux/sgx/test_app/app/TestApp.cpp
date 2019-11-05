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


#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>

#include "TestApp.h"

#include "TestEnclave_u.h"


#include <femc_common.h>
#include <femc_runner.h>


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid Intel® Software Guard Extensions device.",
        "Please make sure Intel® Software Guard Extensions module is enabled in the BIOS, and install Intel® Software Guard Extensions driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "Intel® Software Guard Extensions device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

void print_binary(const char * tag, const char* buf, size_t len)
{
    printf ("{\" %s\":\"", tag);
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\"}\n");
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(TESTENCLAVE_FILENAME, 1, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}


int uocall_get_targetinfo(void *target_info_buf, size_t buf_size)
{
    femc_runner_status_t femc_ret;
    int ret;
    printf("Femc rest call to get targetinfo\n");
    // call the CPPREST function
    struct femc_bytes *target_info = femc_bytes_with_external_buf(target_info_buf, buf_size, false);
    if (!target_info) {
        printf("Failed Femc rest call to alloc targetinfo\n");
        return -1;
    }
    // call the CPPREST function
    femc_ret = femc_runner_get_target_info(target_info);
    if (femc_ret.err != FEMC_RUNNER_SUCCESS) {
        printf("Failed femc_runner_get_target_info err %ld, http err %d \n", femc_ret.err, femc_ret.http_err);
        return femc_ret.err;
    }

    ret = femc_bytes_len(target_info);

    //print_binary("urts target info",(const char*)femc_bytes_data(target_info), ret);

    femc_bytes_free(target_info); /* frees the femc_bytes, but not the wrapped buffer */
    printf("Success femc_runner_get_target_info size %d \n", ret);
    //femc_bytes_free(target_info); /* frees the femc_bytes, but not the wrapped buffer */
    return ret;

}

int uocall_local_attest( void *req_buf, size_t buf_size_req, void *rsp_buf, size_t buf_size_rsp)
{
    femc_runner_status_t femc_ret;
    int ret;
    printf( "Femc rest call local attest, req_size %ld \n", buf_size_req);

    struct femc_bytes *la_req = femc_bytes_with_external_buf(req_buf, buf_size_req, true);
    struct femc_bytes *la_rsp = femc_bytes_with_external_buf(rsp_buf, buf_size_rsp, false);
    if (!la_req || !la_rsp) {
        printf("Failed Femc rest call to alloc la_req & la_rsp\n");
        ret = -1;
        goto out;
    }
    //print_binary("urts la_req ",(const char*)femc_bytes_data(la_req), buf_size_req);
    // call the CPPREST function
    femc_ret = femc_runner_do_local_attestation(la_req, la_rsp);
    if (femc_ret.err != FEMC_RUNNER_SUCCESS) {
        printf("Failed femc_runner_do_local_attestation err %ld, http err %d \n", femc_ret.err, femc_ret.http_err);
        ret = femc_ret.err;
        goto out;
    }
    ret = femc_bytes_len(la_rsp);

    //print_binary("urts la_rsp ",(const char*)femc_bytes_data(la_rsp), ret);

    printf("Success femc_runner_get_target_info size %d \n", ret);

out:
    /* these free the femc_bytes objects, but not the wrapped buffers */
    femc_bytes_free(la_req);
    femc_bytes_free(la_rsp);
    return ret;
}

int uocall_remote_attest(void *req_buf, size_t buf_size_req, void *rsp_buf, size_t buf_size_rsp)
{
    femc_runner_status_t femc_ret;
    int ret;
    const unsigned char *buf = NULL;

    printf( "Femc rest call remote attest, req_size %ld \n", buf_size_req);
    struct femc_bytes *ra_req = femc_bytes_with_external_buf(req_buf, buf_size_req, true);
    struct femc_bytes *ra_rsp = femc_bytes_with_external_buf(rsp_buf, buf_size_rsp, false);
    if (!ra_req || !ra_rsp) {
        printf("Failed Femc rest call to alloc la_req & la_rsp\n");
        ret = -1;
        goto out;
    }
    // call the CPPREST function
    femc_ret = femc_runner_do_remote_attestation(ra_req, ra_rsp);
    if (femc_ret.err != FEMC_RUNNER_SUCCESS) {
        printf("Failed femc_runner_do_remote_attestation err %ld, http err %d \n", femc_ret.err, femc_ret.http_err);
        ret = femc_ret.err;
        goto out;
    }
    ret = femc_bytes_len(ra_rsp);

    buf = (unsigned char*)femc_bytes_data(ra_rsp);
    printf ("{\"otarget info\":\"");
    int i;
    for (i = 0; i < ret; i++) {
        printf("%02x", buf[i]);
    }
    printf("\"}\n");

    printf("Success femc_runner_get_target_info size %d \n", ret);

out:
    /* these free the femc_bytes objects, but not the wrapped buffers */
    femc_bytes_free(ra_req);
    femc_bytes_free(ra_rsp);
    return ret;
}

int uocall_heartbeat(void *req_buf, size_t buf_size)
{
    femc_runner_status_t femc_ret;
    int ret;
    printf("Femc rest send heart beat\n");

    struct femc_bytes *ra_req = femc_bytes_with_external_buf(req_buf, buf_size, true);
    if (!ra_req) {
        printf("Femc rest send heart beat error malloc \n");
        ret = -1;
        goto out;
    }

    femc_ret = femc_runner_send_heartbeat(ra_req);
    if (femc_ret.err != FEMC_RUNNER_SUCCESS) {
        printf("Failed femc_runner_send_heartbeat err %ld, http err %d \n", femc_ret.err, femc_ret.http_err);
        ret = femc_ret.err;
        goto out;
    }
    ret = 0;
    printf("Success ocall_heartbeat size %d \n", ret);
out:
    femc_bytes_free(ra_req);
    return ret;
}

/* OCall functions */
void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
    fflush(stdout);
}


void usgx_exit(int reason)
{
	printf("usgx_exit: %d\n", reason);
	exit(reason);
}


void* thread_test_func(void* p)
{
	new_thread_func(global_eid);
	return NULL;
}

int ucreate_thread()
{
	pthread_t thread;
	int res = pthread_create(&thread, NULL, thread_test_func, NULL);
	return res;
}

int ftx_test(int test)
{
    printf("\n ftx test %d", test);

    return test;
}


/* Application entry */
int main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Changing dir to where the executable is.*/
    char absolutePath[MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]), absolutePath);

    if (ptr == NULL || chdir(absolutePath) != 0)
    	return 1;

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
        return 1;

    sgx_status_t status = t_sgxssl_call_apis(global_eid);
    if (status != SGX_SUCCESS) {
        printf("Call to t_sgxssl_call_apis has failed.\n");
        return 1;    //Test failed
    }

    sgx_destroy_enclave(global_eid);

    femc_runner_status_t ret = femc_runner_get_agent_version(NULL);

    //uocall_get_targetinfo(NULL);

    return 0;
}
