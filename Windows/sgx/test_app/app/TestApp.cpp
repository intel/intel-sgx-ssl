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
#include <winsock2.h>

#include <sgx_urts.h>
#include <sgx_status.h>

#include "TestEnclave_u.h"


#define WIN32_LEAN_AND_MEAN

sgx_enclave_id_t enclaveID = 0;

#define ENCLAVE_FILE L"TestEnclave.signed.dll"

#define CREATE_ENCLAVE_ERR		1
#define WSA_STARTUP_ERR			2
#define GETADDRINFO_ERR			3
#define DO_SSL_SESSION_ERR		4
#define INVALID_SOCKET_ERR		5
#define INIT_ALOG_ERR			6


#include "alog.h"
#define TEST_RESULTS_FILE_NAME		"testResult.csv"
#define TEST_CATEGORY_BASIC_TEST	"basic_test"
#define ENCLAVE_FILE "TestEnclave.signed.dll"

#include <time.h>

#pragma warning(disable: 4996)

int sgxssl__gmtime64_test()
{
	sgx_status_t status;
	struct tm enc_res, *res = NULL, *t_res = &enc_res;
	time_t cur_tm = _time64(&cur_tm);
	int st = 0;
	time_t tm = 1;

	char test_case_id[AT_CASEID_MAX_LEN] = "SGXOpenSSL__gmtime64_test";

	// Set test case ID
	int ret = ALogSetCaseID(test_case_id);
	if (ret != 0) {
		printf("Setting ALog logger test case ID to %s has failed.\n", test_case_id);
		return 1;
	}

	printf("test %s start\n", __FUNCTION__);

	for (tm = cur_tm; tm > 0; tm -= 100000) {
		res = _gmtime64(&tm);
		status = t_sgxssl__gmtime64(enclaveID, (uint64_t)tm, (void *)t_res, (uint32_t)sizeof(struct tm));
		if (status != SGX_SUCCESS)
		{
			printf("%s: status [%d]\n", __FUNCTION__, status);
			ALogPrintEx(FAIL, "Test sgxssl__gmtime64 implementation inside an enclave, status = %d, time = %ld", status, tm);
			st = 1;
			break;
		}

		if (res->tm_sec != t_res->tm_sec ||
			res->tm_min != t_res->tm_min ||
			res->tm_hour != t_res->tm_hour ||
			res->tm_mday != t_res->tm_mday ||
			res->tm_mon != t_res->tm_mon ||
			res->tm_year != t_res->tm_year ||
			res->tm_wday != t_res->tm_wday ||
			res->tm_yday != t_res->tm_yday ||
			res->tm_wday != t_res->tm_wday ||
			res->tm_isdst != t_res->tm_isdst)
		{
			printf("Check failed for tm = %ld\n", tm);
			ALogPrintEx(FAIL, "Test sgxssl__gmtime64 implementation inside an enclave, time = %ld", tm);
			st = 1;
			break;
		}
	}

	if (st == 0) {
		ALogPrintEx(PASS, "Test sgxssl__gmtime64 implementation inside an enclave");
	}
	printf("test %s end\n", __FUNCTION__);

	return st;
}

#define TEST_CASE_PREFIX	"SGXOpenSSL_"

int run_test(char* test_name, sgx_status_t(*func_name)(sgx_enclave_id_t eid, int* retval))
{
	int retVal = 0;
	sgx_status_t status;
	char test_case_id[AT_CASEID_MAX_LEN] = TEST_CASE_PREFIX;
	size_t pref_len = strlen(TEST_CASE_PREFIX);
	int copy_len = strlen(test_name);
	if (copy_len > AT_CASEID_MAX_LEN - pref_len - 1) {
		copy_len = AT_CASEID_MAX_LEN - pref_len - 1;
	}
	strncpy_s(test_case_id + pref_len, AT_CASEID_MAX_LEN - pref_len, test_name, copy_len);
	test_case_id[pref_len + copy_len] = '\0';

	// Set test case ID
	int ret = ALogSetCaseID(test_case_id);
	if (ret != 0) {
		printf("Setting ALog logger test case ID to %s has failed.\n", test_case_id);
		return 1;
	}

	// Run the test and report test results
	printf("test %s start\n", test_name);
	status = func_name(enclaveID, &retVal);
	if (status != SGX_SUCCESS || retVal != 0)
	{
		printf("%s: status [%d] return value [%d]\n", test_name, status, retVal);
		ALogPrintEx(FAIL, "Run OpenSSL built-in %s test inside an enclave, status = %d, return value = %d", test_name, status, retVal);
		return 1;
	}
	else {
		ALogPrintEx(PASS, "Run OpenSSL built-in %s test inside an enclave.", test_name);
	}
	printf("test %s end\n", test_name);

	return retVal;
}


int run_all_tests()
{
	int stop_on_failure = 1;

	if (sgxssl__gmtime64_test() != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("rsa_test", rsa_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("des_test", des_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("bn_test", bn_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("dh_test", dh_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("ec_test", ec_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("ecdh_test", ecdh_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("ecdsa_test", ecdsa_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("rand_test", rand_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("sha1_test", sha1_test) != 0 && stop_on_failure) {
		return 1;
	}
	if (run_test("sha256_test", sha256_test) != 0 && stop_on_failure) {
		return 1;
	}


	//#define SUPPORT_FILES_APIS

#ifdef SUPPORT_FILES_APIS
	if (run_test("evp_test", evp_test) != 0 && stop_on_failure) {
		return 1;
	}

	if (run_test("ssl_tests", ssl_tests) != 0 && stop_on_failure) {
		return 1;
	}

	// run the same test again - this time it will run in FIPS mode
	if (run_test("ssl_tests", ssl_tests) != 0 && stop_on_failure) {
		return 1;
	}
#endif

	return 0;
}

#define OPENSSL_HOST		"www.openssl.org"
#define PORT				443
#define OPENSSL_GET_REQUEST	"GET / HTTP/1.1\r\n" \
	"Host: www.openssl.org\r\n" \
	"Connection: keep-alive\r\n" \
	"\r\n\r\n";
//"Pragma: no-cache\r\n"
//"Cache-Control: no-cache\r\n"
//"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
//"User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36\r\n"
//"Accept-Encoding: gzip, deflate, sdch\r\n"
//"Accept-Language: en-US,en;q=0.8,he;q=0.6,ru;q=0.4\r\n"
//"\r\n\r\n";


typedef uintptr_t ssl_ssion_handle;

int g_interactive_debug = 0;

int main(int argc, char **argv)
{
	int retVal = 0;

	// Following the Intel® Software Guard Extensions SDK daily build test suite requirements, we use ALog logger tp report test results.
	// Init the ALog logger
	printf("test %s start\n", __FUNCTION__);
	retVal = ALogInit((const char *)TEST_RESULTS_FILE_NAME, ALCSV, ALFILE);
	if (retVal != 0) {
		printf("Initialize ALog logger has failed.\n");
		exit(INIT_ALOG_ERR);
	}
	retVal = ALogSetCategory(TEST_CATEGORY_BASIC_TEST);
	if (retVal != 0) {
		printf("Setting ALog logger category has failed.\n");
		ALogClose();	// Close the ALog logger
		exit(INIT_ALOG_ERR);
	}

	// create an enclave
	sgx_launch_token_t launchToken = { 0 };
	int launchTokenUpdated = 0;
	sgx_status_t status = sgx_create_enclave(ENCLAVE_FILE, 1, &launchToken, &launchTokenUpdated, &enclaveID, NULL);
	if (status != SGX_SUCCESS)
	{
		printf("Create enclave has failed. Status = 0x%x\n", status);
		if (g_interactive_debug) {
			printf("\n\nhit any key to exit\n");
			getchar();
		}
		ALogClose();	// Close the ALog logger
		exit(CREATE_ENCLAVE_ERR);
	}

	// for FIPS mode to work, we need to set the current fingerprint for win32
#if defined(FIPS_SUPPORT) && !(defined _WIN64)
	status = FINGERPRINT_premain_fake32(enclaveID, &retVal);
	if (status != SGX_SUCCESS || retVal != 0)
	{
		printf("FINGERPRINT_premain_fake32 has failed. Status = 0x%x, retVal = %d\n", status, retVal);
		if (g_interactive_debug) {
			printf("\n\nhit any key to exit\n");
			getchar();
		}
		exit(6);
	}
#endif

	status = t_init_enclave(enclaveID);
	if (status != SGX_SUCCESS) {
		goto cleanup;
	}

	retVal = run_all_tests();
	if (retVal != 0)
		goto cleanup;

#ifdef NO_INTEL_PROXY
	// Following tests will fail when running through Intel proxy.
	// To run these tests, bypass Intel proxy by using Employee Hotspot connection.
	retVal = run_ssl_test();
	if (retVal != 0)
		goto cleanup;

	retVal = run_dxlsgx_test1();
	if (retVal != 0)
		goto cleanup;
#endif

cleanup:
	if (enclaveID != 0)
		sgx_destroy_enclave(enclaveID);

	ALogClose();	// Close the ALog logger
	if (g_interactive_debug) {
		printf("\n\ntests finished with retVal: %d, hit any key to exit\n", retVal);
		getchar();
	}
	printf("\n\ntests finished with retVal: %d\n", retVal);

	return retVal;
}


#ifdef __cplusplus
extern "C" {
#endif

	void uprint(const char* str)
	{
		printf("%s", str);
	}
#ifdef __cplusplus
}
#endif
