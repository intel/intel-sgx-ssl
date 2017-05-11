/**
*   Copyright(C) 2016 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"

#define FAKE_PIPE_READ_FD	0xFAFAFAFALL
#define FAKE_PIPE_WRITE_FD	0xFBFBFBFBLL

#define ENCLAVE_PAGE_SIZE	0x1000	// 4096 B

extern "C" {

int sgxssl_pipe (int pipefd[2])
{
	FSTART;

	// The function is used only by the engines/e_dasync.c (dummy async engine).
	// Adding fake implementation only to be able to distinguish pipe read/write from socket read/write
	pipefd[0] = FAKE_PIPE_READ_FD;
	pipefd[1] = FAKE_PIPE_WRITE_FD;

	FEND;

	// On error, -1 is returned, and errno is set appropriately
	return 0;
}

size_t sgxssl_write (int fd, const void *buf, size_t n)
{
	FSTART;

	if (fd == FAKE_PIPE_WRITE_FD) {
		// With pipes the function is used only by the engines/e_dasync.c (dummy async engine).
		SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

		FEND;
		// On error, -1 is returned, and errno is set appropriately
		return -1;
	}

	// In addition, the function is used by bss_sock.c as writesocket function.
	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;

}

size_t sgxssl_read(int fd, void *buf, size_t count)
{
	FSTART;

	if (fd == FAKE_PIPE_READ_FD) {
		// With pipes the function is used only by the engines/e_dasync.c (dummy async engine).
		SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

		FEND;
		// On error, -1 is returned, and errno is set appropriately
		return -1;
	}

	// In addition, the function is used by bss_sock.c as readsocket function.
	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;
}

// TODO
int sgxssl_close(int fd)
{
	FSTART;

	if (fd == FAKE_PIPE_READ_FD ||
		fd == FAKE_PIPE_WRITE_FD) {
		// With pipes the function is used only by the engines/e_dasync.c (dummy async engine).
		SGX_UNSUPPORTED_FUNCTION(SET_ERRNO);

		FEND;
		// On error, -1 is returned, and errno is set appropriately
		return -1;
	}

	// In addition, the function is used by b_sock2.c as closesocket function.
	// It is unreachable under the assumption that TLS support is not required.
	// Otherwise should be implemented as OCALL.
	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;
}

long sgxssl_sysconf(int name)
{
	FSTART;

	// Used by mem_sec.c
	if (name == _SC_PAGESIZE) {
		return ENCLAVE_PAGE_SIZE;
	}

	SGX_UNREACHABLE_CODE(SET_ERRNO);
	FEND;

	return -1;
}


} // extern "C"
