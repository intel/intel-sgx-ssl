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

#include <map>
#include <sgx_spinlock.h>
#include <sgx_thread.h>

#include "tcommon.h"
#include "sgx_tsgxssl_t.h"


static sgx_spinlock_t pthread_once_lock = SGX_SPINLOCK_INITIALIZER;

typedef void (*destr_function) (void *);

typedef int sgxssl_pthread_once_t;

extern "C" {

int sgxssl_pthread_once (sgxssl_pthread_once_t *once_control, void (*init_routine) (void))
{
	FSTART;

	if (once_control == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	volatile sgxssl_pthread_once_t * once_control_p = once_control;

	sgx_spin_lock(&pthread_once_lock);

	if (*once_control != ONCE_CONTROL_INIT &&
		*once_control != ONCE_CONTROL_COMPLETE &&
		*once_control != ONCE_CONTROL_BUSY) {

		sgx_spin_unlock(&pthread_once_lock);

		SGX_UNREACHABLE_CODE(SET_ERRNO);
		FEND;
		return EINVAL;

	}

	while (*once_control == ONCE_CONTROL_BUSY) {
		sgx_spin_unlock(&pthread_once_lock);

		sgx_spin_lock(&pthread_once_lock);
	}

	// First call by any thread in a process with a given once_control causes init_routne to be executed and completed.
	// Subsequent calls with the given once_control shall not call the inti_routin.
	if (*once_control == ONCE_CONTROL_INIT) {

		*once_control_p = ONCE_CONTROL_BUSY;
		sgx_spin_unlock(&pthread_once_lock);

		// init function is called outside the lock to support recursive sgxssl_pthread_once
		// where init_routine() itself calls sgxssl_pthread_once()
		if (init_routine != NULL)
			init_routine();

		sgx_spin_lock(&pthread_once_lock);
		*once_control_p = ONCE_CONTROL_COMPLETE;
	}
	sgx_spin_unlock(&pthread_once_lock);


	FEND;
	return 0;
}

//Thread forking isn't supported inside enclave.
int sgxssl_pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void))
{
    FSTART;
    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;
    //Operation not permitted
    return EPERM;
}

}

