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

#include "libsgx_tsgxssl_t.h"
#include "tCommon.h"
#include <sgx_thread.h>
#include <sgx_spinlock.h>
#include <map>

struct mutex_count
{
	mutex_count() : spin_count(0), mutex(NULL) {}
	DWORD spin_count;
	sgx_thread_mutex_t* mutex;
};


static sgx_spinlock_t thread_add_lock = SGX_SPINLOCK_INITIALIZER;
static sgx_spinlock_t thread_once_lock = SGX_SPINLOCK_INITIALIZER;
static sgx_spinlock_t mutex_map_lock = SGX_SPINLOCK_INITIALIZER;

static std::map<void*, mutex_count*> mutex_info_map;


extern "C" {

	bool WINAPI sgxssl_InitializeCriticalSectionAndSpinCount(
		_Out_ void *lpCriticalSection,
		_In_ DWORD dwSpinCount
	)
	{
		FSTART;
		sgx_thread_mutex_t *mutex = NULL;
		mutex_count* p_mutex_dat = NULL;

		if (lpCriticalSection == NULL) {
			errno = EINVAL;
			FEND;
			return 0;
		}

		try {
			mutex = new sgx_thread_mutex_t();
		}
		catch (std::bad_alloc e) {
			// On error errno is set and returned
			(void)e; // remove warning
			errno = ENOMEM;
			FEND;
			return 0;
		}
		
		if (sgx_thread_mutex_init(mutex, NULL) != 0) {
			errno = EINVAL;
			FEND;
			return 0;
		}

		try {
			p_mutex_dat = new mutex_count;
		}
		catch (std::bad_alloc e)
		{
			sgx_spin_unlock(&mutex_map_lock);
			(void)e; // remove warning
			if (p_mutex_dat != NULL) // second memory allocation failed
				delete p_mutex_dat;
			errno = ENOMEM;
			FEND;
			return 0;
		}
		p_mutex_dat->mutex = mutex;
		p_mutex_dat->spin_count = dwSpinCount;;

		sgx_spin_lock(&mutex_map_lock);
		mutex_info_map[lpCriticalSection] = p_mutex_dat;
		sgx_spin_unlock(&mutex_map_lock);

		FEND;
		return 1;
	}

	void	WINAPI sgxssl_EnterCriticalSection(_Inout_ void *lpCriticalSection)
	{
		FSTART;
		DWORD mutex_counter = 0;
		if (lpCriticalSection == NULL) {
			errno = EINVAL;
			FEND;
			return;
		}

		sgx_spin_lock(&mutex_map_lock);
		std::map<void*, mutex_count*>::iterator it = mutex_info_map.find(lpCriticalSection);
		if (it == mutex_info_map.end() || it->second == NULL) {

			sgx_spin_unlock(&mutex_map_lock);

			// On error errno is set to EINVAL and errno is returned
			errno = EINVAL;
			FEND;
			return;
		}
		sgx_spin_unlock(&mutex_map_lock);

		sgx_thread_mutex_t * mutex_it = it->second->mutex;
		mutex_counter = it->second->spin_count;
		for (int i = 0; i < mutex_counter; i++) {
			if (!sgx_thread_mutex_trylock(mutex_it)) {
				return;
			}
		}

		if (sgx_thread_mutex_lock(mutex_it) == EINVAL) {
			errno = EINVAL;
		}
		FEND;
			return;
	}

	void	WINAPI sgxssl_LeaveCriticalSection(_Inout_ void *lpCriticalSection)
	{
		FSTART;
		if (lpCriticalSection == NULL) {
			errno = EINVAL;
			FEND;
			return;
		}

		sgx_spin_lock(&mutex_map_lock);
		std::map<void*, mutex_count*>::iterator it = mutex_info_map.find(lpCriticalSection);
		if (it == mutex_info_map.end() || it->second == NULL) {

			sgx_spin_unlock(&mutex_map_lock);

			// On error errno is set to EINVAL and errno is returned
			errno = EINVAL;
			FEND;
			return;
		}
		sgx_spin_unlock(&mutex_map_lock);

		sgx_thread_mutex_t * mutex_it = it->second->mutex;
		sgx_thread_mutex_unlock(mutex_it);

		FEND;
		return;


	}

	void	WINAPI sgxssl_DeleteCriticalSection(_Inout_ void *lpCriticalSection)
	{
		FSTART;

		if (lpCriticalSection == NULL) {
			errno = EINVAL;
			FEND;
			return;
		}

		// Find and remove the mutex_it from the map
		sgx_spin_lock(&mutex_map_lock);
		std::map<void*, mutex_count*>::iterator it = mutex_info_map.find(lpCriticalSection);
		if (it == mutex_info_map.end() || it->second == NULL) {

			sgx_spin_unlock(&mutex_map_lock);

			// On error errno is set and returned
			errno = EINVAL;
			FEND;
			return;
		}

		// Free mutex and delete the mutex_it
		sgx_thread_mutex_t * mutex_it = it->second->mutex;

		sgx_thread_mutex_destroy(mutex_it);
		delete mutex_it;

		// delete the mutex_info_map entry
		mutex_info_map.erase(it);

		sgx_spin_unlock(&mutex_map_lock);

		FEND;
		return;
	}



}