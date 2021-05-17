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

static sgx_spinlock_t pthread_key_lock = SGX_SPINLOCK_INITIALIZER;
static std::map<pthread_key_t, destr_function> pthread_key_destr_func_map;
static pthread_key_t	pthread_next_key = 1;

static std::map<pthread_key_t, std::map<sgx_thread_t, const void*> *> thread_specific_data_map;

extern "C" {

int sgxssl_pthread_once (pthread_once_t *once_control, void (*init_routine) (void))
{
	FSTART;

	if (once_control == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	volatile pthread_once_t * once_control_p = once_control;

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

int sgxssl_pthread_key_create (pthread_key_t *key, void (*destr_function) (void *))
{
	FSTART;

	if (key == NULL) {
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	if (pthread_next_key == 0) {
		// Keys number overflow
		errno = EFAULT;
		FEND;
		return EFAULT;
	}

	sgx_spin_lock(&pthread_key_lock);
	*key = pthread_next_key;
	try {
		pthread_key_destr_func_map[pthread_next_key] = destr_function;
	} catch (std::bad_alloc e) {
		(void)e;
		sgx_spin_unlock(&pthread_key_lock);
		errno = ENOMEM;
		FEND;
		return ENOMEM;
	}
	pthread_next_key++;
	sgx_spin_unlock(&pthread_key_lock);

	// NOTE: Destructor functions are registered to be called at thread exit
	// We keep them, even we don't have a chance to run them as OpenSSL doesn't run pthread_exit

	FEND;
	return 0;
}

int sgxssl_pthread_key_delete (pthread_key_t key)
{
	FSTART;

	sgx_spin_lock(&pthread_key_lock);

	std::map<pthread_key_t, destr_function>::iterator map_it = pthread_key_destr_func_map.find(key);
	if ( map_it == pthread_key_destr_func_map.end()) {

		sgx_spin_unlock(&pthread_key_lock);
		// the key value is invalid
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	std::map<pthread_key_t, std::map<sgx_thread_t, const void*> * >::iterator it = thread_specific_data_map.find(key);
	if (it != thread_specific_data_map.end()) {
		std::map<sgx_thread_t, const void*> * p_data_map = it->second;

		if (p_data_map != NULL) {
			// Clear all the entries from the internal thread to data map
			p_data_map->clear();

			// Delete the data map itself
			delete p_data_map;
		}
		else {
			errno = EFAULT;
			FEND;
			return EFAULT;
		}

		// Erase the thread_specific_data_map entry with the given key
		thread_specific_data_map.erase(it);
	}

	// Erase the pthread_key_destr_func_map entry with the given key.
	pthread_key_destr_func_map.erase(map_it);

	// NOTE: Regarding the application data, it is the responsibility of the application to free/cleanup
	// any data related to the deleted key or associated thread-specific data on any thread.

	// If there are no keys in use, reset the next key number
	if (pthread_key_destr_func_map.empty()) {
		pthread_next_key = 1;
	}

	sgx_spin_unlock(&pthread_key_lock);

	FEND;
	return 0;
}

void * sgxssl_pthread_getspecific (pthread_key_t key)
{
	sgx_spin_lock(&pthread_key_lock);

	std::map<pthread_key_t, std::map<sgx_thread_t, const void*> *>::iterator it = thread_specific_data_map.find(key);

	if (it == thread_specific_data_map.end() ||	it->second == NULL) {
		sgx_spin_unlock(&pthread_key_lock);
		FEND;
		return NULL;
	}

	std::map<sgx_thread_t, const void*> * p_data_map = it->second;
	std::map<sgx_thread_t, const void*>::iterator iter = p_data_map->find(sgx_thread_self());

	if (iter == p_data_map->end()) {
		sgx_spin_unlock(&pthread_key_lock);
		FEND;
		return NULL;
	}

	void *data = (void *)iter->second;
	sgx_spin_unlock(&pthread_key_lock);
	FEND;

	return data;
}

int sgxssl_pthread_setspecific (pthread_key_t key, const void *data)
{
	sgx_spin_lock(&pthread_key_lock);

	std::map<pthread_key_t, destr_function>::iterator iter = pthread_key_destr_func_map.find(key);
	if ( iter == pthread_key_destr_func_map.end()) {

		sgx_spin_unlock(&pthread_key_lock);
		// the key value is invalid
		errno = EINVAL;
		FEND;
		return EINVAL;
	}

	std::map<sgx_thread_t, const void*> * p_data_map = NULL;
	std::map<pthread_key_t, std::map<sgx_thread_t, const void*> *>::iterator it = thread_specific_data_map.find(key);

	if (it == thread_specific_data_map.end() ||	it->second == NULL) {
		try {
			p_data_map = new std::map<sgx_thread_t, const void*>;
			thread_specific_data_map[key] = p_data_map;
		}
		catch (std::bad_alloc e)
		{
			sgx_spin_unlock(&pthread_key_lock);
			(void)e; // remove warning
			if (p_data_map != NULL) // second memory allocation failed
				delete p_data_map;
			errno = ENOMEM;
			FEND;
			return ENOMEM;
		}
	}
	else {
		p_data_map = it->second;
	}

	try {
		(*p_data_map)[sgx_thread_self()] = data;
	}
	catch (std::bad_alloc e)
	{
		sgx_spin_unlock(&pthread_key_lock);
		(void)e; // remove warning
		errno = ENOMEM;
		FEND;
		return ENOMEM;
	}
		
	sgx_spin_unlock(&pthread_key_lock);

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

