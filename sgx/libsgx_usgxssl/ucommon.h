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

#ifndef __UCOMMON_H__
#define __UCOMMON_H__


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#pragma warning( disable: 4100 )

#define SGX_BUFSIZ 512

#define PRINT(...) 	{printf(__VA_ARGS__);}

#define DO_SGX_WARN
//#define DO_SGX_LOG

#define SGX_ERROR(...) PRINT("UERROR: " __VA_ARGS__)
#ifdef DO_SGX_WARN
#define SGX_WARNING(...) PRINT("UWARNING: "  __VA_ARGS__)
#else
#define SGX_WARNING(...)
#endif
#ifdef DO_SGX_LOG
#define SGX_LOG(...) PRINT("ULOG: "  __VA_ARGS__)
#else
#define SGX_LOG(...)
#endif

#define SGX_EXIT(err) exit(err)

#define SGX_ASSERT(expr, ...) \
{ \
	if (!(expr)) \
	{ \
		SGX_ERROR("File: %s, Line: %d\n", __FILE__, __LINE__); \
		SGX_ERROR(__VA_ARGS__); \
		SGX_EXIT(-1); \
	} \
}

#define SGX_CHECK(status)  \
{ \
	if (status != SGX_SUCCESS) \
	{ \
		SGX_ERROR("Check failed %s:%d, status = 0x%x\n", __FILE__, __LINE__, status); \
		SGX_EXIT(-1); \
	} \
}

#define SGX_ALLOC_CHECK(ptr) \
{ \
	if ((void*)(ptr) == NULL) \
	{ \
		SGX_ERROR("Alloc has failed - %s(%d)\n", __FILE__, __LINE__); \
		SGX_EXIT(-1); \
	} \
}

#define SGX_ASSERT_STRUCT_SIZE(struct_type, struct_size) \
	SGX_ASSERT(sizeof(struct_type) == struct_size, \
	 ": Error!!! "#struct_size" (%d) != sizeof("#struct_type") (%ld)\n", \
	struct_size, sizeof(struct_type))
//	__FUNCTION__ ": Error!!! "#struct_size" (%d) != sizeof("#struct_type") (%d)\n", 

#define SGX_ASSERT_SIZES_EQUAL(size1, size2) \
	SGX_ASSERT(size1 == size2, \
	__FUNCTION__ ": Error!!! "#size1" (%d) != "#size2" (%d)\n",size1, size2)

#endif // __UCOMMON_H__
