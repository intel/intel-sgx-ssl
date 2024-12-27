/**
 *
 * Copyright(c) 2024 Intel Corporation All Rights Reserved.
 *
 * The source code contained or described herein and all documents related to
 * the source code ("Material") are owned by Intel Corporation or its suppliers
 * or licensors. Title to the Material remains with Intel Corporation or its
 * suppliers and licensors. The Material contains trade secrets and proprietary
 * and confidential information of Intel or its suppliers and licensors. The
 * Material is protected by worldwide copyright and trade secret laws and treaty
 * provisions. No part of the Material may be used, copied, reproduced, modified,
 * published, uploaded, posted, transmitted, distributed, or disclosed in any
 * way without Intel's prior express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by Intel(R) in writing.
 *
 */

#ifndef _ANSI_COLOR_UTILS_H_
#define _ANSI_COLOR_UTILS_H_

/* Used to eliminate unused variable and variable set but not used warnings */
#define UNUSED(val) (void)(val)

typedef enum {
    RESET_C,
    BLACK_C,
    RED_C,
    GREEN_C,
    YELLOW_C,
    BLUE_C,
    MAGENTA_C,
    CYAN_C,
    WHITE_C
} ANSI_COLOR;

/* ANSI escape codes for colors */
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_COLOR_BLACK   "\x1b[30m"
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE   "\x1b[37m"

#define PRINT_PASS(s) \
    { \
        printf(ANSI_COLOR_GREEN "%s" ANSI_COLOR_RESET, s); \
    };
#define PRINT_WARNING(s) \
    { \
        printf(ANSI_COLOR_YELLOW "%s" ANSI_COLOR_RESET, s); \
    };
#define PRINT_ERROR(s) \
    { \
        printf(ANSI_COLOR_RED "%s" ANSI_COLOR_RESET, s); \
    };


#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#endif /* !_ANSI_COLOR_UTILS_H_ */
