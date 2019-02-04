/*
 * Copyright (c) 2019 Fraunhofer AISEC. See the COPYRIGHT
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef NONE_MACROS_H
#define NONE_MACROS_H

#include "error.h"

/// Try an expression and return `-EINVAL` and unref `pkt` if its return value is smaller than 0.
#define try_einval(e) do {\
    int r = (e);\
    if (r < 0) {\
        err("Error in try_einval: %d", r);\
        net_pkt_unref(pkt);\
        return -EINVAL;\
    }\
} while (0)

/// Try a function returning an OscoreError, returning given up after logging a message and unrefing `pkt` in case of error.
#define try_oscore(e, ret) do {\
    int r = (e);\
    if (r != OscoreNoError) {\
        err("Error during OSCORE conversion: %d", r);\
        net_pkt_unref(pkt);\
        return ret;\
    }\
} while (0)

/// Try an oscore operation, logging a message, unrefing `pkt` and returning `-EINVAL` in case of error.
#define try_oscore_einval(e) try_oscore(e, -EINVAL)
/// Try an oscore operation, logging a message, unrefing `pkt` and returning in case of error.
#define try_oscore_void(e) try_oscore(e, )

/// Logs the bytes of an array with given message, data-pointer and length in hex.
#define log_hex(msg, data, len) do {\
    char buf[len * 3 + 1];\
    int i = 0;\
    for (i = 0; i < len; i++) {\
        sprintf(&buf[i*3], "%02x ", data[i]);\
    }\
    buf[i*3] = 0;\
    SYS_LOG_INF(msg " (%d bytes): %s", len, buf);\
} while (0)

#endif //NONE_MACROS_H
