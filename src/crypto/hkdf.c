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

#include <tinycrypt/hmac.h>
#include "hkdf.h"

OscoreError hkdf_sha256(array salt, array ikm, array info, array out) {
    u8_t default_salt[32] = { 0 };

    // "Note that [RFC5869] specifies that if the salt is not provided, it is
    // set to a string of zeros.  For implementation purposes, not providing
    // the salt is the same as setting the salt to the empty byte string.
    // OSCORE sets the salt default value to empty byte string, which is
    // converted to a string of zeroes (see Section 2.2 of [RFC5869])".
    if (salt.ptr == NULL || salt.len == 0) {
        salt.ptr = default_salt;
        salt.len = 32;
    }
    struct tc_hmac_state_struct h;

    // extract
    u8_t prk[32];
    memset(&h, 0x00, sizeof(h));
    try_tc(tc_hmac_set_key(&h, salt.ptr, salt.len));
    try_tc(tc_hmac_init(&h));
    try_tc(tc_hmac_update(&h, ikm.ptr, ikm.len));
    try_tc(tc_hmac_final(prk, TC_SHA256_DIGEST_SIZE, &h));

    // expand
    // "N = ceil(L/HashLen)"
    size_t iterations = (out.len + 31) / 32;
    // "L length of output keying material in octets (<= 255*HashLen)"
    if (iterations > 255) {
        return OscoreOutTooLong;
    }

    u8_t t[32] = { 0 };
    for (u8_t i = 1; i <= iterations; i++) {
        memset(&h, 0x00, sizeof(h));
        try_tc(tc_hmac_set_key(&h, prk, 32));
        try_tc(tc_hmac_init(&h));
        if (i > 1) {
            try_tc(tc_hmac_update(&h, t, 32));
        }
        try_tc(tc_hmac_update(&h, info.ptr, info.len));
        try_tc(tc_hmac_update(&h, &i, 1));
        try_tc(tc_hmac_final(t, TC_SHA256_DIGEST_SIZE, &h));
        if (out.len < i * 32) {
            memcpy(&out.ptr[(i-1) * 32], t, out.len % 32);
        } else {
            memcpy(&out.ptr[(i-1) * 32], t, 32);
        }
    }
    return OscoreNoError;
}

