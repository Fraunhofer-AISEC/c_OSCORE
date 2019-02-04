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

#include "oscore_option.h"

//  0 1 2 3 4 5 6 7 <------------- n bytes -------------->
// +-+-+-+-+-+-+-+-+--------------------------------------
// |0 0 0|h|k|  n  |       Partial IV (if any) ...
// +-+-+-+-+-+-+-+-+--------------------------------------
//
//  <- 1 byte -> <----- s bytes ------>
// +------------+----------------------+------------------+
// | s (if any) | kid context (if any) | kid (if any) ... |
// +------------+----------------------+------------------+
// n: partial IV length
// k: kid flag (if kid is contained)
// h: kid context flag (if kid context is contained)

OscoreError from_oscore_option(array option_value, struct unprotected* unprotected) {
    ensure(option_value.len != 0, OscoreInvalidOptionLength);
    // oscore octet: 0b000hknnn
    u8_t h = (u8_t)(option_value.ptr[0] & 0b00010000) >> 4;
    u8_t k = (u8_t)(option_value.ptr[0] & 0b00001000) >> 3;
    u8_t n = (u8_t)(option_value.ptr[0] & 0b00000111);
    u8_t s = h != 0 ? (u8_t)(option_value.ptr[1 + n]) : (u8_t)0;

    // verify option length
    size_t len_without_kid = 1;
    len_without_kid += n;
    // even if k is specified, the actual id might be the empty array
    len_without_kid += k ? 0 : 0;
    len_without_kid += h ? 1 + s : 0;
    ensure(option_value.len >= len_without_kid, OscoreInvalidOptionLength);

    // check output array lengths
    ensure(unprotected->partial_iv.len >= n, OscoreInvalidPartialIvLength);
    ensure(unprotected->kid.len >= option_value.len - len_without_kid, OscoreInvalidKidLength);
    ensure(unprotected->kid_context.len >= s, OscoreInvalidKidContextLength);

    int index = 1;
    // we can't use memcpy here, as passing NULL to memcpy is UB
    // partial IV
    for (int i = 0; i < n; i++) {
        unprotected->partial_iv.ptr[i] = option_value.ptr[index];
        index++;
    }
    unprotected->partial_iv.len = n;
    // skip `s`
    if (h) {
        index++;
    }
    // kid context
    for (int i = 0; i < s; i++) {
        unprotected->kid_context.ptr[i] = option_value.ptr[index];
        index++;
    }
    unprotected->kid_context.len = s;
    // kid
    for (int i = 0; i < option_value.len - len_without_kid; i++) {
        unprotected->kid.ptr[i] = option_value.ptr[index];
        index++;
    }
    unprotected->kid.len = option_value.len - len_without_kid;
    assert_actually(index == option_value.len, "expected to have consumed full option value; index=%d, value_len=%d", index, option_value.len);
    return OscoreNoError;
}

OscoreError to_oscore_option(struct unprotected unprotected, array option_value) {
    // kid context: "This parameter [...] MUST NOT be present in responses"
    ensure(unprotected.kid_context.len == 0 && unprotected.kid_context.ptr == NULL, OscoreKidContextError);
    // oscore octet: 0b000hknnn
    u8_t h = (u8_t)(unprotected.kid_context.ptr != NULL) << 4;
    u8_t k = (u8_t)(unprotected.kid.ptr != NULL) << 3;
    ensure(unprotected.partial_iv.len < 8, OscoreInvalidPartialIvLength);
    u8_t n = (u8_t)unprotected.partial_iv.len;
    option_value.ptr[0] = h | k | n;
    int index = 1;
    // partial IV
    for (int i = 0; i < unprotected.partial_iv.len; i++) {
        option_value.ptr[index] = unprotected.partial_iv.ptr[i];
        index++;
    }
    // kid context
    if (unprotected.kid_context.ptr != NULL) {
        ensure(unprotected.kid_context.len < 256, OscoreInvalidKidContextLength);
        option_value.ptr[index] = (u8_t)unprotected.kid_context.len;
        index++;
        memcpy(&option_value.ptr[index], unprotected.kid_context.ptr, unprotected.kid_context.len);
        index += unprotected.kid_context.len;
    }
    // kid
    for (int i = 0; i < unprotected.kid.len; i++) {
        option_value.ptr[index] = unprotected.kid.ptr[i];
        index++;
    }
    assert_actually(index == option_value_length(unprotected), "invalid length somehow, this shouldn't happen");
    return OscoreNoError;
}


size_t option_value_length(struct unprotected unprotected) {
    // flag-byte + piv + [kidcontext-len + kidcontext] + kid
    size_t kid_context_len = (unprotected.kid_context.ptr == NULL ? 0 : 1 + unprotected.kid_context.len);
    return 1 + unprotected.partial_iv.len + kid_context_len + unprotected.kid.len;
}

