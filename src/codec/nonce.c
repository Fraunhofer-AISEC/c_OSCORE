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

#include "nonce.h"

OscoreError create_nonce(array id_piv, array partial_iv, array common_iv, u8_t* out) {
    // piv must be stripped
    ensure(partial_iv.len == 1 || partial_iv.ptr[0] != 0, OscoreInvalidIvUntrimmed);

    // "1. left-padding the PIV in network byte order with zeroes to exactly 5 bytes"
    u8_t padded_piv[5] = { 0 };
    memcpy(&padded_piv[sizeof(padded_piv) - partial_iv.len], partial_iv.ptr, partial_iv.len);
    // "2. left-padding the ID_PIV in network byte order with zeroes to exactly nonce length minus 6 bytes,"
    // TODO: actually be generic over the algorithm
    u8_t padded_id_piv[13 - 6] = { 0 };
    memcpy(&padded_id_piv[sizeof(padded_id_piv) - id_piv.len], id_piv.ptr, id_piv.len);
    // "3. concatenating the size of the ID_PIV (a single byte S) with the padded ID_PIV and the padded PIV,"
    out[0] = (u8_t)id_piv.len;
    memcpy(&out[1], padded_id_piv, sizeof(padded_id_piv));
    memcpy(&out[1 + sizeof(padded_id_piv)], padded_piv, sizeof(padded_piv));
    // "4. and then XORing with the Common IV."
    ensure_eq(common_iv.len, 13, OscoreInvalidIvLength);
    for (int i = 0; i < common_iv.len; i++) {
        out[i] ^= common_iv.ptr[i];
    }
    return OscoreNoError;
}

