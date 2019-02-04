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

#ifndef NONE_OSCORE_OPTION_H
#define NONE_OSCORE_OPTION_H

#include "../util/error.h"
#include "../util/array.h"

struct unprotected {
    array partial_iv;
    /// can be null, can be EMPTY_ARRAY
    array kid;
    /**
     * can be null
     * MUST be shorter than 256 bytes
     */
    array kid_context;
};

/**
 * Parses the OSCORE Option value into `unprotected`
 * @param option_value OSCORE Option value
 * @param unprotected Output to parse into. The arrays MUST have been allocated already: `partial_iv` up to 8 bytes,
 *          `kid`'s length is defined by the crypto algorithm used and `kid_context` up to 256 bytes.
 *          The actual length of both arrays will be set by this function.
 *          The `kid` might be an empty array (signaled by non-null pointer with length 0) if the kid is the empty
 *          byte-string.
 * @return OscoreError
 */
OscoreError from_oscore_option(array option_value, struct unprotected* unprotected);
/**
 * Encodes the unprotected data to the OSCORE Option value
 * @param unprotected unprotected data
 * @param option_value out-parameter to write OSCORE Option value into, MUST have a length of at least
 *          `option_value_length(...)` bytes
 * @return OscoreError
 */
OscoreError to_oscore_option(struct unprotected unprotected, array option_value);

/**
 * Returns the length of the OSCORE Option's value
 * @param unprotected Unprotected data
 * @return Length of the OSCORE Option's value
 */
size_t option_value_length(struct unprotected unprotected);

#endif //NONE_OSCORE_OPTION_H
