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

#ifndef NONE_HKDF_H
#define NONE_HKDF_H

#include "../util/array.h"
#include "../util/error.h"

/**
 * Calculates the HKDF-SHA256
 * @param salt array containing the salt parameter. Can have any length.
 * @param ikm input key material. Can have any length.
 * @param info HKDF info parameter. Can have any length.
 * @param out out-array. Can have any length.
 * @return OscoreError
 */
OscoreError hkdf_sha256(array salt, array ikm, array info, array out);

#endif //NONE_HKDF_H
