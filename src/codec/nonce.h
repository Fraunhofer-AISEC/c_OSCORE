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

#ifndef NONE_NONCE_H
#define NONE_NONCE_H

#include "../util/error.h"
#include "../util/array.h"

/**
 * Create the OSCORE nonce.
 * @param id_piv "Sender ID of the endpoint that generated the Partial IV"
 * @param partial_iv MUST be max 5 bytes long
 * @param common_iv MUST be 13 bytes long
 * @param out MUST be 13 bytes long
 */
OscoreError create_nonce(array id_piv, array partial_iv, array common_iv, u8_t* out);

#endif //NONE_NONCE_H
