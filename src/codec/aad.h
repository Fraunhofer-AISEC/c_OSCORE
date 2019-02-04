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

#ifndef NONE_AAD_H
#define NONE_AAD_H

#include <net/coap.h>
#include "../crypto/security_context.h"
#include "../util/array.h"
#include "../util/error.h"

/**
 * Get the byte-length of the serialized AAD structure.
 * This should be used to reserve enough memory before calling `create_aad`.
 * @param options CoAP Options to include in AAD (only Class I Options will be included)
 * @param opt_num Number of options
 * @param aead_alg AEAD Algorithm to use
 * @param kid KID parameter. This should be the Recipient ID.
 * @param piv PIV parameter. This should be the request sender sequence number.
 * @param out out-parameter to store length in
 * @return OscoreError
 */
OscoreError aad_length(struct coap_option* options, u16_t opt_num, enum aead_algorithm aead_alg, array kid, array piv,
                       size_t* out);

/**
 * Serialize given parameters into the AAD structure.
 * @param options CoAP Options to include in AAD (only Class I Options will be included)
 * @param opt_num Number of options
 * @param aead_alg AEAD Algorithm to use
 * @param kid KID parameter. This should be the Recipient ID.
 * @param piv PIV parameter. This should be the request sender sequence number.
 * @param out out-array. Must have the exact length as provided by `aad_length`.
 * @return OscoreError
 */
OscoreError create_aad(struct coap_option* options, u16_t opt_num, enum aead_algorithm aead_alg, array kid, array piv,
                       array out);

#endif //NONE_AAD_H
