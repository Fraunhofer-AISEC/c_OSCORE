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

#ifndef NONE_OSCORE_COSE_H
#define NONE_OSCORE_COSE_H

#include "../util/array.h"
#include "../util/error.h"

/**
 * Encrypts the plaintext and encodes it as COSE_Encrypt0 structure
 * @param key 16-byte key
 * @param nonce 13-byte nonce
 * @param ciphertext AEAD'd ciphertext
 * @param aad additional data to include in MAC verification
 * @param plaintext out-parameter to write payload into, MUST be exactly ciphertext.len - 8 bytes long
 * @return OscoreError
 */
OscoreError from_oscore_cose_encrypt0(u8_t* key, u8_t* nonce, array ciphertext, array aad, array plaintext);

/**
 * Encrypts the plaintext and encodes it as COSE_Encrypt0 structure
 * @param key 16-byte key
 * @param nonce 13-byte nonce
 * @param plaintext plaintext to encrypt
 * @param aad additional data to include in MAC calculation
 * @param payload out-parameter to write payload into, MUST be exactly plaintext.len + 8 bytes long
 * @return OscoreError
 */
OscoreError to_oscore_cose_encrypt0(u8_t* key, u8_t* nonce, array plaintext, array aad, array payload);

#endif //NONE_OSCORE_COSE_H
