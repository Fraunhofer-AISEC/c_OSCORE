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

#ifndef NONE_AES_H
#define NONE_AES_H

#include "../util/array.h"
#include "../util/error.h"

/**
 * AES-CCM-16-64-128 Encryption
 * @param key 16-byte key
 * @param nonce 13-byte nonce
 * @param plaintext plaintext to encrypt
 * @param ad additional data to include in MAC calculation
 * @param ciphertext out-parameter to write ciphertext into, must have a length equal to the length of the plaintext + 8 bytes
 * @return OscoreError
 */
OscoreError aes_ccm_encrypt(u8_t* key, u8_t* nonce, array plaintext, array ad, array ciphertext);

/**
 * AES-CCM-16-64-128 Decryption
 * @param key 16-byte key
 * @param nonce 13-byte nonce
 * @param ciphertext ciphertext to decrypt
 * @param ad additional data to include in MAC verification
 * @param plaintext out-parameter to write plaintext into, must have a length equal to the length of the ciphertext - 8 bytes
 * @return OscoreError
 */
OscoreError aes_ccm_decrypt(u8_t* key, u8_t* nonce, array ciphertext, array ad, array plaintext);

#endif //NONE_AES_H
