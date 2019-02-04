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

#include <tinycrypt/ccm_mode.h>
#include "aes.h"

OscoreError aes_ccm_encrypt(u8_t* key, u8_t* nonce, array plaintext, array ad, array ciphertext) {
    ensure_eq(ciphertext.len, plaintext.len + 8, OscoreInvalidOutLength);
    struct tc_aes_key_sched_struct s;
    try_tc(tc_aes128_set_encrypt_key(&s, key));
    struct tc_ccm_mode_struct ccm_mode;
    try_tc(tc_ccm_config(&ccm_mode, &s, nonce, 13, 8));
    try_tc(tc_ccm_generation_encryption(ciphertext.ptr, ciphertext.len, ad.ptr, ad.len, plaintext.ptr, plaintext.len, &ccm_mode));
    return OscoreNoError;
}

OscoreError aes_ccm_decrypt(u8_t* key, u8_t* nonce, array ciphertext, array ad, array plaintext) {
    ensure_eq(plaintext.len, ciphertext.len - 8, OscoreInvalidOutLength);
    struct tc_aes_key_sched_struct s;
    try_tc(tc_aes128_set_encrypt_key(&s, key));
    struct tc_ccm_mode_struct ccm_mode;
    try_tc(tc_ccm_config(&ccm_mode, &s, nonce, 13, 8));
    try_tc(tc_ccm_decryption_verification(plaintext.ptr, plaintext.len, ad.ptr, ad.len, ciphertext.ptr, ciphertext.len, &ccm_mode));
    return OscoreNoError;
}
