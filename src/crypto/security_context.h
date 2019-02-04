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

#ifndef NONE_SECURITY_CONTEXT_H
#define NONE_SECURITY_CONTEXT_H

#include "../util/array.h"
#include "../util/error.h"

// TODO: support multiple algorithms (with all of their different parameter sizes)
// TODO: allow algorithms to be encoded as strings
// implementation of AES_CCM_16_64_128 REQUIRED
enum aead_algorithm {
    /// AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
    AES_CCM_16_64_128 = 10,
    // ...
};

// TODO: support multiple algorithms
// implementation of SHA_256 REQUIRED
enum hkdf {
    SHA_256,
//    SHA_512,
//    AES_MAC_128,
//    AES_MAC_256,
};

enum derive_type {
    KEY,
    IV,
};

// TODO: find out actual type (Section 4.1.2.6 of RFC6347)
typedef void* replay_window;

// (Master Secret, Master Salt, SenderID) MUST be unique

/// MUST be pre-established
struct pre_established {
    const array master_secret;
    const array sender_id;
    const array recipient_id;
    // assume this to be pre-established, not mentioned in specification v14
    const array common_id_context;
    /// optional, NULL if not provided
    const struct pre_established_opt* opt;
};

/// MAY be pre-established
struct pre_established_opt {
    /// default AES-CCM-16-64-128 (COSE encoding 10)
    // TODO: actually be generic over the algorithm
    const enum aead_algorithm aead_alg;
    /// default empty string
    const array master_salt;
    /// default HKDF-SHA-256
    // TODO: actually be generic over the algorithm
    const enum hkdf kdf;
    /// default DTLS-type replay protection & window-size 32
    replay_window replay_window;
};

/**
 * @brief Common Context
 * Contains information common to the Sender and Recipient Contexts
 */
struct common_context {
    enum aead_algorithm aead_alg;
    enum hkdf kdf;
    array master_secret;
    array master_salt;
    array id_context;
    array common_iv;
};

/// Sender Context used for encrypting outbound messages
struct sender_context {
    array sender_id;
    array sender_key;
    u8_t sender_seq_num[5];
};

/// Recipient Context used to decrypt inbound messages
struct recipient_context {
    array recipient_id;
    array recipient_key;
    // TODO: actually implement
    replay_window replay_window;
};

/**
 *
 * @param pre pre-established data
 * @param common_iv_ptr pointer to 13 bytes long memory where Common IV will be written to
 * @param out out-pointer (can be uninitialized)
 * @return OscoreError
 */
OscoreError derive_common_context(struct pre_established pre, u8_t* common_iv_ptr, struct common_context* out);
/**
 *
 * @param pre pre-established data
 * @param sender_key_ptr pointer to 16 bytes long memory where Sender Key will be written to
 * @param out out-pointer (can be uninitialized)
 * @return OscoreError
 */
OscoreError derive_sender_context(struct pre_established pre, u8_t* sender_key_ptr, struct sender_context* out);
/**
 *
 * @param pre pre-established data
 * @param recipient_key_ptr point to 16 bytes long memory where Recipient Key will be written to
 * @param out out-pointer (can be uninitialized)
 * @return OscoreError
 */
OscoreError derive_recipient_context(struct pre_established pre, u8_t* recipient_key_ptr, struct recipient_context* out);

#endif //NONE_SECURITY_CONTEXT_H
