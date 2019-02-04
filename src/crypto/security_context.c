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

#include "security_context.h"
#include "hkdf.h"
#include "../codec/hkdf_info.h"

static enum aead_algorithm get_aead_alg(struct pre_established pre) {
    return pre.opt != NULL ? pre.opt->aead_alg : AES_CCM_16_64_128;
}

static array get_master_salt(struct pre_established pre) {
    array defaul = {
            .len = 0,
            .ptr = (u8_t*) "",
    };
    return pre.opt != NULL ? pre.opt->master_salt : defaul;
}

static enum hkdf get_kdf(struct pre_established pre) {
    return pre.opt != NULL ? pre.opt->kdf : SHA_256;
}

static replay_window get_replay_window(struct pre_established pre) {
    // TODO: correct default replay window
    return pre.opt != NULL ? pre.opt->replay_window : NULL;
}

/**
 * Common derive procedure used to derive the Common IV and Sender / Recipient Keys
 * @param pre pre-established data
 * @param id empty array for Common IV, sender / recipient ID for their respective keys
 * @param id_context ID Context (may be NULL)
 * @param type IV for Common IV, KEY for Sender / Recipient Keys
 * @param out out-array. Must be initialized
 * @return OscoreError
 */
static OscoreError derive(struct pre_established pre, array id, array id_context, enum derive_type type, array out) {
    ensure(out.len != 0, OscoreInvalidOutLength);
    enum aead_algorithm aead_alg = get_aead_alg(pre);
    array master_salt = get_master_salt(pre);
    enum hkdf kdf = get_kdf(pre);

    size_t len;
    try(hkdf_info_len(id, id_context, aead_alg, type, &len));
    u8_t info_bytes[len];
    array info = {
            .len = len,
            .ptr = info_bytes,
    };
    try(create_hkdf_info(id, id_context, aead_alg, type, info));
    switch (kdf) {
        case SHA_256:
            try(hkdf_sha256(master_salt, pre.master_secret, info, out));
            break;
        default:
            panic("Unknown / unimplemented kdf, we ded now");
    }
    return OscoreNoError;
}

OscoreError derive_common_context(struct pre_established pre, u8_t* common_iv_ptr, struct common_context* out) {
    array common_iv = {
            .len = 13,
            .ptr = common_iv_ptr,
    };
    try(derive(pre, EMPTY_ARRAY, pre.common_id_context, IV, common_iv));
    struct common_context ret = {
            .aead_alg = get_aead_alg(pre),
            .kdf = get_kdf(pre),
            .master_secret = pre.master_secret,
            .master_salt = get_master_salt(pre),
            .id_context = pre.common_id_context,
            .common_iv = common_iv,
    };
    *out = ret;
    return OscoreNoError;
}

OscoreError derive_sender_context(struct pre_established pre, u8_t* sender_key_ptr, struct sender_context* out) {
    array sender_key = {
            .len = 16,
            .ptr = sender_key_ptr,
    };
    try(derive(pre, pre.sender_id, pre.common_id_context, KEY, sender_key));
    // TODO: load sender_seq_num from storage
    struct sender_context ret = {
            .sender_id = pre.sender_id,
            .sender_key = sender_key,
            .sender_seq_num = { 0 },
    };
    *out = ret;
    return OscoreNoError;
}

OscoreError derive_recipient_context(struct pre_established pre, u8_t* recipient_key_ptr, struct recipient_context* out) {
    replay_window replay_window = get_replay_window(pre);
    array recipient_key = {
            .len = 16,
            .ptr = recipient_key_ptr,
    };
    try(derive(pre, pre.recipient_id, pre.common_id_context, KEY, recipient_key));
    struct recipient_context ret = {
            .recipient_id = pre.recipient_id,
            .recipient_key = recipient_key,
            .replay_window = replay_window,
    };
    *out = ret;
    return OscoreNoError;
}

