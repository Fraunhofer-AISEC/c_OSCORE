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

#include "aad.h"
#include "../oscore/options.h"

OscoreError aad_length(struct coap_option* options, u16_t opt_num, enum aead_algorithm aead_alg, array kid, array piv,
                       size_t* out) {
    CborEncoder enc;
    cbor_encoder_init(&enc, NULL, 0, 0);
    CborEncoder array_enc;
    CborEncoder array_enc2;
    try_cbor_oom(cbor_encoder_create_array(&enc, &array_enc, 5));
    // oscore_version
    try_cbor_oom(cbor_encode_uint(&array_enc, 1));
    // algorithms
    try_cbor_oom(cbor_encoder_create_array(&array_enc, &array_enc2, 1));
    // alg_aead
    try_cbor_oom(cbor_encode_int(&array_enc2, aead_alg));
    try_cbor_oom(cbor_encoder_close_container(&array_enc, &array_enc2));
    // request_kid
    try_cbor_oom(cbor_encode_byte_string(&array_enc, kid.ptr, kid.len));
    // request_piv
    try_cbor_oom(cbor_encode_byte_string(&array_enc, piv.ptr, piv.len));
    // options
    u32_t encoded_opt_i_len = encoded_option_len(options, opt_num, CLASS_I);
    u8_t encoded_opt_i_bytes[encoded_opt_i_len];
    array opts_i = {
        .len = encoded_opt_i_len,
        .ptr = encoded_opt_i_bytes,
    };
    u32_t size = encode_options(options, opt_num, CLASS_I, &opts_i.ptr[0]);
    assert_eq(size, encoded_opt_i_len);
    try_cbor_oom(cbor_encode_byte_string(&array_enc, opts_i.ptr, opts_i.len));
    // finish up
    try_cbor_oom(cbor_encoder_close_container(&enc, &array_enc));
    *out = cbor_encoder_get_extra_bytes_needed(&enc);
    return OscoreNoError;
}

OscoreError create_aad(struct coap_option* options, u16_t opt_num, enum aead_algorithm aead_alg, array kid, array piv,
                       array out) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out.ptr, out.len, 0);
    CborEncoder array_enc;
    CborEncoder array_enc2;
    try_cbor(cbor_encoder_create_array(&enc, &array_enc, 5));
    // oscore_version
    try_cbor(cbor_encode_uint(&array_enc, 1));
    // algorithms
    try_cbor(cbor_encoder_create_array(&array_enc, &array_enc2, 1));
    // alg_aead
    try_cbor(cbor_encode_int(&array_enc2, aead_alg));
    try_cbor(cbor_encoder_close_container(&array_enc, &array_enc2));
    // request_kid
    try_cbor(cbor_encode_byte_string(&array_enc, kid.ptr, kid.len));
    // request_piv
    try_cbor(cbor_encode_byte_string(&array_enc, piv.ptr, piv.len));
    // options
    u32_t encoded_opt_i_len = encoded_option_len(options, opt_num, CLASS_I);
    u8_t encoded_opt_i_bytes[encoded_opt_i_len];
    array opts_i = {
        .len = encoded_opt_i_len,
        .ptr = encoded_opt_i_bytes,
    };
    u32_t size = encode_options(options, opt_num, CLASS_I, &opts_i.ptr[0]);
    assert_eq(size, encoded_opt_i_len);
    try_cbor(cbor_encode_byte_string(&array_enc, opts_i.ptr, opts_i.len));
    // finish up
    try_cbor(cbor_encoder_close_container(&enc, &array_enc));
    return OscoreNoError;
}
