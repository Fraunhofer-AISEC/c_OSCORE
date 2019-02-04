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

#include "oscore_cose.h"
#include "aes.h"

// COSE Object:
// protected: empty
// unprotected:
//  - "Partial IV": sender sequence number without leading zeroes (except `0`, which is `0x00`)
//  - "kid": sender id
//  - (optional) "kid context"

static OscoreError create_enc_structure(array external_aad, array out) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out.ptr, out.len, 0);
    CborEncoder array_enc;
    try_cbor(cbor_encoder_create_array(&enc, &array_enc, 3));
    // context
    try_cbor(cbor_encode_text_stringz(&array_enc, "Encrypt0"));
    // protected
    try_cbor(cbor_encode_byte_string(&array_enc, NULL, 0));
    // external_aad
    try_cbor(cbor_encode_byte_string(&array_enc, external_aad.ptr, external_aad.len));
    try_cbor(cbor_encoder_close_container(&enc, &array_enc));
    return OscoreNoError;
}

static OscoreError enc_structure_length(array external_aad, size_t* out) {
    CborEncoder enc;
    cbor_encoder_init(&enc, NULL, 0, 0);
    CborEncoder array_enc;
    try_cbor_oom(cbor_encoder_create_array(&enc, &array_enc, 3));
    // context
    try_cbor_oom(cbor_encode_text_stringz(&array_enc, "Encrypt0"));
    // protected
    try_cbor_oom(cbor_encode_byte_string(&array_enc, NULL, 0));
    // external_aad
    try_cbor_oom(cbor_encode_byte_string(&array_enc, external_aad.ptr, external_aad.len));
    try_cbor_oom(cbor_encoder_close_container(&enc, &array_enc));
    *out = cbor_encoder_get_extra_bytes_needed(&enc);
    return OscoreNoError;
}

OscoreError from_oscore_cose_encrypt0(u8_t* key, u8_t* nonce, array ciphertext, array aad, array plaintext) {
    ensure_eq(plaintext.len, ciphertext.len - 8, OscoreInvalidOutLength);

    // get enc_structure
    size_t enc_structure_len;
    try(enc_structure_length(aad, &enc_structure_len));

    u8_t enc_structure_bytes[enc_structure_len];
    array enc_structure = {
            .len = enc_structure_len,
            .ptr = enc_structure_bytes,
    };
    try(create_enc_structure(aad, enc_structure));

    // decrypt
    try(aes_ccm_decrypt(&key[0], &nonce[0], ciphertext, enc_structure, plaintext));
    return OscoreNoError;
}

OscoreError to_oscore_cose_encrypt0(u8_t* key, u8_t* nonce, array plaintext, array aad, array payload) {
    ensure_eq(payload.len, plaintext.len + 8, OscoreInvalidOutLength);

    // get enc_structure
    size_t enc_structure_len;
    try(enc_structure_length(aad, &enc_structure_len));

    u8_t enc_structure_bytes[enc_structure_len];
    array enc_structure = {
        .len = enc_structure_len,
        .ptr = enc_structure_bytes,
    };
    try(create_enc_structure(aad, enc_structure));

    // encrypt
    try(aes_ccm_encrypt(&key[0], &nonce[0], plaintext, enc_structure, payload));
    return OscoreNoError;

    // This would have been the actual COSE_Encrypt0 encoding.
    // Due to the OSCORE Header Compression this isn't needed.
//    // convert
//    CborEncoder enc;
//    cbor_encoder_init(&enc, out.ptr, out.len, 0);
//    CborEncoder array_enc;
//    CborEncoder unprotected_enc;
//    try_cbor(cbor_encoder_create_array(&enc, &array_enc, 3));
//    // protected
//    try_cbor(cbor_encode_byte_string(&array_enc, NULL, 0));
//    // unprotected
//    try_cbor(cbor_encoder_create_map(&array_enc, &unprotected_enc, 2));
//        // partial_iv
//        try_cbor(cbor_encode_int(&unprotected_enc, PartialIv));
//        try_cbor(cbor_encode_byte_string(&unprotected_enc, unprotected.partial_iv.ptr, unprotected.partial_iv.len));
//        // kid
//        try_cbor(cbor_encode_int(&unprotected_enc, Kid));
//        try_cbor(cbor_encode_byte_string(&unprotected_enc, unprotected.kid.ptr, unprotected.kid.len));
//    try_cbor(cbor_encoder_close_container(&array_enc, &unprotected_enc));
//    // ciphertext
//    try_cbor(cbor_encode_byte_string(&array_enc, ciphertext.ptr, ciphertext.len));
//    try_cbor(cbor_encoder_close_container(&enc, &array_enc));

}

