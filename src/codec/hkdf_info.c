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

#include "hkdf_info.h"

// HKDF = composition of HKDF-Extract and HKDF-Expand (RFC5869)
// output = HKDF(salt, IKM, info, L
// * salt = Master Salt
// * IKM = Master Secret
// * info = CBOR-array [
//      id: bstr,
//      alg_aead: int / tstr,
//      type: tstr,
//      L: uint,
//   ]
//      + id: SenderID / RecipientID for keys; empty string for CommonIV
//      + alg_aead: AEAD Algorithm
//      + type: "Key" / "IV", ascii string without nul-terminator
//      + L: size of key/iv for AEAD alg
//          - in bytes
// * https://www.iana.org/assignments/cose/cose.xhtml

OscoreError hkdf_info_len(array id, array id_context, enum aead_algorithm aead_alg, enum derive_type type, size_t* out) {
    CborEncoder enc;
    cbor_encoder_init(&enc, NULL, 0, 0);
    CborEncoder array_enc;
    char* type_enc;
    u64_t l;
    switch (type) {
        case KEY:
            type_enc = "KEY";
            l = 16;
            break;
        case IV:
            type_enc = "IV";
            l = 13;
            break;
        default:
            panic("This can't happen");
    }
    try_cbor_oom(cbor_encoder_create_array(&enc, &array_enc, 5));
    try_cbor_oom(cbor_encode_byte_string(&array_enc, id.ptr, id.len));
    if (id_context.ptr == NULL) {
        try_cbor_oom(cbor_encode_null(&array_enc));
    } else {
        try_cbor_oom(cbor_encode_byte_string(&array_enc, id_context.ptr, id_context.len));
    }
    try_cbor_oom(cbor_encode_int(&array_enc, aead_alg));
    try_cbor_oom(cbor_encode_text_stringz(&array_enc, type_enc));
    try_cbor_oom(cbor_encode_uint(&array_enc, l));
    try_cbor_oom(cbor_encoder_close_container(&enc, &array_enc));
    *out = cbor_encoder_get_extra_bytes_needed(&enc);
    return OscoreNoError;
}

OscoreError create_hkdf_info(array id, array id_context, enum aead_algorithm aead_alg, enum derive_type type, array out) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out.ptr, out.len, 0);
    CborEncoder array_enc;
    char* type_enc;
    u64_t l;
    switch (type) {
        case KEY:
            type_enc = "Key";
            l = 16;
            break;
        case IV:
            type_enc = "IV";
            l = 13;
            break;
        default:
            panic("This can't happen");
    }
    try_cbor(cbor_encoder_create_array(&enc, &array_enc, 5));
    try_cbor(cbor_encode_byte_string(&array_enc, id.ptr, id.len));
    if (id_context.ptr == NULL) {
        try_cbor(cbor_encode_null(&array_enc));
    } else {
        try_cbor(cbor_encode_byte_string(&array_enc, id_context.ptr, id_context.len));
    }
    try_cbor(cbor_encode_int(&array_enc, aead_alg));
    try_cbor(cbor_encode_text_stringz(&array_enc, type_enc));
    try_cbor(cbor_encode_uint(&array_enc, l));
    try_cbor(cbor_encoder_close_container(&enc, &array_enc));
    return OscoreNoError;
}

