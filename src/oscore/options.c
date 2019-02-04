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

#include "options.h"
#include "oscore.h"

bool is_class_e(u16_t code) {
    // blacklist, because OSCORE dictates that unknown options SHALL be processed as class E
    return code != COAP_OPTION_URI_HOST
           && code != COAP_OPTION_URI_PORT
           && code != COAP_OPTION_OSCORE
           && code != COAP_OPTION_PROXY_URI
           && code != COAP_OPTION_PROXY_SCHEME;
}

bool is_class_u(u16_t code) {
    return code == COAP_OPTION_URI_HOST
           || code == COAP_OPTION_OBSERVE
           || code == COAP_OPTION_URI_PORT
           || code == COAP_OPTION_OSCORE
           // "A server MAY set a Class U Max-Age message field with value zero to OSCORE error responses"
           //           || code == COAP_OPTION_MAX_AGE
           // "In this case the Block options SHALL be processed by OSCORE as normal Inner Options"
           //           || code == COAP_OPTION_BLOCK2
           //           || code == COAP_OPTION_BLOCK1
           //           || code == COAP_OPTION_SIZE2
           //           || code == COAP_OPTION_SIZE1
           || code == COAP_OPTION_PROXY_URI
           || code == COAP_OPTION_PROXY_SCHEME
           || code == 258; // No-Response
}

bool is_class_i(u16_t code) {
    // "Note: There are currently no Class I option message fields defined."
    return false;
}

bool (*class_to_condition(enum option_class class))(u16_t code) {
    switch (class) {
//        case ClassU:
//            return is_class_u;
        case CLASS_I:
            return is_class_i;
        case CLASS_E:
            return is_class_e;
        default:
            panic("Didn't expect Class U options as they are handled somewhere else");
    }
}

u8_t option_field_len(u16_t value) {
    if (value < 13) {
        return 0;
    } else if (value < 269) {
        return 1;
    } else {
        return 2;
    }
}

array get_option_value(struct coap_option* options, u8_t opt_num, u16_t code) {
    u16_t total_delta = 0;
    for (int i = 0; i < opt_num; i++) {
        total_delta += options[i].delta;
        if (code == total_delta) {
            array ret = {
                .len = options[i].len,
                .ptr = &options[i].value[0],
            };
            return ret;
        }
    }
    return NULL_ARRAY;
}

/**
 * Possibly reads the extended field and saves it into the value. Doesn't overwrite the value parameter if there is no
 * extended field.
 * @param input Pointer to the possible extended field
 * @param field_len length of the extended field
 * @param value out-parameter. Will only be overwritten if @a field_len is greater than 0.
 */
static void read_field(u8_t* input, u16_t field_len, u16_t* value) {
    if (field_len != 0) {
        if (field_len == 1) {
            *value = (u16_t)(input[0] + 13);
        } else if (field_len == 2) {
            u32_t d = ((u32_t)input[0] << 8) + (u32_t)input[1] + 269;
            // TODO: find out actual max-length of option values allowed
            //       zephyr only allows u16_t as option value length and by default only has 12 bytes option value
            assert_actually(d < UINT16_MAX, "not sure if this is an actual assumption we can make");
            *value = (u16_t)d;
        } else {
            panic("unreachable");
        }
    }
}

//      0   1   2   3   4   5   6   7
//   +---------------+---------------+
//   |  Option Delta | Option Length |   1 byte
//   +---------------+---------------+
//   .         Option Delta          .   0-2 bytes
//   .          (extended)           .
//   +-------------------------------+
//   .         Option Length         .   0-2 bytes
//   .          (extended)           .
//   +-------------------------------+
//   .         Option Value          .   0 or more bytes
//   .                               .
//   +-------------------------------+

/**
 * Performs actual CoAP Option decoding. Look at the documentation of `decode_options` and `num_options`.
 */
static OscoreError decode_options_internal(array options, struct coap_option* out, u16_t* offset_out, u16_t* num_out) {
    u16_t num = 0;
    u16_t offset = 0;
    while (offset < options.len && options.ptr[offset] != 0xff) {
        // first byte
        u8_t first = options.ptr[offset];
        u16_t delta = (u8_t)((u8_t)(first & 0xf0) >> 4);
        u8_t delta_len = option_field_len(delta);
        u16_t len = (u8_t)(first & 0x0f);
        u8_t len_len = option_field_len(len);
        ensure(options.len >= offset + 1 + delta_len + len_len, OscoreInvalidOptionLength);
        offset += 1;

        // delta
        read_field(&options.ptr[offset], delta_len, &delta);
        offset += delta_len;

        // length
        read_field(&options.ptr[offset], len_len, &len);
        offset += len_len;

        ensure(options.len >= offset + len, OscoreInvalidOptionLength);
        if (out != NULL) {
            if (len > sizeof(out[num].value)) {
                SYS_LOG_WRN("cropping CoAP option %d length from %zu to %zu bytes", delta, len, sizeof(out[num].value));
            }
            out[num].delta = delta;
            out[num].len = min(sizeof(out[num].value), len);
            memcpy(&out[num].value[0], &options.ptr[offset], out[num].len);
        }
        num += 1;
        offset += len;
    }
    if (offset_out != NULL) {
        *offset_out = offset;
    }
    if (num_out != NULL) {
        *num_out = num;
    }
    return OscoreNoError;
}


OscoreError num_options(array options, u16_t* out) {
    return decode_options_internal(options, NULL, 0, out);
}

// parse_options of coap.h is private, thus we need to reimplement it.
// In fact we need to reimplement it anyways because we need a way to just get the number of options (see `num_options`)
OscoreError decode_options(array options, struct coap_option* out, u16_t* offset_out) {
    return decode_options_internal(options, out, offset_out, NULL);
}


u32_t encoded_option_len(struct coap_option* options, u16_t opt_num, enum option_class class) {
    bool (*condition)(u16_t) = class_to_condition(class);
    u32_t len = 0;
    u16_t total_delta = 0;
    for (int i = 0; i < opt_num; i++) {
        total_delta += options[i].delta;
        u16_t code = total_delta;
        if (!condition(code)) {
            continue;
        }

        len += 1 + option_field_len(options[i].delta) + option_field_len(options[i].len) + options[i].len;
    }
    return len;
}

u32_t encode_options(struct coap_option* options, u16_t opt_num, enum option_class class, u8_t* out) {
    bool (*condition)(u16_t) = class_to_condition(class);

    u32_t index = 0;
    u16_t skipped_delta = 0;
    for (int i = 0; i < opt_num; i++) {
        // skip options which aren't of requested class
        u16_t delta = options[i].delta + skipped_delta;
        if (!condition(delta)) {
            skipped_delta += options[i].delta;
            continue;
        }
        skipped_delta = 0;

        struct coap_option option = options[i];

        // special cases
        // Class E:
        //   * Max-Age: inner: normal inner processing
        //   * Proxy-Uri: covered by Uri-Path and Uri-Query
        //   * Block Options: normal inner processing
        //   * Observe: TODO
        //   * No-Response: normal inner processing

        u16_t length = option.len;
        u8_t delta_length_field = 0;
        u8_t delta_len = option_field_len(delta);
        u8_t length_len = option_field_len(length);
        // TODO: refactor to remove code duplication
        // delta
        if (delta_len == 0) {
            delta_length_field |= delta << 4;
        } else if (delta_len == 1) {
            delta_length_field |= 13 << 4;
            out[index + 1] =  (u8_t)(delta - 13);
        } else {
            assert_eq(delta_len, 2);
            delta_length_field |= 14 << 4;
            out[index + 1] = (u8_t)(((delta - 269) >> 8) & 0xff);
            out[index + 2] = (u8_t)(((delta - 269) >> 0) & 0xff);
        }
        // length
        if (length_len == 0) {
            delta_length_field |= length;
        } else if (length_len == 1) {
            delta_length_field |= 13;
            out[index + delta_len + 1] =  (u8_t)(length - 13);
        } else {
            assert_eq(length_len, 2);
            delta_length_field |= 14;
            out[index + delta_len + 1] = (u8_t)(((length - 269) >> 8) & 0xff);
            out[index + delta_len + 2] = (u8_t)(((length - 269) >> 0) & 0xff);
        }
        out[index] = delta_length_field;
        index += 1 + delta_len + length_len;
        // value
        memcpy(&out[index], &option.value[0], length);
        index += length;
    }
    return index;
}

