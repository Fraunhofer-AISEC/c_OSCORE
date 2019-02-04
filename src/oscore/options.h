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

#ifndef NONE_OSCORE_OPTIONS_H
#define NONE_OSCORE_OPTIONS_H

#include <net/coap.h>
#include "../util/array.h"
#include "../util/error.h"

enum option_class {
    // handled specially
//    CLASS_U,
    CLASS_I,
    CLASS_E,
};

/**
 * Returns whether the CoAP Option with given `code` is a Class E Option (encrypted)
 * @param code CoAP Option's code
 * @return true if the option is a Class E Option
 */
bool is_class_e(u16_t code);
/**
 * Returns whether the CoAP Option with given `code` is a Class U Option (unprotected)
 * @param code CoAP Option's code
 * @return true if the option is a Class U Option
 */
bool is_class_u(u16_t code);
/**
 * Returns whether the CoAP Option with given `code` is a Class I Option (integrity protected)
 * @param code CoAP Option's code
 * @return true if the option is a Class I Option
 */
bool is_class_i(u16_t code);
/**
 * Converts a `option_class` to the function that tests if a given CoAP Option code belongs to that class.
 * @param class `option_class` to get test-function for.
 * @return Function testing if a given CoAP Option code belongs to given class
 */
bool (*class_to_condition(enum option_class class))(u16_t code);

/**
 * Given a value from the CoAP option header returns the length of the possibly following extended field.
 * @param value Value within the CoAP Option header
 * @return Length of the possibly following extended field
 */
u8_t option_field_len(u16_t value);

/**
 * Returns the first instance of the option matching given code. There might be more, but this function will only ever
 * return the first instance.
 * @param options List of CoAP Options
 * @param opt_num Number of CoAP Options in that list
 * @param code CoAP Option's Code to find value for
 * @return Option's value, or NULL_ARRAY otw.
 */
array get_option_value(struct coap_option* options, u8_t opt_num, u16_t code);
/**
 * Returns the number of options contained in the given encoded option array until the payload marker or end of array
 * is reached.
 * @param options Byte-Array containing the encdoded options
 * @return OscoreError
 */
OscoreError num_options(array options, u16_t* out);
/**
 * Parses the passed options until the payload marker of end of array and writes them into @a out.
 * Returns the number of parsed options and writes the number of bytes consumed into @a offset_out.
 * If @a out is NULL, this function doesn't write parsed options, but still returns the number of options.
 * @param options
 * @param out Out-array. Must be at least `num_options(...)` long or NULL.
 * @param offset_out Pointer to write byte-length of options into. Can be NULL.
 * @return OscoreError
 */
OscoreError decode_options(array options, struct coap_option* out, u16_t* offset_out);
/**
 * Returns the length in bytes of the serialized options of given class.
 * @param options CoAP Option array containing all options (possibly including ones of other classes)
 * @param opt_num Number of CoAP options in @a options.
 * @param class Class of the options to encode
 * @return length in bytes
 */
u32_t encoded_option_len(struct coap_option* options, u16_t opt_num, enum option_class class);
/**
 * Encodes all options in given array having given class.
 * @param options CoAP Option array containing all options (possibly including ones of other classes)
 * @param opt_num Number of CoAP options in @a options.
 * @param class Class of the options to encode
 * @param out out-pointer. Must be at least `encoded_option_len(...)` bytes long.
 * @return encoded length in bytes
 */
u32_t encode_options(struct coap_option* options, u16_t opt_num, enum option_class class, u8_t* out);

#endif //NONE_OSCORE_OPTIONS_H
