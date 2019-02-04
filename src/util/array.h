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

#ifndef NONE_ARRAY_H
#define NONE_ARRAY_H

#include <stdbool.h>
#include <stddef.h>
#include <zephyr/types.h>

/// Array with pointer and length.
typedef struct array {
    size_t len;
    u8_t* ptr;
} array;

/// Empty Array with len=0 but with a non-null pointer.
array EMPTY_ARRAY;

/// Null Array with len=0 and a null pointer.
array NULL_ARRAY;

/**
 * Compares if the given two arrays have an equal content.
 *
 * Handles null-arrays correctly
 * @param left first array
 * @param right second array
 * @return if the contents of given arrays are equal
 */
bool array_equals(array left, array right);

#endif //NONE_ARRAY_H
