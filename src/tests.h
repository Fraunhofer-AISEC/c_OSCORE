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

#ifndef NONE_TESTS_H
#define NONE_TESTS_H

/// RFC5869 Test Vectors: Test Case 1
void test_hkdf_sha256_tc1();
/// RFC5869 Test Vectors: Test Case 2
void test_hkdf_sha256_tc2();
/// draft-ietf-core-object-security-14: Test Vector 1: Key Derivation with Master Salt: Server
void test_derive_sender_key();
/// draft-ietf-core-object-security-14: Test Vector 1: Key Derivation with Master Salt: Server
void test_derive_recipient_key();
/// draft-ietf-core-object-security-14: Test Vector 1: Key Derivation with Master Salt: Server
void test_derive_common_iv();

#endif //NONE_TESTS_H
