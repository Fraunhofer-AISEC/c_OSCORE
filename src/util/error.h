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

#ifndef NONE_ERROR_H
#define NONE_ERROR_H

#include <tinycrypt/constants.h>
#include <logging/sys_log.h>
#include <cbor.h>

/**
 * Error type used throughout the whole oscore implementation.
 *
 * Every function that might error returns an OscoreError and writes its return value into an out-parameter.
 * The `try` macro can be used to bubble up this error.
 */
typedef enum OscoreError {
    OscoreNoError = 0,
    OscoreCborError = 1,
    OscoreTinyCryptError = 2,

    OscoreInvalidIvLength = 256,
    OscoreInvalidKeyLength = 257,
    OscoreInvalidOptionLength = 258,
    OscoreInvalidPartialIvLength = 259,
    OscoreInvalidKidLength = 260,
    OscoreInvalidKidContextLength = 261,
    OscoreInvalidKid = 262,
    OscoreInvalidIvUntrimmed = 263,
    OscoreOutTooLong = 264,
    OscoreKidContextError = 265,
    OscoreInvalidOutLength = 266,
    OscorePayloadNoPayloadMarker = 267,

    OscoreUriHttpParserError = 512,
    OscoreUriInvalidProtocol = 513,
    OscoreUriInvalidFragment = 514,
    OscoreCoapPacketInitError = 515,
    OscoreCoapPacketAppendError = 516,
    OscoreNetPacketAppendError = 517,
    OscoreNetPacketReadError = 518,

    OscoreCoapPacketParseError = 768,
    OscoreCoapPacketNoPayload = 769,
    OscoreNoOscoreOption = 770,
    OscoreInvalidVersion = 771,
    OscoreInvalidType = 772,
    OscoreInvalidTokenLength = 773,

    OscorePktError = 1024,
} OscoreError;

/// Logs a message prepended with the filename and line at warn level
#define warn(msg, ...) SYS_LOG_WRN("%s:%d: "msg, __FILE__, __LINE__, ##__VA_ARGS__)
/// Logs a message prepended with the filename and line at error level
#define err(msg, ...) SYS_LOG_ERR("%s:%d: "msg, __FILE__, __LINE__, ##__VA_ARGS__)

/// Try a TinyCrypt operation, returning from the function with OscoreTinyCryptError if it errored.
#define try_tc(e) do {\
    int res = (e);\
    if (res != TC_CRYPTO_SUCCESS) {\
        warn("Error during TinyCrypt execution: %d", res);\
        return OscoreTinyCryptError;\
    }\
} while (0)

/// Try a TinyCbor operation, returning from the function with OscoreCborError if it errored.
#define try_cbor(e) do {\
    int res = (e);\
    if (res != CborNoError) {\
        warn("Error during TinyCbor execution: %d", res);\
        return OscoreCborError;\
    }\
} while (0)

/**
 * Try a TinyCbor operation, returning from the function with OscoreCborError if it didn't produce CborErrorOutOfMemory.
 *
 * This is useful for getting an encoded buffer's length before allocating it and encoding into it.
 */
#define try_cbor_oom(e) do {\
    int res = (e);\
    if (res != CborErrorOutOfMemory) {\
        warn("Error during TinyCbor execution, expected CborErrorOurOfMemory, got %d", res);\
        return OscoreCborError;\
    }\
} while (0)

/**
 * Try a `http_parser_parse_url` operation, returning from the function with OscoreUriHttpParserError if it
 * returned a nonzero value.
 */
#define try_http_parser(e) do {\
    int res = (e);\
    if (res != 0) {\
        warn("Error during http_parser: %d", res);\
        return OscoreUriHttpParserError;\
    }\
} while (0)

/**
 * Try an operation returning an `OscoreError`.
 *
 * Propagates error case up to the callee.
 */
#define try(e) do {\
    int res = (e);\
    if (res != OscoreNoError) {\
        warn("Error during execution: %d", res);\
        return res;\
    }\
} while (0)

/// internal macro used by `ensure*` methods
#define ensure_internal(e, msg, error, ...) do {\
    if (!(e)) {\
        warn("Ensure `" #e "` failed with `" msg "`", ##__VA_ARGS__);\
        return error;\
    }\
} while (0)

/// Ensure an assumption, returning the passed error if isn't met.
#define ensure(e, error) ensure_internal(e, "false", error)

/// Ensure that two values are equal, returning the passed error if it failed.
#define ensure_eq(l, r, error) do {\
    int left = (l);\
    int right = (r);\
    ensure_internal((left == right), "(%d == %d)", error, left, right);\
} while (0)

/// Log an error message and start spinning afterwards.
#define panic(msg, ...) do {\
    err(msg ", spinning...", ##__VA_ARGS__);\
    while (1) {}\
} while (0)

// the provided assert is a noop
/// Assert an expression, panicking if it isn't met.
#define assert_actually(e, msg, ...) do {\
    if (!(e)) {\
        panic("assertion failed: `" #e "` with \"" msg "\"", ##__VA_ARGS__);\
    }\
} while(0)

/// Assert that two values are equal, panicking if it isn't the case.
#define assert_eq(e1, e2) do {\
    assert_actually((e1) == (e2), "not equal");\
} while(0)

/// Assert that two values are different, panicking if they are equal.
#define assert_ne(e1, e2) do {\
    assert_actually(e1 != e2, "not not equal");\
} while(0)

/// Panicks if the passed OscoreError is not a success.
#define assert_no_error(e) do {\
    if ((e) != OscoreNoError) { panic("Got error %d", e); }\
} while (0)

#endif //NONE_ERROR_H
