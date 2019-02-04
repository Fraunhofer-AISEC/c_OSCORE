# c_OSCORE

This is a partial OSCORE (draft version 14) Proof of Concept Server implementation
on top of Zephyr OS for the 96Boards Nitrogen.
The ipsp and coap_server samples of zephyr are combined to set up CoAP over 6lowpan over Bluetooth.
On top of that OSCORE is implemented.

Developed and tested with zephyr commit
[3712fd34154f0db06085135e4bbfed4b63c34d85](https://github.com/zephyrproject-rtos/zephyr/commit/3712fd34154f0db06085135e4bbfed4b63c34d85).

* [Building](#building)
* [Documentation / Doxygen](#documentation--doxygen)
* [Structure](#structure)
    * [Folders](#folders)
    * [Error Handling](#error-handling)
        * [Assertions / Ensure](#assertions--ensure)
    * [Packet Flow](#packet-flow)
* [Quick Overview over OSCORE](#quick-overview-over-oscore)
    * [OSCORE Packet](#oscore-packet)
        * [CoAP Packet](#coap-packet)
            * [CoAP Options](#coap-options)
        * [OSCORE Option](#oscore-option)
        * [OSCORE Ciphertext](#oscore-ciphertext)
            * [OSCORE Nonce](#oscore-nonce)
            * [OSCORE Plaintext](#oscore-plaintext)
            * [OSCORE COSE Object](#oscore-cose-object)
            * [OSCORE AAD](#oscore-aad)
* [Future Work](#future-work)
* [Licensing](#licensing)
* [Contribution](#contribution)

# Building

The arm-none-eabi-gcc toolchain must be installed.
On archlinux, this can be done with `aurman -S arm-none-eabi-gcc`.

The zephyr repository must be accessible locally.
It can be cloned with `git clone https://github.com/zephyrproject-rtos/zephyr`.

Before building, set the variables in the first few lines of [`CMakeLists.txt`](CMakeLists.txt).

* `ZEPHYR_BASE`: Base directory of the zephyr repository.
* `GCCARMEMB_TOOLCHAIN_PATH`: Directory which contains the `bin` directory which contains
   `arm-none-eabi-*` tools.
   On arch that's `/usr/`.
* `ZEPHYR_TOOLCHAIN_VARIANT`: Toolchain to use, e.g. `gccarmemb`.
* `BOARD`: The board to compile for, e.g. `96b_nitrogen`.

After setting the variables, execute the following:

```sh
mkdir build && cd build
cmake ..
make
```

Then flash the file `build/zephyr/zephyr.hex`.

# Documentation / Doxygen

Execute `doxygen` to generate the documentation of all functions in this project.
This will also render the callgraphs of all functions which should be used to
navigate the code easilier.
Unfortunately the callgraph doesn't include imported functions from zephyr.

# Structure

While the entrypoint is `main.c`, it only sets up the CoAP server in the kernel.
The kernel then calls `server/coap-server.c:udp_receive` for every packet, which parses parts of the CoAP packet
and calls the kernel API to select the correct resource (from `resources.h`).
In that function the existence of the OSCORE Option is checked.
If it is set, `oscore/oscore.c:from_oscore` is called, which decrypts the packet, builds a new unencrypted package
and unrefs the original package.

Currently, there is only one experimental backend API for OSCORE, written in `server/oscore_post.c`.
It performs the same as `server/coap-server.c:piggyback_get`, except that it converts the
produced CoAP packet into an OSCORE packet by calling `oscore/oscore.c:into_oscore`.
The function `into_oscore` creates a new, encrypted packet and unrefs the unencrypted one.

## Folders

* `codec`: Handles encoding and decoding of the AAD, HKDF-Info, nonce, and the OSCORE CoAP Option value.
* `crypto`: Provides tinycrypt's AES with a nice API.
  Implements HKDF based on tinycrypt's hmac_sha256.
  Implements derivation functions for the OSCORE Security-Contexts.
  Implements Enc_Structure and COSE_Encrypt0 (OSCORE compressed) encoding and encryption.
* `oscore`: Implements the OSCORE → CoAP and CoAP → OSCORE Packet conversion.
  Includes CoAP-URI parsing and construction according to OSCORE spec and some other CoAP helpers.
* `server`: OSCORE API implementation. Zephyr setup of CoAP Server and 6LoWPAN over Bluetooth.
* `util`: Contains `array` data structure, error handling 

## Error Handling

All possible errors are defined in the `CborError` enum in `error.h`.
Every function that can produce an error returns a `CborError`.
If a function returns data other than an error, they returned via output parameters,
which are the last parameters of a function.

The `CborError` is bubbled up until the functions calling `{from,into}_oscore`, which need to return
a different error.

There are several `try*` macros, which make the bubbling-up process easier.
Those macros evaluate the given expression, check if the expression resulted in an error code
in the respective context and return the corresponding `CborError`.
If the operation succeeded, execution is continued.

In order to get a poor-man's stack trace, all try functions log at warn-level.
The log message contains the file, line number, and original error code, to
enable easier debugging by providing a somewhat helpful error trace.

There are the following `try*` macros:

* `try_tc`: Try a tinycrypt operation, checking for `TC_CRYPTO_SUCCESS`.
    Returns `OscoreTinyCryptError` if the operation didn't succeed.
* `try_cbor`: Try a tinycbor operation, checking for `CborNoError`.
    Returns `OscoreCborError` if the operation failed.
* `try_cbor_oom`: Try a tinycbor operation, checking for `CborErrorOutOfMemory`.
    Returns `OscoreCborError` if anything else is returned.
    This is used to find out the length of a CBOR-encoded payload.
* `try_http_parser`: Try a `http_parser_parse_url` operation,
    returning `OscoreUriHttpParserError` if it fails.
* `try`: Try an operation returning an `OscoreError`, checking for `OscoreNoError`.
    Returns the found error.
    
### Assertions / Ensure

Assertions are used to check for logic guarantees, which should always
hold throughout the code.
The provided `assert` macro is a noop, which is why we created a custom
`assert_actually` macro (and derivatives like `assert_eq`).
These macros check their input, logging an error message and spinning if it isn't met.
They should only be used for unrecoverable logic failures.

For user errors or recoverable bugs, the `ensure` macro family should be used.
Those macros take a `CborError` as last parameter, which is returned if the condition is not met.

## Packet Flow

```
+-------------+    +-------------+    +-------------+    +-------------+    +--------------------+
| udp_receive |--->| from_oscore |--->| oscore_post |--->| into_oscore |--->| net_context_sendto |
+-------------+    +-------------+    +-------------+    +-------------+    +--------------------+
```

* `server/coap_server.c:udp_receive`
    * Check if packet contains OSCORE Option
    * If yes, decrypt packet, creating "normal" CoAP packet (`from_oscore`)
    * Pass packet to routing API
* `oscore/oscore.c:from_oscore`
    * Parse OSCORE option
    * Read payload
    * Create nonce
    * Create AAD
    * Decrypt payload
    * Decode options
    * Create output packet header
    * Merge unprotected and decrypted options
    * Copy payload
* `server/oscore_post:oscore_post`
    * Parse packet
    * Create unencrypted response packet (`"Hello World"`)
    * Pass packet to `into_oscore`
    * Send off OSCORE packet (zephyr's `net_context_sendto`)
* `oscore/oscore:into_oscore`
    * Get request packet's OSCORE option (to create nonce from)
    * Create nonce
    * Parse Options
    * Create AAD (including Class I options)
    * Encrypt payload (including Class E opitons)
    * Create OSCORE option
    * Create output packet header
    * Write Class U options
    * Copy encrypted payload
    
# Quick Overview over OSCORE

### OSCORE Packet

* [CoAP Packet](#coap-packet) with [OSCORE Option](#oscore-option)
    and [OSCORE Ciphertext](#oscore-ciphertext) as Payload


##### CoAP Packet

* <https://tools.ietf.org/html/rfc7252#section-3>

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver| T |  TKL  |      Code     |          Message ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Token (if any, TKL bytes) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Options (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 1 1 1 1 1 1 1|    Payload (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

###### CoAP Options

* <https://tools.ietf.org/html/rfc7252#section-3.1>

```
  0   1   2   3   4   5   6   7
+---------------+---------------+
|  Option Delta | Option Length |   1 byte
+---------------+---------------+
.         Option Delta          .   0-2 bytes
.          (extended)           .
+-------------------------------+
.         Option Length         .   0-2 bytes
.          (extended)           .
+-------------------------------+
.         Option Value          .   0 or more bytes
.                               .
+-------------------------------+
```

##### OSCORE Option

* <https://tools.ietf.org/html/draft-ietf-core-object-security-14#section-6.1>

```
 0 1 2 3 4 5 6 7 <------------- n bytes -------------->
+-+-+-+-+-+-+-+-+--------------------------------------
|0 0 0|h|k|  n  |       Partial IV (if any) ...
+-+-+-+-+-+-+-+-+--------------------------------------

 <- 1 byte -> <----- s bytes ------>
+------------+----------------------+------------------+
| s (if any) | kid context (if any) | kid (if any) ... |
+------------+----------------------+------------------+
```

##### OSCORE Ciphertext

* AES-CCM-16-64-128 
    * 8 byte mac
    * 13 byte nonce
* Key: Sender Key
* Nonce: [OSCORE Nonce](#oscore-nonce)
* Plaintext: [OSCORE Plaintext](#oscore-plaintext)
* AAD: [OSCORE COSE Object](#oscore-cose-object)

###### OSCORE Nonce

* <https://tools.ietf.org/html/draft-ietf-core-object-security-14#section-5.2>

```
     <- nonce length minus 6 B -> <-- 5 bytes -->
+---+-------------------+--------+---------+-----+
| S |      padding      | ID_PIV | padding | PIV |----+
+---+-------------------+--------+---------+-----+    |
                                                      |
 <---------------- nonce length ---------------->     |
+------------------------------------------------+    |
|                   Common IV                    |->(XOR)
+------------------------------------------------+    |
                                                      |
 <---------------- nonce length ---------------->     |
+------------------------------------------------+    |
|                     Nonce                      |<---+
+------------------------------------------------+
```


###### OSCORE Plaintext

* <https://tools.ietf.org/html/draft-ietf-core-object-security-14#section-5.3>

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |    Class E options (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 1 1 1 1 1 1 1|    Payload (if any) ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 (only if there
   is payload)
```

###### OSCORE COSE Object

* <https://tools.ietf.org/html/draft-ietf-core-object-security-14#section-5>
* Enc-Structure
* CBOR encoded as array

```
+----------------------+
| Context ("Encrypt0") |
+----------------------+
|    Protected ("")    |
+----------------------+
|     external_aad     | (see OSCORE AAD)
+----------------------+
```

###### OSCORE AAD

* <https://tools.ietf.org/html/draft-ietf-core-object-security-14#section-5.4>
* CBOR encoded as array

```
+-------------------------+
|    OSCORE Version (1)   |
+-------------------------+
| Algorithms ([alg_aead]) |
+-------------------------+
|       request_kid       |
+-------------------------+
|       request_piv       |
+-------------------------+
|      Class I Options    |
+-------------------------+
```

# Future Work

There are several TODOs in the code, which mark optional and unimplemented features and possible cleanup.
Additionally, there are some ideas which are not implemented yet, but might be of value.
Here is an (incomplete) list of TODOs and ideas:

1. Support multiple Security Contexts. Currently only a single sender (the server) and receiver (the client) are supported.
    This allows multiple clients to connect to the server.
1. Volatile memset `sender_key` and `receiver_key` after they are used and recalculate them just before use.
    That way the keys are in memory only for a short time.
    At the same time, the keys can easily be calculated from the pre-established data, so this is probably irrelevant.

# Licensing

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option with parts copyrighted by the Intel Corporation under the Apache License (Version 2.0).
For more information see [COPYRIGHT.md](COPYRIGHT.md).

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by
you shall be dual licensed as above, without any additional terms or conditions.
