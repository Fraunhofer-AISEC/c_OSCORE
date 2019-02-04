Apart from the exceptions documented below, the c_OSCORE project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

The OSCORE implementation in c_OSCORE is the work of the Fraunhofer AISEC.
It is based and written on the zephyr embedded operating system and uses some APIs provided by zephyr.

c_OSCORE includes and merges two examples found in the zephyr project to build a fully running
OSCORE implementation on CoAP over 6LoWPAN over Bluetooth.
The zehpyr version used is commit [`8b9042c4192e1625744eb3b7fe60bc82ac6f336d`](https://github.com/zephyrproject-rtos/zephyr/tree/8b9042c4192e1625744eb3b7fe60bc82ac6f336d).
The original examples used, `ipsp` and `coap-server`, are released under the
Apache License (Version 2.0) Copyright (c) 2016 Intel Corporation.
The files in this project falling under that Apache License (Version 2.0) with their respective changes are
marked as such in their respective copyright headers.
The exact list of performed changes are:

* `src/server/ipsp.{c,h}` (from `samples/bluetooth/ipsp/src/main.c`),
    * Renamed `main` to `ipsp_init`
    * Removed topmost comment about that file being the entrypoint
    * Exported `ipsp_init` declaration in `ipsp.h`
* `src/server/{coap-server.{c,h},resources.h}` (from `samples/net/coap_server/src/coap-server.c`)
    * Made private methods public
    * Exported public method declarations in `coap-server.h`
    * Renamed `main` to `coap_server_init`
    * Added glue-code to decrypt OSCORE messages before routing
    * Added required includes
    * Extracted `resources` into `resources.h`
    * Added OSCORE API path to `resources`
* `src/server/oscore_post.{c,h}`
    * Copied over from `samples/net/coap_server/src/coap-server.c:piggyback_get`
    * Modified to build correct packet payload for OSCORE tests
    * Use macro for error checking
    * Transform resulting packet to OSCORE
    * Create header file with function signature
* `prj.conf` (from `samples/bluetooth/ipsp/prj.conf` and `samples/net/coap_server/prj.conf`)
    * Merged prjs of both projects
    * Added required libraries for OSCORE
    * Modified some settings (like STACK_SIZE variables)
* `CMakeLists.txt` (from `samples/net/coap_server/CMakeLists.txt`)
    * Added / extracted variables for easier use
    * Glob files from subdirectories
    * Add tinycbor

All other files are written by the Fraunhofer AISEC and follow the licensing stated at the beginning of this file.
