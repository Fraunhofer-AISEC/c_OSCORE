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

#if 1
#define SYS_LOG_DOMAIN "main"
#define SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <net/net_pkt.h>

#include "main.h"
#include "tests.h"
#include "server/coap-server.h"
#include "server/ipsp.h"
#include "oscore/oscore.h"
#include "util/macros.h"


// TODO: Support multiple security contexts
// TODO: Select correct security context based on ID Context in the request
void main(void) {
    SYS_LOG_INF("main started");
    test_hkdf_sha256_tc1();
    test_hkdf_sha256_tc2();
    test_derive_sender_key();
    test_derive_recipient_key();
    test_derive_common_iv();

    assert_eq(oscore_init(PRE_ESTABLISHED), OscoreNoError);
    coap_server_init();
    ipsp_init();
}
