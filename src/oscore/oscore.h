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

#ifndef NONE_OSCORE_H
#define NONE_OSCORE_H

#include <sys_io.h>
#include <net/coap.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/ccm_mode.h>
#include "../util/array.h"
#include "../crypto/security_context.h"


extern u8_t MASTER_SECRET[16];
extern u8_t SENDER_ID[1];
extern u8_t RECIPIENT_ID[0];
extern struct pre_established PRE_ESTABLISHED;

// TODO: temporary assignment to comply with oscore_californium and aiocoap
static const int COAP_OPTION_OSCORE = 9;

/**
 * Initializes the security contexts given the pre-established data.
 * This function must be called before invoking `into_oscore` or `from_oscore`.
 * It should be called once during app initialisaiton.
 * @param pre_established pre-established data
 * @return OscoreError
 */
OscoreError oscore_init(struct pre_established pre_established);
// There are two ways of implementing oscore transformation. The first is to make the user build the packet
// with a custom API similar to how coap-packets are built. That would be rather fast but require the user
// to rewrite everything if they have already implemented a coap handler.
// The second way is to transform an existing already built coap message into an oscore message.
// This is easier to integrate for the user as he simply needs to call the transformation function
// with the built object. But that method has more overhead because first the coap message needs to be build,
// then parsed again, an internal plaintext buffer needs to be allocated and encrypted and the new coap (oscore)
// needs to be allocated and filled.
// Nevertheless this is an implementation of the second way for simplicity and easier integration.
//
// Observer is not supported ("Observe [RFC7641] is an optional feature")
// TODO: support Observer

/**
 * Decrypts an OSCORE coap_packet and transforms it into a CoAP packet
 * @param request Packet to decrypt
 * @param out out-pointer which will contain the decrypted CoAP packet
 * @return OscoreError
 */
OscoreError from_oscore(struct coap_packet request, struct coap_packet* out);

/**
 * Encrypts a coap_packet and converts it to its OSCORE form
 * @param response Packet to encrypt. The packet will be consumed and freed.
 * @param request Original request packet
 * @param out out-pointer which will contain the transformed OSCORE packet
 * @return OscoreError
 */
OscoreError into_oscore(struct coap_packet response, struct coap_packet* request, struct coap_packet* out);

#endif //NONE_OSCORE_H
