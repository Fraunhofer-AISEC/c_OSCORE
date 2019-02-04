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

#ifndef NONE_COAP_HELPER_H
#define NONE_COAP_HELPER_H

#include <net/coap.h>
#include "../util/error.h"
#include "../util/array.h"

/**
 * Parses CoAP Options from given packet.
 * @param pkt Packet to parse CoAP Options from.
 * @param options Option-array to parse into.
 * @param opt_num Length of option-array @a options.
 * @return OscoreError
 */
OscoreError get_options(struct coap_packet* pkt, struct coap_option* options, u8_t* opt_num);

struct payload_info {
    u16_t offset;
    u16_t len;
    struct net_buf* frag;
};

/**
 * Get info about the position and length of a packet's payload (without headers)
 * @param pkt Packet to get payload from.
 * @param info out-pointer to write payload info into (must have memory allocated with it).
 * @return OscoreError
 */
OscoreError get_payload_info(struct coap_packet* pkt, struct payload_info* info);

/**
 * Read the packet's payload into the output-array.
 * @param info Payload info as retrieved from `get_payload_info`.
 * @param payload Array with a length of `payload_info.len`, which the payload will be written to.
 * @return OscoreError
 */
OscoreError read_payload(struct payload_info info, array payload);

#endif //NONE_COAP_HELPER_H
