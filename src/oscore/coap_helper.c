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

#include <net/udp.h>
#include "coap_helper.h"

OscoreError get_options(struct coap_packet* pkt, struct coap_option* options, u8_t* opt_num) {
    // we need to distinguish between actually parsed options and untouched ones to find out the actual opt_num
    for (int i = 0; i < *opt_num; i++) {
        // "The option numbers between 65000 and 65535 inclusive are reserved for experiments.
        //  They are not meant for vendor-specific use of any kind and MUST NOT be used in operational deployments." (RFC7252)
        // We are just going to assign these numbers as delta.
        // If they are still that number after parsing, they haven't been touched.
        // The delta actually represents the difference between the last occurred option and the current one.
        // As these numbers are at the upper end of the range of an u16_t, we don't need to care about the value
        // being a very high delta, because that would either land in the experimental range or overflow.
        // Options must be ordered, thus overflow can't occur and clients sending such packets are malicious.
        // They can't do anything with those malicious packets because we just use that number for aborting counting.
        options[i].delta = 65530;
    }
    coap_packet_parse(pkt, pkt->pkt, &options[0], *opt_num);
    // get actual number of parsed options
    u8_t actual_opt_num;
    for (actual_opt_num = 0; actual_opt_num < *opt_num; actual_opt_num++) {
        if (options[actual_opt_num].delta == 65530) {
            break;
        }
    }
    // no `-1` needed because `opt_num` is a length and `actual_opt_num` an index
    *opt_num = actual_opt_num;
    return OscoreNoError;
}

OscoreError get_payload_info(struct coap_packet* pkt, struct payload_info* info) {
    u16_t offset;
    u16_t len;
    struct net_buf* frag = coap_packet_get_payload(pkt, &offset, &len);
    ensure(!(frag == NULL && offset == 0xffff), OscoreCoapPacketParseError);
    ensure(!(frag == NULL && offset == 0), OscoreCoapPacketNoPayload);
    struct payload_info res = {
        .offset = offset,
        .len = len,
        .frag = frag,
    };
    *info = res;
    return OscoreNoError;
}

OscoreError read_payload(struct payload_info info, array payload) {
    u16_t new_pos;
    struct net_buf* ret = net_frag_read(info.frag, info.offset, &new_pos, info.len, &payload.ptr[0]);
    ensure(!(ret == NULL && new_pos == 0xFFFF), OscoreNetPacketReadError);
    return OscoreNoError;
}
