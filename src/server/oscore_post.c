/*
 * Copyright (c) 2016 Intel Corporation
 * Modified by Fraunhofer AISEC, see the COPYRIGHT file
 * at the top-level directory of this distribution for
 * a list of all changes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net/udp.h>
#include "oscore_post.h"
#include "../oscore/oscore.h"
#include "../util/macros.h"
#include "coap-server.h"

int oscore_post(struct coap_resource *resource,
                struct coap_packet *request)
{
    SYS_LOG_INF("oscore_post");

    struct sockaddr_in6 from;
    get_from_ip_addr(request, &from);
//    u8_t code = coap_header_get_code(request);
    u8_t type = coap_header_get_type(request);
    u16_t id = coap_header_get_id(request);
    u8_t token[8];
    u8_t tkl = coap_header_get_token(request, token);

    struct net_pkt* pkt = net_pkt_get_tx(context, K_FOREVER);
    struct net_buf* frag = net_pkt_get_data(context, K_FOREVER);

    net_pkt_frag_add(pkt, frag);

    if (type == COAP_TYPE_CON) {
        type = COAP_TYPE_ACK;
    } else {
        type = COAP_TYPE_NON_CON;
    }

    struct coap_packet response;
    try_einval(coap_packet_init(&response, pkt, 1, type,
                                tkl, &token[0],
                                COAP_RESPONSE_CODE_CONTENT, id));

    try_einval(coap_packet_append_option(&response, COAP_OPTION_CONTENT_FORMAT,
                                         &plain_text_format,
                                         sizeof(plain_text_format)));

    int r = coap_packet_append_payload_marker(&response);
    if (r) {
        net_pkt_unref(pkt);
        return -EINVAL;
    }

    u8_t* payload = "Hello World!";

    try_einval(coap_packet_append_payload(&response, payload,
                                          (u16_t)strlen((const char*)payload)));

    struct coap_packet oscore;
    try_oscore_einval(into_oscore(response, request, &oscore));

    int res = net_context_sendto(oscore.pkt, (const struct sockaddr *)&from,
                                 sizeof(struct sockaddr_in6),
                                 NULL, 0, NULL, NULL);
    SYS_LOG_INF("sent");
    return res;
}