/*
 * Copyright (c) 2015-2016 Intel Corporation
 * Modified by Fraunhofer AISEC, see the COPYRIGHT file
 * at the top-level directory of this distribution for
 * a list of all changes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NONE_COAP_SERVER_H
#define NONE_COAP_SERVER_H

#include <sys_io.h>
#include <net/coap.h>

extern struct net_context *context;
static const u8_t plain_text_format;

void coap_server_init();
int piggyback_get(struct coap_resource *resource,
                         struct coap_packet *request);
void get_from_ip_addr(struct coap_packet *cpkt,
                             struct sockaddr_in6 *from);
int test_post(struct coap_resource *resource,
                     struct coap_packet *request);
int test_del(struct coap_resource *resource,
                    struct coap_packet *request);
int test_put(struct coap_resource *resource,
                    struct coap_packet *request);
int query_get(struct coap_resource *resource,
                     struct coap_packet *request);
int separate_get(struct coap_resource *resource,
                        struct coap_packet *request);
int large_get(struct coap_resource *resource,
                     struct coap_packet *request);
int location_query_post(struct coap_resource *resource,
                               struct coap_packet *request);
int large_update_put(struct coap_resource *resource,
                            struct coap_packet *request);
int large_create_post(struct coap_resource *resource,
                             struct coap_packet *request);
int obs_get(struct coap_resource *resource,
                   struct coap_packet *request);
void obs_notify(struct coap_resource *resource,
                       struct coap_observer *observer);
int well_known_core_get(struct coap_resource *resource,
                               struct coap_packet *request);
int core_get(struct coap_resource *resource,
                    struct coap_packet *request);

#endif //NONE_COAP_SERVER_H
